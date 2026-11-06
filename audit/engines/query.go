package engines

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// DefaultQueryCacheSize matches the CodeGraph session cache bound in the
// design. The manager uses a FIFO cache of rendered QuerySpec values.
const DefaultQueryCacheSize = 512

const maxQueryTextBytes = 1 << 20

// Render compiles one DetectionIntent into a QuerySpec for the requested
// engine. It validates the intent's structural requirements (for example a
// sink/taint query may not have an empty sink list) before looking up a
// template. Language/engine availability is additionally checked by the
// manager using Probe capabilities.
func Render(engine string, intent DetectionIntent) (QuerySpec, error) {
	return render(engine, intent, "", "")
}

// RenderForSource renders with runtime engine/source identity. The identity is
// part of the cache key so a binary upgrade or a new commit never reuses stale
// query artifacts.
func RenderForSource(engine string, intent DetectionIntent, engineVersion, commit string) (QuerySpec, error) {
	return render(engine, intent, engineVersion, commit)
}

func render(engine string, intent DetectionIntent, engineVersion, commit string) (QuerySpec, error) {
	normalizedEngine := normalizeEngineName(engine)
	if normalizedEngine == "" {
		return QuerySpec{}, fmt.Errorf("%w: unknown engine %q", ErrUnsupported, engine)
	}
	if err := validateIntentForRender(intent); err != nil {
		return QuerySpec{}, err
	}
	intent.Language = normalizeIntentLanguage(intent.Language)
	if intent.Language == "" {
		return QuerySpec{}, fmt.Errorf("%w: intent language is required", ErrInvalidQuery)
	}

	spec, err := lookupTemplate(normalizedEngine, intent.Language, intent.QueryKind)
	fallbackFrom := ""
	if err != nil && intent.QueryKind == QueryKindTaint && errors.Is(err, ErrUnsupported) {
		// Sink-only templates are still useful when an engine has no taint
		// template for a language. Keep the engine in the job set instead of
		// dropping the intent entirely.
		if sinkSpec, sinkErr := lookupTemplate(normalizedEngine, intent.Language, QueryKindSink); sinkErr == nil {
			spec = sinkSpec
			intent.QueryKind = QueryKindSink
			fallbackFrom = QueryKindTaint
			err = nil
		}
	}
	if err != nil {
		return QuerySpec{}, err
	}
	params := buildQueryParams(intent)
	engineVersion = strings.TrimSpace(engineVersion)
	commit = strings.TrimSpace(commit)
	irHash := IntentIRHash(intent)
	cacheKey := queryCacheKeyParts(normalizedEngine, intent.Language, intent.QueryKind, spec.ID, params, engineVersion, commit, irHash, TemplateVersion)
	specID := "qs-" + cacheKey[:16]

	queryText, err := spec.render(templateInput{
		Intent:   intent,
		Params:   params,
		SpecID:   specID,
		Template: spec.ID,
	})
	if err != nil {
		return QuerySpec{}, err
	}
	if strings.TrimSpace(queryText) == "" {
		return QuerySpec{}, fmt.Errorf("%w: template %s produced empty query text", ErrInvalidQuery, spec.ID)
	}
	if len(queryText) > maxQueryTextBytes {
		return QuerySpec{}, fmt.Errorf("%w: query text exceeds %d bytes", ErrInvalidQuery, maxQueryTextBytes)
	}

	provenance := map[string]any{
		"template_version": TemplateVersion,
		"ir_hash":          irHash,
		"engine_version":   engineVersion,
		"commit":           commit,
		"generated_by":     "template",
		"verified":         false,
		"engine_language":  spec.Language,
		"notes":            "Template assets are verified only for the engine/language combination covered by integration tests.",
	}
	if fallbackFrom != "" {
		provenance["fallback"] = true
		provenance["fallback_from"] = fallbackFrom
	}

	return QuerySpec{
		ID:              specID,
		IntentID:        intent.ID,
		Engine:          normalizedEngine,
		Language:        intent.Language,
		QueryKind:       intent.QueryKind,
		Template:        spec.ID,
		TemplateVersion: TemplateVersion,
		EngineVersion:   engineVersion,
		Commit:          commit,
		IRHash:          irHash,
		QueryText:       queryText,
		QueryPath:       queryPathFor(normalizedEngine, specID),
		ExpectedFormat:  spec.Format,
		GeneratedBy:     "template",
		Params:          params,
		Provenance:      provenance,
	}, nil
}

// RenderAll renders every preferred engine for an intent. Engine-specific
// failures (unsupported templates, unusable symbol sets) are collected and
// skipped as long as at least one engine renders; callers that need to record
// per-engine gaps should call Render directly and inspect the error.
func RenderAll(intent DetectionIntent) ([]QuerySpec, error) {
	engines := intent.PreferredEngines
	if len(engines) == 0 {
		engines = []string{EngineCodeQL, EngineJoern, EngineCodeGraph}
	}
	seen := make(map[string]struct{}, len(engines))
	specs := make([]QuerySpec, 0, len(engines))
	failures := make([]error, 0)
	for _, rawEngine := range engines {
		engine := normalizeEngineName(rawEngine)
		if engine == "" {
			failures = append(failures, fmt.Errorf("%w: unknown engine %q", ErrUnsupported, rawEngine))
			continue
		}
		if _, exists := seen[engine]; exists {
			continue
		}
		seen[engine] = struct{}{}

		spec, err := Render(engine, intent)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		specs = append(specs, spec)
	}
	if len(specs) == 0 {
		if len(failures) == 0 {
			return nil, fmt.Errorf("%w: intent has no preferred engines", ErrUnsupported)
		}
		return nil, errors.Join(failures...)
	}
	return specs, nil
}

// ValidateQuerySpec performs engine-independent QuerySpec validation. Engine
// adapters still validate their native query syntax and capabilities.
func ValidateQuerySpec(q QuerySpec) error {
	if normalizeEngineName(q.Engine) == "" {
		return fmt.Errorf("%w: unknown engine %q", ErrInvalidQuery, q.Engine)
	}
	if strings.TrimSpace(q.Language) == "" {
		return fmt.Errorf("%w: query language is required", ErrInvalidQuery)
	}
	if !validQueryKind(q.QueryKind) {
		return fmt.Errorf("%w: unknown query kind %q", ErrInvalidQuery, q.QueryKind)
	}
	if strings.TrimSpace(q.Template) == "" {
		return fmt.Errorf("%w: query template is required", ErrInvalidQuery)
	}
	if strings.TrimSpace(q.QueryText) == "" {
		return fmt.Errorf("%w: query text is required", ErrInvalidQuery)
	}
	if len(q.QueryText) > maxQueryTextBytes {
		return fmt.Errorf("%w: query text exceeds %d bytes", ErrInvalidQuery, maxQueryTextBytes)
	}
	if q.QueryKind == QueryKindSink || q.QueryKind == QueryKindTaint {
		if len(paramStringSlice(q.Params, "sinks")) == 0 {
			return fmt.Errorf("%w: %s query requires at least one sink", ErrInvalidQuery, q.QueryKind)
		}
	}
	if q.QueryKind == QueryKindTaint {
		if len(paramStringSlice(q.Params, "sources")) == 0 {
			return fmt.Errorf("%w: taint query requires at least one source", ErrInvalidQuery)
		}
	}
	return nil
}

func validateIntentForRender(intent DetectionIntent) error {
	if strings.TrimSpace(intent.Language) == "" {
		return fmt.Errorf("%w: intent language is required", ErrInvalidQuery)
	}
	if !validQueryKind(intent.QueryKind) {
		return fmt.Errorf("%w: unknown query kind %q", ErrInvalidQuery, intent.QueryKind)
	}
	if intent.QueryKind == QueryKindSink || intent.QueryKind == QueryKindTaint {
		if len(intent.Sinks) == 0 {
			return fmt.Errorf("%w: %s intent requires at least one sink", ErrInvalidQuery, intent.QueryKind)
		}
	}
	if intent.QueryKind == QueryKindTaint && len(intent.Sources) == 0 {
		return fmt.Errorf("%w: taint intent requires at least one source", ErrInvalidQuery)
	}
	return nil
}

func buildQueryParams(intent DetectionIntent) map[string]any {
	maxResults := intent.Constraints.MaxResults
	if maxResults <= 0 {
		maxResults = 200
	}
	params := map[string]any{
		"sources":        patternValues(intent.Sources),
		"sinks":          patternValues(intent.Sinks),
		"sanitizers":     patternValues(intent.Sanitizers),
		"propagators":    patternValues(intent.Propagators),
		"sink_symbols":   methodSymbols(intent.Sinks),
		"source_symbols": methodSymbols(intent.Sources),
		"pattern_digest": patternDigest(intent),
		"scope_paths":    stringSliceOrEmpty(intent.Scope.Paths),
		"scope_modules":  stringSliceOrEmpty(intent.Scope.Modules),
		"scope_symbols":  stringSliceOrEmpty(intent.Scope.Symbols),
		"scope_exclude":  stringSliceOrEmpty(intent.Scope.Exclude),
		"max_results":    maxResults,
		"severity_min":   strings.TrimSpace(intent.Constraints.SeverityMin),
		"cwe":            strings.TrimSpace(intent.CWE),
	}
	if intent.Constraints.Reachable != nil {
		params["reachable"] = *intent.Constraints.Reachable
	}
	if intent.Constraints.AuthRequired != nil {
		params["auth_required"] = *intent.Constraints.AuthRequired
	}
	return params
}

func patternValues(patterns []Pattern) []string {
	out := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		text := strings.TrimSpace(pattern.Pattern)
		if text == "" {
			continue
		}
		if _, exists := seen[text]; exists {
			continue
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	sort.Strings(out)
	if len(out) > maxIntentPatterns {
		out = out[:maxIntentPatterns]
	}
	return out
}

func patternDigest(intent DetectionIntent) string {
	values := make([]string, 0, len(intent.Sources)+len(intent.Sinks)+len(intent.Sanitizers)+len(intent.Propagators))
	for _, list := range [][]Pattern{intent.Sources, intent.Sinks, intent.Sanitizers, intent.Propagators} {
		for _, pattern := range list {
			values = append(values, normalizeMatch(pattern.Match)+":"+strings.TrimSpace(pattern.Pattern))
		}
	}
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, "\x1f")))
	return hex.EncodeToString(sum[:8])
}

func stringSliceOrEmpty(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	if out == nil {
		return []string{}
	}
	return out
}

func queryPathFor(engine, specID string) string {
	switch engine {
	case EngineCodeQL:
		return "queries/codeql/" + specID + "/query.ql"
	case EngineJoern:
		return "queries/joern/" + specID + "/query.sc"
	case EngineCodeGraph:
		return "queries/codegraph/" + specID + ".txt"
	default:
		return ""
	}
}

// QueryCacheKey computes the canonical cache key for a rendered QuerySpec:
// sha256(engine|language|query_kind|template|canonical(params)). The
// runtime-only ArtifactPath is deliberately excluded.
func QueryCacheKey(q QuerySpec) string {
	return queryCacheKeyParts(q.Engine, q.Language, q.QueryKind, q.Template, q.Params, q.EngineVersion, q.Commit, q.IRHash, q.TemplateVersion)
}

func queryCacheKeyParts(engine, language, queryKind, templateID string, params map[string]any, engineVersion, commit, irHash, templateVersion string) string {
	normalizedEngine := normalizeEngineName(engine)
	if normalizedEngine == "" {
		normalizedEngine = strings.ToLower(strings.TrimSpace(engine))
	}
	engine = normalizedEngine
	language = normalizeIntentLanguage(language)
	queryKind = strings.ToLower(strings.TrimSpace(queryKind))
	templateID = strings.TrimSpace(templateID)
	templateVersion = strings.TrimSpace(templateVersion)
	if templateVersion == "" {
		templateVersion = TemplateVersion
	}
	if params == nil {
		params = map[string]any{}
	}
	material := struct {
		Engine          string         `json:"engine"`
		Language        string         `json:"language"`
		QueryKind       string         `json:"query_kind"`
		Template        string         `json:"template"`
		TemplateVersion string         `json:"template_version"`
		EngineVersion   string         `json:"engine_version"`
		Commit          string         `json:"commit"`
		IRHash          string         `json:"ir_hash"`
		Params          map[string]any `json:"params"`
	}{
		Engine:          engine,
		Language:        language,
		QueryKind:       queryKind,
		Template:        templateID,
		TemplateVersion: templateVersion,
		EngineVersion:   strings.TrimSpace(engineVersion),
		Commit:          strings.TrimSpace(commit),
		IRHash:          strings.TrimSpace(irHash),
		Params:          params,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		// Generated params are always JSON-marshalable. Keep the key
		// deterministic for callers that pass an exotic map by falling back to
		// a stable string projection of the individual fields.
		encoded = []byte(fmt.Sprintf("%s|%s|%s|%s|%v", engine, language, queryKind, templateID, params))
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// IntentIRHash returns a deterministic hash of the engine-independent intent
// IR. Runtime-only provenance is excluded so the same logical intent remains
// cache-compatible across model invocations.
func IntentIRHash(intent DetectionIntent) string {
	material := struct {
		Language         string      `json:"language"`
		CWE              string      `json:"cwe"`
		QueryKind        string      `json:"query_kind"`
		Sources          []Pattern   `json:"sources"`
		Sinks            []Pattern   `json:"sinks"`
		Sanitizers       []Pattern   `json:"sanitizers"`
		Propagators      []Pattern   `json:"propagators"`
		Scope            Scope       `json:"scope"`
		Constraints      Constraints `json:"constraints"`
		PreferredEngines []string    `json:"preferred_engines"`
	}{
		Language:         normalizeIntentLanguage(intent.Language),
		CWE:              normalizeCWEID(intent.CWE),
		QueryKind:        strings.ToLower(strings.TrimSpace(intent.QueryKind)),
		Sources:          sortedPatterns(intent.Sources),
		Sinks:            sortedPatterns(intent.Sinks),
		Sanitizers:       sortedPatterns(intent.Sanitizers),
		Propagators:      sortedPatterns(intent.Propagators),
		Scope:            canonicalScope(intent.Scope),
		Constraints:      intent.Constraints,
		PreferredEngines: sortedStrings(intent.PreferredEngines),
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		encoded = []byte(fmt.Sprintf("%+v", material))
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func sortedPatterns(patterns []Pattern) []Pattern {
	out := append([]Pattern(nil), patterns...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Match != out[j].Match {
			return out[i].Match < out[j].Match
		}
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func canonicalScope(scope Scope) Scope {
	return Scope{
		Paths:   sortedStrings(scope.Paths),
		Modules: sortedStrings(scope.Modules),
		Symbols: sortedStrings(scope.Symbols),
		Exclude: sortedStrings(scope.Exclude),
	}
}

// QueryCache is a bounded FIFO cache of rendered QuerySpec values. It is safe
// for concurrent use.
type QueryCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]QuerySpec
	order   []string
	hits    int
	misses  int
}

// NewQueryCache creates a cache with the given maximum entry count. A
// non-positive bound selects DefaultQueryCacheSize.
func NewQueryCache(maxEntries int) *QueryCache {
	if maxEntries <= 0 {
		maxEntries = DefaultQueryCacheSize
	}
	return &QueryCache{
		max:     maxEntries,
		entries: make(map[string]QuerySpec),
	}
}

// Get returns a copy of the cached spec and records a hit or miss.
func (c *QueryCache) Get(key string) (QuerySpec, bool) {
	if c == nil {
		return QuerySpec{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]QuerySpec)
	}
	spec, ok := c.entries[key]
	if !ok {
		c.misses++
		return QuerySpec{}, false
	}
	c.hits++
	return cloneQuerySpec(spec), true
}

// Put stores spec under key and evicts the oldest entry when the cache is full.
// Updating an existing key does not change its FIFO position.
func (c *QueryCache) Put(key string, spec QuerySpec) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]QuerySpec)
	}
	if _, exists := c.entries[key]; exists {
		c.entries[key] = cloneQuerySpec(spec)
		return
	}
	for len(c.entries) >= c.max && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
	c.entries[key] = cloneQuerySpec(spec)
	c.order = append(c.order, key)
}

// Len returns the current number of cached specs.
func (c *QueryCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Hits returns the number of successful Get calls.
func (c *QueryCache) Hits() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits
}

// Misses returns the number of failed Get calls.
func (c *QueryCache) Misses() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.misses
}

func cloneQuerySpec(spec QuerySpec) QuerySpec {
	clone := spec
	if spec.Params != nil {
		clone.Params = make(map[string]any, len(spec.Params))
		for key, value := range spec.Params {
			clone.Params[key] = cloneParamValue(value)
		}
	}
	if spec.Provenance != nil {
		clone.Provenance = make(map[string]any, len(spec.Provenance))
		for key, value := range spec.Provenance {
			clone.Provenance[key] = cloneParamValue(value)
		}
	}
	return clone
}

func cloneParamValue(value any) any {
	switch typed := value.(type) {
	case []string:
		if typed == nil {
			return []string(nil)
		}
		out := make([]string, len(typed))
		copy(out, typed)
		return out
	case []any:
		if typed == nil {
			return []any(nil)
		}
		out := make([]any, len(typed))
		for index, entry := range typed {
			out[index] = cloneParamValue(entry)
		}
		return out
	case map[string]any:
		if typed == nil {
			return map[string]any(nil)
		}
		out := make(map[string]any, len(typed))
		for key, entry := range typed {
			out[key] = cloneParamValue(entry)
		}
		return out
	default:
		return value
	}
}

func paramStringSlice(params map[string]any, key string) []string {
	if params == nil {
		return nil
	}
	switch values := params[key].(type) {
	case []string:
		return values
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

// PatternSymbols exposes the normalized method-name symbols used in generated
// engine queries. It is useful for diagnostics and for follow-up server wiring.
func PatternSymbols(patterns []Pattern) []string {
	return methodSymbols(patterns)
}
