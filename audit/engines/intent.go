package engines

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/audit"
)

// Intent construction limits. The registry can contain hundreds of sink
// symbols for a single CWE; bounding the intent keeps database JSON, query
// text, and prompt context predictable. The query renderer applies a tighter
// engine-specific cap later.
const (
	minIntentPatternLength = 4
	maxIntentPatterns      = 200
	maxFrameworkPatternLen = 512
)

// p0CWEOrder is the deterministic P0 ordering from appendix A of the design.
// Intents for these CWEs sort ahead of all other planned CWEs.
var p0CWEOrder = []string{
	"CWE-78", "CWE-94", "CWE-22", "CWE-918", "CWE-502",
	"CWE-79", "CWE-89", "CWE-611", "CWE-327", "CWE-287",
	"CWE-798", "CWE-434", "CWE-347", "CWE-295", "CWE-352",
	"CWE-862", "CWE-639", "CWE-470", "CWE-601", "CWE-1321",
	"CWE-93", "CWE-940", "CWE-119", "CWE-134", "CWE-416",
	"CWE-415",
}

var (
	intentCWEIDPattern      = regexp.MustCompile(`^CWE-[0-9]+$`)
	symbolIdentifierPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	frameworkIdentifierRE   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	genericPatternNames     = map[string]struct{}{
		"get": {}, "set": {}, "read": {}, "write": {}, "open": {},
		"close": {}, "run": {}, "find": {}, "command": {},
	}
	// broadSourceNames are terminal identifiers that match too much when used
	// as an engine-level source regex (for example flask.request.args -> args).
	// Dotted framework patterns remain available for CodeGraph, but they must
	// not become a bare method-name source in CodeQL/Joern.
	broadSourceNames = map[string]struct{}{
		"args": {}, "argument": {}, "arguments": {}, "body": {}, "code": {},
		"config": {}, "content": {}, "cookie": {}, "cookies": {}, "data": {},
		"element": {}, "elements": {}, "env": {}, "field": {}, "fields": {},
		"file": {}, "files": {}, "form": {}, "header": {}, "headers": {},
		"host": {}, "id": {}, "input": {}, "item": {}, "items": {}, "json": {},
		"key": {}, "list": {}, "map": {}, "method": {}, "methods": {},
		"name": {}, "object": {}, "option": {}, "options": {}, "param": {},
		"params": {}, "path": {}, "post": {}, "query": {}, "request": {},
		"response": {}, "result": {}, "results": {}, "session": {},
		"setting": {}, "settings": {}, "source": {}, "string": {}, "text": {},
		"token": {}, "url": {}, "user": {}, "value": {}, "values": {},
	}
)

// BuildDetectionIntents deterministically converts a plan and registry into
// sink_rule detection intents. For each planned language/CWE it collects sink
// definitions for that CWE, source definitions for the language, sanitizer
// definitions for that CWE (or wildcard), and framework taint pairs. A CWE
// without any sink is skipped because a sink_rule intent with no sink would be
// unexecutable; phase-requirement intents are constructed by the caller.
func BuildDetectionIntents(plan audit.Plan, reg audit.Registry) ([]DetectionIntent, error) {
	languages, cwesByLanguage := plannedLanguageCWEs(plan)
	if len(languages) == 0 {
		return []DetectionIntent{}, nil
	}

	cweNames := make(map[string]string, len(reg.CWE))
	for _, definition := range reg.CWE {
		id := normalizeCWEID(definition.ID)
		if id == "" {
			continue
		}
		cweNames[id] = strings.TrimSpace(definition.Name)
	}

	intents := make([]DetectionIntent, 0)
	for _, language := range languages {
		plannedCWEs := cwesByLanguage[language]
		if len(plannedCWEs) == 0 {
			continue
		}

		taint, err := buildTaintContributions(reg, language)
		if err != nil {
			return nil, err
		}
		defs := reg.SinksFor(language)
		languageSources := patternsFromDefinitions(defs, "source", "")

		seenCWE := make(map[string]struct{}, len(plannedCWEs))
		for planIndex, rawCWE := range plannedCWEs {
			cwe := normalizeCWEID(rawCWE)
			if !intentCWEIDPattern.MatchString(cwe) {
				continue
			}
			if _, exists := seenCWE[cwe]; exists {
				continue
			}
			seenCWE[cwe] = struct{}{}

			sinks := patternsFromDefinitions(defs, "sink", cwe)
			sinks = append(sinks, taint.sinks[cwe]...)
			sinks = dedupePatterns(sinks)
			if len(sinks) == 0 {
				// sink_rule intents without a sink are explicitly skipped.
				continue
			}

			sources := append(append([]Pattern(nil), languageSources...), taint.sources[cwe]...)
			sources = dedupePatterns(sources)
			sanitizers := dedupePatterns(patternsFromDefinitions(defs, "sanitizer", cwe))

			queryKind := QueryKindSink
			if len(sources) > 0 {
				queryKind = QueryKindTaint
			}

			scope := Scope{
				Paths:   []string{},
				Modules: append([]string(nil), plan.Modules...),
				Symbols: []string{},
				Exclude: []string{},
			}
			intent := DetectionIntent{
				ID:               detectionIntentID(language, cwe, queryKind, sinks),
				Origin:           OriginSinkRule,
				Language:         language,
				CWE:              cwe,
				Title:            intentTitle(cweNames[cwe], cwe, language, queryKind),
				QueryKind:        queryKind,
				Sources:          sources,
				Sinks:            sinks,
				Sanitizers:       sanitizers,
				Propagators:      []Pattern{},
				Scope:            scope,
				Constraints:      defaultIntentConstraints(),
				PreferredEngines: []string{EngineCodeQL, EngineJoern, EngineCodeGraph},
				Priority:         intentPriority(cwe, planIndex),
			}
			intents = append(intents, intent)
		}
	}

	// P0 CWEs first in the fixed appendix-A order; stable sorting preserves
	// plan language order for equal priorities.
	sort.SliceStable(intents, func(i, j int) bool {
		return intents[i].Priority > intents[j].Priority
	})
	return intents, nil
}

func defaultIntentConstraints() Constraints {
	return Constraints{
		MaxResults:  200,
		SeverityMin: "medium",
	}
}

// plannedLanguageCWEs merges plan language aliases into canonical audit
// languages and returns a deterministic language order plus the planned CWE
// list for each language.
func plannedLanguageCWEs(plan audit.Plan) ([]string, map[string][]string) {
	languageOrder := make([]string, 0, len(plan.Languages))
	seenLanguage := make(map[string]struct{})
	cwesByLanguage := make(map[string][]string)
	cweSeen := make(map[string]map[string]struct{})

	addLanguage := func(raw string) string {
		language := normalizeIntentLanguage(raw)
		if language == "" {
			return ""
		}
		if _, exists := seenLanguage[language]; !exists {
			seenLanguage[language] = struct{}{}
			languageOrder = append(languageOrder, language)
		}
		return language
	}

	for _, raw := range plan.Languages {
		addLanguage(raw)
	}

	keys := make([]string, 0, len(plan.PlannedCWEs))
	for rawLanguage := range plan.PlannedCWEs {
		keys = append(keys, rawLanguage)
	}
	sort.Strings(keys)
	for _, rawLanguage := range keys {
		language := addLanguage(rawLanguage)
		if language == "" {
			continue
		}
		if cweSeen[language] == nil {
			cweSeen[language] = make(map[string]struct{})
		}
		for _, rawCWE := range plan.PlannedCWEs[rawLanguage] {
			cwe := normalizeCWEID(rawCWE)
			if cwe == "" {
				continue
			}
			if _, exists := cweSeen[language][cwe]; exists {
				continue
			}
			cweSeen[language][cwe] = struct{}{}
			cwesByLanguage[language] = append(cwesByLanguage[language], cwe)
		}
	}

	// Languages named only by PlannedCWEs were added above. Any language with
	// no planned CWEs is retained in the order but yields no intents.
	return languageOrder, cwesByLanguage
}

func normalizeIntentLanguage(raw string) string {
	language := audit.NormalizeLanguage(raw)
	if language == "" {
		language = strings.ToLower(strings.TrimSpace(raw))
	}
	return language
}

func normalizeCWEID(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

func normalizeMatch(match string) string {
	switch strings.ToLower(strings.TrimSpace(match)) {
	case "", MatchMethodCall:
		return MatchMethodCall
	case MatchType:
		return MatchType
	case MatchRegex:
		return MatchRegex
	default:
		return ""
	}
}

func intentPriority(cwe string, planIndex int) int {
	for index, p0 := range p0CWEOrder {
		if cwe == p0 {
			return priorityP0Base - index
		}
	}
	return priorityOtherBase - planIndex
}

func intentTitle(cweName, cwe, language, queryKind string) string {
	label := strings.TrimSpace(cweName)
	if label == "" {
		label = cwe
	}
	switch queryKind {
	case QueryKindTaint:
		return fmt.Sprintf("%s (%s) tainted dataflow in %s", label, cwe, language)
	default:
		return fmt.Sprintf("%s (%s) sink detection in %s", label, cwe, language)
	}
}

func detectionIntentID(language, cwe, queryKind string, sinks []Pattern) string {
	patterns := make([]string, 0, len(sinks))
	for _, sink := range sinks {
		patterns = append(patterns, sink.Pattern)
	}
	sort.Strings(patterns)
	material := strings.Join([]string{language, cwe, queryKind, strings.Join(patterns, "\x1f")}, "|")
	sum := sha256.Sum256([]byte(material))
	return "intent-" + hex.EncodeToString(sum[:])
}

// patternsFromDefinitions extracts deduplicatable patterns from registry
// definitions. For kind=source, CWE filtering is intentionally skipped because
// registry sources are language-wide (usually cweId "*"). For kind=sink, a
// wildcard definition is not a concrete sink and is skipped.
func patternsFromDefinitions(defs []audit.SinkDefinition, kind, cwe string) []Pattern {
	out := make([]Pattern, 0)
	for _, definition := range defs {
		if !strings.EqualFold(strings.TrimSpace(definition.Kind), kind) {
			continue
		}
		defCWE := normalizeCWEID(definition.CWEID)
		switch kind {
		case "sink":
			if defCWE == "" || defCWE == "*" || defCWE != cwe {
				continue
			}
		case "sanitizer":
			if defCWE != "" && defCWE != "*" && defCWE != cwe {
				continue
			}
		}

		symbol, ok := shortPatternSymbol(definition.Symbol)
		if !ok {
			continue
		}
		if kind == "source" && isBroadSourceName(symbol) {
			continue
		}
		name := strings.TrimSpace(definition.Description)
		if name == "" {
			name = symbol
		}
		out = append(out, Pattern{Name: name, Pattern: symbol, Match: MatchMethodCall})
	}
	return out
}

// shortPatternSymbol reduces a registry API symbol to its terminal callable
// name. A trailing call signature is removed before the last dotted segment so
// "Statement.executeQuery(java.lang.String)" still yields executeQuery, while
// "cursor().execute" yields execute. Unbalanced parentheses fall back to the
// first-open-paren rule, and generic/short names are dropped.
func shortPatternSymbol(raw string) (string, bool) {
	candidate := stripTrailingCallSignature(strings.TrimSpace(raw))
	if idx := strings.LastIndexByte(candidate, '.'); idx >= 0 {
		candidate = candidate[idx+1:]
	}
	if idx := strings.IndexByte(candidate, '('); idx >= 0 {
		candidate = candidate[:idx]
	}
	if idx := strings.LastIndex(candidate, "::"); idx >= 0 {
		candidate = candidate[idx+2:]
	}
	candidate = strings.Join(strings.Fields(candidate), "")
	if !symbolIdentifierPattern.MatchString(candidate) {
		return "", false
	}
	if len(candidate) < minIntentPatternLength {
		return "", false
	}
	if _, generic := genericPatternNames[strings.ToLower(candidate)]; generic {
		return "", false
	}
	return candidate, true
}

// stripTrailingCallSignature removes the final balanced "(...)" call suffix.
// It intentionally leaves interior calls in place: cursor().execute has no
// trailing signature, while executeQuery(String) does.
func stripTrailingCallSignature(raw string) string {
	if raw == "" || !strings.HasSuffix(raw, ")") {
		return raw
	}
	depth := 0
	for index := len(raw) - 1; index >= 0; index-- {
		switch raw[index] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return strings.TrimSpace(raw[:index])
			}
		}
	}
	return raw
}

func dedupePatterns(patterns []Pattern) []Pattern {
	out := make([]Pattern, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		pattern.Pattern = strings.TrimSpace(pattern.Pattern)
		pattern.Name = strings.TrimSpace(pattern.Name)
		pattern.Match = normalizeMatch(pattern.Match)
		if pattern.Pattern == "" || pattern.Match == "" {
			continue
		}
		key := pattern.Match + "\x00" + pattern.Pattern
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, pattern)
		if len(out) >= maxIntentPatterns {
			break
		}
	}
	return out
}

// taintContributions holds framework-derived sources and sinks keyed by CWE.
type taintContributions struct {
	sources map[string][]Pattern
	sinks   map[string][]Pattern
}

type taintFramework struct {
	Name    string                  `json:"name"`
	Sources []taintFrameworkPattern `json:"sources"`
	Sinks   []taintFrameworkPattern `json:"sinks"`
	Pairs   []taintFrameworkPair    `json:"source_sink_pairs"`
}

type taintFrameworkPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Type    string `json:"type"`
}

type taintFrameworkPair struct {
	Source string `json:"source"`
	Sink   string `json:"sink"`
	CWE    string `json:"cwe"`
}

func buildTaintContributions(reg audit.Registry, language string) (taintContributions, error) {
	out := taintContributions{
		sources: make(map[string][]Pattern),
		sinks:   make(map[string][]Pattern),
	}
	for _, registry := range reg.TaintsFor(language) {
		frameworks, err := decodeTaintFrameworks(registry.Frameworks)
		if err != nil {
			name := strings.TrimSpace(registry.RegistryName)
			if name == "" {
				name = language
			}
			return out, fmt.Errorf("decode taint registry %q for %s: %w", name, language, err)
		}
		for _, framework := range frameworks {
			sourceByName := make(map[string]taintFrameworkPattern, len(framework.Sources))
			for _, source := range framework.Sources {
				sourceByName[strings.TrimSpace(source.Name)] = source
				sourceByName[strings.ToLower(strings.TrimSpace(source.Name))] = source
			}
			sinkByName := make(map[string]taintFrameworkPattern, len(framework.Sinks))
			for _, sink := range framework.Sinks {
				sinkByName[strings.TrimSpace(sink.Name)] = sink
				sinkByName[strings.ToLower(strings.TrimSpace(sink.Name))] = sink
			}
			frameworkName := strings.TrimSpace(framework.Name)
			for _, pair := range framework.Pairs {
				cwe := normalizeCWEID(pair.CWE)
				if !intentCWEIDPattern.MatchString(cwe) {
					continue
				}
				sourceName, sourcePattern := frameworkPatternForPair(sourceByName, pair.Source)
				sinkName, sinkPattern := frameworkPatternForPair(sinkByName, pair.Sink)
				out.sources[cwe] = appendFrameworkPatterns(
					out.sources[cwe], frameworkName, "source", sourceName, sourcePattern)
				out.sinks[cwe] = appendFrameworkPatterns(
					out.sinks[cwe], frameworkName, "sink", sinkName, sinkPattern)
			}
		}
	}
	return out, nil
}

// decodeTaintFrameworks accepts the exported schema's array-of-frameworks form
// as well as a {frameworks:[...]} wrapper or a single framework object. The
// registry schema is owned by Omni-Audit, so being liberal here avoids a
// dependency on one exact serialization.
func decodeTaintFrameworks(raw json.RawMessage) ([]taintFramework, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	switch trimmed[0] {
	case '[':
		var frameworks []taintFramework
		if err := json.Unmarshal(trimmed, &frameworks); err != nil {
			return nil, err
		}
		return frameworks, nil
	case '{':
		var wrapper struct {
			Frameworks []taintFramework `json:"frameworks"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err == nil && wrapper.Frameworks != nil {
			return wrapper.Frameworks, nil
		}
		var single taintFramework
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return nil, err
		}
		return []taintFramework{single}, nil
	default:
		return nil, fmt.Errorf("frameworks must be a JSON array or object")
	}
}

func frameworkPatternForPair(index map[string]taintFrameworkPattern, name string) (string, string) {
	trimmed := strings.TrimSpace(name)
	if entry, ok := index[trimmed]; ok {
		pattern := strings.TrimSpace(entry.Pattern)
		if pattern != "" {
			return firstNonBlank(entry.Name, trimmed), pattern
		}
	}
	if entry, ok := index[strings.ToLower(trimmed)]; ok {
		pattern := strings.TrimSpace(entry.Pattern)
		if pattern != "" {
			return firstNonBlank(entry.Name, trimmed), pattern
		}
	}
	return trimmed, trimmed
}

func appendFrameworkPatterns(list []Pattern, frameworkName, kind, name, raw string) []Pattern {
	raw = normalizeFrameworkPattern(raw)
	if raw == "" {
		return list
	}
	displayName := strings.TrimSpace(frameworkName)
	if displayName == "" {
		displayName = "framework"
	}
	if name = strings.TrimSpace(name); name != "" {
		displayName = displayName + "/" + kind + "/" + name
	} else {
		displayName = displayName + "/" + kind
	}

	match := MatchRegex
	if strings.HasPrefix(raw, "@") {
		match = MatchType
	}
	if kind == "source" && isBroadSourcePattern(raw) {
		return list
	}
	list = append(list, Pattern{Name: displayName, Pattern: raw, Match: match})
	if match == MatchRegex {
		for _, symbol := range frameworkMethodSymbols(raw) {
			if kind == "source" && isBroadSourceName(symbol) {
				continue
			}
			list = append(list, Pattern{Name: displayName, Pattern: symbol, Match: MatchMethodCall})
		}
	}
	return list
}

func isBroadSourceName(symbol string) bool {
	_, broad := broadSourceNames[strings.ToLower(strings.TrimSpace(symbol))]
	return broad
}

func isBroadSourcePattern(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return true
	}
	if strings.Contains(trimmed, ".*") || strings.Contains(trimmed, ".+") {
		return true
	}
	// Strip simple regex anchors and escapes before checking the terminal name.
	cleaned := strings.Trim(trimmed, "^$")
	cleaned = strings.NewReplacer(`\.`, ".", `\(`, "(", `\)`, ")", `\|`, "|").Replace(cleaned)
	if strings.ContainsAny(cleaned, "|()[]{}?*+") {
		return false
	}
	if _, broad := broadSourceNames[strings.ToLower(cleaned)]; broad {
		return true
	}
	return false
}

func normalizeFrameworkPattern(raw string) string {
	cleaned := strings.TrimSpace(raw)
	cleaned = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		default:
			return r
		}
	}, cleaned)
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	if len(cleaned) > maxFrameworkPatternLen {
		cleaned = cleaned[:maxFrameworkPatternLen]
	}
	return cleaned
}

// frameworkMethodSymbols best-effort extracts callable identifiers from a
// framework regex pattern (for example "executeQuery|execute"). The raw regex is
// retained as a separate pattern for CodeGraph, while CodeQL/Joern name lists
// use only these sanitized identifiers.
func frameworkMethodSymbols(raw string) []string {
	segments := strings.Split(raw, "|")
	seen := make(map[string]struct{})
	out := make([]string, 0, len(segments))
	for _, segment := range segments {
		identifiers := frameworkIdentifierRE.FindAllString(segment, -1)
		if len(identifiers) == 0 {
			continue
		}
		candidate := identifiers[len(identifiers)-1]
		if len(candidate) < minIntentPatternLength {
			continue
		}
		if _, generic := genericPatternNames[strings.ToLower(candidate)]; generic {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
