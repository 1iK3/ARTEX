package engines

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultEngineConcurrency = 1
	MaxEngineConcurrency     = 4
)

// Manager owns the engine registry, probe capabilities, prepared artifacts,
// and the rendered-query cache. It is safe for concurrent use; engine calls are
// made outside the manager lock.
type Manager struct {
	mu           sync.Mutex
	engines      map[string]Engine
	capabilities map[string]Capability
	prepared     map[string]preparedState
	cache        *QueryCache
	sourceCommit string
	concurrency  int
}

type preparedState struct {
	prepared    Prepared
	fingerprint string
}

// NewManager builds a manager with a default 512-entry query cache.
func NewManager(engines ...Engine) *Manager {
	return NewManagerWithCache(NewQueryCache(DefaultQueryCacheSize), engines...)
}

// NewManagerWithCache builds a manager using an explicit query cache. A nil
// cache is replaced with the default cache.
func NewManagerWithCache(cache *QueryCache, engines ...Engine) *Manager {
	if cache == nil {
		cache = NewQueryCache(DefaultQueryCacheSize)
	}
	manager := &Manager{
		engines:      make(map[string]Engine),
		capabilities: make(map[string]Capability),
		prepared:     make(map[string]preparedState),
		cache:        cache,
		concurrency:  DefaultEngineConcurrency,
	}
	for _, engine := range engines {
		_ = manager.Register(engine)
	}
	return manager
}

// SetEngineConcurrency bounds the number of intent/engine jobs that may call
// into adapters at the same time. Values below one restore the safe default;
// values above MaxEngineConcurrency are capped.
func (m *Manager) SetEngineConcurrency(limit int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.concurrency = normalizeEngineConcurrency(limit)
}

// Register adds or replaces one engine. Registering an engine clears its
// cached capability and prepared artifact.
func (m *Manager) Register(engine Engine) error {
	if m == nil || engine == nil {
		return errors.New("engines: nil engine")
	}
	name := normalizeEngineName(engine.Name())
	if name == "" {
		return fmt.Errorf("engines: unsupported engine name %q", engine.Name())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.engines == nil {
		m.engines = make(map[string]Engine)
	}
	m.engines[name] = engine
	delete(m.capabilities, name)
	delete(m.prepared, name)
	return nil
}

// Cache returns the manager's rendered-query cache.
func (m *Manager) Cache() *QueryCache {
	if m == nil {
		return nil
	}
	return m.cache
}

// Names returns the registered engine names in sorted order.
func (m *Manager) Names() []string {
	if m == nil {
		return []string{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.engines))
	for name := range m.engines {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Engine returns one registered engine.
func (m *Manager) Engine(name string) (Engine, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	engine, ok := m.engines[normalizeEngineName(name)]
	return engine, ok
}

// ProbeAll probes every registered engine and updates cached capabilities.
// Expected unavailability is returned in the capability map, not as an error.
func (m *Manager) ProbeAll(ctx context.Context) map[string]Capability {
	if m == nil {
		return map[string]Capability{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	engines := make(map[string]Engine, len(m.engines))
	for name, engine := range m.engines {
		engines[name] = engine
	}
	m.mu.Unlock()

	names := make([]string, 0, len(engines))
	for name := range engines {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make(map[string]Capability, len(engines))
	for _, name := range names {
		capability, err := engines[name].Probe(ctx)
		capability = sanitizeCapability(capability, err)
		m.mu.Lock()
		if m.capabilities == nil {
			m.capabilities = make(map[string]Capability)
		}
		m.capabilities[name] = capability
		m.mu.Unlock()
		result[name] = capability
	}
	return result
}

// Capabilities returns a copy of the currently cached capability map.
func (m *Manager) Capabilities() map[string]Capability {
	if m == nil {
		return map[string]Capability{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Capability, len(m.capabilities))
	for name, capability := range m.capabilities {
		capability.Languages = append([]string(nil), capability.Languages...)
		out[name] = capability
	}
	return out
}

// Capability returns one cached capability.
func (m *Manager) Capability(name string) (Capability, bool) {
	if m == nil {
		return Capability{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	capability, ok := m.capabilities[normalizeEngineName(name)]
	if ok {
		capability.Languages = append([]string(nil), capability.Languages...)
	}
	return capability, ok
}

// PrepareAll prepares every available engine that supports at least one target
// language. Repeating the same request reuses the existing prepared artifact.
// Per-language gaps are recorded on Prepared.Unsupported; actual Prepare
// failures are returned in the error slice.
func (m *Manager) PrepareAll(ctx context.Context, src SourceRef, langs []string, opts PrepareOptions) (map[string]Prepared, []error) {
	result := make(map[string]Prepared)
	if m == nil {
		return result, []error{errors.New("engines: nil manager")}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	languages := normalizeLanguageList(langs)
	if len(languages) == 0 {
		languages = normalizeLanguageList(src.Languages)
	}
	if len(languages) == 0 {
		return result, []error{fmt.Errorf("%w: no languages to prepare", ErrInvalidSource)}
	}

	m.mu.Lock()
	engines := make(map[string]Engine, len(m.engines))
	for name, engine := range m.engines {
		engines[name] = engine
	}
	m.mu.Unlock()
	names := make([]string, 0, len(engines))
	for name := range engines {
		names = append(names, name)
	}
	sort.Strings(names)

	var failures []error
	for _, name := range names {
		engine := engines[name]
		capability := m.ensureCapability(ctx, name, engine)
		if !capability.Available {
			continue
		}
		supported := filterSupportedLanguages(capability.Languages, languages)
		if len(supported) == 0 {
			continue
		}
		fingerprint := prepareFingerprint(src, supported, opts)
		if cached, ok := m.preparedFor(name); ok && cached.fingerprint == fingerprint {
			result[name] = copyPrepared(cached.prepared)
			continue
		}

		prepared, err := engine.Prepare(ctx, src, supported, opts)
		if prepared.Engine == "" {
			prepared.Engine = name
		}
		prepared.Warnings = redactEngineMessages(prepared.Warnings)
		prepared.Unsupported = redactEngineMap(prepared.Unsupported)
		if hasPreparedData(prepared) || err == nil {
			m.mu.Lock()
			if m.prepared == nil {
				m.prepared = make(map[string]preparedState)
			}
			m.prepared[name] = preparedState{prepared: copyPrepared(prepared), fingerprint: fingerprint}
			m.mu.Unlock()
		}
		result[name] = copyPrepared(prepared)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s prepare: %w", name, redactEngineError(err)))
		}
	}
	m.setSourceCommit(src.Commit)
	return result, failures
}

// RunIntents renders, validates, and executes each intent for the selected
// engines, recording one JobResult per intent/engine pair. Findings are
// cross-engine normalized before they are returned. Engine errors never abort
// other engines or intents.
func (m *Manager) RunIntents(ctx context.Context, intents []DetectionIntent, engineNames []string) ([]EngineFinding, []JobResult) {
	if m == nil {
		return []EngineFinding{}, []JobResult{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	engines := make(map[string]Engine, len(m.engines))
	for name, engine := range m.engines {
		engines[name] = engine
	}
	m.mu.Unlock()

	type intentJob struct {
		intent DetectionIntent
		engine string
	}
	jobs := make([]intentJob, 0)
	for _, intent := range intents {
		selected := selectEngines(intent, engineNames, engines)
		for _, name := range selected {
			jobs = append(jobs, intentJob{intent: intent, engine: name})
		}
	}

	capabilities := make(map[string]Capability, len(engines))
	for _, job := range jobs {
		if _, exists := capabilities[job.engine]; exists {
			continue
		}
		engine, registered := engines[job.engine]
		if !registered {
			capabilities[job.engine] = Capability{Available: false}
			continue
		}
		capabilities[job.engine] = m.ensureCapability(ctx, job.engine, engine)
	}

	findings := make([]EngineFinding, 0)
	results := make([]JobResult, len(jobs))
	if len(jobs) == 0 {
		return Normalize(findings), results
	}

	var findingsMu sync.Mutex
	var workers sync.WaitGroup
	workerCount := m.engineConcurrency()
	if workerCount > len(jobs) {
		workerCount = len(jobs)
	}
	work := make(chan int)
	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range work {
				job := jobs[index]
				intent := job.intent
				name := job.engine
				started := time.Now()
				result := JobResult{Engine: name, IntentID: intent.ID}
				engine, registered := engines[name]
				if !registered {
					results[index] = completeJob(result, started, JobStatusSkipped, "engine not registered")
					continue
				}
				capability := capabilities[name]
				if !capability.Available {
					reason := firstNonEmpty(capability.Reason, "unavailable")
					results[index] = completeJob(result, started, JobStatusSkipped, "engine unavailable: "+reason)
					continue
				}
				if !languageSupported(capability.Languages, intent.Language) {
					results[index] = completeJob(result, started, JobStatusSkipped,
						"language not supported: "+intent.Language)
					continue
				}
				artifactPath := ""
				if name != EngineCodeGraph {
					prepared, ok := m.preparedFor(name)
					if ok {
						path, reason, blocked := preparedArtifact(prepared.prepared, intent.Language)
						if blocked {
							results[index] = completeJob(result, started, JobStatusSkipped, reason)
							continue
						}
						artifactPath = path
					}
				}

				query, err := m.renderCached(intent, name, capability.Version, m.currentSourceCommit())
				if err != nil {
					status := JobStatusFailed
					if errors.Is(err, ErrUnsupported) {
						status = JobStatusSkipped
					}
					results[index] = completeJob(result, started, status, err.Error())
					continue
				}
				result.QueryHash = QueryCacheKey(query)
				if err := ValidateQuerySpec(query); err != nil {
					results[index] = completeJob(result, started, JobStatusFailed, err.Error())
					continue
				}
				if artifactPath != "" {
					query.ArtifactPath = artifactPath
				}
				if err := engine.Validate(ctx, query); err != nil {
					results[index] = completeJob(result, started, JobStatusFailed, err.Error())
					continue
				}

				engineFindings, runErr := engine.Run(ctx, query)
				findingsMu.Lock()
				for _, finding := range engineFindings {
					findings = append(findings, annotateFinding(finding, query, intent))
				}
				findingsMu.Unlock()
				if runErr != nil {
					results[index] = completeJob(result, started, JobStatusFailed, runErr.Error())
					continue
				}
				results[index] = completeJob(result, started, JobStatusDone, "")
			}
		}()
	}
	for index := range jobs {
		work <- index
	}
	close(work)
	workers.Wait()
	return Normalize(findings), results
}

func (m *Manager) engineConcurrency() int {
	if m == nil {
		return DefaultEngineConcurrency
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.concurrency <= 0 {
		return DefaultEngineConcurrency
	}
	return m.concurrency
}

func normalizeEngineConcurrency(limit int) int {
	if limit <= 0 {
		return DefaultEngineConcurrency
	}
	if limit > MaxEngineConcurrency {
		return MaxEngineConcurrency
	}
	return limit
}

func (m *Manager) ensureCapability(ctx context.Context, name string, engine Engine) Capability {
	if m == nil || engine == nil {
		return Capability{Available: false, Reason: "engine not registered"}
	}
	m.mu.Lock()
	capability, ok := m.capabilities[name]
	m.mu.Unlock()
	if ok {
		capability.Languages = append([]string(nil), capability.Languages...)
		return capability
	}
	probed, err := engine.Probe(ctx)
	probed = sanitizeCapability(probed, err)
	m.mu.Lock()
	if m.capabilities == nil {
		m.capabilities = make(map[string]Capability)
	}
	m.capabilities[name] = probed
	m.mu.Unlock()
	probed.Languages = append([]string(nil), probed.Languages...)
	return probed
}

func sanitizeCapability(capability Capability, err error) Capability {
	if err != nil {
		capability.Available = false
		if strings.TrimSpace(capability.Reason) == "" {
			capability.Reason = "probe failed: " + err.Error()
		}
	}
	if !capability.Available && strings.TrimSpace(capability.Reason) == "" {
		capability.Reason = "unavailable"
	}
	capability.Reason = RedactEngineText(capability.Reason)
	capability.Languages = append([]string(nil), capability.Languages...)
	return capability
}

func (m *Manager) preparedFor(name string) (preparedState, bool) {
	if m == nil {
		return preparedState{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.prepared[name]
	if !ok {
		return preparedState{}, false
	}
	state.prepared = copyPrepared(state.prepared)
	return state, true
}

func (m *Manager) renderCached(intent DetectionIntent, engine, engineVersion, commit string) (QuerySpec, error) {
	normalizedEngine := normalizeEngineName(engine)
	if normalizedEngine == "" {
		return QuerySpec{}, fmt.Errorf("%w: unknown engine %q", ErrUnsupported, engine)
	}
	// Render first: a taint intent may legitimately fall back to a sink-only
	// template, and the effective QueryKind is part of the cache key.
	query, err := RenderForSource(normalizedEngine, intent, engineVersion, commit)
	if err != nil {
		return QuerySpec{}, err
	}
	key := QueryCacheKey(query)
	if m.cache != nil {
		if cached, ok := m.cache.Get(key); ok {
			cached.IntentID = intent.ID
			return cached, nil
		}
		m.cache.Put(key, query)
	}
	return query, nil
}

func (m *Manager) setSourceCommit(commit string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.sourceCommit = strings.TrimSpace(commit)
	m.mu.Unlock()
}

func (m *Manager) currentSourceCommit() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sourceCommit
}

func selectEngines(intent DetectionIntent, requested []string, engines map[string]Engine) []string {
	raw := requested
	if len(raw) == 0 {
		raw = intent.PreferredEngines
	}
	seen := make(map[string]struct{})
	selected := make([]string, 0, len(raw))
	for _, name := range raw {
		normalized := normalizeEngineName(name)
		if normalized == "" {
			normalized = strings.ToLower(strings.TrimSpace(name))
		}
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		selected = append(selected, normalized)
	}
	if len(selected) > 0 {
		return selected
	}
	names := make([]string, 0, len(engines))
	for name := range engines {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func preparedArtifact(prepared Prepared, language string) (path, reason string, blocked bool) {
	target := normalizeIntentLanguage(language)
	if prepared.Paths != nil {
		if artifact := strings.TrimSpace(prepared.Paths[target]); artifact != "" {
			return artifact, "", false
		}
		if artifact := strings.TrimSpace(prepared.Paths["*"]); artifact != "" {
			return artifact, "", false
		}
	}
	if prepared.Unsupported != nil {
		if why := strings.TrimSpace(prepared.Unsupported[target]); why != "" {
			return "", "engine preparation gap: " + why, true
		}
	}
	if len(prepared.Languages) > 0 {
		return "", "engine not prepared for language " + language, true
	}
	return "", "", false
}

func hasPreparedData(prepared Prepared) bool {
	return len(prepared.Paths) > 0 ||
		len(prepared.Unsupported) > 0 ||
		len(prepared.Languages) > 0
}

func annotateFinding(finding EngineFinding, query QuerySpec, intent DetectionIntent) EngineFinding {
	if strings.TrimSpace(finding.Engine) == "" {
		finding.Engine = query.Engine
	}
	if strings.TrimSpace(finding.QueryID) == "" {
		finding.QueryID = query.ID
	}
	if strings.TrimSpace(finding.CWE) == "" {
		finding.CWE = firstNonEmpty(paramString(query.Params, "cwe"), intent.CWE)
	}
	if strings.TrimSpace(finding.Language) == "" {
		finding.Language = intent.Language
	}
	if finding.Payload == nil {
		finding.Payload = make(map[string]any)
	}
	if _, exists := finding.Payload["intent_id"]; !exists {
		finding.Payload["intent_id"] = intent.ID
	}
	return finding
}

func finishJob(results *[]JobResult, result JobResult, started time.Time, status, message string) {
	*results = append(*results, completeJob(result, started, status, message))
}

func completeJob(result JobResult, started time.Time, status, message string) JobResult {
	result.Status = status
	result.Error = RedactEngineText(message)
	result.Duration = time.Since(started)
	return result
}

func prepareFingerprint(src SourceRef, languages []string, opts PrepareOptions) string {
	material := struct {
		Root           string        `json:"root"`
		RepoKey        string        `json:"repo_key"`
		Commit         string        `json:"commit"`
		Prebuilt       string        `json:"prebuilt"`
		OptionPrebuilt string        `json:"option_prebuilt"`
		WorkDir        string        `json:"work_dir"`
		RAMMB          int           `json:"ram_mb"`
		Languages      []string      `json:"languages"`
		Timeout        time.Duration `json:"timeout"`
	}{
		Root:           src.Root,
		RepoKey:        src.RepoKey,
		Commit:         src.Commit,
		Prebuilt:       src.PrebuiltPath,
		OptionPrebuilt: opts.PrebuiltPath,
		WorkDir:        opts.WorkDir,
		RAMMB:          opts.RAMMB,
		Languages:      sortedCopy(normalizeLanguageList(languages)),
		Timeout:        opts.Timeout,
	}
	encoded, _ := json.Marshal(material)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
