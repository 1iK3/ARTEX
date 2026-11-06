package engines

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/audit"
)

func fakeWithCapability(name string, languages ...string) *fakeEngine {
	return &fakeEngine{
		name: name,
		capability: Capability{
			Available: true,
			Version:   "test",
			Languages: languages,
		},
	}
}

func resultForEngine(t *testing.T, results []JobResult, engine string) JobResult {
	t.Helper()
	for _, result := range results {
		if result.Engine == engine {
			return result
		}
	}
	t.Fatalf("no job result for engine %q: %+v", engine, results)
	return JobResult{}
}

func TestManagerCapabilityGating(t *testing.T) {
	available := fakeWithCapability(EngineCodeQL, audit.Java)
	available.findings = []EngineFinding{testFinding(EngineCodeQL, 0.75, 42)}
	unavailable := fakeWithCapability(EngineJoern, audit.Java)
	unavailable.capability = Capability{Available: false, Reason: "binary_missing"}

	manager := NewManager(available, unavailable)
	intent := testJavaTaintIntent()
	intent.PreferredEngines = []string{EngineCodeQL, EngineJoern}

	findings, results := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	if len(results) != 2 {
		t.Fatalf("job results = %d, want 2: %+v", len(results), results)
	}
	if result := resultForEngine(t, results, EngineCodeQL); result.Status != JobStatusDone || result.Error != "" {
		t.Errorf("codeql result = %+v", result)
	}
	if result := resultForEngine(t, results, EngineJoern); result.Status != JobStatusSkipped || !strings.Contains(result.Error, "binary_missing") {
		t.Errorf("joern result = %+v", result)
	}
	if _, _, _, runCalls := unavailable.counts(); runCalls != 0 {
		t.Errorf("unavailable engine ran %d times", runCalls)
	}
	if _, _, validateCalls, runCalls := available.counts(); validateCalls != 1 || runCalls != 1 {
		t.Errorf("available engine validate/run = %d/%d", validateCalls, runCalls)
	}
	if result := resultForEngine(t, results, EngineCodeQL); result.QueryHash == "" {
		t.Error("done job has no query hash")
	}
}

func TestRunIntentsEngineConcurrencyLimit(t *testing.T) {
	names := []string{EngineCodeQL, EngineJoern, EngineCodeGraph}
	engines := make([]*fakeEngine, 0, len(names))
	var mu sync.Mutex
	active := 0
	maxActive := 0
	for _, name := range names {
		engine := fakeWithCapability(name, audit.Java)
		engine.runFn = func(ctx context.Context, q QuerySpec) ([]EngineFinding, error) {
			mu.Lock()
			active++
			if active > maxActive {
				maxActive = active
			}
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			active--
			mu.Unlock()
			return nil, nil
		}
		engines = append(engines, engine)
	}

	manager := NewManager(engines[0], engines[1], engines[2])
	manager.SetEngineConcurrency(2)
	intent := testJavaTaintIntent()
	intent.PreferredEngines = names

	_, results := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	if maxActive != 2 {
		t.Fatalf("max concurrent engine runs = %d, want 2", maxActive)
	}
	if len(results) != len(names) {
		t.Fatalf("job results = %d, want %d", len(results), len(names))
	}
	for index, result := range results {
		if result.Engine != names[index] || result.Status != JobStatusDone {
			t.Fatalf("job result %d = %+v, want engine %s done", index, result, names[index])
		}
	}
}

func TestManagerLanguageGatingSkipsRender(t *testing.T) {
	engine := fakeWithCapability(EngineCodeQL, audit.Python)
	cache := NewQueryCache(8)
	manager := NewManagerWithCache(cache, engine)
	intent := testJavaTaintIntent()
	intent.PreferredEngines = []string{EngineCodeQL}

	findings, results := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
	result := resultForEngine(t, results, EngineCodeQL)
	if result.Status != JobStatusSkipped || !strings.Contains(result.Error, "language not supported") {
		t.Errorf("result = %+v", result)
	}
	if _, _, validateCalls, runCalls := engine.counts(); validateCalls != 0 || runCalls != 0 {
		t.Errorf("engine invoked for unsupported language: %d/%d", validateCalls, runCalls)
	}
	if cache.Misses() != 0 {
		t.Errorf("query was rendered for unsupported language: misses=%d", cache.Misses())
	}
}

func TestManagerPrepareOnce(t *testing.T) {
	engine := fakeWithCapability(EngineCodeQL, audit.Java, audit.Python)
	manager := NewManager(engine)
	src := SourceRef{Root: t.TempDir()}
	opts := PrepareOptions{WorkDir: t.TempDir()}

	first, failures := manager.PrepareAll(context.Background(), src, []string{audit.Java, audit.Python}, opts)
	if len(failures) != 0 {
		t.Fatalf("prepare failures: %v", failures)
	}
	if first[EngineCodeQL].Paths[audit.Java] == "" {
		t.Fatalf("prepared = %+v", first)
	}
	second, failures := manager.PrepareAll(context.Background(), src, []string{audit.Java, audit.Python}, opts)
	if len(failures) != 0 {
		t.Fatalf("second prepare failures: %v", failures)
	}
	if second[EngineCodeQL].Paths[audit.Java] != first[EngineCodeQL].Paths[audit.Java] {
		t.Error("cached prepare returned a different artifact")
	}
	if _, prepareCalls, _, _ := engine.counts(); prepareCalls != 1 {
		t.Errorf("prepare calls = %d, want 1", prepareCalls)
	}

	if _, failures := manager.PrepareAll(context.Background(), src, []string{audit.Python}, opts); len(failures) != 0 {
		t.Fatalf("third prepare failures: %v", failures)
	}
	if _, prepareCalls, _, _ := engine.counts(); prepareCalls != 2 {
		t.Errorf("prepare calls after language change = %d, want 2", prepareCalls)
	}
}

func TestManagerPrepareFailureRecorded(t *testing.T) {
	engine := fakeWithCapability(EngineCodeQL, audit.Java)
	engine.prepareFn = func(ctx context.Context, src SourceRef, langs []string, opts PrepareOptions) (Prepared, error) {
		return Prepared{Engine: EngineCodeQL}, errors.New("database create failed")
	}
	manager := NewManager(engine)
	prepared, failures := manager.PrepareAll(context.Background(), SourceRef{Root: t.TempDir()}, []string{audit.Java}, PrepareOptions{})
	if len(failures) != 1 || !strings.Contains(failures[0].Error(), "database create failed") {
		t.Fatalf("failures = %v", failures)
	}
	if prepared[EngineCodeQL].Engine != EngineCodeQL {
		t.Errorf("prepared result = %+v", prepared)
	}
}

func TestManagerPreparedLanguageGap(t *testing.T) {
	engine := fakeWithCapability(EngineCodeQL, audit.Java, audit.Python)
	manager := NewManager(engine)
	if _, failures := manager.PrepareAll(context.Background(), SourceRef{Root: t.TempDir()}, []string{audit.Java}, PrepareOptions{WorkDir: t.TempDir()}); len(failures) != 0 {
		t.Fatalf("prepare failures: %v", failures)
	}
	pythonIntent := sinkIntent(audit.Python, "CWE-89", "execute")
	pythonIntent.PreferredEngines = []string{EngineCodeQL}
	_, results := manager.RunIntents(context.Background(), []DetectionIntent{pythonIntent}, nil)
	result := resultForEngine(t, results, EngineCodeQL)
	if result.Status != JobStatusSkipped || !strings.Contains(result.Error, "not prepared") {
		t.Errorf("prepared language gap result = %+v", result)
	}
	if _, _, _, runCalls := engine.counts(); runCalls != 0 {
		t.Errorf("engine ran despite preparation gap: %d", runCalls)
	}
}

func TestManagerValidationAndRunErrors(t *testing.T) {
	t.Run("validation error", func(t *testing.T) {
		engine := fakeWithCapability(EngineCodeQL, audit.Java)
		engine.validateErr = errors.New("query compile failed")
		manager := NewManager(engine)
		intent := testJavaTaintIntent()
		intent.PreferredEngines = []string{EngineCodeQL}
		_, results := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
		result := resultForEngine(t, results, EngineCodeQL)
		if result.Status != JobStatusFailed || !strings.Contains(result.Error, "query compile failed") {
			t.Errorf("result = %+v", result)
		}
		if _, _, _, runCalls := engine.counts(); runCalls != 0 {
			t.Errorf("engine ran after validation failure: %d", runCalls)
		}
	})

	t.Run("execution error", func(t *testing.T) {
		engine := fakeWithCapability(EngineCodeQL, audit.Java)
		engine.runErr = errors.New("analysis crashed")
		manager := NewManager(engine)
		intent := testJavaTaintIntent()
		intent.PreferredEngines = []string{EngineCodeQL}
		_, results := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
		result := resultForEngine(t, results, EngineCodeQL)
		if result.Status != JobStatusFailed || !strings.Contains(result.Error, "analysis crashed") {
			t.Errorf("result = %+v", result)
		}
		if _, _, _, runCalls := engine.counts(); runCalls != 1 {
			t.Errorf("run calls = %d", runCalls)
		}
	})
}

func TestManagerCorrelationAndAnnotation(t *testing.T) {
	codeQL := fakeWithCapability(EngineCodeQL, audit.Java)
	codeQLFindings := testFinding("", 0.75, 42)
	codeQLFindings.CWE = ""
	codeQLFindings.Language = ""
	codeQLFindings.QueryID = ""
	codeQLFindings.Payload = nil
	codeQL.findings = []EngineFinding{codeQLFindings}

	joern := fakeWithCapability(EngineJoern, audit.Java)
	joern.findings = []EngineFinding{testFinding(EngineJoern, 0.65, 44)}

	manager := NewManager(codeQL, joern)
	intent := testJavaTaintIntent()
	intent.PreferredEngines = []string{EngineCodeQL, EngineJoern}
	findings, results := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	if len(findings) != 1 {
		t.Fatalf("correlated findings = %d: %+v", len(findings), findings)
	}
	finding := findings[0]
	if finding.CWE != "CWE-89" || finding.Language != audit.Java || finding.Engine == "" {
		t.Errorf("annotated finding = %+v", finding)
	}
	if finding.QueryID == "" {
		t.Error("query ID was not annotated")
	}
	if finding.Confidence != 0.85 {
		t.Errorf("confidence = %v, want 0.85", finding.Confidence)
	}
	engines, _ := finding.Payload["engines"].([]map[string]any)
	if len(engines) != 2 {
		t.Errorf("correlated engines = %+v", engines)
	}
	if finding.Payload["intent_id"] != intent.ID {
		t.Errorf("intent_id payload = %v", finding.Payload["intent_id"])
	}
	for _, result := range results {
		if result.Status != JobStatusDone {
			t.Errorf("job result = %+v", result)
		}
	}
}

func TestManagerQueryCacheHit(t *testing.T) {
	engine := fakeWithCapability(EngineCodeQL, audit.Java)
	cache := NewQueryCache(8)
	manager := NewManagerWithCache(cache, engine)
	intent := testJavaTaintIntent()
	intent.PreferredEngines = []string{EngineCodeQL}

	_, firstResults := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	_, secondResults := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	if cache.Hits() != 1 {
		t.Errorf("cache hits = %d, want 1", cache.Hits())
	}
	if cache.Misses() != 1 {
		t.Errorf("cache misses = %d, want 1", cache.Misses())
	}
	first := resultForEngine(t, firstResults, EngineCodeQL)
	second := resultForEngine(t, secondResults, EngineCodeQL)
	if first.QueryHash == "" || first.QueryHash != second.QueryHash {
		t.Errorf("query hashes = %q / %q", first.QueryHash, second.QueryHash)
	}
	if _, _, validateCalls, runCalls := engine.counts(); validateCalls != 2 || runCalls != 2 {
		t.Errorf("engine calls = %d/%d, want 2/2", validateCalls, runCalls)
	}
}

func TestManagerQueryHashIncludesEngineVersionAndCommit(t *testing.T) {
	intent := testJavaTaintIntent()
	intent.PreferredEngines = []string{EngineCodeQL}

	versionA := fakeWithCapability(EngineCodeQL, audit.Java)
	versionA.capability.Version = "1.0.0"
	versionB := fakeWithCapability(EngineCodeQL, audit.Java)
	versionB.capability.Version = "1.0.1"
	_, resultsA := NewManager(versionA).RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	_, resultsB := NewManager(versionB).RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	hashA := resultForEngine(t, resultsA, EngineCodeQL).QueryHash
	hashB := resultForEngine(t, resultsB, EngineCodeQL).QueryHash
	if hashA == "" || hashA == hashB {
		t.Fatalf("engine-version query hashes = %q / %q, want distinct", hashA, hashB)
	}

	engine := fakeWithCapability(EngineCodeQL, audit.Java)
	manager := NewManager(engine)
	source := SourceRef{Root: "source", Languages: []string{audit.Java}}
	source.Commit = "0123456789abcdef"
	if _, failures := manager.PrepareAll(context.Background(), source, []string{audit.Java}, PrepareOptions{}); len(failures) != 0 {
		t.Fatalf("PrepareAll: %v", failures)
	}
	_, firstResults := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	source.Commit = "fedcba9876543210"
	if _, failures := manager.PrepareAll(context.Background(), source, []string{audit.Java}, PrepareOptions{}); len(failures) != 0 {
		t.Fatalf("PrepareAll second commit: %v", failures)
	}
	_, secondResults := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	firstHash := resultForEngine(t, firstResults, EngineCodeQL).QueryHash
	secondHash := resultForEngine(t, secondResults, EngineCodeQL).QueryHash
	if firstHash == "" || firstHash == secondHash {
		t.Fatalf("commit query hashes = %q / %q, want distinct", firstHash, secondHash)
	}
}

func TestManagerProbeAllAndUnknownEngine(t *testing.T) {
	a := fakeWithCapability(EngineCodeQL, audit.Java)
	b := fakeWithCapability(EngineCodeGraph, audit.Go)
	manager := NewManager(a, b)
	caps := manager.ProbeAll(context.Background())
	if len(caps) != 2 || !caps[EngineCodeQL].Available || !caps[EngineCodeGraph].Available {
		t.Errorf("capabilities = %+v", caps)
	}
	if probeCalls, _, _, _ := a.counts(); probeCalls != 1 {
		t.Errorf("probe calls = %d", probeCalls)
	}

	intent := testJavaTaintIntent()
	_, results := manager.RunIntents(context.Background(), []DetectionIntent{intent}, []string{"not-an-engine"})
	if len(results) != 1 || results[0].Status != JobStatusSkipped || !strings.Contains(results[0].Error, "not registered") {
		t.Errorf("unknown engine results = %+v", results)
	}
}

func TestManagerRedactsEngineErrorPaths(t *testing.T) {
	engine := fakeWithCapability(EngineCodeQL, audit.Java)
	engine.runErr = errors.New("analysis failed at C:/Users/alice/AppData/Local/Temp/x and C:/Users/alice/.codeql/packages and /home/alice/work")
	manager := NewManager(engine)
	intent := testJavaTaintIntent()
	intent.PreferredEngines = []string{EngineCodeQL}
	_, results := manager.RunIntents(context.Background(), []DetectionIntent{intent}, nil)
	result := resultForEngine(t, results, EngineCodeQL)
	for _, forbidden := range []string{"C:/Users", "AppData", ".codeql", "/home/alice"} {
		if strings.Contains(result.Error, forbidden) {
			t.Fatalf("JobResult.Error leaked %q: %s", forbidden, result.Error)
		}
	}
}
