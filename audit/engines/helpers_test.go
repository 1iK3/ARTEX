package engines

import (
	"context"
	"sync"

	"github.com/Autumn-27/artex/audit"
)

type execCall struct {
	Name string
	Args []string
	Dir  string
}

type fakeExec struct {
	mu    sync.Mutex
	calls []execCall
	fn    func(ctx context.Context, name string, args []string, dir string) (string, string, error)
}

func (f *fakeExec) run(ctx context.Context, name string, args []string, dir string) (string, string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, execCall{Name: name, Args: append([]string(nil), args...), Dir: dir})
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(ctx, name, args, dir)
	}
	return "", "", nil
}

func (f *fakeExec) snapshot() []execCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]execCall, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeExec) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeExec) find(name string, argPrefix ...string) (execCall, bool) {
	for _, call := range f.snapshot() {
		if call.Name != name {
			continue
		}
		matched := true
		for index, prefix := range argPrefix {
			if index >= len(call.Args) || call.Args[index] != prefix {
				matched = false
				break
			}
		}
		if matched {
			return call, true
		}
	}
	return execCall{}, false
}

type fakeEngine struct {
	name        string
	capability  Capability
	probeErr    error
	prepareFn   func(ctx context.Context, src SourceRef, langs []string, opts PrepareOptions) (Prepared, error)
	validateErr error
	runErr      error
	runFn       func(ctx context.Context, q QuerySpec) ([]EngineFinding, error)
	findings    []EngineFinding

	mu            sync.Mutex
	probeCalls    int
	prepareCalls  int
	validateCalls int
	runCalls      int
	lastQuery     QuerySpec
}

func (f *fakeEngine) Name() string { return f.name }

func (f *fakeEngine) Probe(ctx context.Context) (Capability, error) {
	f.mu.Lock()
	f.probeCalls++
	f.mu.Unlock()
	return f.capability, f.probeErr
}

func (f *fakeEngine) Prepare(ctx context.Context, src SourceRef, langs []string, opts PrepareOptions) (Prepared, error) {
	f.mu.Lock()
	f.prepareCalls++
	f.mu.Unlock()
	if f.prepareFn != nil {
		return f.prepareFn(ctx, src, langs, opts)
	}
	paths := make(map[string]string, len(langs))
	for _, language := range langs {
		paths[language] = "artifact-" + f.name + "-" + language
	}
	return Prepared{
		Engine:     f.name,
		Languages:  append([]string(nil), langs...),
		Paths:      paths,
		BuildModes: map[string]string{},
	}, nil
}

func (f *fakeEngine) Validate(ctx context.Context, q QuerySpec) error {
	f.mu.Lock()
	f.validateCalls++
	f.lastQuery = q
	f.mu.Unlock()
	return f.validateErr
}

func (f *fakeEngine) Run(ctx context.Context, q QuerySpec) ([]EngineFinding, error) {
	f.mu.Lock()
	f.runCalls++
	f.lastQuery = q
	f.mu.Unlock()
	if f.runFn != nil {
		return f.runFn(ctx, q)
	}
	out := make([]EngineFinding, len(f.findings))
	copy(out, f.findings)
	return out, f.runErr
}

func (f *fakeEngine) Close() error { return nil }

func (f *fakeEngine) counts() (probe, prepare, validate, run int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.probeCalls, f.prepareCalls, f.validateCalls, f.runCalls
}

func (f *fakeEngine) query() QuerySpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastQuery
}

func testJavaTaintIntent() DetectionIntent {
	return DetectionIntent{
		ID:        "intent-test-java-cwe89",
		Origin:    OriginSinkRule,
		Language:  audit.Java,
		CWE:       "CWE-89",
		Title:     "SQL Injection (CWE-89) tainted dataflow in java",
		QueryKind: QueryKindTaint,
		Sources: []Pattern{
			{Name: "request parameter", Pattern: "getParameter", Match: MatchMethodCall},
			{Name: "request header", Pattern: "getHeader", Match: MatchMethodCall},
		},
		Sinks: []Pattern{
			{Name: "raw query", Pattern: "executeQuery", Match: MatchMethodCall},
			{Name: "raw execute", Pattern: "execute", Match: MatchMethodCall},
		},
		Sanitizers: []Pattern{
			{Name: "binding", Pattern: "setString", Match: MatchMethodCall},
		},
		Scope: Scope{
			Paths:   []string{},
			Modules: []string{"user-service"},
			Symbols: []string{},
			Exclude: []string{},
		},
		Constraints: Constraints{
			MaxResults:  200,
			SeverityMin: "medium",
		},
		PreferredEngines: []string{EngineCodeQL, EngineJoern, EngineCodeGraph},
		Priority:         994,
	}
}

func testFinding(engine string, confidence float64, line int) EngineFinding {
	return EngineFinding{
		Engine:     engine,
		QueryID:    "qs-test",
		CWE:        "CWE-89",
		Language:   audit.Java,
		Message:    "tainted data reaches a query",
		Severity:   audit.SeverityHigh,
		Location:   audit.CodeLocation{Path: "src/main/java/App.java", Line: line, Symbol: "executeQuery"},
		Sink:       &audit.CodeLocation{Path: "src/main/java/App.java", Line: line, Symbol: "java.sql.Statement.executeQuery"},
		Confidence: confidence,
		RawRef:     engine + ":result:0",
		Payload:    map[string]any{"source": "test"},
	}
}

func mustRender(t interface {
	Helper()
	Fatalf(string, ...any)
}, engine string, intent DetectionIntent) QuerySpec {
	q, err := Render(engine, intent)
	if err != nil {
		t.Fatalf("Render(%s) error: %v", engine, err)
	}
	return q
}
