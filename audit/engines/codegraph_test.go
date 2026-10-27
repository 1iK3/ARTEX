package engines

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/audit"
)

type fakeMCPCall struct {
	Tool string
	Args map[string]any
}

type fakeMCPCaller struct {
	mu     sync.Mutex
	calls  []fakeMCPCall
	result string
	err    error
}

func (f *fakeMCPCaller) Call(ctx context.Context, tool string, args map[string]any) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make(map[string]any, len(args))
	for key, value := range args {
		copied[key] = value
	}
	f.calls = append(f.calls, fakeMCPCall{Tool: tool, Args: copied})
	return f.result, f.err
}

func (f *fakeMCPCaller) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeMCPCaller) last() fakeMCPCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return fakeMCPCall{}
	}
	return f.calls[len(f.calls)-1]
}

func newTestCodeGraphEngine(caller audit.MCPCaller) *CodeGraphEngine {
	client := audit.NewCodeGraphClient("project", caller)
	return NewCodeGraphEngine(client)
}

func TestCodeGraphProbePrepareValidate(t *testing.T) {
	caller := &fakeMCPCaller{result: "source"}
	engine := newTestCodeGraphEngine(caller)
	capability, err := engine.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !capability.Available || !capability.BuildModeNone {
		t.Fatalf("capability = %+v", capability)
	}
	if len(capability.Languages) == 0 {
		t.Error("CodeGraph capability has no languages")
	}

	prepared, err := engine.Prepare(context.Background(), SourceRef{Root: t.TempDir()}, []string{audit.Java}, PrepareOptions{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if prepared.Engine != EngineCodeGraph || len(prepared.Languages) != 1 {
		t.Errorf("prepared = %+v", prepared)
	}

	if err := engine.Validate(context.Background(), QuerySpec{Engine: EngineCodeGraph, QueryText: ""}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("empty query error = %v", err)
	}
	if err := engine.Validate(context.Background(), QuerySpec{Engine: EngineCodeGraph, QueryText: "trace it"}); err != nil {
		t.Errorf("valid query: %v", err)
	}
	if err := engine.Validate(context.Background(), QuerySpec{Engine: EngineJoern, QueryText: "trace it"}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("wrong engine error = %v", err)
	}

	nilEngine := &CodeGraphEngine{}
	capability, err = nilEngine.Probe(context.Background())
	if err != nil || capability.Available || capability.Reason != "client_missing" {
		t.Errorf("nil client capability = %+v, err=%v", capability, err)
	}
	if _, err := nilEngine.Prepare(context.Background(), SourceRef{}, nil, PrepareOptions{}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("nil client prepare error = %v", err)
	}
	if _, err := nilEngine.Run(context.Background(), QuerySpec{Engine: EngineCodeGraph, QueryText: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("nil client run error = %v", err)
	}
}

func TestCodeGraphRunReturnsNoStructuredFindings(t *testing.T) {
	caller := &fakeMCPCaller{result: "src/main/java/App.java:42 executeQuery"}
	engine := newTestCodeGraphEngine(caller)
	q := mustRender(t, EngineCodeGraph, testJavaTaintIntent())

	findings, err := engine.Run(context.Background(), q)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("CodeGraph Run findings = %+v, want none", findings)
	}
	if caller.count() != 1 {
		t.Fatalf("MCP calls = %d, want 1", caller.count())
	}
	call := caller.last()
	if call.Tool != "codegraph_explore" {
		t.Errorf("tool = %q", call.Tool)
	}
	query, _ := call.Args["query"].(string)
	if !strings.Contains(query, "Trace source to sink") {
		t.Errorf("query = %q", query)
	}
	if projectPath, _ := call.Args["projectPath"].(string); projectPath == "" {
		t.Error("projectPath was not injected")
	}

	// The client cache keeps a repeated identical query from spending another
	// MCP call.
	if _, err := engine.Run(context.Background(), q); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if caller.count() != 1 {
		t.Errorf("cached CodeGraph query repeated MCP call: %d", caller.count())
	}

	text, err := engine.Explore(context.Background(), "trace executeQuery", 0)
	if err != nil {
		t.Fatalf("Explore: %v", err)
	}
	if text == "" {
		t.Error("Explore returned empty text")
	}
}

func TestCodeGraphRunErrorAndEmptyQuery(t *testing.T) {
	caller := &fakeMCPCaller{err: errors.New("mcp down")}
	engine := newTestCodeGraphEngine(caller)
	if _, err := engine.Run(context.Background(), QuerySpec{Engine: EngineCodeGraph, QueryText: "trace"}); err == nil || !strings.Contains(err.Error(), "mcp down") {
		t.Fatalf("MCP error = %v", err)
	}
	if _, err := engine.Run(context.Background(), QuerySpec{Engine: EngineCodeGraph, QueryText: "   "}); err == nil {
		t.Fatal("empty query should error")
	}
	if _, err := engine.Explore(context.Background(), "", 0); err == nil {
		t.Fatal("empty Explore query should error")
	}
}

func TestMaxFilesParam(t *testing.T) {
	if got := maxFilesParam(map[string]any{"max_files": 4}); got != 4 {
		t.Errorf("int max_files = %d", got)
	}
	if got := maxFilesParam(map[string]any{"max_files": float64(6)}); got != 6 {
		t.Errorf("float max_files = %d", got)
	}
	if got := maxFilesParam(nil); got != 0 {
		t.Errorf("nil max_files = %d", got)
	}
}
