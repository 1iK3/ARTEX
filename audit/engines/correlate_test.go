package engines

import (
	"testing"

	"github.com/Autumn-27/artex/audit"
)

func TestNormalizeMergesEngines(t *testing.T) {
	codeQL := testFinding(EngineCodeQL, 0.75, 42)
	joern := testFinding(EngineJoern, 0.65, 44)
	codeGraph := testFinding(EngineCodeGraph, 0.5, 41)

	normalized := Normalize([]EngineFinding{codeQL, joern, codeGraph})
	if len(normalized) != 1 {
		t.Fatalf("normalized = %d, want 1: %+v", len(normalized), normalized)
	}
	finding := normalized[0]
	if finding.Confidence != 0.95 {
		t.Errorf("confidence = %v, want 0.95 (0.75 + 0.1*2)", finding.Confidence)
	}
	if finding.Engine != EngineCodeQL {
		t.Errorf("engine = %q, want first engine", finding.Engine)
	}
	engines, ok := finding.Payload["engines"].([]map[string]any)
	if !ok || len(engines) != 3 {
		t.Fatalf("payload engines = %#v", finding.Payload["engines"])
	}
	if engines[0]["name"] != EngineCodeGraph || engines[1]["name"] != EngineCodeQL || engines[2]["name"] != EngineJoern {
		t.Errorf("engine ordering = %+v", engines)
	}
	if _, mutated := codeQL.Payload["engines"]; mutated {
		t.Error("Normalize mutated an input payload")
	}
	if finding.Payload["source"] != "test" {
		t.Errorf("merged payload lost source key: %+v", finding.Payload)
	}
}

func TestNormalizeLineWindowAndIdentity(t *testing.T) {
	near := Normalize([]EngineFinding{
		testFinding(EngineCodeQL, 0.5, 42),
		testFinding(EngineCodeQL, 0.5, 44),
	})
	if len(near) != 1 {
		t.Errorf("findings two lines apart = %d, want 1", len(near))
	}
	far := Normalize([]EngineFinding{
		testFinding(EngineCodeQL, 0.5, 42),
		testFinding(EngineCodeQL, 0.5, 45),
	})
	if len(far) != 2 {
		t.Errorf("findings three lines apart = %d, want 2", len(far))
	}

	differentSymbol := testFinding(EngineJoern, 0.5, 42)
	differentSymbol.Sink.Symbol = "java.lang.Runtime.exec"
	differentSymbol.Location.Symbol = "exec"
	if got := Normalize([]EngineFinding{testFinding(EngineCodeQL, 0.5, 42), differentSymbol}); len(got) != 2 {
		t.Errorf("different sink symbol merged: %+v", got)
	}

	differentPath := testFinding(EngineJoern, 0.5, 42)
	differentPath.Sink.Path = "src/main/java/Other.java"
	differentPath.Location.Path = "src/main/java/Other.java"
	if got := Normalize([]EngineFinding{testFinding(EngineCodeQL, 0.5, 42), differentPath}); len(got) != 2 {
		t.Errorf("different path merged: %+v", got)
	}
}

func TestNormalizeSameEngineDoesNotInflate(t *testing.T) {
	normalized := Normalize([]EngineFinding{
		testFinding(EngineCodeQL, 0.5, 42),
		testFinding(EngineCodeQL, 0.75, 42),
	})
	if len(normalized) != 1 {
		t.Fatalf("normalized = %d", len(normalized))
	}
	if normalized[0].Confidence != 0.75 {
		t.Errorf("same-engine confidence = %v, want 0.75", normalized[0].Confidence)
	}
	engines, _ := normalized[0].Payload["engines"].([]map[string]any)
	if len(engines) != 1 {
		t.Errorf("same-engine engines list = %+v", engines)
	}
}

func TestNormalizeConfidenceCap(t *testing.T) {
	findings := []EngineFinding{
		testFinding(EngineCodeQL, 0.75, 42),
		testFinding(EngineJoern, 0.6, 42),
		testFinding(EngineCodeGraph, 0.5, 42),
		testFinding("semgrep", 0.4, 42),
		testFinding("other", 0.3, 42),
	}
	normalized := Normalize(findings)
	if len(normalized) != 1 {
		t.Fatalf("normalized = %d", len(normalized))
	}
	if normalized[0].Confidence != 0.99 {
		t.Errorf("confidence = %v, want 0.99 cap", normalized[0].Confidence)
	}
	engines, _ := normalized[0].Payload["engines"].([]map[string]any)
	if len(engines) != 5 {
		t.Errorf("engine count = %d, want 5", len(engines))
	}
}

func TestNormalizeMergesTraceAndSource(t *testing.T) {
	first := testFinding(EngineCodeQL, 0.5, 42)
	second := testFinding(EngineJoern, 0.65, 42)
	second.Source = &audit.CodeLocation{Path: "src/main/java/Controller.java", Line: 10, Symbol: "getParameter"}
	second.Trace = []audit.TraceStep{
		{Path: "src/main/java/Controller.java", Line: 10, Symbol: "getParameter"},
		{Path: "src/main/java/App.java", Line: 42, Symbol: "executeQuery"},
	}
	normalized := Normalize([]EngineFinding{first, second})
	if len(normalized) != 1 {
		t.Fatalf("normalized = %d", len(normalized))
	}
	finding := normalized[0]
	if finding.Source == nil || finding.Source.Path != "src/main/java/Controller.java" {
		t.Errorf("source = %+v", finding.Source)
	}
	if len(finding.Trace) != 2 {
		t.Errorf("trace = %+v", finding.Trace)
	}
	if finding.Sink == nil || finding.Sink.Line != 42 {
		t.Errorf("sink = %+v", finding.Sink)
	}
}

func TestNormalizeEmptyAndKey(t *testing.T) {
	normalized := Normalize(nil)
	if normalized == nil || len(normalized) != 0 {
		t.Fatalf("Normalize(nil) = %#v", normalized)
	}
	finding := testFinding(EngineCodeQL, 0.5, 42)
	key := CorrelationKey(finding)
	if key == "" {
		t.Fatal("empty correlation key")
	}
	if got := CorrelationKey(finding); got != key {
		t.Error("correlation key is not stable")
	}
}
