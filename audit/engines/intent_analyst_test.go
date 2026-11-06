package engines

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/norma/llm"
)

type fakeIntentAnalystProvider struct {
	model   string
	outputs []string
	err     error
	calls   int
	request []llm.CompletionRequest
}

func (p *fakeIntentAnalystProvider) Model() string {
	return p.model
}

func (p *fakeIntentAnalystProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	p.request = append(p.request, req)
	if p.err != nil {
		return llm.Message{}, "", llm.Usage{}, p.err
	}
	index := p.calls - 1
	if index >= len(p.outputs) {
		index = len(p.outputs) - 1
	}
	return llm.Message{
		Role:    llm.RoleAssistant,
		Content: []llm.ContentBlock{llm.TextBlock(p.outputs[index])},
	}, "stop", llm.Usage{}, nil
}

func intentAnalystRegistry() audit.Registry {
	return audit.Registry{
		CWE: []audit.CWEDefinition{
			{ID: "CWE-434", Name: "Unrestricted Upload of File with Dangerous Type", Priority: "P0"},
			{ID: "CWE-918", Name: "Server-Side Request Forgery", Priority: "P0"},
			{ID: "CWE-754", Name: "Improper Check for Unusual or Exceptional Conditions", Priority: "P1"},
			{ID: "CWE-754", Name: "Improper Check for Unusual or Exceptional Conditions", Priority: "P1"},
		},
		Sinks: map[string][]audit.SinkDefinition{
			audit.Java: {
				{CWEID: "CWE-434", Symbol: "org.apache.commons.fileupload.FileItem.write", Kind: "sink"},
				{CWEID: "CWE-918", Symbol: "java.net.URL.openConnection", Kind: "sink"},
			},
		},
	}
}

func validIntentAnalystOutput() string {
	return `{
  "intents": [
    {
      "language": "java",
      "cwe": "CWE-434",
      "title": "重点检查文件上传",
      "query_kind": "sink",
      "sinks": [{"pattern": "write", "match": "method_call"}],
      "preferred_engines": ["joern"]
    },
    {
      "language": "java",
      "cwe": "CWE-918",
      "title": "重点检查 SSRF",
      "query_kind": "taint",
      "sources": [{"pattern": "getParameter", "match": "method_call"}],
      "sinks": [{"pattern": "openConnection", "match": "method_call"}],
      "preferred_engines": ["codeql", "joern"]
    }
  ]
}`
}

func TestIntentAnalystParsesUserGoal(t *testing.T) {
	raw := validIntentAnalystOutput()
	provider := &fakeIntentAnalystProvider{model: "test-model", outputs: []string{raw}}
	analyst := &IntentAnalyst{Provider: provider}

	result, err := analyst.Analyze(context.Background(), IntentAnalystInput{
		Goal:        "重点看文件上传和 SSRF",
		Languages:   []string{audit.Java},
		Registry:    intentAnalystRegistry(),
		EngineNames: []string{EngineCodeQL, EngineJoern},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Intents) != 2 {
		t.Fatalf("intent count = %d, want 2: %+v", len(result.Intents), result.Intents)
	}
	if result.Intents[0].CWE != "CWE-434" || result.Intents[0].Language != audit.Java {
		t.Errorf("first intent = %s/%s, want CWE-434/java", result.Intents[0].CWE, result.Intents[0].Language)
	}
	if result.Intents[1].CWE != "CWE-918" || result.Intents[1].Language != audit.Java {
		t.Errorf("second intent = %s/%s, want CWE-918/java", result.Intents[1].CWE, result.Intents[1].Language)
	}
	if result.Intents[0].Origin != OriginLLM {
		t.Errorf("origin = %q, want %q", result.Intents[0].Origin, OriginLLM)
	}
	if !hasPattern(result.Intents[0].Sinks, "write", MatchMethodCall) {
		t.Errorf("upload sinks = %+v", result.Intents[0].Sinks)
	}
	if !hasPattern(result.Intents[1].Sources, "getParameter", MatchMethodCall) ||
		!hasPattern(result.Intents[1].Sinks, "openConnection", MatchMethodCall) {
		t.Errorf("SSRF IR = %+v / %+v", result.Intents[1].Sources, result.Intents[1].Sinks)
	}

	sum := sha256.Sum256([]byte(raw))
	wantHash := hex.EncodeToString(sum[:])
	if result.Provenance["model"] != "test-model" ||
		result.Provenance["prompt_version"] != IntentPromptVersion ||
		result.Provenance["raw_output_hash"] != wantHash ||
		result.Provenance["recognition_source"] != "llm" ||
		result.Provenance["repair_attempts"] != 0 {
		t.Fatalf("provenance = %#v", result.Provenance)
	}
	if provider.calls != 1 {
		t.Errorf("provider calls = %d, want 1", provider.calls)
	}
	if len(provider.request) != 1 || len(provider.request[0].Messages) != 1 {
		t.Fatalf("completion request = %+v", provider.request)
	}
	if !strings.Contains(provider.request[0].Messages[0].Text(), "重点看文件上传和 SSRF") {
		t.Errorf("prompt omitted user goal: %+v", provider.request[0].Messages)
	}
}

func TestIntentAnalystAcceptsSemanticErrorContractIntent(t *testing.T) {
	raw := `{
  "intents": [
    {
      "language": "java",
      "cwe": "CWE-754",
      "title": "Decoder error contract",
      "query_kind": "error_contract",
      "scope": {"symbols": ["DecodeBlockTypeAndLength"]},
      "preferred_engines": ["codeql", "joern", "codegraph"]
    }
  ]
}`
	provider := &fakeIntentAnalystProvider{model: "test-model", outputs: []string{raw}}
	analyst := &IntentAnalyst{Provider: provider}

	result, err := analyst.Analyze(context.Background(), IntentAnalystInput{
		Goal:        "重点看解码器错误状态处理",
		Languages:   []string{audit.Java},
		Registry:    intentAnalystRegistry(),
		EngineNames: []string{EngineCodeQL, EngineJoern, EngineCodeGraph},
	})
	if err != nil {
		t.Fatalf("Analyze semantic intent: %v", err)
	}
	if len(result.Intents) != 1 {
		t.Fatalf("intent count = %d, want 1: %+v", len(result.Intents), result.Intents)
	}
	intent := result.Intents[0]
	if intent.QueryKind != QueryKindErrorContract {
		t.Fatalf("query kind = %q, want %q", intent.QueryKind, QueryKindErrorContract)
	}
	if len(intent.PreferredEngines) != 1 || intent.PreferredEngines[0] != EngineCodeGraph {
		t.Fatalf("preferred engines = %+v, want only codegraph", intent.PreferredEngines)
	}
	if result.Provenance["prompt_version"] != IntentPromptVersion || IntentPromptVersion != "v2" {
		t.Fatalf("prompt version = %v/%v, want v2", result.Provenance["prompt_version"], IntentPromptVersion)
	}
	if len(provider.request) != 1 || len(provider.request[0].System) != 1 {
		t.Fatalf("completion request = %+v", provider.request)
	}
	systemPrompt := provider.request[0].System[0]
	for _, want := range []string{
		"错误契约",
		"永久错误",
		"临时可恢复状态",
		"宏",
		"调用方契约",
		"固定大小缓冲",
		"重试循环",
	} {
		if !strings.Contains(systemPrompt, want) {
			t.Errorf("system prompt missing %q:\n%s", want, systemPrompt)
		}
	}
}

func TestIntentAnalystRepairsInvalidJSONThenSucceeds(t *testing.T) {
	provider := &fakeIntentAnalystProvider{model: "test-model", outputs: []string{
		`{"intents":[{"language":"java","cwe":"CWE-434","query_text":"def foo = 1"}]}`,
		validIntentAnalystOutput(),
	}}
	analyst := &IntentAnalyst{Provider: provider}

	result, err := analyst.Analyze(context.Background(), IntentAnalystInput{
		Goal:        "重点看文件上传和 SSRF",
		Languages:   []string{audit.Java},
		Registry:    intentAnalystRegistry(),
		EngineNames: []string{EngineCodeQL, EngineJoern},
	})
	if err != nil {
		t.Fatalf("Analyze after repair: %v", err)
	}
	if provider.calls != 2 {
		t.Errorf("provider calls = %d, want 2", provider.calls)
	}
	if result.Provenance["repair_attempts"] != 1 {
		t.Errorf("repair attempts = %v, want 1", result.Provenance["repair_attempts"])
	}
}

func TestIntentAnalystStopsAfterTwoRepairs(t *testing.T) {
	output := `{"intents":[{"language":"java","cwe":"CWE-434","query_text":"println(1)"}]}`
	provider := &fakeIntentAnalystProvider{model: "test-model", outputs: []string{output}}
	analyst := &IntentAnalyst{Provider: provider}

	failed, err := analyst.Analyze(context.Background(), IntentAnalystInput{
		Goal:        "重点看文件上传和 SSRF",
		Languages:   []string{audit.Java},
		Registry:    intentAnalystRegistry(),
		EngineNames: []string{EngineCodeQL, EngineJoern},
	})
	if err == nil {
		t.Fatal("Analyze unexpectedly accepted executable query text")
	}
	if provider.calls != 3 {
		t.Errorf("provider calls = %d, want initial + 2 repairs", provider.calls)
	}
	if !strings.Contains(err.Error(), "query_text") {
		t.Errorf("error does not identify unknown executable field: %v", err)
	}
	if failed.Provenance["recognition_source"] != "fallback" ||
		failed.Provenance["raw_output_hash"] == "" ||
		failed.Provenance["repair_attempts"] != 2 {
		t.Fatalf("failed analysis provenance = %#v", failed.Provenance)
	}
}

func TestIntentAnalystRejectsInvalidIR(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "unknown language",
			raw:  `{"intents":[{"language":"ruby","cwe":"CWE-434","title":"upload","query_kind":"sink","sinks":[{"pattern":"write","match":"method_call"}]}]}`,
			want: "language",
		},
		{
			name: "unknown cwe",
			raw:  `{"intents":[{"language":"java","cwe":"CWE-999","title":"upload","query_kind":"sink","sinks":[{"pattern":"write","match":"method_call"}]}]}`,
			want: "CWE",
		},
		{
			name: "unknown engine",
			raw:  `{"intents":[{"language":"java","cwe":"CWE-434","title":"upload","query_kind":"sink","sinks":[{"pattern":"write","match":"method_call"}],"preferred_engines":["bash"]}]}`,
			want: "engine",
		},
		{
			name: "scope escape",
			raw:  `{"intents":[{"language":"java","cwe":"CWE-434","title":"upload","query_kind":"sink","sinks":[{"pattern":"write","match":"method_call"}],"scope":{"paths":["../outside"]}}]}`,
			want: "scope",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &fakeIntentAnalystProvider{model: "test-model", outputs: []string{test.raw}}
			analyst := &IntentAnalyst{Provider: provider}
			_, err := analyst.Analyze(context.Background(), IntentAnalystInput{
				Goal:        "重点看文件上传和 SSRF",
				Languages:   []string{audit.Java},
				Registry:    intentAnalystRegistry(),
				EngineNames: []string{EngineCodeQL, EngineJoern},
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}
