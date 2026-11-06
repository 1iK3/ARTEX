package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/audit/engines"
)

func TestMergeAuditIntentAnalysisFallsBackOnError(t *testing.T) {
	deterministic := []engines.DetectionIntent{{
		ID:       "sink-rule",
		Origin:   engines.OriginSinkRule,
		Language: audit.Java,
		CWE:      "CWE-89",
	}}
	analysisErr := errors.New("provider unavailable")

	analysis := engines.IntentAnalysisResult{Provenance: map[string]any{
		"model":              "test-model",
		"prompt_version":     engines.IntentPromptVersion,
		"raw_output_hash":    "invalid-hash",
		"recognition_source": "llm",
		"repair_attempts":    2,
	}}

	merged, record := mergeAuditIntentAnalysis(deterministic, analysis, analysisErr)
	if len(merged) != 1 || merged[0].ID != "sink-rule" {
		t.Fatalf("merged intents = %+v, want deterministic fallback", merged)
	}
	if record.RecognitionSource != "fallback" || !record.Fallback || record.Error != analysisErr.Error() {
		t.Fatalf("record = %+v, want fallback provider error", record)
	}
	if record.Model != "test-model" || record.PromptVersion != engines.IntentPromptVersion ||
		record.RawOutputHash != "invalid-hash" || record.RepairAttempts != 2 {
		t.Fatalf("fallback provenance was discarded: %+v", record)
	}
	if len(record.QueryGaps) != 1 || !strings.Contains(record.QueryGaps[0], "已回退确定性") {
		t.Fatalf("query gaps = %+v", record.QueryGaps)
	}
}

func TestAuditEngineThreads(t *testing.T) {
	tests := []struct {
		name string
		cfg  audit.Config
		want int
	}{
		{name: "default", cfg: audit.Config{}, want: 2},
		{name: "configured", cfg: audit.Config{Budgets: map[string]any{"codeql_threads": 8}}, want: 8},
		{name: "capped", cfg: audit.Config{Budgets: map[string]any{"codeql_threads": 128}}, want: 16},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := auditEngineThreads(tc.cfg); got != tc.want {
				t.Fatalf("auditEngineThreads(%+v) = %d, want %d", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestAuditEngineRAMMB(t *testing.T) {
	tests := []struct {
		name string
		cfg  audit.Config
		want int
	}{
		{name: "default", cfg: audit.Config{}, want: 4096},
		{name: "configured", cfg: audit.Config{Budgets: map[string]any{"codeql_ram_mb": 8192}}, want: 8192},
		{name: "capped", cfg: audit.Config{Budgets: map[string]any{"codeql_ram_mb": 131072}}, want: 32768},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := auditEngineRAMMB(tc.cfg); got != tc.want {
				t.Fatalf("auditEngineRAMMB(%+v) = %d, want %d", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestAuditEngineConcurrency(t *testing.T) {
	tests := []struct {
		name string
		cfg  audit.Config
		want int
	}{
		{name: "default", cfg: audit.Config{}, want: 1},
		{name: "configured", cfg: audit.Config{Budgets: map[string]any{"engine_concurrency": 2}}, want: 2},
		{name: "capped", cfg: audit.Config{Budgets: map[string]any{"engine_concurrency": 16}}, want: 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := auditEngineConcurrency(tc.cfg); got != tc.want {
				t.Fatalf("auditEngineConcurrency(%+v) = %d, want %d", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestMergeAuditIntentAnalysisAppendsLLMIntents(t *testing.T) {
	deterministic := []engines.DetectionIntent{{
		ID:       "sink-rule",
		Origin:   engines.OriginSinkRule,
		Language: audit.Java,
		CWE:      "CWE-89",
	}}
	llmIntents := []engines.DetectionIntent{{
		ID:       "llm-ssrf",
		Origin:   engines.OriginLLM,
		Language: audit.Java,
		CWE:      "CWE-918",
	}}
	result := engines.IntentAnalysisResult{
		Intents: llmIntents,
		Provenance: map[string]any{
			"model":              "test-model",
			"prompt_version":     engines.IntentPromptVersion,
			"raw_output_hash":    "abc123",
			"recognition_source": "llm",
			"repair_attempts":    1,
		},
	}

	merged, record := mergeAuditIntentAnalysis(deterministic, result, nil)
	if len(merged) != 2 || merged[1].ID != "llm-ssrf" || merged[1].Origin != engines.OriginLLM {
		t.Fatalf("merged intents = %+v", merged)
	}
	if record.RecognitionSource != "llm" || record.Model != "test-model" ||
		record.PromptVersion != engines.IntentPromptVersion || record.RawOutputHash != "abc123" ||
		record.RepairAttempts != 1 || record.IntentCount != 1 || record.Fallback {
		t.Fatalf("record = %+v", record)
	}
	if len(record.QueryGaps) != 0 {
		t.Fatalf("successful analysis should not create gaps: %+v", record.QueryGaps)
	}
}
