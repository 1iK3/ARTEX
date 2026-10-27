package engines

import (
	"context"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/audit"
)

// CodeGraphEngine adapts the existing task-scoped audit.CodeGraphClient. It
// deliberately returns no EngineFinding values: CodeGraph output is free-form
// source/trace text consumed by the worker LLM, not a structured taint result.
// The value of this adapter in the detection layer is query synthesis plus a
// uniform capability/prepare contract.
type CodeGraphEngine struct {
	Client *audit.CodeGraphClient
}

// NewCodeGraphEngine wraps an already-indexed task CodeGraph client.
func NewCodeGraphEngine(client *audit.CodeGraphClient) *CodeGraphEngine {
	return &CodeGraphEngine{Client: client}
}

func (e *CodeGraphEngine) Name() string { return EngineCodeGraph }

func (e *CodeGraphEngine) Close() error { return nil }

// Probe reports available whenever the caller supplied a client. CodeGraph
// indexing happens before the client is created, so Probe cannot improve on
// that decision.
func (e *CodeGraphEngine) Probe(ctx context.Context) (Capability, error) {
	if e == nil || e.Client == nil {
		return Capability{Available: false, Reason: "client_missing"}, nil
	}
	return Capability{
		Available:     true,
		Path:          "mcp:codegraph",
		Languages:     audit.Languages(),
		BuildModeNone: true,
	}, nil
}

// Prepare is a no-op because the caller creates and indexes the CodeGraph
// client before wiring the manager.
func (e *CodeGraphEngine) Prepare(ctx context.Context, src SourceRef, langs []string, opts PrepareOptions) (Prepared, error) {
	if e == nil || e.Client == nil {
		return Prepared{Engine: EngineCodeGraph}, fmt.Errorf("%w: CodeGraph client is not configured", ErrUnavailable)
	}
	languages := normalizeLanguageList(langs)
	if len(languages) == 0 {
		languages = normalizeLanguageList(src.Languages)
	}
	return Prepared{
		Engine:     EngineCodeGraph,
		Languages:  languages,
		BuildModes: map[string]string{},
		Warnings:   []string{"CodeGraph index is prepared by the caller; no engine artifact was created"},
	}, nil
}

func (e *CodeGraphEngine) Validate(ctx context.Context, q QuerySpec) error {
	if normalizeEngineName(q.Engine) != "" && normalizeEngineName(q.Engine) != EngineCodeGraph {
		return fmt.Errorf("%w: CodeGraph engine received an engine %q query", ErrInvalidQuery, q.Engine)
	}
	if e == nil || e.Client == nil {
		return fmt.Errorf("%w: CodeGraph client is not configured", ErrUnavailable)
	}
	if strings.TrimSpace(q.QueryText) == "" {
		return fmt.Errorf("%w: CodeGraph query text is empty", ErrInvalidQuery)
	}
	if len(q.QueryText) > 64<<10 {
		return fmt.Errorf("%w: CodeGraph query exceeds 64 KiB", ErrInvalidQuery)
	}
	return nil
}

// Run executes codegraph_explore and intentionally returns no findings. The
// raw text is available to workers through the shared client; structured
// findings must be written by the worker with evidence.
func (e *CodeGraphEngine) Run(ctx context.Context, q QuerySpec) ([]EngineFinding, error) {
	if err := e.Validate(ctx, q); err != nil {
		return nil, err
	}
	if _, err := e.Explore(ctx, q.QueryText, maxFilesParam(q.Params)); err != nil {
		return nil, err
	}
	return []EngineFinding{}, nil
}

// Explore exposes the raw CodeGraph result for callers that want the text
// without going through the Engine Run contract.
func (e *CodeGraphEngine) Explore(ctx context.Context, query string, maxFiles int) (string, error) {
	if e == nil || e.Client == nil {
		return "", fmt.Errorf("%w: CodeGraph client is not configured", ErrUnavailable)
	}
	text, err := e.Client.Explore(ctx, query, maxFiles)
	if err != nil {
		return "", fmt.Errorf("codegraph explore: %w", err)
	}
	return text, nil
}

func maxFilesParam(params map[string]any) int {
	if params == nil {
		return 0
	}
	switch value := params["max_files"].(type) {
	case int:
		return value
	case float64:
		return int(value)
	default:
		return 0
	}
}
