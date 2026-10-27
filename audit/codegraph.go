package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// MCPCaller is the narrow MCP surface a task-scoped CodeGraph client needs. The
// server implements it on top of the CodeGraph stdio MCP client; tests use a fake.
type MCPCaller interface {
	Call(ctx context.Context, tool string, args map[string]any) (string, error)
}

const (
	// codeGraphMaxCacheEntries bounds the session-level query cache. The oldest
	// entry is evicted first (FIFO), matching the Omni-Audit reference behavior.
	codeGraphMaxCacheEntries = 512

	// codeGraphPerResultChars is the per-result text cap. CodeGraph output is
	// mostly verbatim source, so 15K preserves useful context while preventing a
	// single trace from blowing up the agent's context.
	codeGraphPerResultChars = 15_000
	// codeGraphCumulativeBudgetChars is the per-agent-loop cumulative result
	// budget. Once exhausted, later results are capped much tighter.
	codeGraphCumulativeBudgetChars = 60_000
	// codeGraphBudgetExhaustedChars is the per-result cap after the cumulative
	// budget is exhausted.
	codeGraphBudgetExhaustedChars = 3_000
)

// CodeGraphClient is a per-task-session wrapper around the CodeGraph MCP tools.
// It injects the task's project path, caches successful results by tool +
// canonical JSON arguments, warns on repeated identical queries, and truncates
// results against both a per-result cap and a per-loop cumulative budget.
//
// A client is intentionally scoped to one agent loop: ResetLoopBudget (or a new
// client) starts a fresh cumulative budget. The cache and duplicate counters are
// shared across that loop so retries do not re-spend context.
type CodeGraphClient struct {
	projectPath string
	caller      MCPCaller

	mu         sync.Mutex
	cache      map[string]string // cache key -> truncated result text
	order      []string          // FIFO insertion order for cache eviction
	counts     map[string]int    // cache key -> successful executions (miss + hits)
	cumulative int               // chars returned by fresh (non-cache) results this loop
}

// NewCodeGraphClient builds a task-scoped client. projectPath is resolved to an
// absolute native path because the CodeGraph MCP server requires an absolute
// project path (on Windows, filepath.Abs produces the expected drive-letter path).
func NewCodeGraphClient(projectPath string, caller MCPCaller) *CodeGraphClient {
	projectPath = strings.TrimSpace(projectPath)
	if projectPath != "" {
		if abs, err := filepath.Abs(projectPath); err == nil {
			projectPath = filepath.Clean(abs)
		}
	}
	return &CodeGraphClient{
		projectPath: projectPath,
		caller:      caller,
		cache:       make(map[string]string),
		counts:      make(map[string]int),
	}
}

// Explore runs codegraph_explore with the task project path injected. maxFiles
// is forwarded only when positive; zero leaves the MCP server default in place.
func (c *CodeGraphClient) Explore(ctx context.Context, query string, maxFiles int) (string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return "", errors.New("codegraph_explore: query 不能为空")
	}
	args := map[string]any{"query": query}
	if maxFiles > 0 {
		args["maxFiles"] = maxFiles
	}
	return c.Run(ctx, "codegraph_explore", args)
}

// Run invokes any CodeGraph MCP tool through the same injection, cache,
// duplicate-warning, and truncation policy as Explore. tool must be non-empty.
func (c *CodeGraphClient) Run(ctx context.Context, tool string, args map[string]any) (string, error) {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return "", errors.New("codegraph: 工具名不能为空")
	}
	if c == nil || c.caller == nil {
		return "", errors.New("codegraph: MCP 调用器未配置（CodeGraph 不可用）；请先启动任务级 CodeGraph MCP，或在启用兜底时改用 code_search/code_read")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	callArgs := make(map[string]any, len(args)+1)
	for key, value := range args {
		callArgs[key] = value
	}
	if c.projectPath != "" && codeGraphArgMissing(callArgs["projectPath"]) {
		callArgs["projectPath"] = c.projectPath
	}
	key, err := codeGraphCacheKey(tool, callArgs)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = make(map[string]string)
	}
	if c.counts == nil {
		c.counts = make(map[string]int)
	}

	if cached, ok := c.cache[key]; ok {
		c.counts[key]++
		count := c.counts[key]
		if count >= 3 {
			return fmt.Sprintf(
				"⚠️ 重复查询警告: 该查询已执行 %d 次,结果与之前完全相同(缓存命中)。请停止重复查询同一符号,改用已有结果继续分析。\n\n%s",
				count, cached,
			), nil
		}
		return cached, nil
	}

	result, err := c.caller.Call(ctx, tool, callArgs)
	if err != nil {
		// Errors are transient (MCP unavailable, timeout) and must stay retryable,
		// so they are deliberately not cached.
		return "", fmt.Errorf("codegraph %s 调用失败: %w", tool, err)
	}

	truncated := c.truncateLocked(result)
	if len(c.cache) >= codeGraphMaxCacheEntries && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.cache, oldest)
		delete(c.counts, oldest)
	}
	c.cache[key] = truncated
	c.order = append(c.order, key)
	c.counts[key] = 1
	return truncated, nil
}

// ResetLoopBudget resets only the cumulative character budget. The cache and
// duplicate-query counters deliberately survive: a new loop can still reuse
// results already fetched in this task session.
func (c *CodeGraphClient) ResetLoopBudget() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.cumulative = 0
	c.mu.Unlock()
}

func codeGraphArgMissing(value any) bool {
	if value == nil {
		return true
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text) == ""
	}
	return false
}

// codeGraphCacheKey canonicalizes arguments through encoding/json, which sorts
// object keys recursively, so logically identical calls share one cache entry.
func codeGraphCacheKey(tool string, args map[string]any) (string, error) {
	encoded, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("codegraph: 序列化查询参数失败: %w", err)
	}
	return tool + "\x00" + string(encoded), nil
}

// truncateLocked applies the per-result cap and the cumulative loop budget. The
// cumulative counter tracks fresh (non-cache) results only, matching the
// reference client: a cache hit returns the already-truncated text and does not
// spend additional budget.
func (c *CodeGraphClient) truncateLocked(result string) string {
	runes := []rune(result)
	budgetExhausted := c.cumulative >= codeGraphCumulativeBudgetChars
	perResultCap := codeGraphPerResultChars
	if budgetExhausted {
		perResultCap = codeGraphBudgetExhaustedChars
	}
	effectiveCap := perResultCap
	if !budgetExhausted {
		remaining := codeGraphCumulativeBudgetChars - c.cumulative
		if remaining < effectiveCap {
			effectiveCap = remaining
		}
	}
	if effectiveCap < 0 {
		effectiveCap = 0
	}

	if len(runes) <= effectiveCap {
		c.cumulative += len(runes)
		return result
	}

	dropped := len(runes) - effectiveCap
	marker := fmt.Sprintf("\n…[TRUNCATED by harness: %d chars dropped — 用更小 maxFiles 精确读取]", dropped)
	if budgetExhausted {
		marker = fmt.Sprintf("\n…[TRUNCATED by harness: 循环累计预算已耗尽,%d chars dropped — 用已有结果继续分析]", dropped)
	}
	c.cumulative += effectiveCap
	return string(runes[:effectiveCap]) + marker
}
