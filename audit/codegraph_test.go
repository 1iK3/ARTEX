package audit

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeMCPCaller struct {
	mu    sync.Mutex
	calls int
	tools []string
	args  []map[string]any
	fn    func(tool string, args map[string]any) (string, error)
}

func (f *fakeMCPCaller) Call(_ context.Context, tool string, args map[string]any) (string, error) {
	f.mu.Lock()
	f.calls++
	f.tools = append(f.tools, tool)
	copied := make(map[string]any, len(args))
	for key, value := range args {
		copied[key] = value
	}
	f.args = append(f.args, copied)
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(tool, args)
	}
	return "ok", nil
}

func (f *fakeMCPCaller) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeMCPCaller) lastArgs() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.args) == 0 {
		return nil
	}
	return f.args[len(f.args)-1]
}

func TestCodeGraphExploreInjectsAbsoluteProjectPath(t *testing.T) {
	fake := &fakeMCPCaller{}
	client := NewCodeGraphClient("relative-project", fake)

	if _, err := client.Explore(context.Background(), "AuthService", 12); err != nil {
		t.Fatalf("Explore: %v", err)
	}
	wantAbs, err := filepath.Abs("relative-project")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	args := fake.lastArgs()
	if got := args["projectPath"]; got != filepath.Clean(wantAbs) {
		t.Fatalf("projectPath = %v, want %q", got, filepath.Clean(wantAbs))
	}
	if got := args["query"]; got != "AuthService" {
		t.Fatalf("query = %v", got)
	}
	if got := args["maxFiles"]; got != 12 {
		t.Fatalf("maxFiles = %v", got)
	}
	if tool := fake.tools[0]; tool != "codegraph_explore" {
		t.Fatalf("tool = %q", tool)
	}
}

func TestCodeGraphCacheHitAvoidsSecondCall(t *testing.T) {
	fake := &fakeMCPCaller{fn: func(string, map[string]any) (string, error) {
		return "cached source", nil
	}}
	client := NewCodeGraphClient("", fake)

	first, err := client.Explore(context.Background(), "login", 5)
	if err != nil {
		t.Fatalf("first Explore: %v", err)
	}
	second, err := client.Explore(context.Background(), "login", 5)
	if err != nil {
		t.Fatalf("second Explore: %v", err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("caller invoked %d times, want 1 (cache hit)", fake.callCount())
	}
	if first != second {
		t.Fatalf("cache hit changed text: %q vs %q", first, second)
	}
	if strings.Contains(second, "重复查询警告") {
		t.Fatalf("second call must not warn yet: %q", second)
	}
}

func TestCodeGraphDuplicateWarningOnThirdHit(t *testing.T) {
	fake := &fakeMCPCaller{fn: func(string, map[string]any) (string, error) {
		return "same result", nil
	}}
	client := NewCodeGraphClient("", fake)

	for i := 1; i <= 3; i++ {
		out, err := client.Explore(context.Background(), "SameSymbol", 0)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if i < 3 {
			if strings.Contains(out, "重复查询警告") {
				t.Fatalf("call %d should not warn: %q", i, out)
			}
			continue
		}
		if !strings.Contains(out, "⚠️ 重复查询警告") {
			t.Fatalf("third call missing warning: %q", out)
		}
		if !strings.Contains(out, "已执行 3 次") {
			t.Fatalf("third call missing count: %q", out)
		}
		if !strings.HasSuffix(out, "same result") {
			t.Fatalf("warning must prefix the cached result: %q", out)
		}
	}
	if fake.callCount() != 1 {
		t.Fatalf("caller invoked %d times, want 1", fake.callCount())
	}
}

func TestCodeGraphTruncationPerResult(t *testing.T) {
	payload := strings.Repeat("a", 20_000)
	fake := &fakeMCPCaller{fn: func(string, map[string]any) (string, error) {
		return payload, nil
	}}
	client := NewCodeGraphClient("", fake)

	out, err := client.Explore(context.Background(), "big", 0)
	if err != nil {
		t.Fatalf("Explore: %v", err)
	}
	if !strings.HasPrefix(out, strings.Repeat("a", codeGraphPerResultChars)) {
		t.Fatalf("truncated result does not start with capped payload")
	}
	if !strings.Contains(out, "TRUNCATED by harness") {
		t.Fatalf("missing truncation marker: %q", out[len(out)-120:])
	}
	if !strings.Contains(out, "chars dropped") {
		t.Fatalf("missing dropped count: %q", out[len(out)-120:])
	}
}

func TestCodeGraphCumulativeBudgetAndReset(t *testing.T) {
	payload := strings.Repeat("b", 20_000)
	fake := &fakeMCPCaller{fn: func(string, map[string]any) (string, error) {
		return payload, nil
	}}
	client := NewCodeGraphClient("", fake)
	ctx := context.Background()

	// Four fresh results of 15K each consume exactly the 60K loop budget.
	for i := 0; i < 4; i++ {
		out, err := client.Explore(ctx, fmt.Sprintf("q%d", i), 0)
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if strings.Contains(out, "循环累计预算已耗尽") {
			t.Fatalf("query %d still has budget but was tight-capped", i)
		}
	}
	exhausted, err := client.Explore(ctx, "q-exhausted", 0)
	if err != nil {
		t.Fatalf("exhausted query: %v", err)
	}
	if !strings.Contains(exhausted, "循环累计预算已耗尽") {
		t.Fatalf("expected exhausted-budget marker: %q", exhausted[len(exhausted)-140:])
	}
	if !strings.HasPrefix(exhausted, strings.Repeat("b", codeGraphBudgetExhaustedChars)) {
		t.Fatalf("exhausted result not capped to %d chars", codeGraphBudgetExhaustedChars)
	}

	client.ResetLoopBudget()
	afterReset, err := client.Explore(ctx, "q-reset", 0)
	if err != nil {
		t.Fatalf("after reset: %v", err)
	}
	if strings.Contains(afterReset, "循环累计预算已耗尽") {
		t.Fatalf("ResetLoopBudget did not restore the per-result cap")
	}
	if !strings.HasPrefix(afterReset, strings.Repeat("b", codeGraphPerResultChars)) {
		t.Fatalf("after reset expected full per-result cap")
	}
}

func TestCodeGraphErrorsAreNotCached(t *testing.T) {
	boom := errors.New("mcp unavailable")
	first := true
	fake := &fakeMCPCaller{fn: func(string, map[string]any) (string, error) {
		if first {
			first = false
			return "", boom
		}
		return "recovered", nil
	}}
	client := NewCodeGraphClient("", fake)
	ctx := context.Background()

	if _, err := client.Explore(ctx, "flaky", 0); err == nil || !errors.Is(err, boom) {
		t.Fatalf("first error = %v, want wrapped %v", err, boom)
	}
	out, err := client.Explore(ctx, "flaky", 0)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if out != "recovered" {
		t.Fatalf("retry result = %q", out)
	}
	if fake.callCount() != 2 {
		t.Fatalf("caller invoked %d times, want 2 (error must not be cached)", fake.callCount())
	}
}

func TestCodeGraphRunValidationAndCanonicalArgs(t *testing.T) {
	fake := &fakeMCPCaller{fn: func(string, map[string]any) (string, error) {
		return "node", nil
	}}
	client := NewCodeGraphClient("", fake)
	ctx := context.Background()

	if _, err := client.Run(ctx, "   ", nil); err == nil {
		t.Fatal("empty tool name must fail")
	}
	if _, err := NewCodeGraphClient("", nil).Run(ctx, "codegraph_node", nil); err == nil {
		t.Fatal("nil caller must fail")
	}

	if _, err := client.Run(ctx, "codegraph_node", map[string]any{"symbol": "A", "projectPath": ""}); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if _, err := client.Run(ctx, "codegraph_node", map[string]any{"projectPath": "", "symbol": "A"}); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("canonical args should share a cache entry; calls=%d", fake.callCount())
	}
}

func TestCodeGraphCacheIsFIFO(t *testing.T) {
	fake := &fakeMCPCaller{fn: func(string, map[string]any) (string, error) {
		return "x", nil
	}}
	client := NewCodeGraphClient("", fake)
	ctx := context.Background()

	for i := 0; i < codeGraphMaxCacheEntries+1; i++ {
		if _, err := client.Explore(ctx, fmt.Sprintf("q-%d", i), 0); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	client.mu.Lock()
	cacheLen := len(client.cache)
	client.mu.Unlock()
	if cacheLen != codeGraphMaxCacheEntries {
		t.Fatalf("cache size = %d, want %d", cacheLen, codeGraphMaxCacheEntries)
	}
	if fake.callCount() != codeGraphMaxCacheEntries+1 {
		t.Fatalf("calls before re-query = %d", fake.callCount())
	}
	// The oldest entry (q-0) was evicted, so querying it must call again.
	if _, err := client.Explore(ctx, "q-0", 0); err != nil {
		t.Fatalf("re-query oldest: %v", err)
	}
	if fake.callCount() != codeGraphMaxCacheEntries+2 {
		t.Fatalf("FIFO eviction failed: calls=%d", fake.callCount())
	}
}
