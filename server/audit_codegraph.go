package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/norma/mcp"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	auditCLITimeout       = 60 * time.Second
	auditCLIOutputCap     = 1 << 20 // 1 MiB
	auditMCPStartTimeout  = 30 * time.Second
	auditCodeGraphTimeout = 15 * time.Minute
)

// auditCodeGraph adapts the two CodeGraph surfaces used by audit workers:
//
//   - the stdio MCP server (codegraph_explore) through audit.CodeGraphClient,
//     which supplies caching, duplicate warnings and per-loop budgets;
//   - the CodeGraph CLI (node/files/callers/callees/impact), which the current
//     MCP server does not necessarily expose.
//
// MCP startup is lazy: constructing the adapter during agent-bundle assembly must
// not spawn a subprocess or block admission. If MCP startup or a tool call fails,
// Explore falls back to the equivalent CLI command; the director separately
// records a fallback backend when the initial index step fails.
type auditCodeGraph struct {
	client *audit.CodeGraphClient
	bin    string
	root   string

	mu           sync.Mutex
	mcp          *mcp.Client
	mcpTools     map[string]actool.CoreTool
	mcpAttempted bool
	mcpErr       error
	closed       bool

	// runCLI is a test seam; nil uses runAuditCodeGraphCLI.
	runCLI func(ctx context.Context, sub string, args ...string) (string, error)
}

func newAuditCodeGraph(bin, root string) *auditCodeGraph {
	g := &auditCodeGraph{
		bin:  strings.TrimSpace(bin),
		root: strings.TrimSpace(root),
	}
	g.client = audit.NewCodeGraphClient(g.root, g)
	return g
}

func (s *Server) auditCodeGraphBin() string {
	if bin := strings.TrimSpace(os.Getenv("ARTEX_CODEGRAPH_BIN")); bin != "" {
		return bin
	}
	if s != nil && s.m != nil && s.m.pg != nil {
		if bin, ok, err := s.m.pg.GetSetting("audit.codegraph_bin"); err == nil && ok {
			if trimmed := strings.TrimSpace(bin); trimmed != "" {
				return trimmed
			}
		}
	}
	return "codegraph"
}

func (s *Server) auditSnapshotForTask(t *Task) string {
	if t == nil {
		return ""
	}
	if id, err := parseTaskID(t.ID); err == nil && s.m != nil && s.m.pg != nil {
		if session, err := s.m.pg.GetAuditSession(id); err == nil && session != nil && strings.TrimSpace(session.SnapshotPath) != "" {
			return session.SnapshotPath
		}
	}
	if s.m == nil {
		return ""
	}
	return filepath.Join(s.m.dir, "tasks", t.ID, "audit", "source")
}

// auditGraphFor returns the cached per-task adapter. The adapter itself was made
// cheap to construct, so this is safe to call while holding taskAgentMu.
func (s *Server) auditGraphFor(t *Task) agent.AuditCodeGraph {
	if s == nil || t == nil {
		return nil
	}
	s.auditGraphMu.Lock()
	defer s.auditGraphMu.Unlock()
	if g := s.auditGraphs[t.ID]; g != nil {
		return g
	}
	if s.auditGraphs == nil {
		s.auditGraphs = map[string]*auditCodeGraph{}
	}
	g := newAuditCodeGraph(s.auditCodeGraphBin(), s.auditSnapshotForTask(t))
	s.auditGraphs[t.ID] = g
	return g
}

func (s *Server) closeAuditGraph(taskID string) {
	if s == nil || taskID == "" {
		return
	}
	s.auditGraphMu.Lock()
	g := s.auditGraphs[taskID]
	delete(s.auditGraphs, taskID)
	s.auditGraphMu.Unlock()
	if g != nil {
		_ = g.Close()
	}
}

func (s *Server) closeAllAuditGraphs() {
	if s == nil {
		return
	}
	s.auditGraphMu.Lock()
	graphs := s.auditGraphs
	s.auditGraphs = map[string]*auditCodeGraph{}
	s.auditGraphMu.Unlock()
	for _, g := range graphs {
		_ = g.Close()
	}
}

func (g *auditCodeGraph) Explore(ctx context.Context, query string, maxFiles int) (string, error) {
	if g == nil || g.client == nil {
		return "", errors.New("CodeGraph 未配置")
	}
	out, err := g.client.Explore(ctx, query, maxFiles)
	if err == nil {
		return out, nil
	}
	mcpErr := err
	args := []string{query}
	if maxFiles > 0 {
		args = append(args, "--max-files", strconv.Itoa(maxFiles))
	}
	cliOut, cliErr := g.run(ctx, "explore", args...)
	if cliErr == nil {
		return cliOut, nil
	}
	return "", fmt.Errorf("CodeGraph MCP 查询失败: %v；CLI explore 兜底也失败: %v", mcpErr, cliErr)
}

func (g *auditCodeGraph) Node(ctx context.Context, symbol string) (string, error) {
	return g.symbolCLI(ctx, "node", symbol)
}

func (g *auditCodeGraph) Files(ctx context.Context) (string, error) {
	return g.run(ctx, "files")
}

func (g *auditCodeGraph) Callers(ctx context.Context, symbol string) (string, error) {
	return g.symbolCLI(ctx, "callers", symbol)
}

func (g *auditCodeGraph) Callees(ctx context.Context, symbol string) (string, error) {
	return g.symbolCLI(ctx, "callees", symbol)
}

func (g *auditCodeGraph) Impact(ctx context.Context, symbol string) (string, error) {
	return g.symbolCLI(ctx, "impact", symbol)
}

func (g *auditCodeGraph) ResetLoopBudget() {
	if g != nil && g.client != nil {
		g.client.ResetLoopBudget()
	}
}

func (g *auditCodeGraph) symbolCLI(ctx context.Context, sub, symbol string) (string, error) {
	symbol = strings.TrimSpace(symbol)
	if symbol == "" {
		return "", fmt.Errorf("codegraph %s: symbol 不能为空", sub)
	}
	return g.run(ctx, sub, symbol)
}

func (g *auditCodeGraph) run(ctx context.Context, sub string, args ...string) (string, error) {
	if g == nil {
		return "", errors.New("CodeGraph 未配置")
	}
	if strings.TrimSpace(g.root) == "" {
		return "", errors.New("CodeGraph 项目路径为空（审计源码快照尚未就绪）")
	}
	if g.runCLI != nil {
		return g.runCLI(ctx, sub, args...)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, auditCLITimeout)
	defer cancel()
	return runAuditCodeGraphCLI(runCtx, g.bin, g.root, sub, args...)
}

// Call implements audit.MCPCaller: it lists the MCP tools once, then invokes the
// requested tool and flattens its text content. Unavailable tools return an
// actionable error naming the tools the server does expose.
func (g *auditCodeGraph) Call(ctx context.Context, tool string, args map[string]any) (string, error) {
	tools, err := g.mcpToolMap(ctx)
	if err != nil {
		return "", err
	}
	return callAuditMCPTool(ctx, tools, g.root, tool, args)
}

func callAuditMCPTool(ctx context.Context, tools map[string]actool.CoreTool, root, tool string, args map[string]any) (string, error) {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return "", errors.New("codegraph: 工具名不能为空")
	}
	full := tool
	if !strings.HasPrefix(full, "mcp__") {
		full = mcp.ToolName("codegraph", tool)
	}
	core, ok := tools[full]
	if !ok {
		names := make([]string, 0, len(tools))
		for name := range tools {
			names = append(names, name)
		}
		sort.Strings(names)
		return "", fmt.Errorf("CodeGraph MCP 未提供工具 %s（当前可用：%s）", tool, strings.Join(names, ", "))
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("codegraph: 序列化工具参数失败: %w", err)
	}
	res, err := core.Call(ctx, raw, &actool.ToolContext{WorkingDir: root})
	if err != nil {
		return "", err
	}
	text := res.Flatten()
	if res.IsError {
		if strings.TrimSpace(text) == "" {
			text = "工具返回错误"
		}
		return "", errors.New(text)
	}
	return text, nil
}

func (g *auditCodeGraph) mcpToolMap(ctx context.Context) (map[string]actool.CoreTool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.mcpTools != nil {
		return g.mcpTools, nil
	}
	if g.mcpAttempted {
		if g.mcpErr != nil {
			return nil, g.mcpErr
		}
		return nil, errors.New("CodeGraph MCP 不可用")
	}
	g.mcpAttempted = true
	if g.closed {
		g.mcpErr = errors.New("CodeGraph 客户端已关闭")
		return nil, g.mcpErr
	}
	if strings.TrimSpace(g.bin) == "" {
		g.mcpErr = errors.New("CodeGraph 二进制未配置（设置 ARTEX_CODEGRAPH_BIN 或 audit.codegraph_bin）")
		return nil, g.mcpErr
	}
	if strings.TrimSpace(g.root) == "" {
		g.mcpErr = errors.New("CodeGraph 项目路径为空（审计源码快照尚未就绪）")
		return nil, g.mcpErr
	}
	startCtx := ctx
	if startCtx == nil {
		startCtx = context.Background()
	}
	var cancel context.CancelFunc
	startCtx, cancel = context.WithTimeout(startCtx, auditMCPStartTimeout)
	defer cancel()
	client, err := mcp.NewStdioClient(startCtx, "codegraph", g.bin, nil, "serve", "--mcp", "-p", g.root)
	if err != nil {
		g.mcpErr = fmt.Errorf("启动 CodeGraph MCP 失败: %w", err)
		return nil, g.mcpErr
	}
	tools, err := client.Tools(startCtx)
	if err != nil {
		_ = client.Close()
		g.mcpErr = fmt.Errorf("列出 CodeGraph MCP 工具失败: %w", err)
		return nil, g.mcpErr
	}
	g.mcp = client
	g.mcpTools = make(map[string]actool.CoreTool, len(tools))
	for _, tool := range tools {
		g.mcpTools[tool.Name()] = tool
	}
	return g.mcpTools, nil
}

func (g *auditCodeGraph) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	if g.mcp != nil {
		err := g.mcp.Close()
		g.mcp = nil
		g.mcpTools = nil
		return err
	}
	return nil
}

// auditCodeGraphCLIArgs builds the CLI argument list with the project path last.
// Pure so tests can pin the command shape without executing CodeGraph.
func auditCodeGraphCLIArgs(sub string, args []string, root string) []string {
	out := make([]string, 0, len(args)+3)
	out = append(out, sub)
	out = append(out, args...)
	if strings.TrimSpace(root) != "" {
		out = append(out, "-p", root)
	}
	return out
}

func runAuditCodeGraphCLI(ctx context.Context, bin, root, sub string, args ...string) (string, error) {
	bin = strings.TrimSpace(bin)
	if bin == "" {
		return "", errors.New("CodeGraph 二进制未配置（设置 ARTEX_CODEGRAPH_BIN 或 audit.codegraph_bin）")
	}
	cmd := exec.CommandContext(ctx, bin, auditCodeGraphCLIArgs(sub, args, root)...)
	buf := &auditCappedBuffer{limit: auditCLIOutputCap}
	cmd.Stdout = buf
	cmd.Stderr = buf
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	if ctx.Err() != nil {
		return "", fmt.Errorf("codegraph %s 超时或被取消", sub)
	}
	if err != nil {
		if out == "" {
			out = err.Error()
		}
		return "", fmt.Errorf("codegraph %s 失败: %s", sub, out)
	}
	if out == "" {
		return "", fmt.Errorf("codegraph %s 没有返回内容", sub)
	}
	return out, nil
}

// runCodeGraphIndex builds the task snapshot's CodeGraph index. init creates a
// fresh index; an existing .codegraph directory is rebuilt with index. The CLI
// accepts the target path as a positional argument for both subcommands.
func runCodeGraphIndex(ctx context.Context, bin, root string) error {
	bin = strings.TrimSpace(bin)
	if bin == "" {
		return errors.New("CodeGraph 二进制未配置")
	}
	if strings.TrimSpace(root) == "" {
		return errors.New("CodeGraph 项目路径为空")
	}
	sub := "init"
	if info, err := os.Stat(filepath.Join(root, ".codegraph")); err == nil && info.IsDir() {
		sub = "index"
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, auditCodeGraphTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, bin, sub, root)
	buf := &auditCappedBuffer{limit: auditCLIOutputCap}
	cmd.Stdout = buf
	cmd.Stderr = buf
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	if runCtx.Err() != nil {
		return fmt.Errorf("codegraph %s 超时或被取消", sub)
	}
	if err != nil {
		if out == "" {
			out = err.Error()
		}
		return fmt.Errorf("codegraph %s 失败: %s", sub, out)
	}
	return nil
}

type auditCappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *auditCappedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		b.truncated = true
		return len(p), nil
	}
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *auditCappedBuffer) String() string {
	if b.truncated {
		return b.buf.String() + "\n…[output truncated at 1 MiB]"
	}
	return b.buf.String()
}
