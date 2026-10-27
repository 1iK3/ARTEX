package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLiveAuditCodeGraphAdapter exercises the real CodeGraph CLI + stdio MCP
// adapter against a throwaway indexed repository. It is opt-in because the
// codegraph binary is an external dependency.
func TestLiveAuditCodeGraphAdapter(t *testing.T) {
	if os.Getenv("ARTEX_CODEGRAPH_LIVE_TEST") != "1" {
		t.Skip("set ARTEX_CODEGRAPH_LIVE_TEST=1 to run the live CodeGraph adapter test")
	}
	if _, err := exec.LookPath("codegraph"); err != nil {
		t.Skipf("codegraph binary not available: %v", err)
	}
	dir, err := os.MkdirTemp("", "artex-codegraph-live-*")
	if err != nil {
		t.Fatal(err)
	}
	// CodeGraph may keep a SQLite handle for a moment after the MCP process is
	// killed; retry instead of failing t.TempDir cleanup on Windows.
	t.Cleanup(func() {
		for i := 0; i < 20; i++ {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	})
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/live\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc helper() string { return \"hi\" }\n\nfunc main() { _ = helper() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := runCodeGraphIndex(ctx, "codegraph", dir); err != nil {
		t.Fatalf("index: %v", err)
	}
	g := newAuditCodeGraph("codegraph", dir)
	defer g.Close()

	explore, err := g.Explore(ctx, "helper", 5)
	if err != nil {
		t.Fatalf("explore: %v", err)
	}
	if !strings.Contains(explore, "helper") {
		t.Fatalf("explore output does not mention helper: %s", explore)
	}
	files, err := g.Files(ctx)
	if err != nil || !strings.Contains(files, "main.go") {
		t.Fatalf("files = %q, %v", files, err)
	}
	node, err := g.Node(ctx, "helper")
	if err != nil || !strings.Contains(node, "helper") {
		t.Fatalf("node = %q, %v", node, err)
	}
}
