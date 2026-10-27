package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestAuditRoutesRequireAuthAndRejectPentestTasks(t *testing.T) {
	m := &Manager{tasks: map[string]*Task{
		"7": {ID: "7", Mode: db.TaskModePentest},
	}}
	s := &Server{m: m, engine: &Engine{}, jwtKey: []byte("audit-route-test-key")}
	handler := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/api/tasks/7/audit/progress",
		"/api/tasks/7/audit/report",
		"/api/tasks/7/audit/source/file?path=a.go&line=1",
		"/api/audit/capabilities",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without auth = %d, want 401", path, rec.Code)
		}
	}
	for _, path := range []string{
		"/api/tasks/7/audit/progress",
		"/api/tasks/7/audit/report",
		"/api/tasks/7/audit/source/file?path=a.go&line=1",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s for pentest task = %d body=%s, want 400", path, rec.Code, rec.Body.String())
		}
	}

	t.Setenv("ARTEX_CODEGRAPH_BIN", filepath.Join(t.TempDir(), "missing-codegraph"))
	t.Setenv("ARTEX_CODEQL_BIN", filepath.Join(t.TempDir(), "missing-codeql"))
	t.Setenv("ARTEX_JOERN_BIN", filepath.Join(t.TempDir(), "missing-joern"))
	req := httptest.NewRequest(http.MethodGet, "/api/audit/capabilities", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"codegraph"`) {
		t.Fatalf("capabilities route = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuditTaskHandlersRejectNonCodeAudit(t *testing.T) {
	m := &Manager{tasks: map[string]*Task{
		"7": {ID: "7", Mode: db.TaskModePentest},
	}}
	s := &Server{m: m, engine: &Engine{}}
	handlers := []struct {
		name    string
		handler http.HandlerFunc
		path    string
	}{
		{"progress", s.auditProgress, "/api/tasks/7/audit/progress"},
		{"report", s.auditReport, "/api/tasks/7/audit/report"},
		{"source", s.auditSourceFile, "/api/tasks/7/audit/source/file?path=a.go&line=1"},
	}
	for _, tc := range handlers {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.SetPathValue("id", "7")
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s, want 400", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "不是代码审计任务") {
				t.Fatalf("body = %s", rec.Body.String())
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/tasks/missing/audit/progress", nil)
	req.SetPathValue("id", "missing")
	rec := httptest.NewRecorder()
	s.auditProgress(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing task status = %d, want 404", rec.Code)
	}
}

func TestAuditCapabilitiesHandler(t *testing.T) {
	t.Setenv("ARTEX_CODEGRAPH_BIN", filepath.Join(t.TempDir(), "no-codegraph"))
	t.Setenv("ARTEX_CODEQL_BIN", filepath.Join(t.TempDir(), "no-codeql"))
	t.Setenv("ARTEX_JOERN_BIN", filepath.Join(t.TempDir(), "no-joern"))
	rootA := filepath.Join(t.TempDir(), "alpha-repo")
	rootB := filepath.Join(t.TempDir(), "beta-repo")
	t.Setenv("ARTEX_AUDIT_LOCAL_ROOTS", rootA+";"+rootB)
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/audit/capabilities", nil)
	rec := httptest.NewRecorder()
	s.auditCapabilities(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Codegraph struct {
			Available bool   `json:"available"`
			Path      string `json:"path"`
			Version   string `json:"version"`
		} `json:"codegraph"`
		CodeQL struct {
			Available bool `json:"available"`
		} `json:"codeql"`
		Joern struct {
			Available bool `json:"available"`
		} `json:"joern"`
		LocalRoots struct {
			Count     int      `json:"count"`
			Basenames []string `json:"basenames"`
		} `json:"local_roots"`
		Limits map[string]any `json:"limits"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Codegraph.Available || out.CodeQL.Available || out.Joern.Available {
		t.Fatalf("non-existent engine binaries reported available: %+v", out)
	}
	if out.Codegraph.Path != "" {
		t.Fatalf("unavailable engine should not expose a path: %+v", out.Codegraph)
	}
	if out.LocalRoots.Count != 2 || strings.Join(out.LocalRoots.Basenames, ",") != "alpha-repo,beta-repo" {
		t.Fatalf("local roots = %+v", out.LocalRoots)
	}
	if out.Limits["max_files"] != float64(200000) || out.Limits["max_rounds"] != float64(10) {
		t.Fatalf("limits = %+v", out.Limits)
	}
	for _, rawRoot := range []string{rootA, rootB} {
		if strings.Contains(rec.Body.String(), rawRoot) {
			t.Fatalf("capabilities leaked a raw local root %q", rawRoot)
		}
	}
}

func TestProbeAuditEngineBestEffort(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not on PATH")
	}
	capability := probeAuditEngine(context.Background(), "go")
	if !capability.Available || capability.Path == "" || capability.Version == "" {
		t.Fatalf("go probe = %+v", capability)
	}
	if capability.Path != filepath.Base(capability.Path) || filepath.IsAbs(capability.Path) {
		t.Fatalf("capabilities must expose only an engine basename, got %q", capability.Path)
	}
	if strings.Contains(capability.Version, "\n") || len(capability.Version) > auditVersionOutputLimit {
		t.Fatalf("version not normalized: %q", capability.Version)
	}
}

func TestAuditReportNotReadyResponse(t *testing.T) {
	session := &db.AuditSession{
		Status: db.AuditStatusRunning, Round: 2, MaxRounds: 3,
		SnapshotPath: "/private/source",
		GateResults:  json.RawMessage(`{"round":2,"forced":false,"gates":{"phase":{"name":"Gate-Phase","passed":false,"reason":"missing S11"}}}`),
	}
	rec := httptest.NewRecorder()
	writeAuditReportNotReady(rec, session)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if strings.Contains(rec.Body.String(), session.SnapshotPath) {
		t.Fatal("not-ready response leaked snapshot path")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	gates, _ := body["gates"].(map[string]any)
	if body["status"] != db.AuditStatusRunning || body["round"] != float64(2) ||
		body["max_rounds"] != float64(3) || body["report_ready"] != false ||
		gates == nil || gates["phase"] == nil {
		t.Fatalf("body = %#v", body)
	}
}

func TestAuditSourceWindow(t *testing.T) {
	start, end := auditSourceWindow(0)
	if start != 1 || end != auditSourceWindowLines {
		t.Fatalf("default window = %d-%d", start, end)
	}
	start, end = auditSourceWindow(42)
	if start != 42 || end != 42+auditSourceWindowLines-1 {
		t.Fatalf("line window = %d-%d", start, end)
	}
}
