package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
)

func TestAuditResolveTaskModeOptions(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "repo")
	outside := filepath.Join(root, "..", "other-repo")

	t.Run("pentest default", func(t *testing.T) {
		got, err := resolveTaskModeOptions("", nil, "existing goal", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.Mode != db.TaskModePentest || got.Goal != "existing goal" || len(got.AuditConfig) != 0 {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("pentest rejects audit", func(t *testing.T) {
		if _, err := resolveTaskModeOptions(db.TaskModePentest, &audit.Config{SourceType: audit.SourceGit, RepoURL: "https://example.com/a.git"}, "g", nil); err == nil || !strings.Contains(err.Error(), "不支持 audit 配置") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("code audit requires audit", func(t *testing.T) {
		if _, err := resolveTaskModeOptions(db.TaskModeCodeAudit, nil, "g", nil); err == nil || !strings.Contains(err.Error(), "缺少 audit 配置") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("invalid mode", func(t *testing.T) {
		if _, err := resolveTaskModeOptions("recon", nil, "g", nil); err == nil || !strings.Contains(err.Error(), "无效的任务模式") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("git code audit normalizes and defaults goal", func(t *testing.T) {
		got, err := resolveTaskModeOptions(db.TaskModeCodeAudit, &audit.Config{
			SourceType: " GIT ",
			RepoURL:    "https://example.com/a.git",
			Languages:  []string{"js", "Kotlin"},
		}, "   ", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.Mode != db.TaskModeCodeAudit {
			t.Fatalf("mode = %q", got.Mode)
		}
		if !strings.Contains(got.Goal, "https://example.com/a.git") || !strings.Contains(got.Goal, "全量深度代码审计") {
			t.Fatalf("goal = %q", got.Goal)
		}
		var cfg audit.Config
		if err := json.Unmarshal(got.AuditConfig, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.SourceType != audit.SourceGit || cfg.Depth != audit.DepthDeep || cfg.MaxRounds != 5 ||
			cfg.CWEScope != audit.CWEScopeCore || cfg.Engines[audit.EngineCodeGraph] != "required" {
			t.Fatalf("config not normalized: %+v", cfg)
		}
		if strings.Join(cfg.Languages, ",") != "javascript,kotlin" {
			t.Fatalf("languages = %v", cfg.Languages)
		}
	})

	t.Run("local code audit uses root and keeps user goal", func(t *testing.T) {
		got, err := resolveTaskModeOptions(db.TaskModeCodeAudit, &audit.Config{
			SourceType: audit.SourceLocal, LocalPath: inside, Depth: audit.DepthQuick,
		}, "用户目标", []string{root})
		if err != nil {
			t.Fatal(err)
		}
		if got.Goal != "用户目标" {
			t.Fatalf("goal = %q", got.Goal)
		}
		var cfg audit.Config
		if err := json.Unmarshal(got.AuditConfig, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.LocalPath != inside || cfg.MaxRounds != 1 {
			t.Fatalf("config = %+v", cfg)
		}
	})

	t.Run("zip default goal", func(t *testing.T) {
		got, err := resolveTaskModeOptions("CODE_AUDIT", &audit.Config{
			SourceType: audit.SourceZip, UploadID: "stage-1",
		}, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got.Goal, "stage-1") {
			t.Fatalf("goal = %q", got.Goal)
		}
	})

	t.Run("local outside root", func(t *testing.T) {
		_, err := resolveTaskModeOptions(db.TaskModeCodeAudit, &audit.Config{
			SourceType: audit.SourceLocal, LocalPath: outside,
		}, "g", []string{root})
		if err == nil || !strings.Contains(err.Error(), "本地目录不在允许范围") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("local roots not configured", func(t *testing.T) {
		_, err := resolveTaskModeOptions(db.TaskModeCodeAudit, &audit.Config{
			SourceType: audit.SourceLocal, LocalPath: inside,
		}, "g", nil)
		if err == nil || !strings.Contains(err.Error(), "未配置本地审计根目录") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("deep codegraph off rejected", func(t *testing.T) {
		_, err := resolveTaskModeOptions(db.TaskModeCodeAudit, &audit.Config{
			SourceType: audit.SourceZip, UploadID: "u", Depth: audit.DepthDeep,
			Engines: map[string]string{audit.EngineCodeGraph: "off"},
		}, "g", nil)
		if err == nil || !strings.Contains(err.Error(), "engines.codegraph 不能为 off") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestAuditDecodeConfig(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, {}, json.RawMessage("null")} {
		cfg, err := decodeAuditConfig(raw)
		if err != nil || cfg != nil {
			t.Fatalf("decodeAuditConfig(%q) = %+v, %v; want nil, nil", raw, cfg, err)
		}
	}
	cfg, err := decodeAuditConfig(json.RawMessage(`{"source_type":"zip","upload_id":"u"}`))
	if err != nil || cfg == nil || cfg.SourceType != audit.SourceZip || cfg.UploadID != "u" {
		t.Fatalf("decoded = %+v, %v", cfg, err)
	}
	if _, err := decodeAuditConfig(json.RawMessage(`[]`)); err == nil {
		t.Fatal("array audit config should fail to decode into audit.Config")
	}
}

func TestAuditParseLocalRoots(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	got := parseAuditLocalRoots(" " + rootA + " , " + rootB + ";" + rootA + " ; ")
	if len(got) != 2 {
		t.Fatalf("roots = %#v, want 2 entries", got)
	}
	if got[0] != filepath.Clean(rootA) || got[1] != filepath.Clean(rootB) {
		t.Fatalf("roots = %#v, want [%s %s]", got, rootA, rootB)
	}
	if roots := parseAuditLocalRoots(""); len(roots) != 0 {
		t.Fatalf("empty env roots = %#v", roots)
	}

	t.Setenv("ARTEX_AUDIT_LOCAL_ROOTS", rootA+";"+rootB)
	if roots := (&Server{}).auditLocalRoots(); len(roots) != 2 {
		t.Fatalf("auditLocalRoots = %#v", roots)
	}
}

func TestAuditTemplateModeConfig(t *testing.T) {
	if mode, raw, err := normalizeTemplateModeConfig("", nil, nil); err != nil || mode != db.TaskModePentest || string(raw) != "{}" {
		t.Fatalf("default template config = %q %s %v", mode, raw, err)
	}
	if mode, raw, err := normalizeTemplateModeConfig("pentest", json.RawMessage(`{}`), nil); err != nil || mode != db.TaskModePentest || string(raw) != "{}" {
		t.Fatalf("pentest template config = %q %s %v", mode, raw, err)
	}
	if _, _, err := normalizeTemplateModeConfig("pentest", json.RawMessage(`{"source_type":"zip"}`), nil); err == nil ||
		!strings.Contains(err.Error(), "不支持 audit 配置") {
		t.Fatalf("pentest non-empty audit error = %v", err)
	}
	if _, _, err := normalizeTemplateModeConfig(db.TaskModeCodeAudit, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "缺少 audit 配置") {
		t.Fatalf("missing audit error = %v", err)
	}
	if _, _, err := normalizeTemplateModeConfig("recon", nil, nil); err == nil ||
		!strings.Contains(err.Error(), "无效的任务模式") {
		t.Fatalf("invalid mode error = %v", err)
	}
	mode, raw, err := normalizeTemplateModeConfig(db.TaskModeCodeAudit, json.RawMessage(`{"source_type":"zip","upload_id":"u","depth":"quick"}`), nil)
	if err != nil || mode != db.TaskModeCodeAudit {
		t.Fatalf("code audit template = %q %s %v", mode, raw, err)
	}
	var cfg audit.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.MaxRounds != 1 || cfg.Engines[audit.EngineCodeQL] != "auto" {
		t.Fatalf("template config not normalized: %+v", cfg)
	}
	if _, _, err := normalizeTemplateModeConfig(db.TaskModeCodeAudit, json.RawMessage(`{"source_type":"file"}`), nil); err == nil {
		t.Fatal("invalid code audit template config should fail")
	}
}

func TestAuditTemplatePatchMode(t *testing.T) {
	if _, err := templatePatchMode(nil); err == nil || !strings.Contains(err.Error(), "不能为空") {
		t.Fatalf("null mode error = %v", err)
	}
	for _, raw := range []string{"", "   "} {
		raw := raw
		if _, err := templatePatchMode(&raw); err == nil || !strings.Contains(err.Error(), "不能为空") {
			t.Fatalf("blank mode %q error = %v", raw, err)
		}
	}
	invalid := "recon"
	if _, err := templatePatchMode(&invalid); err == nil || !strings.Contains(err.Error(), "无效的任务模式") {
		t.Fatalf("invalid mode error = %v", err)
	}
	for raw, want := range map[string]string{"CODE_AUDIT": db.TaskModeCodeAudit, " Pentest ": db.TaskModePentest} {
		raw := raw
		mode, err := templatePatchMode(&raw)
		if err != nil || mode != want {
			t.Fatalf("templatePatchMode(%q) = %q, %v; want %q", raw, mode, err, want)
		}
	}
}

func TestAuditCodeAuditSkipsDeadlineCoordinator(t *testing.T) {
	engine := &Engine{}
	task := &Task{ID: "42", Mode: db.TaskModeCodeAudit, TimeoutSeconds: 30}
	engine.startDeadlineCoordinator(context.Background(), task)
	if _, ok := engine.coordStarted.Load(task.ID); ok {
		t.Fatal("code_audit task entered the pentest deadline coordinator")
	}
	engine.settleTask(context.Background(), task)
	if engine.isSettling(task.ID) {
		t.Fatal("code_audit task entered the pentest settle path")
	}
}

func TestGoalAPIRejectsCodeAudit(t *testing.T) {
	m := &Manager{tasks: map[string]*Task{
		"7": {ID: "7", Mode: db.TaskModeCodeAudit},
	}}
	s := &Server{m: m, engine: &Engine{}}
	cases := []struct {
		name    string
		method  string
		path    string
		body    string
		handler http.HandlerFunc
	}{
		{"add", http.MethodPost, "/api/tasks/7/goals", `{"text":"new goal"}`, s.addGoal},
		{"edit", http.MethodPatch, "/api/tasks/7/goals/1", `{"text":"edited"}`, s.editGoal},
		{"delete", http.MethodDelete, "/api/tasks/7/goals/1", ``, s.deleteGoal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.SetPathValue("id", "7")
			req.SetPathValue("gid", "1")
			recorder := httptest.NewRecorder()
			tc.handler(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s, want 400", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "代码审计任务暂不支持") {
				t.Fatalf("body = %s, want code_audit rejection", recorder.Body.String())
			}
		})
	}
}

func TestAuditSpawnTaskSchema(t *testing.T) {
	schema, err := json.Marshal((&Server{}).toolSpawnTask().InputSchema())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"task_mode"`, `"code_audit"`, `"audit"`, `"source_type"`, `"local_path"`} {
		if !strings.Contains(string(schema), want) {
			t.Fatalf("spawn_task schema lacks %s: %s", want, schema)
		}
	}
}

func TestAuditArchiveUnsupportedMapsToConflict(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeArchiveError(recorder, fmt.Errorf("%w: task 7", db.ErrTaskArchiveUnsupported))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "does not support archiving") {
		t.Fatalf("body = %q, want the underlying error message", body)
	}
}

func TestAuditTaskDTOFields(t *testing.T) {
	pentest := taskDTO(&Task{ID: "1"}, "created")
	if pentest.TaskMode != db.TaskModePentest {
		t.Fatalf("legacy task mode = %q, want %q", pentest.TaskMode, db.TaskModePentest)
	}
	if len(pentest.AuditConfig) != 0 {
		t.Fatalf("legacy task audit_config = %s, want omitted", pentest.AuditConfig)
	}

	raw := json.RawMessage(`{"source_type":"zip","upload_id":"u"}`)
	auditTask := taskDTO(&Task{ID: "2", Mode: db.TaskModeCodeAudit, AuditConfig: raw}, "created")
	if auditTask.TaskMode != db.TaskModeCodeAudit {
		t.Fatalf("task mode = %q", auditTask.TaskMode)
	}
	if string(auditTask.AuditConfig) != string(raw) {
		t.Fatalf("audit_config = %s, want %s", auditTask.AuditConfig, raw)
	}
	raw[0] = '['
	if string(auditTask.AuditConfig) == string(raw) {
		t.Fatal("DTO audit_config must be a copy, not an alias")
	}
}

// TestAuditTemplatePatchEmptyModeHTTP verifies explicit null/blank PATCH
// task_mode is rejected without downgrading the template or wiping its config.
func TestAuditTemplatePatchEmptyModeHTTP(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	template, err := m.pg.CreateTaskTemplate(db.TaskTemplateInput{
		Name:        fmt.Sprintf("audit-empty-mode-%d", time.Now().UnixNano()),
		Description: "audit template",
		Goal:        "audit goal",
		Mode:        db.TaskModeCodeAudit,
		AuditConfig: json.RawMessage(`{"source_type":"zip","upload_id":"u","depth":"deep"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.DeleteTaskTemplate(template.ID) })

	do := func(body map[string]any) (int, map[string]any) {
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/task-templates/%d", template.ID), bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		s.Handler().ServeHTTP(recorder, req)
		var out map[string]any
		_ = json.Unmarshal(recorder.Body.Bytes(), &out)
		return recorder.Code, out
	}
	for _, body := range []map[string]any{
		{"task_mode": nil},
		{"task_mode": ""},
		{"task_mode": "   "},
	} {
		code, out := do(body)
		if code != http.StatusBadRequest {
			t.Fatalf("PATCH %v status = %d body=%v, want 400", body, code, out)
		}
		if msg, _ := out["error"].(string); !strings.Contains(msg, "task_mode 不能为空") {
			t.Fatalf("PATCH %v error = %q", body, msg)
		}
	}
	got, err := m.pg.GetTaskTemplate(template.ID)
	if err != nil || got == nil {
		t.Fatalf("GetTaskTemplate = %+v, %v", got, err)
	}
	if got.Mode != db.TaskModeCodeAudit {
		t.Fatalf("mode = %q after rejected PATCH, want %q", got.Mode, db.TaskModeCodeAudit)
	}
	var cfg audit.Config
	if err := json.Unmarshal(got.AuditConfig, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SourceType != audit.SourceZip || cfg.UploadID != "u" {
		t.Fatalf("audit_config was changed by rejected PATCH: %+v", cfg)
	}
}

// TestCreateTaskAuditHTTPValidation exercises the HTTP validation path. It needs
// a PostgreSQL-backed Manager only because Server routing/auth is constructed
// there; every assertion fails before a task row is written.
func TestCreateTaskAuditHTTPValidation(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Setenv("ARTEX_AUDIT_LOCAL_ROOTS", root)

	do := func(body map[string]any) (int, map[string]any) {
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{
			name: "invalid mode",
			body: map[string]any{"description": "d", "task_mode": "recon"},
			want: "无效的任务模式",
		},
		{
			name: "code audit missing config",
			body: map[string]any{"description": "d", "task_mode": db.TaskModeCodeAudit},
			want: "缺少 audit 配置",
		},
		{
			name: "pentest with config",
			body: map[string]any{"description": "d", "audit": map[string]any{"source_type": "zip", "upload_id": "u"}},
			want: "不支持 audit 配置",
		},
		{
			name: "local outside root",
			body: map[string]any{
				"description": "d", "task_mode": db.TaskModeCodeAudit,
				"audit": map[string]any{"source_type": "local", "local_path": filepath.Join(root, "..", "outside")},
			},
			want: "本地目录不在允许范围",
		},
		{
			name: "deep codegraph off",
			body: map[string]any{
				"description": "d", "task_mode": db.TaskModeCodeAudit,
				"audit": map[string]any{
					"source_type": "zip", "upload_id": "u", "depth": "deep",
					"engines": map[string]any{"codegraph": "off"},
				},
			},
			want: "engines.codegraph 不能为 off",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := do(tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%v, want 400", code, body)
			}
			if msg, _ := body["error"].(string); !strings.Contains(msg, tc.want) {
				t.Fatalf("error = %q, want substring %q", msg, tc.want)
			}
		})
	}
}
