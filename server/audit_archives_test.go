package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestCodeAuditArchiveRestoreKeepsReportAndPentestIdle(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	parsed, parseErr := url.Parse(dsn)
	if parseErr != nil {
		t.Skipf("invalid database DSN (%v) — skipping", parseErr)
	}
	databaseName := fmt.Sprintf("artex_audit_archive_%d", time.Now().UnixNano())
	parsed.Path = "/" + databaseName
	isolatedDSN := parsed.String()
	t.Setenv("ARTEX_PG_DSN", isolatedDSN)
	defer dropArchiveTestDatabase(t, isolatedDSN)

	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	s := &Server{
		m: m, engine: NewEngine(m), ctx: context.Background(),
		archiveWake: make(chan struct{}, 1), chatBusy: map[string]bool{},
		chatCancel: map[string]context.CancelCauseFunc{},
	}

	task, err := m.CreateTaskWithOptions("code audit archive restore", "audit fixture", db.TaskCreateOptions{
		Mode:           db.TaskModeCodeAudit,
		AuditConfig:    json.RawMessage(`{"source_type":"zip","depth":"quick","max_rounds":1}`),
		TimeoutSeconds: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	taskIDInt, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	taskID := task.ID
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM audit_sessions WHERE task_id=$1`, taskIDInt)
		_, _ = m.pg.Exec(`DELETE FROM task_archives WHERE task_id=$1`, taskIDInt)
		_ = m.pg.DeleteTask(taskIDInt)
	})
	report := "# archived code-audit report"
	if _, err := m.pg.CreateAuditSession(db.AuditSession{
		TaskID: taskIDInt, Status: db.AuditStatusDone, SourceType: "zip",
		SourceRef: "zip:fixture:archive", Depth: "quick", Round: 1, MaxRounds: 1,
		ReportMD: report, ReportJSON: json.RawMessage(`{"status":"done"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetTaskPaused(taskID, true); err != nil {
		t.Fatal(err)
	}

	job, err := m.pg.QueueTaskArchive(taskIDInt)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.runOneTaskArchiveJob(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.QueueTaskArchiveRestore(job.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.runOneTaskArchiveJob(); err != nil {
		t.Fatal(err)
	}

	restored, ok := m.Task(taskID)
	if !ok {
		t.Fatal("restored task was not reloaded")
	}
	if restored.Mode != db.TaskModeCodeAudit || !restored.lifecycleSnapshot().Paused {
		t.Fatalf("restored task mode=%s paused=%v; want code_audit/paused", restored.Mode, restored.lifecycleSnapshot().Paused)
	}
	if _, started := s.engine.coordStarted.Load(taskID); started {
		t.Fatal("code-audit restore started the pentest deadline coordinator")
	}
	goals, err := restored.Store.ListByKind(db.KindGoal, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(goals) != 0 {
		t.Fatalf("code-audit restore seeded pentest goals: %d", len(goals))
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/tasks/"+taskID+"/audit/report", nil)
	request.SetPathValue("id", taskID)
	s.auditReport(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("report status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != report {
		t.Fatalf("report body=%q, want %q", recorder.Body.String(), report)
	}
}

func dropArchiveTestDatabase(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		return
	}
	databaseName := strings.TrimPrefix(parsed.Path, "/")
	parsed.Path = "/postgres"
	admin, err := sql.Open("pgx", parsed.String())
	if err != nil {
		return
	}
	defer admin.Close()
	_, _ = admin.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()`, databaseName)
	_, _ = admin.Exec(`DROP DATABASE IF EXISTS "` + databaseName + `"`)
}
