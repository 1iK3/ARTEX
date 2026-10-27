package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
)

func TestAuditDirectorStartDoneSessionKeepsReport(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := &Server{m: m, engine: NewEngine(m)}
	s.auditDirector = newAuditDirector(s)
	// Deliberately incomplete: a finished session must be recognized before
	// config validation so a legacy/incomplete config cannot mark it failed.
	cfg := json.RawMessage(`{}`)
	task, err := m.pg.CreateTaskWithOptions("done session resume", "done", db.TaskCreateOptions{
		Mode: db.TaskModeCodeAudit, AuditConfig: cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })
	report := "# existing report"
	session, err := m.pg.CreateAuditSession(db.AuditSession{
		TaskID: task.ID, Status: db.AuditStatusDone, SourceType: "zip",
		SourceRef: "zip:fixture:abcd", Depth: audit.DepthQuick, Round: 1, MaxRounds: 1,
		ReportMD: report, ReportJSON: json.RawMessage(`{"status":"done"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	serverTask := &Task{
		ID: strconv.FormatInt(task.ID, 10), ExpID: task.ExplorationID,
		Mode: db.TaskModeCodeAudit, AuditConfig: cfg, Store: m.pg.Exploration(task.ExplorationID),
	}
	if err := s.auditDirector.Start(t.Context(), serverTask); err != nil {
		t.Fatalf("Start on done session = %v", err)
	}
	stored, err := m.pg.GetAuditSession(task.ID)
	if err != nil || stored == nil {
		t.Fatalf("session = %+v, %v", stored, err)
	}
	if stored.Status != db.AuditStatusDone || stored.ReportMD != report {
		t.Fatalf("done session was mutated/failed: %+v", stored)
	}
	persistedTask, err := m.pg.GetTask(task.ID)
	if err != nil || persistedTask == nil || persistedTask.Status != "done" {
		t.Fatalf("task status = %+v, %v; want done", persistedTask, err)
	}
	if session.Status != db.AuditStatusDone {
		t.Fatalf("original session fixture mutated: %+v", session)
	}
	if len(s.auditDirector.runs) != 0 {
		t.Fatalf("done session left a live audit run: %+v", s.auditDirector.runs)
	}
}

func TestAuditPreflightExemptsNoSinkCoverage(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := &Server{m: m, engine: NewEngine(m)}
	s.auditDirector = newAuditDirector(s)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_AUDIT_LOCAL_ROOTS", root)
	cfg := audit.Config{
		SourceType: audit.SourceLocal, LocalPath: root, Depth: audit.DepthQuick,
		CWEScope: audit.CWEScopeCore, Languages: []string{"go"}, MaxRounds: 1,
		Engines: map[string]string{audit.EngineCodeGraph: "off", audit.EngineCodeQL: "off", audit.EngineJoern: "off"},
	}
	cfgRaw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	task, err := m.pg.CreateTaskWithOptions("no sink go", "no sink go", db.TaskCreateOptions{
		Mode: db.TaskModeCodeAudit, AuditConfig: cfgRaw,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })
	serverTask := &Task{
		ID: strconv.FormatInt(task.ID, 10), ExpID: task.ExplorationID,
		Mode: db.TaskModeCodeAudit, AuditConfig: cfgRaw, Store: m.pg.Exploration(task.ExplorationID),
		Paused: true, // preflight only; do not start an LLM-backed engine loop
	}
	t.Cleanup(func() { s.auditDirector.Stop(serverTask.ID) })
	if err := s.auditDirector.Start(t.Context(), serverTask); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	session, err := m.pg.GetAuditSession(task.ID)
	if err != nil || session == nil {
		t.Fatalf("session = %+v, %v", session, err)
	}
	rows, err := m.pg.ListAuditCoverage(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Kind == audit.CoverageKindSinkSite {
			t.Fatalf("Go fixture unexpectedly produced a sink site: %+v", row)
		}
		if row.Kind == audit.CoverageKindCWE && (row.Status != audit.CoverageStatusExempt || !audit.ValidExemptionReason(row.Reason)) {
			t.Fatalf("CWE row not exempted: %+v", row)
		}
		if row.Kind == audit.CoverageKindModule && (row.Status != audit.CoverageStatusExempt || !audit.ValidExemptionReason(row.Reason)) {
			t.Fatalf("module row not exempted: %+v", row)
		}
	}
	plan := auditPlanFromSession(session)
	converted := auditCoverageRows(rows)
	if gate := audit.GateCWE(plan, converted); !gate.Passed {
		t.Fatalf("Go no-sink Gate-CWE = %+v", gate)
	}
	if gate := audit.GateCoverage(plan, converted, plan.Depth); !gate.Passed {
		t.Fatalf("Go no-sink Gate-Coverage = %+v", gate)
	}
	phases, err := m.pg.ListAuditPhases(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range phases {
		if phase.Phase != audit.PhaseDetect {
			continue
		}
		if phase.Status != "skipped" || auditPhaseReason(phase) != "no_sinks" {
			t.Fatalf("S4 zero-sink phase = %+v reason=%q", phase, auditPhaseReason(phase))
		}
	}
}

func TestAuditCandidateReceiptRequiresIntentOwnership(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := &Server{m: m, engine: NewEngine(m)}
	task, err := m.pg.CreateTaskWithOptions("candidate ownership", "ownership", db.TaskCreateOptions{
		Mode: db.TaskModeCodeAudit, AuditConfig: json.RawMessage(`{"source_type":"zip","upload_id":"u"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })
	session, err := m.pg.CreateAuditSession(db.AuditSession{TaskID: task.ID, Status: db.AuditStatusRunning, SourceType: "zip", Depth: "quick"})
	if err != nil {
		t.Fatal(err)
	}
	store := m.pg.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{
		"summary": "S4 candidate", "audit": map[string]any{"phase": "S4", "round": 1, "sink_keys": []string{"s1"}},
	}, 8, nil, "audit_director")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.UpsertAuditCoverage([]db.AuditCoverage{{
		SessionID: session.ID, Round: 1, Kind: audit.CoverageKindSinkSite,
		SinkKey: "s1", Status: audit.CoverageStatusPlanned,
	}}); err != nil {
		t.Fatal(err)
	}
	if n, err := m.pg.AssignAuditCoverage(session.ID, 1, []string{"s1"}, intentID); err != nil || n != 1 {
		t.Fatalf("assign = %d, %v", n, err)
	}
	findingNode, err := store.AddNode("finding", map[string]any{"summary": "candidate"}, 9, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	findingID, duplicate, err := m.pg.AddCodeFinding(db.CodeFindingInput{
		TaskID: task.ID, NodeID: findingNode, CWEID: "CWE-89", Title: "SQL injection",
		Severity: "high", Summary: "candidate", Evidence: "proof", Verification: "candidate",
		CodePath: "a.go", CodeLine: 1, CodeSymbol: "query",
	})
	if err != nil || duplicate || findingID <= 0 {
		t.Fatalf("AddCodeFinding = %d/%v/%v", findingID, duplicate, err)
	}
	deps := &serverAuditDeps{s: s}
	receipt := []audit.CoverageReceipt{{SinkKey: "s1", Status: audit.CoverageStatusCandidate, FindingID: findingID}}
	if err := deps.CompleteAuditIntent(t.Context(), task.ID, intentID, receipt, nil); err == nil ||
		!strings.Contains(err.Error(), "不是由意图") {
		t.Fatalf("unowned candidate receipt error = %v", err)
	}
	if _, err := m.pg.Exec(`
INSERT INTO exploration_edges(exploration_id, src_id, rel, dst_id)
VALUES($1,$2,$3,$4)`, task.ExplorationID, intentID, db.RelYields, findingNode); err != nil {
		t.Fatal(err)
	}
	if err := deps.CompleteAuditIntent(t.Context(), task.ID, intentID, receipt, nil); err != nil {
		t.Fatalf("owned candidate receipt failed: %v", err)
	}
}

func TestAuditAssignedFindingsScopedToIntent(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := &Server{m: m, engine: NewEngine(m)}
	task, err := m.pg.CreateTaskWithOptions("assigned findings", "assigned", db.TaskCreateOptions{
		Mode: db.TaskModeCodeAudit, AuditConfig: json.RawMessage(`{"source_type":"zip","upload_id":"u"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })
	if _, err := m.pg.CreateAuditSession(db.AuditSession{TaskID: task.ID, Status: db.AuditStatusRunning, SourceType: "zip", Depth: "quick"}); err != nil {
		t.Fatal(err)
	}
	store := m.pg.Exploration(task.ExplorationID)
	makeFinding := func(cwe, title string, line int) int64 {
		node, err := store.AddNode("finding", map[string]any{"summary": title}, 9, "confirmed", "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		id, _, err := m.pg.AddCodeFinding(db.CodeFindingInput{
			TaskID: task.ID, NodeID: node, CWEID: cwe, Title: title, Severity: "high",
			Summary: title, Evidence: "proof", Verification: "candidate",
			CodePath: "a.go", CodeLine: line, CodeSymbol: "query",
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := makeFinding("CWE-89", "first", 1)
	second := makeFinding("CWE-79", "second", 2)
	intentID, err := store.AddIntent(map[string]any{
		"summary": "S5 verify first only",
		"audit": map[string]any{
			"phase": audit.PhaseVerify, "round": 1,
			"finding_ids": []int64{first},
		},
	}, 9, nil, "audit_director")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := (&serverAuditDeps{s: s}).AssignedFindings(t.Context(), task.ID, intentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ID != first {
		t.Fatalf("assigned findings = %+v, want only finding %d (not %d)", findings, first, second)
	}
}

// TestAuditCompletionGeneratesReport exercises the real director completion path
// (phase bookkeeping -> gates -> report files -> session/readiness). It is
// skipped when PostgreSQL is unavailable, like the other DB-backed tests.
func TestAuditCompletionGeneratesReport(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := &Server{m: m, engine: NewEngine(m)}
	s.auditDirector = newAuditDirector(s)

	task, err := m.pg.CreateTaskWithOptions("audit completion report", "audit completion", db.TaskCreateOptions{
		Mode:        db.TaskModeCodeAudit,
		AuditConfig: json.RawMessage(`{"source_type":"zip","upload_id":"u","depth":"quick","languages":["go"],"max_rounds":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })
	plan := `{"depth":"quick","max_rounds":1,"languages":["go"],"planned_cwes":{},"modules":[],"entry_points":[],"phases":[]}`
	session, err := m.pg.CreateAuditSession(db.AuditSession{
		TaskID: task.ID, Status: db.AuditStatusRunning, SourceType: "zip",
		SourceRef: "zip:fixture:abcd", Depth: audit.DepthQuick, Backend: "fallback",
		Languages: []string{"go"}, Plan: json.RawMessage(plan),
		Engines: json.RawMessage(`{"codegraph":"off"}`),
		Round:   1, MaxRounds: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	phases := []db.AuditPhase{
		{Phase: audit.PhaseIngest, Required: true, Status: "done"},
		{Phase: audit.PhaseProfile, Required: true, Status: "done"},
		{Phase: audit.PhaseSurface, Required: true, Status: "done"},
		{Phase: audit.PhaseDetect, Required: true, Status: "done"},
		{Phase: audit.PhaseReport, Required: true, Status: "pending"},
	}
	if err := m.pg.InsertAuditPhases(session.ID, 1, phases); err != nil {
		t.Fatal(err)
	}
	store := m.pg.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{
		"summary": "S1 profile done",
		"audit":   map[string]any{"phase": audit.PhaseProfile, "round": 1},
	}, 8, nil, "audit_director")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetNodeState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	serverTask := &Task{
		ID: strconv.FormatInt(task.ID, 10), ExpID: task.ExplorationID,
		Mode: db.TaskModeCodeAudit, Store: store,
	}
	start := time.Now()
	s.auditDirector.OnIntentDone(serverTask, intentID, "done")

	updated, err := m.pg.GetAuditSession(task.ID)
	if err != nil || updated == nil {
		t.Fatalf("session = %+v, %v", updated, err)
	}
	if updated.Status != db.AuditStatusDone {
		t.Fatalf("session status = %q, want done (gates=%s)", updated.Status, updated.GateResults)
	}
	if strings.TrimSpace(updated.ReportMD) == "" || len(updated.ReportJSON) == 0 {
		t.Fatalf("report not persisted: md=%d json=%d", len(updated.ReportMD), len(updated.ReportJSON))
	}
	if !strings.Contains(updated.ReportMD, "# 代码安全审计报告") || !strings.Contains(updated.ReportMD, "收敛结论") {
		t.Fatalf("unexpected report body:\n%s", updated.ReportMD)
	}
	var report map[string]any
	if err := json.Unmarshal(updated.ReportJSON, &report); err != nil {
		t.Fatalf("report json invalid: %v", err)
	}
	if report["status"] != db.AuditStatusDone || report["session_id"] != float64(session.ID) {
		t.Fatalf("report json = %#v", report)
	}
	var gateResults map[string]any
	if err := json.Unmarshal(updated.GateResults, &gateResults); err != nil {
		t.Fatalf("gate_results invalid: %v", err)
	}
	if gateResults["round"] != float64(1) || gateResults["forced"] != false {
		t.Fatalf("gate_results = %#v", gateResults)
	}
	updatedPhases, err := m.pg.ListAuditPhases(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	foundS11Done := false
	for _, phase := range updatedPhases {
		if phase.Phase == audit.PhaseReport {
			foundS11Done = phase.Status == "done"
		}
	}
	if !foundS11Done {
		t.Fatalf("S11 was not marked done: %+v", updatedPhases)
	}
	reportDir := filepath.Join(m.dir, "tasks", strconv.FormatInt(task.ID, 10), "audit")
	for _, name := range []string{"report.md", "report.json"} {
		info, statErr := os.Stat(filepath.Join(reportDir, name))
		if statErr != nil || info.Size() == 0 {
			t.Fatalf("%s missing or empty: %+v, %v", name, info, statErr)
		}
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("completion took too long: %s", elapsed)
	}
	ready, err := s.auditDepsFor(serverTask).ReadyToComplete(t.Context(), task.ID)
	if err != nil || !ready {
		t.Fatalf("ReadyToComplete = %v, %v", ready, err)
	}
	if strings.Contains(updated.ReportMD, m.dir) {
		t.Fatalf("report leaked the server workdir %q", m.dir)
	}
}
