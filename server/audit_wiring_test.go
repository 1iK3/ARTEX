package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/mcp"
	actool "github.com/Autumn-27/norma/tool"
)

func TestPlannerWorkerKeys(t *testing.T) {
	p, w := plannerWorkerKeys(&Task{Mode: db.TaskModeCodeAudit})
	if p != "code_planner" || w != "code_worker" {
		t.Fatalf("code_audit keys = %q/%q", p, w)
	}
	p, w = plannerWorkerKeys(&Task{Mode: db.TaskModePentest})
	if p != "planner" || w != "worker" {
		t.Fatalf("pentest keys = %q/%q", p, w)
	}
	p, w = plannerWorkerKeys(nil)
	if p != "planner" || w != "worker" {
		t.Fatalf("nil keys = %q/%q", p, w)
	}
}

func TestBuildAuditSeedIntentsAndPayload(t *testing.T) {
	plan := audit.Plan{
		Languages:   []string{"go"},
		Modules:     []string{"cmd", "internal"},
		PlannedCWEs: map[string][]string{"go": {"CWE-89"}},
	}
	seeds := buildAuditSeedIntents(plan, audit.Profile{Primary: "go"})
	if len(seeds) != 2 {
		t.Fatalf("seed count = %d", len(seeds))
	}
	if seeds[0].Phase != audit.PhaseProfile || seeds[1].Phase != audit.PhaseSurface {
		t.Fatalf("phases = %q/%q", seeds[0].Phase, seeds[1].Phase)
	}
	for _, seed := range seeds {
		if seed.Priority != 8 || seed.Language != "go" {
			t.Fatalf("seed identity = %+v", seed)
		}
		if len(seed.Modules) != 2 || len(seed.SinkKeys) != 0 || len(seed.Deliverables) == 0 {
			t.Fatalf("seed scope = %+v", seed)
		}
	}
	raw, err := json.Marshal(auditSeedPayload(seeds[0], 1))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Summary string `json:"summary"`
		Audit   struct {
			Phase        string         `json:"phase"`
			Round        int            `json:"round"`
			Language     string         `json:"language"`
			Scope        map[string]any `json:"scope"`
			SinkKeys     []string       `json:"sink_keys"`
			Deliverables []string       `json:"deliverables"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Summary == "" || payload.Audit.Phase != audit.PhaseProfile || payload.Audit.Round != 1 ||
		payload.Audit.Language != "go" || payload.Audit.SinkKeys == nil || len(payload.Audit.SinkKeys) != 0 ||
		len(payload.Audit.Deliverables) == 0 {
		t.Fatalf("payload = %+v", payload)
	}
	if !strings.Contains(string(raw), `"sink_keys":[]`) {
		t.Fatalf("sink_keys must serialize as []: %s", raw)
	}
}

func TestAuditPlanCoverageRows(t *testing.T) {
	plan := audit.Plan{
		Languages:   []string{"go"},
		Modules:     []string{"internal"},
		PlannedCWEs: map[string][]string{"go": {"CWE-89", "CWE-22"}},
	}
	sites := []audit.SinkSite{{
		Language: "go", CWE: "CWE-78", Path: "cmd/main.go", Symbol: "exec",
		SinkKey: "sink-1", Line: 12,
	}}
	rows := auditPlanCoverageRows(9, plan, sites, "fallback")
	counts := map[string]int{}
	for _, row := range rows {
		counts[row.Kind]++
		if row.SessionID != 9 || row.Round != 1 || row.Status != audit.CoverageStatusPlanned {
			t.Fatalf("row = %+v", row)
		}
		if row.Engine != "fallback" {
			t.Fatalf("row engine = %q, want fallback", row.Engine)
		}
	}
	if counts[audit.CoverageKindCWE] != 2 || counts[audit.CoverageKindModule] != 1 || counts[audit.CoverageKindSinkSite] != 1 {
		t.Fatalf("kind counts = %v", counts)
	}
	foundCWE := false
	for _, row := range rows {
		if row.Kind == audit.CoverageKindCWE && row.CWE == "CWE-89" {
			foundCWE = row.SinkKey == "cwe:go:CWE-89"
		}
		if row.Kind == audit.CoverageKindSinkSite {
			if row.SinkKey != "sink-1" || row.Module != "cmd" || row.Line != 12 {
				t.Fatalf("sink row = %+v", row)
			}
		}
	}
	if !foundCWE {
		t.Fatal("CWE-89 coverage row missing or wrong key")
	}
}

func TestAuditPrescanLimitsFromBudgets(t *testing.T) {
	cfg := audit.Config{
		IncludeTests: true, IncludeVendor: true,
		Budgets: map[string]any{
			"max_files":         float64(12),
			"max_file_bytes":    int64(34),
			"max_sites_per_cwe": json.Number("56"),
		},
	}
	limits := auditPrescanLimits(cfg)
	if limits.MaxFiles != 12 || limits.MaxFileBytes != 34 || limits.MaxSitesPerCWE != 56 {
		t.Fatalf("limits = %+v", limits)
	}
	if !limits.IncludeTests || !limits.IncludeVendor {
		t.Fatalf("include flags = %+v", limits)
	}
	if got := auditBudgetInt(cfg, "missing"); got != 0 {
		t.Fatalf("missing budget = %d", got)
	}
}

func TestBuildAuditProgress(t *testing.T) {
	session := &db.AuditSession{
		ID: 3, TaskID: 4, Status: db.AuditStatusRunning, Round: 1, MaxRounds: 3,
		Depth: audit.DepthStandard, Backend: audit.EngineCodeGraph, SourceRef: "local:repo:abc",
		Languages: []string{"go"}, Engines: json.RawMessage(`{"codegraph":"required"}`),
	}
	plan := audit.Plan{
		Depth: audit.DepthStandard, Languages: []string{"go"},
		PlannedCWEs: map[string][]string{"go": {"CWE-89"}},
	}
	phases := []db.AuditPhase{{Phase: audit.PhaseProfile, Required: true, Status: "done"}}
	rows := []db.AuditCoverage{
		{Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-89", Status: audit.CoverageStatusScanned},
		{Kind: audit.CoverageKindModule, Module: "internal", Status: audit.CoverageStatusScanned},
	}
	raw, err := buildAuditProgress(auditProgressInput{
		Session: session, Plan: plan, Phases: phases, CoverageRows: rows,
		Intents:       []db.AuditDetectionIntent{{ID: 5, Round: 1, IntentKey: "k", Status: "planned"}},
		IntentSummary: map[string]int{"open": 1},
		Candidates:    []auditCoverageCandidate{{Phase: audit.PhaseDetect, CWE: "CWE-89", Language: "go", Module: "internal", SinkKeys: []string{"s1"}, Priority: 8}},
		Findings:      map[string]int{"candidate": 2}, FindingsTotal: 2,
		Hypotheses: []db.AuditHypothesis{{ID: 8, HypothesisKey: "h", Status: "untested"}},
		Engines:    []db.AuditEngineJob{{ID: 9, Engine: "codegraph", Status: "done", ResultCount: 3}},
		Ready:      false, ReadyReason: "审计报告尚未生成",
	})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	gates := out["gates"].(map[string]any)
	phaseGate := gates["phase"].(map[string]any)
	if phaseGate["passed"] != true {
		t.Fatalf("phase gate = %v", phaseGate)
	}
	coverage := out["coverage"].(map[string]any)
	if coverage["cwe"] != float64(1) {
		t.Fatalf("cwe coverage = %v", coverage["cwe"])
	}
	findings := out["findings"].(map[string]any)
	if findings["total"] != float64(2) {
		t.Fatalf("findings = %v", findings)
	}
	candidates := out["candidates"].([]any)
	if len(candidates) != 1 {
		t.Fatalf("candidates = %v", candidates)
	}
	candidate := candidates[0].(map[string]any)
	if candidate["phase"] != audit.PhaseDetect || candidate["sink_keys"].([]any)[0] != "s1" {
		t.Fatalf("candidate = %v", candidate)
	}
	sessionJSON := out["session"].(map[string]any)
	if _, ok := sessionJSON["snapshot_path"]; ok {
		t.Fatal("audit_progress must not expose snapshot_path")
	}
	if sessionJSON["source_label"] == "" {
		t.Fatal("audit_progress lacks redacted source_label")
	}
	if out["ready_to_complete"] != false {
		t.Fatalf("ready_to_complete = %v", out["ready_to_complete"])
	}
	budget := out["budget"].(map[string]any)
	if budget["max_rounds"] != float64(3) {
		t.Fatalf("budget = %v", budget)
	}
}

func TestAuditReadiness(t *testing.T) {
	session := &db.AuditSession{
		Status: db.AuditStatusDone, Depth: audit.DepthDeep,
		ReportMD: "# report", Languages: []string{"go"},
	}
	plan := audit.Plan{
		Depth: audit.DepthDeep, Languages: []string{"go"},
		PlannedCWEs: map[string][]string{"go": {"CWE-89"}},
	}
	phases := []db.AuditPhase{{Phase: audit.PhaseProfile, Required: true, Status: "done"}}
	rows := []db.AuditCoverage{{
		Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-89", Status: audit.CoverageStatusScanned,
	}}
	if ready, reason := auditReadiness(session, phases, plan, rows); !ready {
		t.Fatalf("expected ready, got false: %s", reason)
	}
	withGaps := *session
	withGaps.Status = db.AuditStatusDoneWithGaps
	if ready, reason := auditReadiness(&withGaps, phases, plan, rows); !ready {
		t.Fatalf("done_with_gaps + report must be ready: %s", reason)
	}

	noReport := *session
	noReport.ReportMD = ""
	if ready, _ := auditReadiness(&noReport, phases, plan, rows); ready {
		t.Fatal("report-less audit must not be ready")
	}
	running := *session
	running.Status = db.AuditStatusRunning
	if ready, _ := auditReadiness(&running, phases, plan, rows); ready {
		t.Fatal("running audit must not be ready even with a stale report")
	}
	ingest := *session
	ingest.Status = db.AuditStatusIngest
	if ready, _ := auditReadiness(&ingest, phases, plan, rows); ready {
		t.Fatal("ingest audit must not be ready")
	}
	if ready, _ := auditReadiness(nil, phases, plan, rows); ready {
		t.Fatal("nil session must not be ready")
	}
}

func TestWriteAuditArtifact(t *testing.T) {
	root := t.TempDir()
	s := &Server{m: &Manager{dir: root}}
	deps := &serverAuditDeps{s: s}
	stored, err := deps.WriteAuditArtifact(context.Background(), 11, "poc/cwe89.py", []byte("print(1)"))
	if err != nil {
		t.Fatal(err)
	}
	if stored != "audit/artifacts/poc/cwe89.py" {
		t.Fatalf("stored = %q", stored)
	}
	data, err := os.ReadFile(filepath.Join(root, "tasks", "11", "audit", "artifacts", "poc", "cwe89.py"))
	if err != nil || string(data) != "print(1)" {
		t.Fatalf("artifact = %q, %v", data, err)
	}
	for _, bad := range []string{"../escape.txt", "/abs.txt", `C:\abs.txt`, "a:b.txt", "CON", "file.txt:stream"} {
		if _, err := deps.WriteAuditArtifact(context.Background(), 11, bad, []byte("x")); err == nil {
			t.Errorf("path %q should be rejected", bad)
		}
	}
}

func TestAuditCodeGraphCLIArgs(t *testing.T) {
	got := auditCodeGraphCLIArgs("callers", []string{"main"}, `C:\repo`)
	want := []string{"callers", "main", "-p", `C:\repo`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	got = auditCodeGraphCLIArgs("files", nil, "")
	want = []string{"files"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
}

func TestCallAuditMCPTool(t *testing.T) {
	var received string
	tools := mcp.InProcessServer("codegraph", []mcp.InProcessTool{{
		Name: "codegraph_explore",
		Handler: func(_ context.Context, args json.RawMessage) (string, error) {
			received = string(args)
			return "explore-output", nil
		},
	}})
	byName := make(map[string]actool.CoreTool, len(tools))
	for _, tool := range tools {
		byName[tool.Name()] = tool
	}
	out, err := callAuditMCPTool(context.Background(), byName, ".", "codegraph_explore", map[string]any{"query": "main"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "explore-output" || !strings.Contains(received, `"query":"main"`) {
		t.Fatalf("out=%q received=%s", out, received)
	}
	if _, err := callAuditMCPTool(context.Background(), byName, ".", "codegraph_node", nil); err == nil ||
		!strings.Contains(err.Error(), "未提供工具") || !strings.Contains(err.Error(), "codegraph_explore") {
		t.Fatalf("missing-tool error = %v", err)
	}
}

func TestDecodeAuditTaskConfig(t *testing.T) {
	raw := json.RawMessage(`{"source_type":"zip","upload_id":"u","depth":"quick"}`)
	cfg, err := decodeAuditTaskConfig(&Task{AuditConfig: raw})
	if err != nil || cfg.SourceType != audit.SourceZip || cfg.UploadID != "u" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	if _, err := decodeAuditTaskConfig(&Task{}); err == nil {
		t.Fatal("missing audit config should fail")
	}
	if _, err := decodeAuditTaskConfig(&Task{AuditConfig: json.RawMessage(`{`)}); err == nil {
		t.Fatal("invalid audit config should fail")
	}
}

func TestSeedPromptsSeedsCodeAudit(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	seedPrompts(m.pg)
	for _, key := range []string{"code_planner", "code_worker"} {
		agentRow, err := m.pg.GetAgentByKey(key)
		if err != nil || agentRow == nil {
			t.Fatalf("agent %s = %+v, %v", key, agentRow, err)
		}
		prompt, err := m.pg.CurrentPrompt(agentRow.ID)
		if err != nil || strings.TrimSpace(prompt) == "" {
			t.Fatalf("prompt %s = %d bytes, %v", key, len(prompt), err)
		}
	}
}

func TestAuditDirectorStartLocalSource(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	// Registered first → runs last, after the task/engine cleanup below.
	t.Cleanup(func() {
		cancel()
		s.auditDirector.StopAll()
		m.Close()
	})

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.py"), []byte("import os\n\ndef run(user_input):\n    eval(user_input)\n    exec(user_input)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_AUDIT_LOCAL_ROOTS", root)
	cfg := fmt.Sprintf(`{"source_type":"local","local_path":%q,"depth":"quick","cwe_scope":"core","max_rounds":1,"languages":["python"],"engines":{"codegraph":"off","codeql":"off","joern":"off"}}`, root)
	task, err := m.pg.CreateTaskWithOptions("audit director test", "audit fixture", db.TaskCreateOptions{
		Mode: db.TaskModeCodeAudit, AuditConfig: json.RawMessage(cfg),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })
	// Keep the task paused so preflight runs but engine loops never start (and
	// never call an LLM configured in a shared dev database).
	if _, err := m.pg.Exec(`UPDATE tasks SET paused=true WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	m.LoadExisting()
	serverTask, ok := m.Task(strconv.FormatInt(task.ID, 10))
	if !ok {
		t.Fatalf("task %d not loaded into manager", task.ID)
	}
	t.Cleanup(func() {
		s.auditDirector.Stop(serverTask.ID)
		s.engine.StopTask(serverTask.ID)
	})

	if err := s.auditDirector.Start(ctx, serverTask); err != nil {
		t.Fatalf("director start: %v", err)
	}
	session, err := m.pg.GetAuditSession(task.ID)
	if err != nil || session == nil {
		t.Fatalf("session = %+v, %v", session, err)
	}
	if session.Status != db.AuditStatusRunning || session.Backend != "fallback" {
		t.Fatalf("session = %+v", session)
	}
	if session.SnapshotPath == "" || session.ReportMD != "" {
		t.Fatalf("session paths = %+v", session)
	}
	phases, err := m.pg.ListAuditPhases(session.ID, 1)
	if err != nil || len(phases) == 0 {
		t.Fatalf("phases = %d, %v", len(phases), err)
	}
	s0Done := false
	for _, phase := range phases {
		if phase.Phase == audit.PhaseIngest && phase.Status == "done" {
			s0Done = true
		}
	}
	if !s0Done {
		t.Fatalf("S0 was not marked done: %+v", phases)
	}
	coverage, err := m.pg.ListAuditCoverage(session.ID, 1)
	if err != nil || len(coverage) == 0 {
		t.Fatalf("coverage = %d, %v", len(coverage), err)
	}
	for _, row := range coverage {
		if row.Engine != "fallback" {
			t.Fatalf("coverage backend = %q, want fallback", row.Engine)
		}
	}
	intents, err := serverTask.Store.ListByKind(db.KindIntent, 100)
	if err != nil {
		t.Fatal(err)
	}
	seeded := map[string]bool{}
	for _, intent := range intents {
		if intent.Origin == "audit_director" {
			seeded[auditIntentPhase(intent.Payload)] = true
		}
	}
	if !seeded[audit.PhaseProfile] || !seeded[audit.PhaseSurface] {
		t.Fatalf("seeded intents = %v", seeded)
	}
	goals, err := serverTask.Store.ListByKind(db.KindGoal, 10)
	if err != nil || len(goals) == 0 {
		t.Fatalf("goals = %d, %v", len(goals), err)
	}

	var s4 *db.Node
	for _, intent := range intents {
		if intent.Origin == "audit_director" && auditIntentPhase(intent.Payload) == audit.PhaseDetect {
			s4 = intent
			break
		}
	}
	if s4 == nil {
		t.Fatalf("no S4 detection intent seeded; coverage=%+v", coverage)
	}
	deps := s.auditDepsFor(serverTask)
	assigned, err := deps.AssignedCoverage(ctx, task.ID, s4.ID)
	if err != nil || len(assigned) == 0 {
		t.Fatalf("assigned coverage = %d, %v", len(assigned), err)
	}
	if err := deps.CompleteAuditIntent(ctx, task.ID, s4.ID, []audit.CoverageReceipt{{
		SinkKey: assigned[0].SinkKey, Status: audit.CoverageStatusScanned,
	}}, nil); err != nil {
		t.Fatalf("complete assigned receipt: %v", err)
	}
	updated, err := m.pg.ListAuditCoverage(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	foundScanned := false
	for _, row := range updated {
		if row.SinkKey == assigned[0].SinkKey && row.Status == audit.CoverageStatusScanned {
			foundScanned = true
		}
	}
	if !foundScanned {
		t.Fatalf("owned receipt did not update coverage: %+v", updated)
	}
	if err := deps.CompleteAuditIntent(ctx, task.ID, s4.ID, []audit.CoverageReceipt{{
		SinkKey: "not-assigned-key", Status: audit.CoverageStatusScanned,
	}}, nil); err == nil {
		t.Fatal("unassigned sink key was accepted")
	}

	// Terminal cleanup must return unreceipted planned rows to the pool while
	// keeping the scanned verdict attached.
	s.auditDirector.OnIntentDone(serverTask, s4.ID, "blocked")
	updated, err = m.pg.ListAuditCoverage(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	releasedKey := ""
	for _, row := range updated {
		if row.Kind != audit.CoverageKindSinkSite {
			continue
		}
		if row.SinkKey == assigned[0].SinkKey {
			if row.IntentID == nil || *row.IntentID != s4.ID || row.Status != audit.CoverageStatusScanned {
				t.Fatalf("completed coverage row changed on release: %+v", row)
			}
			continue
		}
		if row.IntentID == nil && (row.Status == audit.CoverageStatusPlanned || row.Status == audit.CoverageStatusMissed) {
			releasedKey = row.SinkKey
		}
	}
	if releasedKey == "" {
		t.Fatalf("planned coverage row was not released: %+v", updated)
	}

	// A planner intent must claim unowned rows in its own round; a round
	// mismatch is rejected before reassignment.
	mismatchID, err := serverTask.Store.AddIntent(map[string]any{
		"summary": "wrong round",
		"audit": map[string]any{
			"phase": "S4", "round": 2, "sink_keys": []string{releasedKey},
		},
	}, 8, nil, "audit_director")
	if err != nil {
		t.Fatal(err)
	}
	if err := deps.ClaimAuditCoverage(ctx, task.ID, mismatchID, []string{releasedKey}); err == nil {
		t.Fatal("claim with mismatched audit round was accepted")
	}
	_, _ = serverTask.Store.SoftDeleteIntent(mismatchID, "test cleanup")

	claimID, err := serverTask.Store.AddIntent(map[string]any{
		"summary": "claim released sink",
		"audit": map[string]any{
			"phase": "s4", "round": 1, "sink_keys": []string{releasedKey},
		},
	}, 8, nil, "audit_director")
	if err != nil {
		t.Fatal(err)
	}
	if err := deps.ClaimAuditCoverage(ctx, task.ID, claimID, []string{releasedKey}); err != nil {
		t.Fatalf("claim released coverage: %v", err)
	}
	claimed, err := m.pg.ListAuditCoverage(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	foundClaim := false
	for _, row := range claimed {
		if row.SinkKey == releasedKey && row.IntentID != nil && *row.IntentID == claimID {
			foundClaim = true
		}
	}
	if !foundClaim {
		t.Fatalf("claim did not assign coverage: %+v", claimed)
	}
	claimNode, err := serverTask.Store.GetNode(claimID)
	if err != nil || claimNode == nil {
		t.Fatalf("claim intent node = %+v, %v", claimNode, err)
	}
	if phase := auditIntentPhase(claimNode.Payload); phase != audit.PhaseDetect {
		t.Fatalf("claim did not normalize audit phase: %q", phase)
	}

	// Missing snapshot on resume must reset to ingest and rebuild it. The task is
	// still paused, so Start performs preflight and then leaves engine start to
	// admission.
	s.auditDirector.Stop(serverTask.ID)
	if err := os.RemoveAll(session.SnapshotPath); err != nil {
		t.Fatal(err)
	}
	if err := s.auditDirector.Start(ctx, serverTask); err != nil {
		t.Fatalf("director resume after snapshot loss: %v", err)
	}
	resumed, err := m.pg.GetAuditSession(task.ID)
	if err != nil || resumed == nil {
		t.Fatalf("resumed session = %+v, %v", resumed, err)
	}
	if resumed.Status != db.AuditStatusRunning || !auditSnapshotExists(resumed.SnapshotPath) {
		t.Fatalf("resume did not rebuild snapshot: %+v", resumed)
	}
}

func TestAuditDirectorPreflightFailureMarksSessionFailed(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	t.Cleanup(func() {
		cancel()
		s.auditDirector.StopAll()
		m.Close()
	})
	cfg := `{"source_type":"zip","upload_id":"does-not-exist","depth":"quick","cwe_scope":"core","max_rounds":1}`
	dbTask, err := m.pg.CreateTaskWithOptions("audit failure", "audit failure", db.TaskCreateOptions{
		Mode: db.TaskModeCodeAudit, AuditConfig: json.RawMessage(cfg),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(dbTask.ID) })
	task := &Task{
		ID: strconv.FormatInt(dbTask.ID, 10), ExpID: dbTask.ExplorationID,
		Mode: db.TaskModeCodeAudit, AuditConfig: json.RawMessage(cfg),
		Store: m.pg.Exploration(dbTask.ExplorationID),
	}
	if err := s.auditDirector.Start(ctx, task); err == nil {
		t.Fatal("missing zip upload should fail preflight")
	}
	session, err := m.pg.GetAuditSession(dbTask.ID)
	if err != nil || session == nil {
		t.Fatalf("session = %+v, %v", session, err)
	}
	if session.Status != db.AuditStatusFailed {
		t.Fatalf("session status = %q, want failed", session.Status)
	}
	persisted, err := m.pg.GetTask(dbTask.ID)
	if err != nil || persisted == nil || persisted.Status != "failed" {
		t.Fatalf("task status = %+v, %v, want failed", persisted, err)
	}
}

func TestAuditDirectorReleasesTerminalCoverage(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	s := &Server{m: m, engine: NewEngine(m)}
	s.auditDirector = newAuditDirector(s)
	task, err := m.pg.CreateTaskWithOptions("terminal release", "release", db.TaskCreateOptions{
		Mode: db.TaskModeCodeAudit, AuditConfig: json.RawMessage(`{"source_type":"zip","upload_id":"u"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })
	session, err := m.pg.CreateAuditSession(db.AuditSession{
		TaskID: task.ID, Status: db.AuditStatusRunning, SourceType: "zip", Depth: "quick",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := m.pg.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{
		"summary": "S4 batch",
		"audit": map[string]any{
			"phase": "S4", "round": 1, "sink_keys": []string{"planned-1", "planned-2"},
		},
	}, 8, nil, "audit_director")
	if err != nil {
		t.Fatal(err)
	}
	rows := []db.AuditCoverage{
		{SessionID: session.ID, Round: 1, Kind: audit.CoverageKindSinkSite, SinkKey: "planned-1", Status: audit.CoverageStatusPlanned},
		{SessionID: session.ID, Round: 1, Kind: audit.CoverageKindSinkSite, SinkKey: "planned-2", Status: audit.CoverageStatusScanned},
	}
	if err := m.pg.UpsertAuditCoverage(rows); err != nil {
		t.Fatal(err)
	}
	if n, err := m.pg.AssignAuditCoverage(session.ID, 1, []string{"planned-1", "planned-2"}, intentID); err != nil || n != 2 {
		t.Fatalf("assign = %d, %v", n, err)
	}
	serverTask := &Task{
		ID: strconv.FormatInt(task.ID, 10), ExpID: task.ExplorationID,
		Mode: db.TaskModeCodeAudit, Store: store,
	}
	s.auditDirector.OnIntentDone(serverTask, intentID, "blocked")
	listed, err := m.pg.ListAuditCoverage(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	for _, row := range listed {
		switch row.SinkKey {
		case "planned-1":
			released = row.IntentID == nil
		case "planned-2":
			if row.IntentID == nil || *row.IntentID != intentID {
				t.Fatalf("completed row ownership lost: %+v", row)
			}
		}
	}
	if !released {
		t.Fatalf("planned row was not released: %+v", listed)
	}
	activity, _, err := store.ActivityList(nil, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range activity {
		if strings.Contains(item.Summary, "释放 1 个未完成覆盖行") {
			found = true
		}
	}
	if !found {
		t.Fatalf("release activity missing: %+v", activity)
	}
}
