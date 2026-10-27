package server

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
)

func TestRenderAuditReport(t *testing.T) {
	snapshot := `C:\secret-artex\work\tasks\42\audit\source`
	serverRoot := `C:\secret-artex\work`
	session := &db.AuditSession{
		ID: 7, TaskID: 42, Status: db.AuditStatusDoneWithGaps,
		SourceType:   "git",
		SourceRef:    "https://alice:hunter2@example.com/repo.git?token=abc12345",
		SnapshotPath: snapshot, CommitSHA: "0123456789abcdef",
		Depth: audit.DepthDeep, Backend: audit.EngineCodeGraph, Round: 1, MaxRounds: 1,
		Languages: []string{"go"},
		Engines:   json.RawMessage(`{"codegraph":"required","codeql":"auto"}`),
	}
	task := &Task{ID: "42", Name: "支付服务审计", Description: "审计支付服务的输入处理", Goal: "完成代码审计"}
	plan := audit.Plan{
		Depth: audit.DepthDeep, Languages: []string{"go"},
		PlannedCWEs: map[string][]string{"go": {"CWE-89", "CWE-79", "CWE-22", "CWE-94", "CWE-78"}},
		Modules:     []string{"internal/pay", "cmd/api"},
		EntryPoints: []string{"HandlePay"},
	}
	phases := []db.AuditPhase{
		{Phase: audit.PhaseIngest, Required: true, Status: "done"},
		{Phase: audit.PhaseProfile, Required: true, Status: "done"},
		{Phase: audit.PhaseSurface, Required: true, Status: "done"},
		{Phase: audit.PhaseDataFlow, Required: true, Status: "skipped", Gate: json.RawMessage(`{"reason":"no_targets"}`)},
		{Phase: audit.PhaseDetect, Required: true, Status: "done"},
		{Phase: audit.PhaseVerify, Required: true, Status: "done"},
		{Phase: audit.PhaseReport, Required: true, Status: "done"},
	}
	rows := []db.AuditCoverage{
		{Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-89", SinkKey: "cwe:go:CWE-89", Status: audit.CoverageStatusScanned},
		{Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-79", SinkKey: "cwe:go:CWE-79", Status: audit.CoverageStatusCandidate},
		{Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-22", SinkKey: "cwe:go:CWE-22", Status: audit.CoverageStatusExempt, Reason: "no_sinks: fixture"},
		{Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-94", SinkKey: "cwe:go:CWE-94", Status: audit.CoverageStatusMissed, Reason: "budget exhausted"},
		{Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-78", SinkKey: "cwe:go:CWE-78", Status: audit.CoverageStatusScanned},
		{Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-95", SinkKey: "cwe:go:CWE-95", Status: audit.CoverageStatusPlanned},
		{Kind: audit.CoverageKindModule, Module: "internal/pay", SinkKey: "module:internal/pay", Status: audit.CoverageStatusScanned},
		{Kind: audit.CoverageKindModule, Module: "cmd/api", SinkKey: "module:cmd/api", Status: audit.CoverageStatusMissed},
		{Kind: audit.CoverageKindModule, Module: "cmd/worker", SinkKey: "module:cmd/worker", Status: audit.CoverageStatusPlanned},
		{Kind: audit.CoverageKindSinkSite, Language: "go", CWE: "CWE-89", Module: "internal/pay", Path: "internal/pay/db.go", Line: 42, SinkKey: "sink:db", Status: audit.CoverageStatusCandidate, Reason: "needs S5"},
		{Kind: audit.CoverageKindSinkSite, Language: "go", CWE: "CWE-94", Module: "cmd/api", Path: "cmd/api/main.go", Line: 8, SinkKey: "sink:main", Status: audit.CoverageStatusMissed, Reason: "not reached"},
		{Kind: audit.CoverageKindSinkSite, Language: "go", CWE: "CWE-78", Module: "cmd/api", Path: "cmd/api/exec.go", Line: 12, SinkKey: "sink:exec", Status: audit.CoverageStatusPlanned, Reason: "awaiting receipt"},
	}
	confirmedEvidence, err := json.Marshal(audit.CodeEvidence{
		Version: 1, CWEID: "CWE-89", Title: "SQL injection in pay query", Severity: "high", Confidence: 0.92,
		Verification: audit.Verification{
			Status: audit.VerificationConfirmed, Method: audit.MethodTaintTrace,
			AlternativePath: "handler -> repository -> db.Query", DesignValidation: audit.DesignValidationRealVuln,
		},
		Location: audit.CodeLocation{Path: "internal/pay/db.go", Line: 42, Symbol: "payQuery"},
		Source:   &audit.CodeLocation{Path: "internal/pay/handler.go", Line: 11, Symbol: "r.FormValue"},
		Sink:     &audit.CodeLocation{Path: "internal/pay/db.go", Line: 42, Symbol: "db.Query"},
		Trace: []audit.TraceStep{
			{Path: "internal/pay/handler.go", Line: 11, Symbol: "HandlePay", Note: "entry"},
			{Path: "internal/pay/db.go", Line: 42, Symbol: "payQuery", Note: "sink"},
		},
		Sanitizers: []audit.SanitizerVerdict{{Symbol: "quoteIdentifier", Verdict: audit.SanitizerMissing}},
		Reachability: &audit.Reachability{
			Reachable: true, EntryPoint: "GET /pay", AuthRequired: true, AuthStateRecorded: true,
		},
		Impact:   "数据库数据泄露",
		Engines:  []audit.EngineEvidence{{Name: "codeql", QueryID: "q1", Confidence: 0.8, RawRef: "sarif://run/3"}},
		Analysis: audit.Analysis{Phase: audit.PhaseVerify, Round: 1, Backend: audit.EngineCodeGraph},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := []*db.DBFinding{
		{
			ID: 11, Name: "SQL 注入", VulnClass: "CWE-89", CWEID: "CWE-89", Severity: "high",
			Summary: "用户输入进入 SQL 查询", Evidence: "api_key = S3cr3tKeyValue\nsnapshot=" + snapshot,
			Report:   "## 详细说明\n\npassword: hunter2\n" + snapshot,
			CodePath: "internal/pay/db.go", CodeLine: 42, CodeSymbol: "payQuery",
			Confidence: 0.92, Verification: audit.VerificationConfirmed,
			CodeEvidence: confirmedEvidence, AuditRound: 1, AuditPhase: audit.PhaseVerify,
			CreatedAt: time.Date(2026, time.October, 27, 1, 0, 0, 0, time.UTC),
		},
		{
			ID: 12, Name: "反射型 XSS", CWEID: "CWE-79", Severity: "medium",
			Summary: "输出未编码", Evidence: "candidate proof", Verification: audit.VerificationCandidate,
			CodePath: "internal/pay/view.go", CodeLine: 9, CodeSymbol: "render",
		},
		{
			ID: 13, Name: "路径遍历", CWEID: "CWE-22", Severity: "low",
			Summary: "参数已规范化", Evidence: "refuted proof", Verification: audit.VerificationRefuted,
			CodePath: "internal/pay/file.go", CodeLine: 4, CodeSymbol: "openFile",
		},
		{
			ID: 14, Name: "按设计允许", CWEID: "CWE-94", Severity: "high",
			Summary: "插件机制设计意图", Evidence: "design intent", Verification: audit.VerificationDesignIntent,
			CodePath: "cmd/api/plugin.go", CodeLine: 5, CodeSymbol: "loadPlugin",
		},
		{
			ID: 15, Name: "命令执行", CWEID: "CWE-78", Severity: "critical",
			Summary: "尚未复核", Evidence: "unverified proof", Verification: audit.VerificationUnverified,
			CodePath: "cmd/api/main.go", CodeLine: 8, CodeSymbol: "exec.Command",
		},
	}
	hypotheses := []db.AuditHypothesis{
		{
			ID: 3, Statement: "输入是否可绕过过滤", Status: "testing",
			Attempts: json.RawMessage(`[{"action":"attempt","outcome":"failed"}]`),
			Evidence: "token=should-not-leak",
		},
	}
	engineJobs := []db.AuditEngineJob{
		{ID: 1, Engine: "codeql", Status: "failed", Error: "secret=should-not-leak", QueryText: "select * from secret", QueryPath: snapshot},
		{ID: 2, Engine: "joern", Status: "done", ResultCount: 2},
	}
	rounds := []db.AuditRound{{Round: 1, NewFindings: 5, NewConfirmed: 1, NewCandidate: 2, TotalFindings: 5, Decision: "forced converge"}}
	gates := auditGates(plan, auditPhaseStatuses(phases), auditCoverageRows(rows))
	in := auditReportInput{
		Task: task, Session: session, Plan: plan, Phases: phases, CoverageRows: rows,
		Findings: findings, Rounds: rounds, Hypotheses: hypotheses, EngineJobs: engineJobs,
		Gates: gates, Status: db.AuditStatusDoneWithGaps,
		GeneratedAt: time.Date(2026, time.October, 27, 1, 2, 3, 0, time.UTC),
		RedactPaths: []string{snapshot, serverRoot},
	}
	md, raw, err := renderAuditReport(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{
		"# 代码安全审计报告 — 支付服务审计",
		"## 摘要", "## 审计范围与方法", "## 风险总览", "## 发现明细",
		"## 覆盖度与缺口", "## 假设", "## 门禁", "## 附录",
	} {
		if !strings.Contains(md, section) {
			t.Errorf("markdown lacks section %q", section)
		}
	}
	for _, want := range []string{
		"SQL 注入", "未确认", "CWE-89", "CWE-79", "Source：", "Sink：",
		"internal/pay/db.go:42", "quoteIdentifier=missing", "no_sinks: fixture",
		"2026-10-27T01:02:03Z",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	if !strings.Contains(md, "| high | 1 |") || !strings.Contains(md, "| critical | 1 |") ||
		!strings.Contains(md, "| medium | 1 |") {
		t.Fatalf("severity table missing expected counts:\n%s", md)
	}
	for _, forbidden := range []string{snapshot, "hunter2", "S3cr3tKeyValue", "abc12345", "should-not-leak", "snapshot_path"} {
		if strings.Contains(md, forbidden) {
			t.Errorf("markdown leaked %q", forbidden)
		}
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("json leaked %q", forbidden)
		}
	}
	if strings.Contains(string(raw), "select * from secret") {
		t.Error("json leaked engine query text")
	}
	var report struct {
		SessionID   int64                       `json:"session_id"`
		TaskID      int64                       `json:"task_id"`
		Status      string                      `json:"status"`
		Source      auditReportSource           `json:"source"`
		Generated   string                      `json:"generated_at"`
		Scope       auditReportScope            `json:"scope"`
		Method      []string                    `json:"method"`
		Risk        auditReportRisk             `json:"risk"`
		Gates       map[string]audit.GateResult `json:"gates"`
		Coverage    audit.CoverageCounts        `json:"coverage"`
		Engines     auditReportEngines          `json:"engines"`
		Findings    auditReportFindings         `json:"findings"`
		Phases      []auditReportPhase          `json:"phases"`
		Hypotheses  []auditReportHypothesis     `json:"hypotheses"`
		Gaps        auditReportGaps             `json:"gaps"`
		Limitations []string                    `json:"limitations"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.SessionID != 7 || report.TaskID != 42 || report.Status != db.AuditStatusDoneWithGaps ||
		report.Generated != "2026-10-27T01:02:03Z" || report.Source.Commit != "0123456789abcdef" {
		t.Fatalf("report identity = %+v", report)
	}
	if len(report.Findings.Confirmed) != 1 || len(report.Findings.Candidate) != 2 ||
		len(report.Findings.Refuted) != 1 || len(report.Findings.DesignIntent) != 1 {
		t.Fatalf("finding categories = confirmed:%d candidate:%d refuted:%d design:%d",
			len(report.Findings.Confirmed), len(report.Findings.Candidate),
			len(report.Findings.Refuted), len(report.Findings.DesignIntent))
	}
	if report.Findings.Confirmed[0].Evidence == "" || len(report.Findings.Confirmed[0].Trace) != 2 {
		t.Fatalf("confirmed evidence lost: %+v", report.Findings.Confirmed[0])
	}
	if len(report.Phases) != len(phases) || report.Phases[0].Phase != audit.PhaseIngest ||
		report.Phases[len(report.Phases)-1].Phase != audit.PhaseReport {
		t.Fatalf("phases = %+v", report.Phases)
	}
	if len(report.Hypotheses) != 1 || report.Hypotheses[0].Attempts != 1 {
		t.Fatalf("hypotheses = %+v", report.Hypotheses)
	}
	if report.Coverage.PlannedCWE != 5 || report.Coverage.PlannedSites != 3 {
		t.Fatalf("coverage = %+v", report.Coverage)
	}
	if report.Scope.PlannedCWE != 5 || report.Scope.PlannedSinkSites != 3 ||
		strings.Join(report.Scope.Languages, ",") != "go" || len(report.Method) == 0 {
		t.Fatalf("scope/method = %+v / %v", report.Scope, report.Method)
	}
	if report.Risk.Severity["critical"] != 1 || report.Risk.Severity["high"] != 1 ||
		report.Risk.Severity["medium"] != 1 || report.Risk.CWE["CWE-89"] != 1 {
		t.Fatalf("risk aggregates = %+v", report.Risk)
	}
	if len(report.Limitations) == 0 || len(report.Gaps.Coverage) == 0 || len(report.Gaps.Engines) == 0 {
		t.Fatalf("gaps/limitations missing: gaps=%+v limitations=%v", report.Gaps, report.Limitations)
	}
	statuses := map[string]bool{}
	kinds := map[string]bool{}
	for _, gap := range report.Gaps.Coverage {
		statuses[gap.Status] = true
		kinds[gap.Kind] = true
	}
	for _, want := range []string{audit.CoverageStatusPlanned, audit.CoverageStatusMissed, audit.CoverageStatusExempt} {
		if !statuses[want] {
			t.Errorf("gaps coverage lacks status %q: %+v", want, report.Gaps.Coverage)
		}
	}
	for _, kind := range []string{audit.CoverageKindCWE, audit.CoverageKindModule, audit.CoverageKindSinkSite} {
		if !kinds[kind] {
			t.Errorf("gaps coverage lacks kind %q", kind)
		}
	}
	if !slices.Contains(report.Gaps.UncoveredCWEs, "go|CWE-94") {
		t.Fatalf("uncovered CWE gaps = %v", report.Gaps.UncoveredCWEs)
	}
	if !report.Engines.QueryRecordsAvailable {
		t.Fatal("engine query records should be available when jobs exist")
	}
	if len(report.Gates) != 3 || !report.Gates["phase"].Passed {
		t.Fatalf("gates = %+v", report.Gates)
	}
	if report.Gates["coverage"].Passed {
		t.Fatal("coverage gate should fail for missed sink sites at deep depth")
	}
	if len(report.Phases) == 0 || report.Phases[3].Reason != "no_targets" {
		t.Fatalf("phase skip reason lost: %+v", report.Phases)
	}

	mdAgain, rawAgain, err := renderAuditReport(in)
	if err != nil {
		t.Fatal(err)
	}
	if mdAgain != md || string(rawAgain) != string(raw) {
		t.Fatal("report rendering must be deterministic for a fixed generated_at")
	}

	// A different timestamp is the only intentional output delta.
	in.GeneratedAt = in.GeneratedAt.Add(time.Second)
	mdLater, rawLater, err := renderAuditReport(in)
	if err != nil {
		t.Fatal(err)
	}
	if mdLater == md || string(rawLater) == string(raw) {
		t.Fatal("generated_at should be reflected in the report")
	}
}

func TestAuditReportEngineQueryRecordsUnavailable(t *testing.T) {
	session := &db.AuditSession{
		Backend: "fallback", Engines: json.RawMessage(`{"codegraph":"required","codeql":"auto","joern":"off"}`),
	}
	engines := buildAuditReportEngines(session, nil, nil)
	if engines.QueryRecordsAvailable {
		t.Fatal("no jobs must mark engine query records unavailable")
	}
	joined := strings.Join(engines.Gaps, "\n")
	if !strings.Contains(joined, "不可用或不适用") {
		t.Fatalf("engine gaps lack unavailable/not-applicable note: %v", engines.Gaps)
	}
	if strings.Contains(joined, "未产生任务记录") {
		t.Fatalf("must not invent enabled-with-no-job gaps: %v", engines.Gaps)
	}
}

func TestSanitizeAuditText(t *testing.T) {
	paths := []string{`C:\work\tasks\9\audit\source`, "/srv/artex"}
	escapedPath := strings.ReplaceAll(`C:\work\tasks\9\audit\source`, `\`, `\\`)
	input := strings.Join([]string{
		`path=C:\work\tasks\9\audit\source\a.go`,
		"json_escaped=" + escapedPath + `\a.go`,
		"/srv/artex/tasks/9/report.md",
		"api_key = abcdef123456",
		"token: 'zzzzzzzzzz'",
		"Authorization: Bearer abcdefghijklmnop",
		"repo https://alice:hunter2@example.com/x.git",
		"scp alice:hunter2@example.com:repo.git",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"sk-abcdefghijklmnopqrstuvwxyz123456",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretbody\n-----END RSA PRIVATE KEY-----",
	}, "\n")
	got := sanitizeAuditText(input, paths)
	for _, forbidden := range []string{`C:\work\tasks\9`, escapedPath, "/srv/artex", "abcdef123456", "zzzzzzzzzz", "abcdefghijklmnop", "hunter2", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "sk-abcdefghijklmnopqrstuvwxyz123456", "BEGIN RSA PRIVATE KEY", "MIIEowIBAAKCAQEAsecretbody"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("sanitized text still contains %q:\n%s", forbidden, got)
		}
	}
	for _, want := range []string{"[redacted-path]", "[REDACTED]", "[REDACTED-PRIVATE-KEY]", "api_key", "token:", "https://[redacted]@"} {
		if !strings.Contains(got, want) {
			t.Errorf("sanitized text lost %q:\n%s", want, got)
		}
	}
}

func TestAuditReportReadyAndNotReadyResponse(t *testing.T) {
	for _, status := range []string{db.AuditStatusDone, db.AuditStatusDoneWithGaps} {
		if !auditReportReady(&db.AuditSession{Status: status, ReportMD: "# report"}) {
			t.Fatalf("%s with report should be ready", status)
		}
	}
	for _, session := range []*db.AuditSession{
		nil,
		{Status: db.AuditStatusRunning, ReportMD: "# stale"},
		{Status: db.AuditStatusDone},
	} {
		if auditReportReady(session) {
			t.Fatalf("session %+v must not be report-ready", session)
		}
	}
}

func TestAuditReportJSONShapeExcludesSnapshotPath(t *testing.T) {
	session := &db.AuditSession{
		ID: 1, TaskID: 2, Status: db.AuditStatusDone, SnapshotPath: "/private/snapshot",
		SourceType: "local", SourceRef: "local:repo:abcd", Depth: "quick", Languages: []string{"go"},
	}
	plan := audit.Plan{Depth: "quick", Languages: []string{"go"}, PlannedCWEs: map[string][]string{"go": nil}}
	md, raw, err := renderAuditReport(auditReportInput{
		Session: session, Plan: plan, Status: db.AuditStatusDone,
		GeneratedAt: time.Date(2026, time.October, 27, 0, 0, 0, 0, time.UTC),
		RedactPaths: []string{session.SnapshotPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(md, session.SnapshotPath) || strings.Contains(string(raw), session.SnapshotPath) ||
		strings.Contains(string(raw), "snapshot_path") {
		t.Fatalf("report leaked snapshot path:\n%s\n%s", md, raw)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"session_id", "task_id", "source", "depth", "status", "scope",
		"method", "risk", "gates", "coverage", "engines", "findings", "phases", "hypotheses",
		"gaps", "limitations", "generated_at"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("json report lacks %q", key)
		}
	}
	findings, ok := decoded["findings"].(map[string]any)
	if !ok {
		t.Fatalf("findings = %#v", decoded["findings"])
	}
	for _, key := range []string{"confirmed", "candidate", "refuted", "design_intent"} {
		if _, ok := findings[key]; !ok {
			t.Errorf("findings lacks %q", key)
		}
	}
}
