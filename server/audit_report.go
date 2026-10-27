package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
)

// auditReportInput is the complete, already-loaded snapshot rendered into the
// Markdown/JSON audit report. Keeping it pure makes severity ordering and output
// determinism unit-testable without PostgreSQL.
type auditReportInput struct {
	Task         *Task
	Session      *db.AuditSession
	Plan         audit.Plan
	Phases       []db.AuditPhase
	CoverageRows []db.AuditCoverage
	Findings     []*db.DBFinding
	Rounds       []db.AuditRound
	Hypotheses   []db.AuditHypothesis
	EngineJobs   []db.AuditEngineJob
	Gates        map[string]audit.GateResult
	Status       string
	GeneratedAt  time.Time
	RedactPaths  []string
}

type auditReportSource struct {
	Type   string `json:"type"`
	Ref    string `json:"ref"`
	Commit string `json:"commit"`
}

type auditReportPhase struct {
	Phase    string `json:"phase"`
	Required bool   `json:"required"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

type auditReportHypothesis struct {
	Statement string `json:"statement"`
	Status    string `json:"status"`
	Attempts  int    `json:"attempts"`
	Evidence  string `json:"evidence,omitempty"`
}

type auditReportFinding struct {
	ID            int64                    `json:"id"`
	CWE           string                   `json:"cwe,omitempty"`
	Title         string                   `json:"title"`
	Severity      string                   `json:"severity"`
	Verification  string                   `json:"verification"`
	VerifyMethod  string                   `json:"verification_method,omitempty"`
	VerifyReason  string                   `json:"verification_reason,omitempty"`
	Alternative   string                   `json:"alternative_path,omitempty"`
	DesignVerdict string                   `json:"design_validation,omitempty"`
	Confidence    float64                  `json:"confidence"`
	Path          string                   `json:"path,omitempty"`
	Line          int                      `json:"line,omitempty"`
	Symbol        string                   `json:"symbol,omitempty"`
	Summary       string                   `json:"summary,omitempty"`
	Evidence      string                   `json:"evidence,omitempty"`
	Report        string                   `json:"report,omitempty"`
	Source        *audit.CodeLocation      `json:"source,omitempty"`
	Sink          *audit.CodeLocation      `json:"sink,omitempty"`
	Trace         []audit.TraceStep        `json:"trace,omitempty"`
	Sanitizers    []audit.SanitizerVerdict `json:"sanitizers,omitempty"`
	Engines       []audit.EngineEvidence   `json:"engines,omitempty"`
	Reachability  *audit.Reachability      `json:"reachability,omitempty"`
	Preconditions []string                 `json:"preconditions,omitempty"`
	Impact        string                   `json:"impact,omitempty"`
	POC           *audit.POCEvidence       `json:"poc,omitempty"`
	AuditRound    int                      `json:"audit_round,omitempty"`
	AuditPhase    string                   `json:"audit_phase,omitempty"`
}

type auditReportFindings struct {
	Confirmed    []auditReportFinding `json:"confirmed"`
	Candidate    []auditReportFinding `json:"candidate"`
	Refuted      []auditReportFinding `json:"refuted"`
	DesignIntent []auditReportFinding `json:"design_intent"`
}

type auditReportEngineJobCounts struct {
	Total    int `json:"total"`
	Pending  int `json:"pending"`
	Running  int `json:"running"`
	Done     int `json:"done"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
	Canceled int `json:"canceled"`
}

type auditReportEngineCapability struct {
	State         string   `json:"state"`
	Available     bool     `json:"available"`
	Version       string   `json:"version,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	Languages     []string `json:"languages,omitempty"`
	BuildModeNone bool     `json:"build_mode_none,omitempty"`
}

type auditReportEnginePrepared struct {
	Languages   []string          `json:"languages,omitempty"`
	BuildModes  map[string]string `json:"build_modes,omitempty"`
	Unsupported map[string]string `json:"unsupported,omitempty"`
	Warnings    []string          `json:"warnings,omitempty"`
}

type auditReportEngines struct {
	Backend               string                                 `json:"backend,omitempty"`
	Configured            map[string]string                      `json:"configured,omitempty"`
	Capabilities          map[string]auditReportEngineCapability `json:"capabilities,omitempty"`
	Prepared              map[string]auditReportEnginePrepared   `json:"prepared,omitempty"`
	Jobs                  map[string]auditReportEngineJobCounts  `json:"jobs"`
	QueryRecordsAvailable bool                                   `json:"query_records_available"`
	Gaps                  []string                               `json:"gaps"`
}

type auditReportScope struct {
	Languages        []string `json:"languages"`
	Modules          []string `json:"modules"`
	EntryPoints      []string `json:"entry_points"`
	PlannedCWE       int      `json:"planned_cwe"`
	PlannedSinkSites int      `json:"planned_sink_sites"`
}

type auditReportRisk struct {
	Severity map[string]int `json:"severity"`
	CWE      map[string]int `json:"cwe"`
}

type auditReportGapRow struct {
	Status   string `json:"status"`
	Kind     string `json:"kind"`
	Language string `json:"language,omitempty"`
	CWE      string `json:"cwe,omitempty"`
	Module   string `json:"module,omitempty"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
	SinkKey  string `json:"sink_key,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type auditReportGaps struct {
	Coverage      []auditReportGapRow `json:"coverage"`
	UncoveredCWEs []string            `json:"uncovered_cwes"`
	Engines       []string            `json:"engines"`
}

type auditReportJSON struct {
	SessionID   int64                       `json:"session_id"`
	TaskID      int64                       `json:"task_id"`
	Source      auditReportSource           `json:"source"`
	Depth       string                      `json:"depth"`
	Status      string                      `json:"status"`
	Round       int                         `json:"round"`
	MaxRounds   int                         `json:"max_rounds"`
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
	GeneratedAt string                      `json:"generated_at"`
}

// buildAuditReport loads the remaining report inputs (findings, rounds,
// hypotheses, engine jobs) and renders the deterministic report. It never reads
// target source or executes anything.
func (s *Server) buildAuditReport(ctx context.Context, t *Task, session *db.AuditSession, phases []db.AuditPhase, rows []db.AuditCoverage, gates map[string]audit.GateResult, status string, generatedAt time.Time) (string, json.RawMessage, error) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return "", nil, errors.New("审计持久化层不可用")
	}
	if session == nil {
		return "", nil, errors.New("审计会话不存在")
	}
	findings, err := loadAuditReportFindings(ctx, s.m.pg, session.TaskID)
	if err != nil {
		return "", nil, fmt.Errorf("读取 finding 失败: %w", err)
	}
	hypotheses, err := s.m.pg.ListAuditHypotheses(session.ID)
	if err != nil {
		return "", nil, fmt.Errorf("读取假设失败: %w", err)
	}
	engineJobs, err := s.m.pg.ListAuditEngineJobs(session.ID)
	if err != nil {
		return "", nil, fmt.Errorf("读取引擎任务失败: %w", err)
	}
	rounds, err := s.m.pg.ListAuditRounds(session.ID)
	if err != nil {
		return "", nil, fmt.Errorf("读取轮次失败: %w", err)
	}
	redact := make([]string, 0, 3)
	redact = addAuditRedactPath(redact, session.SnapshotPath)
	redact = addAuditRedactPath(redact, s.m.dir)
	if t != nil {
		redact = addAuditRedactPath(redact, filepath.Join(s.m.dir, "tasks", t.ID))
	}
	return renderAuditReport(auditReportInput{
		Task: t, Session: session, Plan: auditPlanFromSession(session),
		Phases: phases, CoverageRows: rows, Findings: findings,
		Rounds: rounds, Hypotheses: hypotheses, EngineJobs: engineJobs,
		Gates: gates, Status: status, GeneratedAt: generatedAt, RedactPaths: redact,
	})
}

// loadAuditReportFindings reads all findings for a task in one query, including
// the full Markdown report and structured code evidence.
func loadAuditReportFindings(ctx context.Context, pg *db.DB, taskID int64) ([]*db.DBFinding, error) {
	rows, err := pg.QueryContext(ctx, `
SELECT id, COALESCE(vulnclass, ''), COALESCE(name, ''), COALESCE(severity, ''),
       COALESCE(summary, ''), COALESCE(evidence, ''), COALESCE(cwe_id, ''),
       COALESCE(code_path, ''), COALESCE(code_line, 0), COALESCE(code_symbol, ''),
       COALESCE(confidence, 0), COALESCE(NULLIF(verification, ''), 'unverified'),
       COALESCE(code_evidence, '{}'::jsonb), COALESCE(audit_round, 0),
       COALESCE(audit_phase, ''), COALESCE(report, ''), created_at
FROM findings WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*db.DBFinding, 0)
	for rows.Next() {
		finding := &db.DBFinding{}
		var codeEvidence []byte
		if err := rows.Scan(
			&finding.ID, &finding.VulnClass, &finding.Name, &finding.Severity,
			&finding.Summary, &finding.Evidence, &finding.CWEID, &finding.CodePath,
			&finding.CodeLine, &finding.CodeSymbol, &finding.Confidence, &finding.Verification,
			&codeEvidence, &finding.AuditRound, &finding.AuditPhase, &finding.Report, &finding.CreatedAt,
		); err != nil {
			return nil, err
		}
		finding.CodeEvidence = append(json.RawMessage(nil), codeEvidence...)
		out = append(out, finding)
	}
	return out, rows.Err()
}

// renderAuditReport is the deterministic renderer. GeneratedAt is the only
// intentionally variable input.
func renderAuditReport(in auditReportInput) (string, json.RawMessage, error) {
	if in.Session == nil {
		return "", nil, errors.New("审计会话不存在")
	}
	generatedAt := in.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now()
	}
	generatedAt = generatedAt.UTC()
	status := strings.TrimSpace(in.Status)
	if status == "" {
		status = in.Session.Status
	}
	source := auditReportSource{
		Type:   sanitizeAuditText(in.Session.SourceType, in.RedactPaths),
		Ref:    sanitizeAuditSourceRef(in.Session.SourceRef, in.RedactPaths),
		Commit: sanitizeAuditText(in.Session.CommitSHA, in.RedactPaths),
	}
	findings := make([]auditReportFinding, 0, len(in.Findings))
	for _, raw := range in.Findings {
		if raw == nil {
			continue
		}
		findings = append(findings, buildAuditReportFinding(raw, in.RedactPaths))
	}
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := auditFindingSeverityRank(findings[i].Severity), auditFindingSeverityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if findings[i].CWE != findings[j].CWE {
			return findings[i].CWE < findings[j].CWE
		}
		return findings[i].ID < findings[j].ID
	})
	categories := auditReportFindings{
		Confirmed: []auditReportFinding{}, Candidate: []auditReportFinding{},
		Refuted: []auditReportFinding{}, DesignIntent: []auditReportFinding{},
	}
	for _, finding := range findings {
		switch normalizeAuditVerification(finding.Verification) {
		case audit.VerificationConfirmed:
			categories.Confirmed = append(categories.Confirmed, finding)
		case audit.VerificationRefuted:
			categories.Refuted = append(categories.Refuted, finding)
		case audit.VerificationDesignIntent:
			categories.DesignIntent = append(categories.DesignIntent, finding)
		default:
			categories.Candidate = append(categories.Candidate, finding)
		}
	}
	plan := normalizeAuditReportPlan(in.Plan, in.Session)
	phases := buildAuditReportPhases(in.Phases, in.RedactPaths)
	hypotheses := buildAuditReportHypotheses(in.Hypotheses, in.RedactPaths)
	engines := buildAuditReportEngines(in.Session, in.EngineJobs, in.RedactPaths)
	coverage := audit.ComputeCoverage(plan, auditCoverageRows(in.CoverageRows))
	gates := in.Gates
	if gates == nil {
		gates = auditGates(plan, auditPhaseStatuses(in.Phases), auditCoverageRows(in.CoverageRows))
	}
	gates = sanitizeAuditGates(gates, in.RedactPaths)
	scope := buildAuditReportScope(plan, in.CoverageRows, in.RedactPaths)
	method := auditReportMethod()
	risk := buildAuditReportRisk(categories)
	gaps := buildAuditReportGaps(plan, in.CoverageRows, engines, in.RedactPaths)
	limitations := auditReportLimitations()

	md := renderAuditMarkdown(auditReportInput{
		Task: in.Task, Session: in.Session, Plan: in.Plan, Phases: in.Phases,
		CoverageRows: in.CoverageRows, Findings: in.Findings, Rounds: in.Rounds,
		Hypotheses: in.Hypotheses, EngineJobs: in.EngineJobs, Gates: gates,
		Status: status, GeneratedAt: generatedAt, RedactPaths: in.RedactPaths,
	}, auditReportMarkdownData{
		source: source, findings: findings, categories: categories, phases: phases,
		hypotheses: hypotheses, engines: engines, coverage: coverage, gates: gates,
		scope: scope, method: method, risk: risk, gaps: gaps, limitations: limitations,
		status: status, generatedAt: generatedAt,
	})

	report := auditReportJSON{
		SessionID: in.Session.ID, TaskID: in.Session.TaskID, Source: source,
		Depth:  firstNonBlank(in.Plan.Depth, in.Session.Depth),
		Status: status, Round: in.Session.Round, MaxRounds: in.Session.MaxRounds,
		Scope: scope, Method: method, Risk: risk, Gates: gates, Coverage: coverage,
		Engines: engines, Findings: categories, Phases: phases, Hypotheses: hypotheses,
		Gaps: gaps, Limitations: limitations,
		GeneratedAt: generatedAt.Format(time.RFC3339),
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("序列化审计报告失败: %w", err)
	}
	return md, raw, nil
}

type auditReportMarkdownData struct {
	source      auditReportSource
	findings    []auditReportFinding
	categories  auditReportFindings
	phases      []auditReportPhase
	hypotheses  []auditReportHypothesis
	engines     auditReportEngines
	coverage    audit.CoverageCounts
	gates       map[string]audit.GateResult
	scope       auditReportScope
	method      []string
	risk        auditReportRisk
	gaps        auditReportGaps
	limitations []string
	status      string
	generatedAt time.Time
}

func renderAuditMarkdown(in auditReportInput, data auditReportMarkdownData) string {
	plan := normalizeAuditReportPlan(in.Plan, in.Session)
	taskTitle := sanitizeAuditText(auditReportTaskTitle(in.Task), in.RedactPaths)
	status := data.status
	var b strings.Builder
	fmt.Fprintf(&b, "# 代码安全审计报告 — %s\n\n", inlineMarkdown(taskTitle))

	b.WriteString("## 摘要\n")
	fmt.Fprintf(&b, "- 任务：%s\n", inlineMarkdown(sanitizeAuditText(auditReportTaskDescription(in.Task), in.RedactPaths)))
	if in.Task != nil && strings.TrimSpace(in.Task.Goal) != "" {
		fmt.Fprintf(&b, "- 目标：%s\n", inlineMarkdown(sanitizeAuditText(strings.TrimSpace(in.Task.Goal), in.RedactPaths)))
	}
	fmt.Fprintf(&b, "- 源：%s", inlineMarkdown(firstNonBlank(data.source.Type, "unknown")))
	if data.source.Ref != "" {
		fmt.Fprintf(&b, " / %s", inlineMarkdown(data.source.Ref))
	}
	if data.source.Commit != "" {
		fmt.Fprintf(&b, " @ `%s`", inlineMarkdown(data.source.Commit))
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- 深度：%s\n", inlineMarkdown(firstNonBlank(plan.Depth, "unknown")))
	fmt.Fprintf(&b, "- 轮次：%d/%d\n", in.Session.Round, in.Session.MaxRounds)
	fmt.Fprintf(&b, "- 后端：%s；引擎配置：%s\n", inlineMarkdown(firstNonBlank(data.engines.Backend, "unknown")), inlineMarkdown(auditEngineSummary(data.engines)))
	if state := auditEngineStateSummary(data.engines); state != "" {
		fmt.Fprintf(&b, "- 引擎状态：%s\n", inlineMarkdown(state))
	}
	queryRecords := "不可用/不适用"
	if data.engines.QueryRecordsAvailable {
		queryRecords = "可用"
	}
	fmt.Fprintf(&b, "- 引擎任务：%d 个（失败 %d）；查询记录：%s\n",
		data.engines.Jobs["all"].Total, data.engines.Jobs["all"].Failed, queryRecords)
	if jobSummary := auditEngineJobSummary(data.engines); jobSummary != "" {
		fmt.Fprintf(&b, "- 引擎任务分布：%s\n", inlineMarkdown(jobSummary))
	}
	fmt.Fprintf(&b, "- 发现统计：确认 %d / 候选或未验证 %d / 已反驳 %d / 设计意图 %d\n",
		len(data.categories.Confirmed), len(data.categories.Candidate),
		len(data.categories.Refuted), len(data.categories.DesignIntent))
	fmt.Fprintf(&b, "- 收敛结论：%s；门禁 %s\n", auditReportStatusLabel(status), auditPassedLabel(data.gates))
	b.WriteString("\n")

	b.WriteString("## 审计范围与方法\n")
	fmt.Fprintf(&b, "- 语言：%s\n", inlineMarkdown(languageSummary(data.scope.Languages)))
	fmt.Fprintf(&b, "- 模块：%d 个", len(data.scope.Modules))
	if len(data.scope.Modules) > 0 {
		fmt.Fprintf(&b, "（%s）", inlineMarkdown(strings.Join(limitStrings(data.scope.Modules, 20), ", ")))
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- 入口点：计划 %d 个\n", len(data.scope.EntryPoints))
	fmt.Fprintf(&b, "- 计划 CWE：%d 个；sink 站点：%d 个\n", data.scope.PlannedCWE, data.scope.PlannedSinkSites)
	fmt.Fprintf(&b, "- 方法：%s\n\n", inlineMarkdown(strings.Join(data.method, "；")))

	b.WriteString("### 阶段与门禁\n")
	b.WriteString("| 阶段 | 必需 | 状态 | 说明 |\n|---|---|---|---|\n")
	for _, phase := range data.phases {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", inlineMarkdown(phase.Phase),
			yesNo(phase.Required), inlineMarkdown(firstNonBlank(phase.Status, "pending")), inlineMarkdown(phase.Reason))
	}
	b.WriteString("\n")
	b.WriteString("| 门禁 | 结果 | 说明 |\n|---|---|---|\n")
	for _, key := range []string{"phase", "coverage", "cwe"} {
		gate, ok := data.gates[key]
		if !ok {
			continue
		}
		result := "通过"
		if !gate.Passed {
			result = "未通过"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", inlineMarkdown(gate.Name), result, inlineMarkdown(gate.Reason))
	}
	b.WriteString("\n")

	b.WriteString("## 风险总览\n")
	b.WriteString("| 严重度 | 数量 |\n|---|---|\n")
	for _, severity := range []string{"critical", "high", "medium", "low", "unknown"} {
		if severity == "unknown" && data.risk.Severity[severity] == 0 {
			continue
		}
		fmt.Fprintf(&b, "| %s | %d |\n", severity, data.risk.Severity[severity])
	}
	b.WriteString("\n")
	if len(data.risk.CWE) > 0 {
		b.WriteString("| CWE | 数量 |\n|---|---|\n")
		for _, cwe := range sortedCWEs(data.risk.CWE) {
			fmt.Fprintf(&b, "| %s | %d |\n", inlineMarkdown(cwe), data.risk.CWE[cwe])
		}
		b.WriteString("\n")
	}

	b.WriteString("## 逐轮过程\n")
	if len(in.Rounds) == 0 {
		fmt.Fprintf(&b, "当前为第 %d 轮，尚无持久化的逐轮汇总。\n\n", in.Session.Round)
	} else {
		b.WriteString("| Round | 新发现 | 确认 | 候选 | 累计 | 决策 |\n|---|---|---|---|---|---|\n")
		for _, round := range in.Rounds {
			fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %s |\n", round.Round,
				round.NewFindings, round.NewConfirmed, round.NewCandidate, round.TotalFindings,
				inlineMarkdown(sanitizeAuditText(round.Decision, in.RedactPaths)))
		}
		b.WriteString("\n")
	}

	b.WriteString("## 发现明细\n")
	if len(data.findings) == 0 {
		b.WriteString("未登记代码审计发现。\n\n")
	} else {
		for i, finding := range data.findings {
			writeAuditReportFinding(&b, i+1, finding)
		}
	}

	b.WriteString("## 覆盖度与缺口\n")
	b.WriteString("| 维度 | 已覆盖/计划 | 覆盖率 |\n|---|---|---|\n")
	fmt.Fprintf(&b, "| CWE | %d/%d | %s |\n", data.coverage.CoveredCWE, data.coverage.PlannedCWE, formatPercent(data.coverage.CWE))
	fmt.Fprintf(&b, "| sink 站点 | %d/%d | %s |\n", data.coverage.CoveredSites, data.coverage.PlannedSites, formatPercent(data.coverage.SinkSites))
	fmt.Fprintf(&b, "| 模块 | %d/%d | %s |\n", data.coverage.CoveredModules, data.coverage.PlannedModules, formatPercent(data.coverage.Modules))
	fmt.Fprintf(&b, "| 入口点 | %d/%d | %s |\n", data.coverage.CoveredEntries, data.coverage.PlannedEntries, formatPercent(data.coverage.EntryPoints))
	b.WriteString("\n")
	if data.coverage.InvalidExemptions > 0 {
		fmt.Fprintf(&b, "- 非法豁免理由：%d 条\n", data.coverage.InvalidExemptions)
	}
	if len(data.gaps.UncoveredCWEs) > 0 {
		fmt.Fprintf(&b, "- 未覆盖 CWE：%s\n", inlineMarkdown(strings.Join(data.gaps.UncoveredCWEs, ", ")))
	}
	if len(data.gaps.Coverage) == 0 {
		b.WriteString("- 未发现 planned/missed/exempt 覆盖行。\n")
	} else {
		b.WriteString("| 状态 | 类型 | CWE | 位置 | 原因 |\n|---|---|---|---|---|\n")
		for _, row := range data.gaps.Coverage {
			location := firstNonBlank(row.Path, row.SinkKey, row.Module, "-")
			if row.Line > 0 {
				location = fmt.Sprintf("%s:%d", location, row.Line)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", inlineMarkdown(row.Status),
				inlineMarkdown(row.Kind), inlineMarkdown(row.CWE),
				inlineMarkdown(location), inlineMarkdown(row.Reason))
		}
	}
	if len(data.gaps.Engines) > 0 {
		b.WriteString("\n引擎缺口：\n")
		for _, gap := range data.gaps.Engines {
			fmt.Fprintf(&b, "- %s\n", inlineMarkdown(gap))
		}
	}
	b.WriteString("\n")

	b.WriteString("## 假设\n")
	if len(data.hypotheses) == 0 {
		b.WriteString("本任务未记录假设。\n\n")
	} else {
		b.WriteString("| 假设 | 状态 | 尝试次数 | 证据 |\n|---|---|---|---|\n")
		for _, hypothesis := range data.hypotheses {
			fmt.Fprintf(&b, "| %s | %s | %d | %s |\n", inlineMarkdown(hypothesis.Statement),
				inlineMarkdown(hypothesis.Status), hypothesis.Attempts, inlineMarkdown(hypothesis.Evidence))
		}
		b.WriteString("\n")
	}

	b.WriteString("## 门禁\n")
	for _, key := range []string{"phase", "coverage", "cwe"} {
		gate, ok := data.gates[key]
		if !ok {
			continue
		}
		result := "通过"
		if !gate.Passed {
			result = "未通过"
		}
		fmt.Fprintf(&b, "### %s — %s\n\n- 说明：%s\n", inlineMarkdown(gate.Name), result, inlineMarkdown(gate.Reason))
		if len(gate.Details) > 0 {
			raw, err := json.Marshal(gate.Details)
			if err == nil {
				fmt.Fprintf(&b, "- 详情：`%s`\n", inlineMarkdown(string(raw)))
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("## 附录\n")
	fmt.Fprintf(&b, "- 生成时间：%s\n", data.generatedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- 报告路径：`tasks/%d/audit/report.md`、`tasks/%d/audit/report.json`\n", in.Session.TaskID, in.Session.TaskID)
	fmt.Fprintf(&b, "- 工作目录：`tasks/%d/`\n", in.Session.TaskID)
	b.WriteString("- 活动记录：任务探索图 activity（数据库持久化）\n")
	b.WriteString("- 限制：\n")
	for _, limitation := range data.limitations {
		fmt.Fprintf(&b, "  - %s\n", inlineMarkdown(limitation))
	}
	return b.String()
}

func writeAuditReportFinding(b *strings.Builder, index int, finding auditReportFinding) {
	verification := normalizeAuditVerification(finding.Verification)
	status := "未确认"
	switch verification {
	case audit.VerificationConfirmed:
		status = "确认"
	case audit.VerificationRefuted:
		status = "已反驳"
	case audit.VerificationDesignIntent:
		status = "设计意图"
	}
	fmt.Fprintf(b, "### %d. [%s] %s — %s（%s）\n\n", index,
		inlineMarkdown(firstNonBlank(finding.Severity, "unknown")),
		inlineMarkdown(firstNonBlank(finding.CWE, "CWE 未标注")),
		inlineMarkdown(firstNonBlank(finding.Title, "未命名发现")), status)
	location := firstNonBlank(finding.Path, "-")
	if finding.Line > 0 {
		location = fmt.Sprintf("%s:%d", location, finding.Line)
	}
	if finding.Symbol != "" {
		location += " (" + finding.Symbol + ")"
	}
	fmt.Fprintf(b, "- 位置：`%s`\n", inlineMarkdown(location))
	fmt.Fprintf(b, "- 验证：%s；置信度 %.2f", inlineMarkdown(verification), finding.Confidence)
	if finding.VerifyMethod != "" {
		fmt.Fprintf(b, "；方式：%s", inlineMarkdown(finding.VerifyMethod))
	}
	b.WriteString("\n")
	if finding.VerifyReason != "" {
		fmt.Fprintf(b, "- 验证说明：%s\n", inlineMarkdown(finding.VerifyReason))
	}
	if finding.Alternative != "" {
		fmt.Fprintf(b, "- 替代路径：%s\n", inlineMarkdown(finding.Alternative))
	}
	if finding.DesignVerdict != "" {
		fmt.Fprintf(b, "- 设计判定：%s\n", inlineMarkdown(finding.DesignVerdict))
	}
	if finding.Summary != "" {
		fmt.Fprintf(b, "- 摘要：%s\n", inlineMarkdown(finding.Summary))
	}
	if verification != audit.VerificationConfirmed {
		b.WriteString("- 状态说明：未确认发现，不应视为已确认漏洞。\n")
	}
	if finding.Source != nil {
		fmt.Fprintf(b, "- Source：%s\n", inlineMarkdown(formatCodeLocation(*finding.Source)))
	}
	if finding.Sink != nil {
		fmt.Fprintf(b, "- Sink：%s\n", inlineMarkdown(formatCodeLocation(*finding.Sink)))
	}
	if len(finding.Trace) > 0 {
		b.WriteString("- Trace：\n")
		for i, step := range finding.Trace {
			note := ""
			if step.Note != "" {
				note = " — " + step.Note
			}
			fmt.Fprintf(b, "  %d. `%s:%d` (%s)%s\n", i+1, inlineMarkdown(step.Path), step.Line, inlineMarkdown(step.Symbol), inlineMarkdown(note))
		}
	}
	if len(finding.Sanitizers) > 0 {
		parts := make([]string, 0, len(finding.Sanitizers))
		for _, sanitizer := range finding.Sanitizers {
			parts = append(parts, sanitizer.Symbol+"="+sanitizer.Verdict)
		}
		fmt.Fprintf(b, "- Sanitizers：%s\n", inlineMarkdown(strings.Join(parts, ", ")))
	}
	if len(finding.Engines) > 0 {
		parts := make([]string, 0, len(finding.Engines))
		for _, engine := range finding.Engines {
			parts = append(parts, engine.Name)
		}
		fmt.Fprintf(b, "- 引擎：%s\n", inlineMarkdown(strings.Join(parts, ", ")))
	}
	if finding.Reachability != nil {
		auth := "未记录"
		if finding.Reachability.AuthStateRecorded {
			auth = "无需认证"
			if finding.Reachability.AuthRequired {
				auth = "需要认证"
			}
		}
		fmt.Fprintf(b, "- 可达性：reachable=%v；入口=%s；认证=%s\n",
			finding.Reachability.Reachable, inlineMarkdown(finding.Reachability.EntryPoint), inlineMarkdown(auth))
	}
	if len(finding.Preconditions) > 0 {
		fmt.Fprintf(b, "- 前置条件：%s\n", inlineMarkdown(strings.Join(finding.Preconditions, "；")))
	}
	if finding.Impact != "" {
		fmt.Fprintf(b, "- 影响：%s\n", inlineMarkdown(finding.Impact))
	}
	if finding.POC != nil {
		fmt.Fprintf(b, "- PoC：kind=%s；artifact=%s；executed=%v；%s\n",
			inlineMarkdown(finding.POC.Kind), inlineMarkdown(finding.POC.ArtifactPath),
			finding.POC.Executed, inlineMarkdown(finding.POC.Description))
	}
	if finding.Evidence != "" {
		b.WriteString("\n**证据**\n\n")
		writeMarkdownFence(b, "text", finding.Evidence)
	}
	if finding.Report != "" {
		b.WriteString("\n**详细报告**\n\n")
		b.WriteString(finding.Report)
		if !strings.HasSuffix(finding.Report, "\n") {
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
}

func buildAuditReportFinding(raw *db.DBFinding, redactPaths []string) auditReportFinding {
	verification := normalizeAuditVerification(raw.Verification)
	finding := auditReportFinding{
		ID: raw.ID, CWE: strings.ToUpper(strings.TrimSpace(raw.CWEID)),
		Title:        strings.TrimSpace(raw.Name),
		Severity:     strings.ToLower(firstNonBlank(raw.Severity, "unknown")),
		Verification: verification, Confidence: raw.Confidence,
		Path: audit.NormalizeCodePath(raw.CodePath), Line: raw.CodeLine, Symbol: raw.CodeSymbol,
		Summary: raw.Summary, Evidence: raw.Evidence, Report: raw.Report,
		AuditRound: raw.AuditRound, AuditPhase: raw.AuditPhase,
	}
	var evidence audit.CodeEvidence
	if len(raw.CodeEvidence) > 0 && json.Unmarshal(raw.CodeEvidence, &evidence) == nil {
		if finding.CWE == "" {
			finding.CWE = strings.ToUpper(strings.TrimSpace(evidence.CWEID))
		}
		if finding.Title == "" {
			finding.Title = strings.TrimSpace(evidence.Title)
		}
		if strings.TrimSpace(raw.Verification) == "" && strings.TrimSpace(evidence.Verification.Status) != "" {
			finding.Verification = normalizeAuditVerification(evidence.Verification.Status)
		}
		finding.VerifyMethod = strings.TrimSpace(evidence.Verification.Method)
		finding.VerifyReason = strings.TrimSpace(evidence.Verification.Reason)
		finding.Alternative = strings.TrimSpace(evidence.Verification.AlternativePath)
		finding.DesignVerdict = strings.TrimSpace(evidence.Verification.DesignValidation)
		if finding.Severity == "" || finding.Severity == "unknown" {
			finding.Severity = strings.ToLower(strings.TrimSpace(evidence.Severity))
		}
		if finding.Confidence == 0 {
			finding.Confidence = evidence.Confidence
		}
		if finding.Path == "" && evidence.Location.Path != "" {
			finding.Path = audit.NormalizeCodePath(evidence.Location.Path)
			finding.Line = evidence.Location.Line
			finding.Symbol = evidence.Location.Symbol
		}
		finding.Source = cloneCodeLocation(evidence.Source)
		finding.Sink = cloneCodeLocation(evidence.Sink)
		finding.Trace = append([]audit.TraceStep(nil), evidence.Trace...)
		finding.Sanitizers = append([]audit.SanitizerVerdict(nil), evidence.Sanitizers...)
		finding.Engines = append([]audit.EngineEvidence(nil), evidence.Engines...)
		finding.Reachability = cloneReachability(evidence.Reachability)
		finding.Preconditions = append([]string(nil), evidence.Preconditions...)
		finding.Impact = evidence.Impact
		if evidence.POC != nil {
			poc := *evidence.POC
			finding.POC = &poc
		}
	}
	if finding.Title == "" {
		finding.Title = firstNonBlank(raw.Summary, raw.VulnClass, "未命名发现")
	}
	finding.Path = sanitizeAuditText(finding.Path, redactPaths)
	finding.Title = sanitizeAuditText(finding.Title, redactPaths)
	finding.Summary = sanitizeAuditText(finding.Summary, redactPaths)
	finding.Evidence = sanitizeAuditText(finding.Evidence, redactPaths)
	finding.Report = sanitizeAuditText(finding.Report, redactPaths)
	finding.Symbol = sanitizeAuditText(finding.Symbol, redactPaths)
	finding.Impact = sanitizeAuditText(finding.Impact, redactPaths)
	finding.VerifyMethod = sanitizeAuditText(finding.VerifyMethod, redactPaths)
	finding.VerifyReason = sanitizeAuditText(finding.VerifyReason, redactPaths)
	finding.Alternative = sanitizeAuditText(finding.Alternative, redactPaths)
	finding.DesignVerdict = sanitizeAuditText(finding.DesignVerdict, redactPaths)
	for i := range finding.Preconditions {
		finding.Preconditions[i] = sanitizeAuditText(finding.Preconditions[i], redactPaths)
	}
	for i := range finding.Trace {
		finding.Trace[i].Path = sanitizeAuditText(finding.Trace[i].Path, redactPaths)
		finding.Trace[i].Symbol = sanitizeAuditText(finding.Trace[i].Symbol, redactPaths)
		finding.Trace[i].Note = sanitizeAuditText(finding.Trace[i].Note, redactPaths)
	}
	for i := range finding.Sanitizers {
		finding.Sanitizers[i].Symbol = sanitizeAuditText(finding.Sanitizers[i].Symbol, redactPaths)
		finding.Sanitizers[i].Note = sanitizeAuditText(finding.Sanitizers[i].Note, redactPaths)
	}
	for i := range finding.Engines {
		finding.Engines[i].Name = sanitizeAuditText(finding.Engines[i].Name, redactPaths)
		finding.Engines[i].QueryID = sanitizeAuditText(finding.Engines[i].QueryID, redactPaths)
		finding.Engines[i].RawRef = sanitizeAuditText(finding.Engines[i].RawRef, redactPaths)
	}
	if finding.Source != nil {
		finding.Source.Path = sanitizeAuditText(finding.Source.Path, redactPaths)
		finding.Source.Symbol = sanitizeAuditText(finding.Source.Symbol, redactPaths)
		finding.Source.Snippet = sanitizeAuditText(finding.Source.Snippet, redactPaths)
		finding.Source.API = sanitizeAuditText(finding.Source.API, redactPaths)
	}
	if finding.Sink != nil {
		finding.Sink.Path = sanitizeAuditText(finding.Sink.Path, redactPaths)
		finding.Sink.Symbol = sanitizeAuditText(finding.Sink.Symbol, redactPaths)
		finding.Sink.Snippet = sanitizeAuditText(finding.Sink.Snippet, redactPaths)
		finding.Sink.API = sanitizeAuditText(finding.Sink.API, redactPaths)
	}
	if finding.Reachability != nil {
		finding.Reachability.EntryPoint = sanitizeAuditText(finding.Reachability.EntryPoint, redactPaths)
		finding.Reachability.Path = sanitizeAuditText(finding.Reachability.Path, redactPaths)
	}
	if finding.POC != nil {
		finding.POC.Kind = sanitizeAuditText(finding.POC.Kind, redactPaths)
		finding.POC.ArtifactPath = sanitizeAuditText(finding.POC.ArtifactPath, redactPaths)
		finding.POC.Description = sanitizeAuditText(finding.POC.Description, redactPaths)
	}
	return finding
}

func buildAuditReportPhases(phases []db.AuditPhase, redactPaths []string) []auditReportPhase {
	out := make([]auditReportPhase, 0, len(phases))
	for _, phase := range phases {
		out = append(out, auditReportPhase{
			Phase: phase.Phase, Required: phase.Required, Status: phase.Status,
			Reason: sanitizeAuditText(auditPhaseReason(phase), redactPaths),
		})
	}
	sort.Slice(out, func(i, j int) bool { return auditPhaseNumber(out[i].Phase) < auditPhaseNumber(out[j].Phase) })
	return out
}

func buildAuditReportHypotheses(hypotheses []db.AuditHypothesis, redactPaths []string) []auditReportHypothesis {
	out := make([]auditReportHypothesis, 0, len(hypotheses))
	for _, hypothesis := range hypotheses {
		attempts := 0
		if len(hypothesis.Attempts) > 0 {
			var list []any
			if json.Unmarshal(hypothesis.Attempts, &list) == nil {
				attempts = len(list)
			}
		}
		out = append(out, auditReportHypothesis{
			Statement: sanitizeAuditText(hypothesis.Statement, redactPaths),
			Status:    hypothesis.Status,
			Attempts:  attempts,
			Evidence:  truncateText(sanitizeAuditText(hypothesis.Evidence, redactPaths), 500),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Statement != out[j].Statement {
			return out[i].Statement < out[j].Statement
		}
		return out[i].Status < out[j].Status
	})
	return out
}

func buildAuditReportEngines(session *db.AuditSession, jobs []db.AuditEngineJob, redactPaths []string) auditReportEngines {
	engines := auditReportEngines{
		Backend:      session.Backend,
		Configured:   map[string]string{},
		Capabilities: map[string]auditReportEngineCapability{},
		Prepared:     map[string]auditReportEnginePrepared{},
		Jobs:         map[string]auditReportEngineJobCounts{},
		Gaps:         []string{},
	}
	record := parseAuditEnginesRecord(session.Engines)
	configured := make(map[string]string, len(record.Configured))
	for engine, mode := range record.Configured {
		configured[sanitizeAuditText(engine, redactPaths)] = sanitizeAuditText(mode, redactPaths)
	}
	engines.Configured = configured
	for engine, capability := range record.Capabilities {
		name := sanitizeAuditText(engine, redactPaths)
		languages := make([]string, 0, len(capability.Languages))
		for _, language := range capability.Languages {
			languages = append(languages, sanitizeAuditText(language, redactPaths))
		}
		engines.Capabilities[name] = auditReportEngineCapability{
			State:         auditEngineState(capability, record.Configured[engine]),
			Available:     capability.Available,
			Version:       sanitizeAuditText(capability.Version, redactPaths),
			Reason:        sanitizeAuditText(capability.Reason, redactPaths),
			Languages:     languages,
			BuildModeNone: capability.BuildModeNone,
		}
	}
	for engine, prepared := range record.Prepared {
		name := sanitizeAuditText(engine, redactPaths)
		entry := auditReportEnginePrepared{
			Languages:   make([]string, 0, len(prepared.Languages)),
			BuildModes:  map[string]string{},
			Unsupported: map[string]string{},
		}
		for _, language := range prepared.Languages {
			entry.Languages = append(entry.Languages, sanitizeAuditText(language, redactPaths))
		}
		for language, mode := range prepared.BuildModes {
			entry.BuildModes[sanitizeAuditText(language, redactPaths)] = sanitizeAuditText(mode, redactPaths)
		}
		for language, reason := range prepared.Unsupported {
			entry.Unsupported[sanitizeAuditText(language, redactPaths)] = sanitizeAuditText(reason, redactPaths)
		}
		entry.Warnings = sanitizeAuditEngineMessages(prepared.Warnings, redactPaths)
		engines.Prepared[name] = entry
	}
	total := auditReportEngineJobCounts{}
	for _, job := range jobs {
		engine := firstNonBlank(strings.TrimSpace(job.Engine), "unknown")
		counts := engines.Jobs[engine]
		counts.Total++
		total.Total++
		switch strings.ToLower(strings.TrimSpace(job.Status)) {
		case "pending", "planned":
			counts.Pending++
			total.Pending++
		case "running":
			counts.Running++
			total.Running++
		case "done", "success", "completed":
			counts.Done++
			total.Done++
		case "failed", "error":
			counts.Failed++
			total.Failed++
		case "skipped":
			counts.Skipped++
			total.Skipped++
		case "canceled", "cancelled", "stopped":
			counts.Canceled++
			total.Canceled++
		}
		engines.Jobs[engine] = counts
	}
	engines.Jobs["all"] = total
	engines.QueryRecordsAvailable = total.Total > 0
	engines.Backend = sanitizeAuditText(engines.Backend, redactPaths)
	if strings.EqualFold(strings.TrimSpace(session.Backend), "fallback") {
		engines.Gaps = append(engines.Gaps, "CodeGraph 索引不可用，已使用只读源码兜底")
	}
	for _, gap := range record.Gaps {
		engines.Gaps = append(engines.Gaps, sanitizeAuditText(gap, redactPaths))
	}
	for _, warning := range record.Warnings {
		engines.Gaps = append(engines.Gaps, "引擎警告: "+sanitizeAuditText(warning, redactPaths))
	}
	for engine, counts := range engines.Jobs {
		if engine == "all" || counts.Failed == 0 {
			continue
		}
		engines.Gaps = append(engines.Gaps, fmt.Sprintf("%s 引擎有 %d 个失败任务", sanitizeAuditText(engine, redactPaths), counts.Failed))
	}
	if !engines.QueryRecordsAvailable {
		engines.Gaps = append(engines.Gaps, "引擎查询记录不可用或不适用（本版本未运行查询引擎）")
	}
	engines.Gaps = dedupeAuditStrings(engines.Gaps)
	sort.Strings(engines.Gaps)
	return engines
}

func dedupeAuditStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func auditEngineJobSummary(engines auditReportEngines) string {
	names := make([]string, 0, len(engines.Jobs))
	for name, counts := range engines.Jobs {
		if name != "all" && counts.Total > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		counts := engines.Jobs[name]
		parts = append(parts, fmt.Sprintf("%s %d（完成 %d/失败 %d/跳过或取消 %d）",
			name, counts.Total, counts.Done, counts.Failed, counts.Skipped+counts.Canceled))
	}
	return strings.Join(parts, "；")
}

func auditEngineStateSummary(engines auditReportEngines) string {
	names := make([]string, 0, len(engines.Capabilities))
	for name := range engines.Capabilities {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		capability := engines.Capabilities[name]
		state := firstNonBlank(capability.State, "unknown")
		if capability.Version != "" && capability.Available {
			state += "(" + capability.Version + ")"
		} else if capability.Reason != "" && !capability.Available {
			state += "(" + capability.Reason + ")"
		}
		parts = append(parts, name+"="+state)
	}
	return strings.Join(parts, ", ")
}

func buildAuditReportScope(plan audit.Plan, rows []db.AuditCoverage, redactPaths []string) auditReportScope {
	languages := make([]string, 0, len(plan.Languages))
	for _, language := range plan.Languages {
		languages = append(languages, sanitizeAuditText(language, redactPaths))
	}
	modules := make([]string, 0, len(plan.Modules))
	for _, module := range plan.Modules {
		modules = append(modules, sanitizeAuditText(module, redactPaths))
	}
	entries := make([]string, 0, len(plan.EntryPoints))
	for _, entry := range plan.EntryPoints {
		entries = append(entries, sanitizeAuditText(entry, redactPaths))
	}
	return auditReportScope{
		Languages: languages, Modules: modules, EntryPoints: entries,
		PlannedCWE: plannedCWECount(plan), PlannedSinkSites: countCoverageKind(rows, audit.CoverageKindSinkSite),
	}
}

func buildAuditReportRisk(categories auditReportFindings) auditReportRisk {
	risk := auditReportRisk{
		Severity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
		CWE:      map[string]int{},
	}
	riskFindings := make([]auditReportFinding, 0, len(categories.Confirmed)+len(categories.Candidate))
	riskFindings = append(riskFindings, categories.Confirmed...)
	riskFindings = append(riskFindings, categories.Candidate...)
	for _, finding := range riskFindings {
		severity := strings.ToLower(firstNonBlank(finding.Severity, "unknown"))
		risk.Severity[severity]++
		if cwe := strings.ToUpper(strings.TrimSpace(finding.CWE)); cwe != "" {
			risk.CWE[cwe]++
		}
	}
	return risk
}

func buildAuditReportGaps(plan audit.Plan, rows []db.AuditCoverage, engines auditReportEngines, redactPaths []string) auditReportGaps {
	gaps := auditReportGaps{
		Coverage: make([]auditReportGapRow, 0), UncoveredCWEs: auditUncoveredCWEs(plan, rows),
		Engines: append([]string(nil), engines.Gaps...),
	}
	for _, row := range auditCoverageGapRows(rows) {
		gaps.Coverage = append(gaps.Coverage, auditReportGapRow{
			Status:   strings.ToLower(strings.TrimSpace(row.Status)),
			Kind:     strings.ToLower(strings.TrimSpace(row.Kind)),
			Language: sanitizeAuditText(row.Language, redactPaths),
			CWE:      strings.ToUpper(strings.TrimSpace(row.CWE)),
			Module:   sanitizeAuditText(row.Module, redactPaths),
			Path:     sanitizeAuditText(row.Path, redactPaths),
			Line:     row.Line,
			SinkKey:  sanitizeAuditText(row.SinkKey, redactPaths),
			Reason:   sanitizeAuditText(row.Reason, redactPaths),
		})
	}
	if gaps.Coverage == nil {
		gaps.Coverage = []auditReportGapRow{}
	}
	if gaps.UncoveredCWEs == nil {
		gaps.UncoveredCWEs = []string{}
	}
	if gaps.Engines == nil {
		gaps.Engines = []string{}
	}
	return gaps
}

func auditUncoveredCWEs(plan audit.Plan, rows []db.AuditCoverage) []string {
	planned := map[string]struct{}{}
	for language, cwes := range plan.PlannedCWEs {
		lang := audit.NormalizeLanguage(language)
		if lang == "" {
			lang = strings.ToLower(strings.TrimSpace(language))
		}
		for _, cwe := range cwes {
			cwe = strings.ToUpper(strings.TrimSpace(cwe))
			if lang == "" || cwe == "" {
				continue
			}
			planned[lang+"|"+cwe] = struct{}{}
		}
	}
	covered := map[string]struct{}{}
	for _, row := range rows {
		status := strings.ToLower(strings.TrimSpace(row.Status))
		coveredStatus := status == audit.CoverageStatusScanned || status == audit.CoverageStatusCandidate || status == audit.CoverageStatusBenign ||
			(status == audit.CoverageStatusExempt && audit.ValidExemptionReason(row.Reason))
		if !coveredStatus {
			continue
		}
		language := audit.NormalizeLanguage(row.Language)
		if language == "" {
			language = strings.ToLower(strings.TrimSpace(row.Language))
		}
		cwe := strings.ToUpper(strings.TrimSpace(row.CWE))
		if language == "" || cwe == "" {
			continue
		}
		covered[language+"|"+cwe] = struct{}{}
	}
	out := make([]string, 0)
	for pair := range planned {
		if _, ok := covered[pair]; !ok {
			out = append(out, pair)
		}
	}
	sort.Strings(out)
	return out
}

func auditReportMethod() []string {
	return []string{
		"静态只读源码分析（不执行目标代码、构建或测试）",
		"CodeGraph 结构分析，失败时使用只读源码兜底",
		"引擎/规则命中仅作为候选，由 code_worker 独立复核 source→sink→trace→sanitizer",
		"覆盖回执 + 结构化 code_evidence + 可追踪假设",
	}
}

func auditReportLimitations() []string {
	return []string{
		"仅静态分析，未执行目标代码、构建或测试；人工复核后仍需在授权环境中验证。",
		"M1 审计保持 round=1，多轮聚焦补扫尚未实现；门禁未通过且无剩余可执行候选时生成 done_with_gaps 部分报告。",
		"引擎查询记录未接入时不可用/不适用，报告只能披露引擎配置与任务计数。",
	}
}

func sanitizeAuditGates(gates map[string]audit.GateResult, redactPaths []string) map[string]audit.GateResult {
	out := make(map[string]audit.GateResult, len(gates))
	for key, gate := range gates {
		clean := gate
		clean.Name = sanitizeAuditText(gate.Name, redactPaths)
		clean.Reason = sanitizeAuditText(gate.Reason, redactPaths)
		if len(gate.Details) > 0 {
			raw, err := json.Marshal(gate.Details)
			if err == nil {
				var decoded any
				if json.Unmarshal(raw, &decoded) == nil {
					if details, ok := sanitizeAuditJSONValue(decoded, redactPaths).(map[string]any); ok {
						clean.Details = details
					}
				}
			}
		}
		out[sanitizeAuditText(key, redactPaths)] = clean
	}
	return out
}

func sanitizeAuditJSONValue(value any, redactPaths []string) any {
	switch typed := value.(type) {
	case string:
		return sanitizeAuditText(typed, redactPaths)
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = sanitizeAuditJSONValue(typed[i], redactPaths)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			out[sanitizeAuditText(key, redactPaths)] = sanitizeAuditJSONValue(nested, redactPaths)
		}
		return out
	default:
		return value
	}
}

func normalizeAuditReportPlan(plan audit.Plan, session *db.AuditSession) audit.Plan {
	if plan.Depth == "" && session != nil {
		plan.Depth = session.Depth
	}
	if len(plan.Languages) == 0 && session != nil {
		plan.Languages = append([]string(nil), session.Languages...)
	}
	if plan.PlannedCWEs == nil {
		plan.PlannedCWEs = map[string][]string{}
	}
	if plan.Depth == "" {
		plan.Depth = audit.DepthDeep
	}
	return plan
}

func auditReportTaskTitle(t *Task) string {
	if t == nil {
		return "代码审计"
	}
	return firstNonBlank(strings.TrimSpace(t.Name), strings.TrimSpace(t.Description), strings.TrimSpace(t.Goal), "代码审计任务 "+t.ID)
}

func auditReportTaskDescription(t *Task) string {
	if t == nil {
		return "-"
	}
	description := strings.TrimSpace(t.Description)
	if description == "" {
		description = strings.TrimSpace(t.Goal)
	}
	if description == "" {
		description = auditReportTaskTitle(t)
	}
	return description
}

func normalizeAuditVerification(verification string) string {
	verification = strings.ToLower(strings.TrimSpace(verification))
	if verification == "" {
		return audit.VerificationUnverified
	}
	return verification
}

func auditFindingSeverityRank(severity string) int {
	return auditSeverityRank(severity)
}

func auditReportStatusLabel(status string) string {
	switch status {
	case db.AuditStatusDone:
		return "完成（门禁通过）"
	case db.AuditStatusDoneWithGaps:
		return "完成（存在覆盖/门禁缺口）"
	default:
		return firstNonBlank(status, "未知")
	}
}

func auditEngineSummary(engines auditReportEngines) string {
	keys := make([]string, 0, len(engines.Configured))
	for engine := range engines.Configured {
		keys = append(keys, engine)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "未记录"
	}
	parts := make([]string, 0, len(keys))
	for _, engine := range keys {
		parts = append(parts, engine+"="+engines.Configured[engine])
	}
	return strings.Join(parts, ", ")
}

func auditPassedLabel(gates map[string]audit.GateResult) string {
	if len(gates) == 0 {
		return "未记录"
	}
	if auditGatesPassed(gates) {
		return "全部通过"
	}
	return "存在未通过项"
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func inlineMarkdown(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", "<br>")
	value = strings.ReplaceAll(value, "|", `\|`)
	if value == "" {
		return "-"
	}
	return value
}

func yesNo(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

func formatPercent(value float64) string {
	return fmt.Sprintf("%.2f%%", value*100)
}

func limitStrings(values []string, max int) []string {
	if max > 0 && len(values) > max {
		return values[:max]
	}
	return values
}

func truncateText(value string, maxRunes int) string {
	if maxRunes <= 0 || utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:maxRunes]) + "…"
}

func plannedCWECount(plan audit.Plan) int {
	seen := map[string]struct{}{}
	for language, cwes := range plan.PlannedCWEs {
		for _, cwe := range cwes {
			key := strings.ToLower(strings.TrimSpace(language)) + "\x00" + strings.ToUpper(strings.TrimSpace(cwe))
			seen[key] = struct{}{}
		}
	}
	return len(seen)
}

func countCoverageKind(rows []db.AuditCoverage, kind string) int {
	count := 0
	for _, row := range rows {
		if strings.EqualFold(strings.TrimSpace(row.Kind), kind) {
			count++
		}
	}
	return count
}

func auditCoverageGapRows(rows []db.AuditCoverage) []db.AuditCoverage {
	out := make([]db.AuditCoverage, 0)
	for _, row := range rows {
		switch strings.ToLower(strings.TrimSpace(row.Status)) {
		case audit.CoverageStatusPlanned, audit.CoverageStatusExempt, audit.CoverageStatusMissed:
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].CWE != out[j].CWE {
			return out[i].CWE < out[j].CWE
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].SinkKey < out[j].SinkKey
	})
	const maxRows = 500
	if len(out) > maxRows {
		out = out[:maxRows]
	}
	return out
}

func sortedCWEs(counts map[string]int) []string {
	out := make([]string, 0, len(counts))
	for cwe := range counts {
		out = append(out, cwe)
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := cweNumber(out[i]), cweNumber(out[j])
		if left != right {
			return left < right
		}
		return out[i] < out[j]
	})
	return out
}

func cweNumber(cwe string) int {
	number, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(cwe), "CWE-"))
	if err != nil {
		return int(^uint(0) >> 1)
	}
	return number
}

func auditPhaseNumber(phase string) int {
	number, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(phase), "S"))
	if err != nil {
		return int(^uint(0) >> 1)
	}
	return number
}

func formatCodeLocation(location audit.CodeLocation) string {
	path := location.Path
	if path == "" {
		path = "-"
	}
	if location.Line > 0 {
		path = fmt.Sprintf("%s:%d", path, location.Line)
	}
	if location.Symbol != "" {
		return fmt.Sprintf("`%s` (%s)", inlineMarkdown(path), inlineMarkdown(location.Symbol))
	}
	return fmt.Sprintf("`%s`", inlineMarkdown(path))
}

func cloneCodeLocation(location *audit.CodeLocation) *audit.CodeLocation {
	if location == nil {
		return nil
	}
	clone := *location
	clone.Path = audit.NormalizeCodePath(clone.Path)
	clone.Snippet = sanitizeAuditText(clone.Snippet, nil)
	return &clone
}

func cloneReachability(reachability *audit.Reachability) *audit.Reachability {
	if reachability == nil {
		return nil
	}
	clone := *reachability
	return &clone
}

func writeMarkdownFence(b *strings.Builder, language, content string) {
	longest := 0
	current := 0
	for _, r := range content {
		if r == '`' {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 0
		}
	}
	width := 3
	if longest >= width {
		width = longest + 1
	}
	fence := strings.Repeat("`", width)
	fmt.Fprintf(b, "%s%s\n%s", fence, language, content)
	if !strings.HasSuffix(content, "\n") {
		b.WriteString("\n")
	}
	fmt.Fprintf(b, "%s\n", fence)
}

var (
	auditURLUserInfoPattern  = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@`)
	auditUserPassPattern     = regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+-]+:[^\s/@]+@`)
	auditBearerPattern       = regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{10,}`)
	auditSecretAssignPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|passwd|authorization)\b(\s*[:=]\s*)(["']?)[^\s"',;}]{6,}`)
	auditKnownSecretPattern  = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b`)
	auditPrivateKeyPattern   = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
)

// sanitizeAuditReportText removes server paths and common credential shapes
// from report text. It is intentionally conservative: report evidence is useful,
// but server-local paths and credentials must never leave the process.
// addAuditRedactPath avoids treating a filesystem root as a redaction token:
// replacing "/" would otherwise mangle every path in the report.
func addAuditRedactPath(paths []string, path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return paths
	}
	clean := filepath.Clean(path)
	if filepath.Dir(clean) == clean {
		return paths
	}
	for _, existing := range paths {
		if existing == path {
			return paths
		}
	}
	return append(paths, path)
}

func sanitizeAuditText(value string, paths []string) string {
	if value == "" {
		return ""
	}
	ordered := append([]string(nil), paths...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return len(strings.TrimSpace(ordered[i])) > len(strings.TrimSpace(ordered[j]))
	})
	for _, path := range ordered {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		variants := []string{
			path,
			filepath.ToSlash(path),
			strings.ReplaceAll(path, `\`, `\\`),
			strings.ReplaceAll(filepath.ToSlash(path), "/", `\/`),
		}
		for _, variant := range variants {
			if variant != "" {
				value = strings.ReplaceAll(value, variant, "[redacted-path]")
			}
		}
	}
	value = auditPrivateKeyPattern.ReplaceAllString(value, `[REDACTED-PRIVATE-KEY]`)
	value = auditURLUserInfoPattern.ReplaceAllString(value, `${1}[redacted]@`)
	value = auditUserPassPattern.ReplaceAllString(value, `[redacted]@`)
	value = auditBearerPattern.ReplaceAllString(value, `${1}[REDACTED]`)
	value = auditSecretAssignPattern.ReplaceAllString(value, `${1}${2}${3}[REDACTED]`)
	value = auditKnownSecretPattern.ReplaceAllString(value, `[REDACTED]`)
	return value
}

func sanitizeAuditSourceRef(sourceRef string, paths []string) string {
	ref := sanitizeAuditText(strings.TrimSpace(sourceRef), paths)
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, "/") || (len(ref) >= 3 && ref[1] == ':' && (ref[2] == '/' || ref[2] == '\\')) {
		if base := filepath.Base(ref); base != "" && base != "." && base != string(filepath.Separator) {
			return base
		}
	}
	return ref
}
