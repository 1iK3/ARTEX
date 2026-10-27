package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/audit/engines"
	"github.com/Autumn-27/artex/db"
)

const (
	auditEngineDefaultSeconds = 1800
	auditEngineMaxSeconds     = 24 * 60 * 60
	auditEngineGapLimit       = 32
	auditEngineWarningLimit   = 64
)

// auditEngineRun is the result of one optional-engine pass during preflight. It
// intentionally carries no absolute paths: EnginesJSON is already redacted and
// Sites are snapshot-relative.
type auditEngineRun struct {
	Capabilities   map[string]engines.Capability
	Prepared       map[string]engines.Prepared
	Findings       []engines.EngineFinding
	Jobs           []engines.JobResult
	Sites          []audit.SinkSite
	EnginesJSON    []byte
	Warnings       []string
	EngineEvidence map[string]auditEngineSiteEvidence
}

// auditEngineSiteEvidence is the per-sink engine corroboration retained for
// coverage rows and merge logic.
type auditEngineSiteEvidence struct {
	Engine     string             `json:"engine"`
	Confidence float64            `json:"confidence"`
	Engines    map[string]float64 `json:"engines,omitempty"`
}

// auditEnginesRecord is the audit_sessions.engines shape written after
// preflight. It keeps the legacy mode map under "configured" so older readers
// can still recover the operator's choices.
type auditEnginesRecord struct {
	Configured   map[string]string             `json:"configured,omitempty"`
	Capabilities map[string]engines.Capability `json:"capabilities,omitempty"`
	Prepared     map[string]engines.Prepared   `json:"prepared,omitempty"`
	Warnings     []string                      `json:"warnings,omitempty"`
	Gaps         []string                      `json:"gaps,omitempty"`
}

// auditMergedSinkSites is the prescan+engine sink inventory. EngineOnly records
// which keys came exclusively from an external engine so coverage rows can be
// stamped with that engine.
type auditMergedSinkSites struct {
	Sites          []audit.SinkSite
	EngineEvidence map[string]auditEngineSiteEvidence
	EngineOnly     map[string]struct{}
}

// runAuditEngines builds detection intents, probes and prepares the configured
// CodeQL/Joern adapters, runs template queries, persists intents/jobs, and
// converts findings into coverage sink sites. Ordinary engine failures become
// warnings/gaps; only setup or persistence errors are returned to the caller.
func (d *AuditDirector) runAuditEngines(ctx context.Context, t *Task, cfg audit.Config, session *db.AuditSession, snapshot string, plan audit.Plan, reg audit.Registry) (auditEngineRun, error) {
	run := auditEngineRun{
		Capabilities:   map[string]engines.Capability{},
		Prepared:       map[string]engines.Prepared{},
		Findings:       []engines.EngineFinding{},
		Jobs:           []engines.JobResult{},
		Sites:          []audit.SinkSite{},
		EngineEvidence: map[string]auditEngineSiteEvidence{},
	}
	if d == nil || d.s == nil || d.s.m == nil || d.s.m.pg == nil {
		return run, errors.New("审计持久化层不可用")
	}
	if session == nil {
		return run, errors.New("审计会话不存在")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	configured := make(map[string]string, len(cfg.Engines))
	for name, mode := range cfg.Engines {
		configured[strings.ToLower(strings.TrimSpace(name))] = strings.ToLower(strings.TrimSpace(mode))
	}
	gaps := make([]string, 0)
	gapSeen := make(map[string]struct{})
	addGap := func(message string) {
		message = strings.TrimSpace(message)
		if message == "" || len(gaps) >= auditEngineGapLimit {
			return
		}
		if _, exists := gapSeen[message]; exists {
			return
		}
		gapSeen[message] = struct{}{}
		gaps = append(gaps, message)
	}
	addWarning := func(message string) {
		message = strings.TrimSpace(message)
		if message == "" || len(run.Warnings) >= auditEngineWarningLimit {
			return
		}
		run.Warnings = append(run.Warnings, message)
	}

	// Detection intents are plan-level artifacts; persist them even when no
	// optional engine is enabled so progress/report and later rounds retain the
	// planned detection surface.
	intents, err := engines.BuildDetectionIntents(plan, reg)
	if err != nil {
		addWarning("检测意图生成失败: " + err.Error())
		addGap("检测意图生成失败，引擎检测已跳过")
		intents = []engines.DetectionIntent{}
	}
	intentDBIDs := make(map[string]int64, len(intents))
	for _, intent := range intents {
		record := db.AuditDetectionIntent{
			SessionID:        session.ID,
			Round:            1,
			IntentKey:        intent.ID,
			Origin:           intent.Origin,
			Language:         intent.Language,
			CWE:              intent.CWE,
			Title:            intent.Title,
			QueryKind:        intent.QueryKind,
			Sources:          auditEngineJSON(intent.Sources),
			Sinks:            auditEngineJSON(intent.Sinks),
			Sanitizers:       auditEngineJSON(intent.Sanitizers),
			Propagators:      auditEngineJSON(intent.Propagators),
			Scope:            auditEngineJSON(intent.Scope),
			Constraints:      auditEngineJSON(intent.Constraints),
			PreferredEngines: auditEngineJSON(intent.PreferredEngines),
			Priority:         intent.Priority,
			Status:           "planned",
		}
		stored, err := d.s.m.pg.InsertAuditDetectionIntent(record)
		if err != nil {
			return run, fmt.Errorf("写入检测意图失败: %w", err)
		}
		if stored != nil {
			intentDBIDs[intent.ID] = stored.ID
		}
	}

	enabled := enabledAuditEngines(cfg)
	if len(enabled) == 0 {
		run.EnginesJSON, _ = json.Marshal(auditEnginesRecord{
			Configured: configured, Capabilities: run.Capabilities, Prepared: run.Prepared,
			Warnings: sanitizeAuditEngineMessages(run.Warnings, nil),
			Gaps:     sanitizeAuditEngineMessages(gaps, nil),
		})
		return run, nil
	}
	if ctx.Err() != nil {
		addWarning("引擎检测在开始前已被取消")
		run.EnginesJSON, _ = json.Marshal(auditEnginesRecord{
			Configured: configured, Capabilities: run.Capabilities, Prepared: run.Prepared,
			Warnings: sanitizeAuditEngineMessages(run.Warnings, nil),
			Gaps:     sanitizeAuditEngineMessages(gaps, nil),
		})
		return run, nil
	}
	if t == nil {
		return run, errors.New("任务不存在，无法准备引擎工作目录")
	}
	if strings.TrimSpace(d.s.m.dir) == "" {
		return run, errors.New("服务器工作目录未配置")
	}
	if strings.TrimSpace(snapshot) == "" {
		return run, errors.New("源码快照不存在，无法准备引擎")
	}
	workDir := filepath.Join(d.s.m.dir, "tasks", t.ID, "audit", "engines")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return run, fmt.Errorf("创建引擎工作目录失败: %w", err)
	}

	engineTimeout := auditEngineTimeout(cfg)
	ramMB := auditBudgetInt(cfg, "codeql_ram_mb")
	runners := make([]engines.Engine, 0, len(enabled))
	enginePaths := make([]string, 0, 8)
	for _, name := range enabled {
		switch name {
		case audit.EngineCodeQL:
			runner := engines.NewCodeQLRunner(d.s.auditEngineBin(audit.EngineCodeQL), workDir)
			runner.SearchPath = d.s.auditEngineSetting("ARTEX_CODEQL_SEARCH_PATH", "audit.codeql_search_path", "")
			runner.DBPath = d.s.auditEngineSetting("ARTEX_CODEQL_DB_PATH", "audit.codeql_db_path", "")
			runner.RAMMB = ramMB
			runner.Timeout = engineTimeout
			enginePaths = append(enginePaths, runner.Bin, filepath.Dir(runner.Bin), runner.SearchPath, runner.DBPath)
			enginePaths = append(enginePaths, filepath.SplitList(runner.SearchPath)...)
			runners = append(runners, runner)
		case audit.EngineJoern:
			runner := engines.NewJoernRunner(
				d.s.auditEngineBin(audit.EngineJoern),
				d.s.auditEngineSetting("ARTEX_JOERN_PARSE_BIN", "audit.joern_parse_bin", "joern-parse"),
				workDir,
			)
			runner.CPGPath = d.s.auditEngineSetting("ARTEX_JOERN_CPG_PATH", "audit.joern_cpg_path", "")
			runner.SandboxCmd = d.s.auditEngineSetting("ARTEX_JOERN_SANDBOX_CMD", "audit.joern_sandbox_cmd", "")
			runner.Timeout = engineTimeout
			enginePaths = append(enginePaths, runner.Bin, filepath.Dir(runner.Bin), runner.ParseBin,
				filepath.Dir(runner.ParseBin), runner.CPGPath)
			runners = append(runners, runner)
		}
	}
	redactions := auditEngineRedactPaths(snapshot, workDir)
	for _, path := range enginePaths {
		redactions = auditEngineAddRedaction(redactions, path)
	}
	if len(runners) == 0 {
		addWarning("未配置可运行的检测引擎适配器")
	}
	manager := engines.NewManager(runners...)
	run.Capabilities = manager.ProbeAll(ctx)

	available := make([]string, 0, len(enabled))
	for _, name := range enabled {
		capability, ok := run.Capabilities[name]
		if !ok {
			addGap(fmt.Sprintf("%s 引擎未完成能力探测", name))
			continue
		}
		if !capability.Available {
			reason := firstNonBlank(capability.Reason, "unavailable")
			required := strings.EqualFold(strings.TrimSpace(cfg.Engines[name]), "required")
			message := fmt.Sprintf("%s 引擎不可用: %s", name, reason)
			if required {
				message = fmt.Sprintf("required %s 引擎不可用: %s", name, reason)
			}
			addGap(message)
			addWarning(message)
			continue
		}
		if !auditEngineSupportsAnyLanguage(capability.Languages, plan.Languages) {
			addGap(fmt.Sprintf("%s 引擎不支持计划语言: %s", name, languageSummary(plan.Languages)))
			continue
		}
		available = append(available, name)
	}

	prepared, failures := manager.PrepareAll(ctx,
		engines.SourceRef{
			Root: snapshot, Languages: append([]string(nil), plan.Languages...),
			Commit: session.CommitSHA,
		},
		plan.Languages,
		engines.PrepareOptions{WorkDir: workDir, RAMMB: ramMB, Timeout: engineTimeout},
	)
	run.Prepared = prepared
	for _, failure := range failures {
		if failure == nil {
			continue
		}
		addWarning("引擎准备失败: " + failure.Error())
		addGap("引擎准备失败: " + failure.Error())
	}
	for engine, result := range prepared {
		for _, warning := range result.Warnings {
			addWarning(engine + ": " + warning)
		}
		unsupported := make([]string, 0, len(result.Unsupported))
		for language, reason := range result.Unsupported {
			unsupported = append(unsupported, language+": "+reason)
		}
		sort.Strings(unsupported)
		for _, gap := range unsupported {
			addGap(fmt.Sprintf("%s 未能准备 %s", engine, gap))
		}
	}

	if len(available) > 0 && len(intents) > 0 && ctx.Err() == nil {
		findings, jobs := manager.RunIntents(ctx, intents, available)
		run.Findings = findings
		run.Jobs = jobs
		resultCounts := auditEngineJobResultCounts(findings)
		for _, job := range jobs {
			var intentID *int64
			if id, ok := intentDBIDs[job.IntentID]; ok && id > 0 {
				value := id
				intentID = &value
			}
			provenance, _ := json.Marshal(map[string]any{
				"intent_key":       job.IntentID,
				"template_version": engines.TemplateVersion,
			})
			stored := db.AuditEngineJob{
				SessionID:   session.ID,
				IntentID:    intentID,
				Engine:      job.Engine,
				JobKind:     "run",
				QueryHash:   job.QueryHash,
				Status:      job.Status,
				ResultCount: resultCounts[job.Engine+"\x00"+job.IntentID],
				DurationMS:  job.Duration.Milliseconds(),
				Error:       sanitizeAuditText(job.Error, redactions),
				Provenance:  provenance,
			}
			if err := d.s.m.pg.UpsertAuditEngineJob(stored); err != nil {
				return run, fmt.Errorf("写入引擎任务失败: %w", err)
			}
		}
		auditEngineJobGaps(jobs, addGap)
	}
	if len(available) == 0 {
		addWarning("没有可用的检测引擎，已保留预扫描结果")
	}
	if ctx.Err() != nil {
		addWarning("引擎检测在完成前被取消")
	}

	run.Sites, run.EngineEvidence = auditEngineSinkSites(run.Findings, intents, snapshot)
	run.Warnings = sanitizeAuditEngineMessages(run.Warnings, redactions)
	gaps = sanitizeAuditEngineMessages(gaps, redactions)
	record := sanitizeAuditEnginesRecord(auditEnginesRecord{
		Configured: configured, Capabilities: run.Capabilities, Prepared: run.Prepared,
		Warnings: run.Warnings, Gaps: gaps,
	}, redactions)
	raw, marshalErr := json.Marshal(record)
	if marshalErr != nil {
		return run, fmt.Errorf("序列化引擎状态失败: %w", marshalErr)
	}
	run.EnginesJSON = raw
	return run, nil
}

// emitAuditEngineActivity reports availability, job outcomes, finding/site
// counts, and bounded warnings without exposing engine or snapshot paths.
func (d *AuditDirector) emitAuditEngineActivity(t *Task, run auditEngineRun) {
	if d == nil || d.s == nil || d.s.engine == nil || t == nil {
		return
	}
	names := make([]string, 0, len(run.Capabilities))
	for name := range run.Capabilities {
		names = append(names, name)
	}
	sort.Strings(names)
	available := make([]string, 0, len(names))
	unavailable := make([]string, 0, len(names))
	for _, name := range names {
		capability := run.Capabilities[name]
		if capability.Available {
			available = append(available, name)
			continue
		}
		unavailable = append(unavailable, name+"("+firstNonBlank(capability.Reason, "unavailable")+")")
	}
	done, failed, skipped := 0, 0, 0
	for _, job := range run.Jobs {
		switch strings.ToLower(strings.TrimSpace(job.Status)) {
		case engines.JobStatusDone:
			done++
		case engines.JobStatusFailed:
			failed++
		case engines.JobStatusSkipped:
			skipped++
		}
	}
	state := "无可用引擎"
	if len(available) > 0 {
		state = "可用 " + strings.Join(available, ", ")
	}
	if len(unavailable) > 0 {
		state += "；不可用 " + strings.Join(unavailable, ", ")
	}
	if len(names) == 0 {
		state = "未配置引擎"
	}
	summary := fmt.Sprintf("代码审计：引擎检测完成（%s；任务 %d：完成 %d/失败 %d/跳过 %d；引擎发现 %d 条，站点 %d 个）",
		state, len(run.Jobs), done, failed, skipped, len(run.Findings), len(run.Sites))
	d.emit(t, db.Activity{Worker: "system", Kind: "text", Summary: summary})
	for index, warning := range run.Warnings {
		if index >= 8 {
			d.emit(t, db.Activity{Worker: "system", Kind: "text",
				Summary: fmt.Sprintf("代码审计：引擎警告过多（共 %d 条），其余见会话引擎状态", len(run.Warnings))})
			break
		}
		d.emit(t, db.Activity{Worker: "system", Kind: "text",
			Summary: "代码审计：引擎警告：" + warning, Detail: warning})
	}
}

func enabledAuditEngines(cfg audit.Config) []string {
	enabled := make([]string, 0, 2)
	for _, name := range []string{audit.EngineCodeQL, audit.EngineJoern} {
		mode := strings.ToLower(strings.TrimSpace(cfg.Engines[name]))
		if mode == "" || mode == "off" {
			continue
		}
		enabled = append(enabled, name)
	}
	return enabled
}

func auditEngineTimeout(cfg audit.Config) time.Duration {
	seconds := auditBudgetInt(cfg, "max_engine_seconds")
	if seconds <= 0 {
		seconds = auditEngineDefaultSeconds
	}
	if seconds > auditEngineMaxSeconds {
		seconds = auditEngineMaxSeconds
	}
	return time.Duration(seconds) * time.Second
}

// auditEngineSetting resolves an operator override from env, then the settings
// table, then fallback. It never returns an absolute path to a caller that
// exposes it without redaction.
func (s *Server) auditEngineSetting(envKey, settingKey, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(envKey)); value != "" {
		return value
	}
	if s != nil && s.m != nil && s.m.pg != nil {
		if value, ok, err := s.m.pg.GetSetting(settingKey); err == nil && ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return fallback
}

func auditEngineSupportsAnyLanguage(supported, planned []string) bool {
	if len(supported) == 0 {
		return true
	}
	allowed := make(map[string]struct{}, len(supported))
	for _, language := range supported {
		normalized := audit.NormalizeLanguage(language)
		if normalized == "" {
			normalized = strings.ToLower(strings.TrimSpace(language))
		}
		if normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}
	for _, language := range planned {
		normalized := audit.NormalizeLanguage(language)
		if normalized == "" {
			normalized = strings.ToLower(strings.TrimSpace(language))
		}
		if _, ok := allowed[normalized]; ok {
			return true
		}
	}
	return false
}

func auditEngineJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage("null")
	}
	return raw
}

// auditEngineSinkSites converts correlated engine findings into sink sites and
// per-site engine evidence. Findings lacking a CWE, snapshot-relative path,
// positive line, or symbol are ignored rather than fabricated into coverage.
func auditEngineSinkSites(findings []engines.EngineFinding, intents []engines.DetectionIntent, snapshot string) ([]audit.SinkSite, map[string]auditEngineSiteEvidence) {
	byIntent := make(map[string]engines.DetectionIntent, len(intents))
	for _, intent := range intents {
		byIntent[intent.ID] = intent
	}
	sites := make(map[string]audit.SinkSite)
	evidence := make(map[string]auditEngineSiteEvidence)
	for _, finding := range findings {
		intent := byIntent[auditEngineFindingIntentID(finding)]
		language := strings.ToLower(strings.TrimSpace(firstNonBlank(finding.Language, intent.Language)))
		if normalized := audit.NormalizeLanguage(language); normalized != "" {
			language = normalized
		}
		cwe := strings.ToUpper(strings.TrimSpace(firstNonBlank(finding.CWE, intent.CWE)))
		rawPath := finding.Location.Path
		line := finding.Location.Line
		if finding.Sink != nil {
			if strings.TrimSpace(finding.Sink.Path) != "" {
				rawPath = finding.Sink.Path
			}
			if finding.Sink.Line > 0 {
				line = finding.Sink.Line
			}
		}
		path, pathOK := auditEngineSnapshotPath(rawPath, snapshot)
		if !pathOK {
			continue
		}
		symbol := auditEngineFindingSinkSymbol(finding, intent)
		if language == "" || cwe == "" || path == "" || line <= 0 {
			continue
		}
		key := audit.SinkKeyFor(language, cwe, path, line, symbol)
		if _, exists := sites[key]; !exists {
			sites[key] = audit.SinkSite{
				Language: language, CWE: cwe, Path: path, Line: line,
				Symbol: symbol, SinkKey: key,
			}
		}
		mergeAuditEngineSiteEvidence(evidence, key, auditEngineFindingEvidence(finding))
	}
	keys := make([]string, 0, len(sites))
	for key := range sites {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := sites[keys[i]], sites[keys[j]]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.CWE != right.CWE {
			return left.CWE < right.CWE
		}
		if left.Symbol != right.Symbol {
			return left.Symbol < right.Symbol
		}
		return left.Language < right.Language
	})
	out := make([]audit.SinkSite, 0, len(keys))
	for _, key := range keys {
		out = append(out, sites[key])
	}
	return out, evidence
}

func auditEngineFindingIntentID(finding engines.EngineFinding) string {
	if finding.Payload == nil {
		return ""
	}
	switch value := finding.Payload["intent_id"].(type) {
	case string:
		return strings.TrimSpace(value)
	case json.Number:
		return value.String()
	default:
		return ""
	}
}

// auditEngineSinkSymbol reduces an engine-reported symbol to the same terminal
// identifier form Prescan uses, so a SARIF fully-qualified name and a Joern call
// name produce the same SinkKey. Prescan applies additional generic/short-name
// filters that engines do not need to repeat.
func auditEngineSinkSymbol(raw string) string {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "::", "."))
	if raw == "" {
		return ""
	}
	symbol := audit.ShortSymbol(raw)
	if index := strings.LastIndexByte(symbol, '.'); index >= 0 {
		symbol = symbol[index+1:]
	}
	if index := strings.IndexByte(symbol, '('); index >= 0 {
		symbol = symbol[:index]
	}
	return strings.Join(strings.Fields(symbol), "")
}

func auditEngineFindingEvidence(finding engines.EngineFinding) map[string]float64 {
	out := make(map[string]float64)
	add := func(name string, confidence float64) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		confidence = normalizeAuditEngineConfidence(confidence)
		if confidence > out[name] {
			out[name] = confidence
		}
	}
	// Normalize stores per-engine confidence in the payload and may boost the
	// finding-level confidence for cross-engine corroboration. Prefer the
	// payload so evidence records each engine's own confidence.
	if payload, ok := finding.Payload["engines"]; ok {
		for _, entry := range auditEnginePayloadEvidence(payload) {
			add(entry.name, entry.confidence)
		}
	}
	if len(out) == 0 {
		add(finding.Engine, finding.Confidence)
	}
	if len(out) == 0 {
		add("unknown", finding.Confidence)
	}
	return out
}

type auditEnginePayloadEngine struct {
	name       string
	confidence float64
}

func auditEnginePayloadEvidence(value any) []auditEnginePayloadEngine {
	out := make([]auditEnginePayloadEngine, 0)
	appendEntry := func(raw any) {
		entry, ok := raw.(map[string]any)
		if !ok {
			return
		}
		name, _ := entry["name"].(string)
		confidence := 0.0
		switch typed := entry["confidence"].(type) {
		case float64:
			confidence = typed
		case float32:
			confidence = float64(typed)
		case int:
			confidence = float64(typed)
		case json.Number:
			if parsed, err := typed.Float64(); err == nil {
				confidence = parsed
			}
		}
		if strings.TrimSpace(name) != "" {
			out = append(out, auditEnginePayloadEngine{name: name, confidence: confidence})
		}
	}
	switch typed := value.(type) {
	case []map[string]any:
		for _, entry := range typed {
			appendEntry(entry)
		}
	case []any:
		for _, entry := range typed {
			appendEntry(entry)
		}
	}
	return out
}

func mergeAuditEngineSiteEvidence(evidence map[string]auditEngineSiteEvidence, key string, values map[string]float64) {
	if len(values) == 0 {
		return
	}
	entry := evidence[key]
	if entry.Engines == nil {
		entry.Engines = make(map[string]float64)
	}
	for name, confidence := range values {
		if confidence > entry.Engines[name] {
			entry.Engines[name] = confidence
		}
	}
	names := make([]string, 0, len(entry.Engines))
	for name := range entry.Engines {
		names = append(names, name)
	}
	sort.Strings(names)
	entry.Engine = ""
	entry.Confidence = 0
	for _, name := range names {
		confidence := entry.Engines[name]
		if entry.Engine == "" || confidence > entry.Confidence {
			entry.Engine = name
			entry.Confidence = confidence
		}
	}
	evidence[key] = entry
}

func normalizeAuditEngineConfidence(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func (e auditEngineSiteEvidence) stamp() string {
	names := make([]string, 0, len(e.Engines))
	for name := range e.Engines {
		names = append(names, name)
	}
	if len(names) == 0 {
		names = append(names, firstNonBlank(e.Engine, "engine"))
	}
	sort.Strings(names)
	return strings.Join(names, "+")
}

// mergeAuditSinkSites merges engine-discovered sites into the prescan inventory
// keyed by SinkKey. Prescan wins duplicate content; engine evidence is retained
// for every key an engine corroborated.
func mergeAuditSinkSites(prescanSites, engineSites []audit.SinkSite, evidence map[string]auditEngineSiteEvidence) auditMergedSinkSites {
	merged := auditMergedSinkSites{
		Sites:          make([]audit.SinkSite, 0, len(prescanSites)+len(engineSites)),
		EngineEvidence: make(map[string]auditEngineSiteEvidence),
		EngineOnly:     make(map[string]struct{}),
	}
	seen := make(map[string]struct{}, len(prescanSites)+len(engineSites))
	for _, site := range prescanSites {
		if site.SinkKey == "" {
			site.SinkKey = audit.SinkKeyFor(site.Language, site.CWE, site.Path, site.Line, site.Symbol)
		}
		if _, exists := seen[site.SinkKey]; exists {
			continue
		}
		seen[site.SinkKey] = struct{}{}
		merged.Sites = append(merged.Sites, site)
	}
	engineOrder := make([]audit.SinkSite, 0, len(engineSites))
	for _, site := range engineSites {
		if site.SinkKey == "" {
			site.SinkKey = audit.SinkKeyFor(site.Language, site.CWE, site.Path, site.Line, site.Symbol)
		}
		if _, exists := seen[site.SinkKey]; exists {
			continue
		}
		seen[site.SinkKey] = struct{}{}
		engineOrder = append(engineOrder, site)
	}
	sort.Slice(engineOrder, func(i, j int) bool {
		left, right := engineOrder[i], engineOrder[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.CWE != right.CWE {
			return left.CWE < right.CWE
		}
		if left.Symbol != right.Symbol {
			return left.Symbol < right.Symbol
		}
		return left.Language < right.Language
	})
	for _, site := range engineOrder {
		merged.Sites = append(merged.Sites, site)
		merged.EngineOnly[site.SinkKey] = struct{}{}
	}
	for key, entry := range evidence {
		if len(entry.Engines) == 0 {
			continue
		}
		merged.EngineEvidence[key] = entry
	}
	return merged
}

// applyAuditEngineCoverageEvidence stamps engine provenance onto sink-site
// coverage rows. Prescan rows keep the backend engine; engine-only rows carry
// the corroborating engine name(s).
func applyAuditEngineCoverageEvidence(rows []db.AuditCoverage, merged auditMergedSinkSites) []db.AuditCoverage {
	if len(merged.EngineEvidence) == 0 {
		return rows
	}
	out := make([]db.AuditCoverage, len(rows))
	copy(out, rows)
	for i := range out {
		if strings.ToLower(strings.TrimSpace(out[i].Kind)) != audit.CoverageKindSinkSite {
			continue
		}
		entry, ok := merged.EngineEvidence[out[i].SinkKey]
		if !ok {
			continue
		}
		payload := map[string]any{
			"engine":     entry.Engine,
			"confidence": entry.Confidence,
			"engines":    entry.Engines,
		}
		if _, engineOnly := merged.EngineOnly[out[i].SinkKey]; engineOnly {
			payload["origin"] = "engine"
			out[i].Engine = entry.stamp()
		} else {
			payload["origin"] = "prescan+engine"
		}
		raw, err := json.Marshal(payload)
		if err == nil {
			out[i].Evidence = raw
		}
	}
	return out
}

var auditEngineMessageCallPattern = regexp.MustCompile(`([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(`)

func auditEngineFindingSinkSymbol(finding engines.EngineFinding, intent engines.DetectionIntent) string {
	candidates := make([]string, 0, 8)
	if finding.Sink != nil {
		candidates = append(candidates, finding.Sink.Symbol)
	}
	candidates = append(candidates, finding.Location.Symbol)
	if finding.Payload != nil {
		if symbol, ok := finding.Payload["symbol"].(string); ok {
			candidates = append(candidates, symbol)
		}
	}
	if len(finding.Trace) > 0 {
		last := finding.Trace[len(finding.Trace)-1]
		candidates = append(candidates, last.Symbol, last.Note)
	}
	candidates = append(candidates, auditEngineSymbolFromMessage(finding.Message))
	for _, pattern := range intent.Sinks {
		if strings.TrimSpace(pattern.Pattern) == "" {
			continue
		}
		if strings.Contains(strings.ToLower(finding.Message), strings.ToLower(pattern.Pattern)) {
			candidates = append(candidates, pattern.Pattern)
		}
	}
	for _, candidate := range candidates {
		if symbol := auditEngineSinkSymbol(candidate); symbol != "" {
			return symbol
		}
	}
	return "engine-sink"
}

func auditEngineSymbolFromMessage(message string) string {
	matches := auditEngineMessageCallPattern.FindAllStringSubmatch(message, -1)
	for index := len(matches) - 1; index >= 0; index-- {
		if len(matches[index]) < 2 {
			continue
		}
		symbol := strings.TrimSpace(matches[index][1])
		if dot := strings.LastIndexByte(symbol, '.'); dot >= 0 {
			symbol = symbol[dot+1:]
		}
		if symbol = strings.TrimSpace(symbol); symbol != "" {
			return symbol
		}
	}
	return ""
}

func auditEngineSnapshotPath(raw, snapshot string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsRune(raw, 0) {
		return "", false
	}
	if strings.HasPrefix(strings.ToLower(raw), "file:") {
		if parsed, err := url.Parse(raw); err == nil && parsed.Path != "" {
			raw = parsed.Path
			if len(raw) >= 3 && raw[0] == '/' && isAuditWindowsDrive(raw[1]) && raw[2] == ':' {
				raw = raw[1:]
			}
		}
	}
	raw = strings.ReplaceAll(raw, "\\", "/")
	raw = strings.Trim(raw, `"'`)
	absolute := auditEngineIsAbsolutePath(raw)
	cleaned := path.Clean(raw)
	if !absolute {
		if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			return "", false
		}
		if filepath.VolumeName(raw) != "" {
			return "", false
		}
	}
	if strings.TrimSpace(snapshot) == "" {
		if absolute {
			return "", false
		}
		return cleaned, true
	}
	root, err := filepath.Abs(snapshot)
	if err != nil {
		return "", false
	}
	root = filepath.Clean(root)
	var candidate string
	if absolute {
		candidate = filepath.Clean(filepath.FromSlash(raw))
		if abs, err := filepath.Abs(candidate); err == nil {
			candidate = abs
		}
	} else {
		candidate = filepath.Join(root, filepath.FromSlash(cleaned))
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", false
	}
	relative = filepath.ToSlash(relative)
	if relative == "." || relative == "" {
		return "", false
	}
	return relative, true
}

func auditEngineIsAbsolutePath(raw string) bool {
	if filepath.IsAbs(raw) || filepath.VolumeName(raw) != "" {
		return true
	}
	if len(raw) >= 3 && isAuditWindowsDrive(raw[0]) && raw[1] == ':' && (raw[2] == '/' || raw[2] == '\\') {
		return true
	}
	return strings.HasPrefix(raw, "/")
}

func isAuditWindowsDrive(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func auditEngineJobResultCounts(findings []engines.EngineFinding) map[string]int {
	counts := make(map[string]int)
	for _, finding := range findings {
		intentID := auditEngineFindingIntentID(finding)
		names := make(map[string]struct{})
		for _, entry := range auditEnginePayloadEvidence(finding.Payload["engines"]) {
			if name := strings.ToLower(strings.TrimSpace(entry.name)); name != "" {
				names[name] = struct{}{}
			}
		}
		if len(names) == 0 {
			name := strings.ToLower(strings.TrimSpace(finding.Engine))
			if name == "" {
				name = "unknown"
			}
			names[name] = struct{}{}
		}
		for name := range names {
			counts[name+"\x00"+intentID]++
		}
	}
	return counts
}

func auditEngineJobGaps(jobs []engines.JobResult, add func(string)) {
	type aggregate struct {
		failed  int
		skipped int
		sample  string
	}
	byEngine := make(map[string]*aggregate)
	order := make([]string, 0)
	for _, job := range jobs {
		engine := strings.ToLower(strings.TrimSpace(job.Engine))
		if engine == "" {
			continue
		}
		entry := byEngine[engine]
		if entry == nil {
			entry = &aggregate{}
			byEngine[engine] = entry
			order = append(order, engine)
		}
		switch strings.ToLower(strings.TrimSpace(job.Status)) {
		case engines.JobStatusFailed:
			entry.failed++
			if entry.sample == "" {
				entry.sample = job.Error
			}
		case engines.JobStatusSkipped:
			entry.skipped++
			if entry.sample == "" {
				entry.sample = job.Error
			}
		}
	}
	sort.Strings(order)
	for _, engine := range order {
		entry := byEngine[engine]
		if entry.failed > 0 {
			add(fmt.Sprintf("%s 任务失败 %d 个: %s", engine, entry.failed, entry.sample))
		}
		if entry.skipped > 0 {
			add(fmt.Sprintf("%s 任务跳过 %d 个: %s", engine, entry.skipped, entry.sample))
		}
	}
}

func auditEngineRedactPaths(snapshot, workDir string) []string {
	paths := make([]string, 0, 8)
	paths = auditEngineAddRedaction(paths, snapshot)
	paths = auditEngineAddRedaction(paths, workDir)
	paths = auditEngineAddRedaction(paths, os.TempDir())
	paths = auditEngineAddRedaction(paths, os.Getenv("JAVA_HOME"))
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		paths = auditEngineAddRedaction(paths, home)
		paths = auditEngineAddRedaction(paths, filepath.Join(home, ".codeql"))
		paths = auditEngineAddRedaction(paths, filepath.Join(home, ".codeql", "packages"))
	}
	return paths
}

// auditEngineAddRedaction only registers host-looking paths. Adding a bare
// executable name such as "codeql" would otherwise corrupt every engine
// message that mentions the engine name.
func auditEngineAddRedaction(paths []string, path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return paths
	}
	if !filepath.IsAbs(path) && !strings.ContainsAny(path, `/\`) {
		return paths
	}
	return addAuditRedactPath(paths, path)
}

func sanitizeAuditEngineMessages(messages []string, redactPaths []string) []string {
	if len(messages) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(messages))
	for _, message := range messages {
		message = strings.TrimSpace(sanitizeAuditText(message, redactPaths))
		if message == "" {
			continue
		}
		out = append(out, message)
	}
	return out
}

// sanitizeAuditEnginesRecord strips host paths from session-facing engine
// state. Artifact paths become basenames; capability paths never leave the
// process as absolute paths.
func sanitizeAuditEnginesRecord(record auditEnginesRecord, redactPaths []string) auditEnginesRecord {
	out := auditEnginesRecord{
		Configured:   make(map[string]string, len(record.Configured)),
		Capabilities: make(map[string]engines.Capability, len(record.Capabilities)),
		Prepared:     make(map[string]engines.Prepared, len(record.Prepared)),
		Warnings:     sanitizeAuditEngineMessages(record.Warnings, redactPaths),
		Gaps:         sanitizeAuditEngineMessages(record.Gaps, redactPaths),
	}
	for name, mode := range record.Configured {
		out.Configured[name] = sanitizeAuditText(mode, redactPaths)
	}
	for name, capability := range record.Capabilities {
		if path := strings.TrimSpace(capability.Path); path != "" {
			capability.Path = filepath.Base(filepath.Clean(path))
		}
		capability.Reason = sanitizeAuditText(capability.Reason, redactPaths)
		capability.Languages = append([]string(nil), capability.Languages...)
		out.Capabilities[name] = capability
	}
	for name, prepared := range record.Prepared {
		if prepared.Paths != nil {
			paths := make(map[string]string, len(prepared.Paths))
			for language, path := range prepared.Paths {
				path = strings.TrimSpace(path)
				if path == "" {
					continue
				}
				paths[language] = filepath.Base(filepath.Clean(path))
			}
			prepared.Paths = paths
		}
		if prepared.Unsupported != nil {
			unsupported := make(map[string]string, len(prepared.Unsupported))
			for language, reason := range prepared.Unsupported {
				unsupported[language] = sanitizeAuditText(reason, redactPaths)
			}
			prepared.Unsupported = unsupported
		}
		if prepared.Warnings != nil {
			prepared.Warnings = sanitizeAuditEngineMessages(prepared.Warnings, redactPaths)
		}
		prepared.Languages = append([]string(nil), prepared.Languages...)
		out.Prepared[name] = prepared
	}
	return out
}

// parseAuditEnginesRecord accepts both the legacy mode map
// ({"codeql":"auto"}) and the combined preflight record.
// auditEngineJSONWithWarnings adds preflight-level warnings (timeout, setup
// failure) to an already-built engines record so they remain visible in
// progress/report even when the engine pass aborted early.
func auditEngineJSONWithWarnings(raw []byte, configured map[string]string, warnings []string) []byte {
	record := parseAuditEnginesRecord(raw)
	if len(record.Configured) == 0 && len(configured) > 0 {
		record.Configured = make(map[string]string, len(configured))
		for name, mode := range configured {
			record.Configured[strings.ToLower(strings.TrimSpace(name))] = strings.ToLower(strings.TrimSpace(mode))
		}
	}
	record.Warnings = dedupeAuditStrings(append(record.Warnings, warnings...))
	record = sanitizeAuditEnginesRecord(record, nil)
	out, err := json.Marshal(record)
	if err != nil {
		return raw
	}
	return out
}

func parseAuditEnginesRecord(raw json.RawMessage) auditEnginesRecord {
	record := auditEnginesRecord{
		Configured:   map[string]string{},
		Capabilities: map[string]engines.Capability{},
		Prepared:     map[string]engines.Prepared{},
	}
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return record
	}
	var legacy map[string]string
	if err := json.Unmarshal(raw, &legacy); err == nil {
		if legacy != nil {
			record.Configured = legacy
		}
		return record
	}
	var combined auditEnginesRecord
	if err := json.Unmarshal(raw, &combined); err != nil {
		return record
	}
	if combined.Configured != nil {
		record.Configured = combined.Configured
	}
	if combined.Capabilities != nil {
		record.Capabilities = combined.Capabilities
	}
	if combined.Prepared != nil {
		record.Prepared = combined.Prepared
	}
	record.Warnings = append([]string(nil), combined.Warnings...)
	record.Gaps = append([]string(nil), combined.Gaps...)
	return record
}

func auditEngineState(capability engines.Capability, configured string) string {
	if capability.Available {
		return "ready"
	}
	if strings.EqualFold(strings.TrimSpace(configured), "off") {
		return "disabled"
	}
	if strings.TrimSpace(capability.Reason) != "" {
		return "unavailable"
	}
	return "unknown"
}
