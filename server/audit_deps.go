package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
)

// serverAuditDeps implements agent.AuditDeps on top of the task stores. Methods
// receive the task id explicitly, so one facade can serve every task.
type serverAuditDeps struct {
	s *Server
}

// auditDepsFor returns the persistence/engine facade for a task. The facade is
// intentionally task-agnostic; task ownership is enforced from the taskID each
// tool/method passes.
func (s *Server) auditDepsFor(t *Task) agent.AuditDeps {
	return &serverAuditDeps{s: s}
}

func (d *serverAuditDeps) ReportCodeFinding(ctx context.Context, in db.RecordFindingInput) (*db.RecordedFinding, error) {
	if d == nil || d.s == nil || d.s.m == nil || d.s.m.pg == nil {
		return nil, errors.New("审计持久化层不可用")
	}
	if in.TaskID <= 0 {
		return nil, errors.New("report_code_finding: task_id 缺失")
	}
	return d.s.evidenceStore().Record(ctx, in, nil)
}

func (d *serverAuditDeps) UpdateFindingVerification(ctx context.Context, taskID, findingID int64, verification, method, evidence, altPath string, confidence *float64) error {
	if d == nil || d.s == nil || d.s.m == nil || d.s.m.pg == nil {
		return errors.New("审计持久化层不可用")
	}
	return d.s.m.pg.UpdateFindingVerification(ctx, taskID, findingID, verification, method, evidence, altPath, confidence)
}

// RecordHypothesis validates and upserts one durable hypothesis. Attempt-like
// actions append to the persisted attempt log; the status mapping is:
//
//	record  → untested
//	attempt → testing (blocked when outcome=blocked)
//	confirm → confirmed
//	refute  → refuted
func (d *serverAuditDeps) RecordHypothesis(ctx context.Context, taskID int64, in agent.AuditHypothesisInput) error {
	session, err := d.session(taskID)
	if err != nil {
		return err
	}
	action := strings.ToLower(strings.TrimSpace(in.Action))
	switch action {
	case "record", "attempt", "confirm", "refute":
	default:
		return fmt.Errorf("未知的假设操作 %q", in.Action)
	}
	outcome := strings.ToLower(strings.TrimSpace(in.Outcome))
	switch outcome {
	case "", "success", "failed", "blocked":
	default:
		return fmt.Errorf("未知的假设结果 %q", in.Outcome)
	}
	statement := strings.TrimSpace(in.Statement)
	if statement == "" {
		return errors.New("假设陈述不能为空")
	}
	if in.Priority < 0 || in.Priority > 10 {
		return errors.New("假设优先级必须在 1-10 之间")
	}

	key := strings.TrimSpace(in.HypothesisKey)
	if key == "" {
		sum := sha256.Sum256([]byte(strconv.FormatInt(taskID, 10) + "|" + statement))
		key = "hyp-" + hex.EncodeToString(sum[:8])
	}
	existing, err := findAuditHypothesis(d.s.m.pg, session.ID, key)
	if err != nil {
		return err
	}
	attempts := make([]map[string]any, 0)
	if existing != nil {
		_ = json.Unmarshal(existing.Attempts, &attempts)
	}
	status := auditHypothesisStatus(action, outcome)
	if action != "record" {
		attempts = append(attempts, map[string]any{
			"round":    session.Round,
			"action":   action,
			"outcome":  outcome,
			"evidence": strings.TrimSpace(in.Evidence),
			"at":       time.Now().UTC().Format(time.RFC3339),
		})
	}
	evidence := strings.TrimSpace(in.Evidence)
	if evidence == "" && existing != nil {
		evidence = existing.Evidence
	}
	priority := in.Priority
	if priority == 0 {
		priority = 5
		if existing != nil && existing.Priority > 0 {
			priority = existing.Priority
		}
	}
	attemptsRaw, err := json.Marshal(attempts)
	if err != nil {
		return fmt.Errorf("encode hypothesis attempts: %w", err)
	}
	return d.s.m.pg.UpsertAuditHypothesis(db.AuditHypothesis{
		SessionID:     session.ID,
		Round:         session.Round,
		HypothesisKey: key,
		Statement:     statement,
		Status:        status,
		Attempts:      attemptsRaw,
		Evidence:      evidence,
		Priority:      priority,
	})
}

func auditHypothesisStatus(action, outcome string) string {
	switch action {
	case "attempt":
		if outcome == "blocked" {
			return "blocked"
		}
		return "testing"
	case "confirm":
		return "confirmed"
	case "refute":
		return "refuted"
	default:
		return "untested"
	}
}

func findAuditHypothesis(pg *db.DB, sessionID int64, key string) (*db.AuditHypothesis, error) {
	all, err := pg.ListAuditHypotheses(sessionID)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].HypothesisKey == key {
			return &all[i], nil
		}
	}
	return nil, nil
}

// CompleteAuditIntent validates the worker's coverage receipts and persists them.
// Candidate receipts must reference a finding owned by the same task; exempt
// receipts must carry a reason; every status must be a worker-reportable one.
func (d *serverAuditDeps) CompleteAuditIntent(ctx context.Context, taskID, intentID int64, coverage []audit.CoverageReceipt, stats map[string]any) error {
	if taskID <= 0 || intentID <= 0 {
		return errors.New("task_id 和 intent_id 必须为正整数")
	}
	session, err := d.session(taskID)
	if err != nil {
		return err
	}
	_, store, err := d.taskAndStore(taskID)
	if err != nil {
		return err
	}
	node, err := store.GetNode(intentID)
	if err != nil {
		return err
	}
	if node == nil || node.Kind != db.KindIntent {
		return fmt.Errorf("意图 %d 不属于任务 %d", intentID, taskID)
	}

	rows, err := d.s.m.pg.ListAuditCoverage(session.ID, session.Round)
	if err != nil {
		return err
	}
	groups, err := buildAuditReceiptGroups(coverage, rows, intentID)
	if err != nil {
		return err
	}
	// Candidate receipts must point at a finding produced by this same intent
	// (intent --yields--> finding node). Task ownership alone is not enough:
	// otherwise one intent could claim another worker's finding as its receipt.
	for i, receipt := range coverage {
		if strings.ToLower(strings.TrimSpace(receipt.Status)) != audit.CoverageStatusCandidate {
			continue
		}
		if err := d.ensureCandidateFindingOwned(ctx, taskID, intentID, receipt.FindingID); err != nil {
			return fmt.Errorf("coverage[%d].finding_id %d: %w", i, receipt.FindingID, err)
		}
	}
	for _, group := range groups {
		n, err := d.s.m.pg.MarkAuditCoverageOwned(session.ID, session.Round, intentID, group.SinkKeys, group.Status, group.Reason)
		if err != nil {
			return err
		}
		if n != int64(len(group.SinkKeys)) {
			return fmt.Errorf("覆盖回执写入不完整：%s 组只更新了 %d/%d 行", group.Status, n, len(group.SinkKeys))
		}
	}

	if len(stats) > 0 {
		phase := auditIntentPhase(node.Payload)
		if phase != "" {
			if err := d.mergePhaseStats(session, phase, intentID, stats); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *serverAuditDeps) ensureCandidateFindingOwned(ctx context.Context, taskID, intentID, findingID int64) error {
	var nodeID int64
	var linked bool
	err := d.s.m.pg.QueryRowContext(ctx, `
SELECT COALESCE(f.node_id, 0),
       EXISTS(
           SELECT 1
           FROM exploration_edges e
           JOIN tasks t ON t.exploration_id = e.exploration_id
           WHERE t.id = $2 AND e.src_id = $3 AND e.rel = $4 AND e.dst_id = f.node_id
       )
FROM findings f
WHERE f.id = $1 AND f.task_id = $2`, findingID, taskID, intentID, db.RelYields).Scan(&nodeID, &linked)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("finding 不存在或不属于任务 %d", taskID)
	}
	if err != nil {
		return err
	}
	if nodeID <= 0 {
		return errors.New("finding 缺少探索节点，无法校验意图归属")
	}
	if !linked {
		return fmt.Errorf("finding 不是由意图 #%d 产生（缺少 intent→finding yields 边）；candidate 回执只能关联本意图刚上报的 finding", intentID)
	}
	return nil
}

type auditReceiptGroup struct {
	Status   string
	Reason   string
	SinkKeys []string
}

// buildAuditReceiptGroups validates receipt shape and ownership against the
// round's coverage rows, then groups by status+reason. Only rows owned by
// intentID are accepted; unknown or unassigned sink keys are hard errors.
func buildAuditReceiptGroups(receipts []audit.CoverageReceipt, rows []db.AuditCoverage, intentID int64) ([]auditReceiptGroup, error) {
	owner := make(map[string]*int64, len(rows))
	for i := range rows {
		owner[rows[i].SinkKey] = rows[i].IntentID
	}
	groups := make(map[string]*auditReceiptGroup)
	order := make([]string, 0, len(receipts))
	seen := make(map[string]struct{}, len(receipts))
	for i, receipt := range receipts {
		sinkKey := strings.TrimSpace(receipt.SinkKey)
		if sinkKey == "" {
			return nil, fmt.Errorf("coverage[%d].sink_key 不能为空", i)
		}
		if _, duplicate := seen[sinkKey]; duplicate {
			return nil, fmt.Errorf("coverage[%d].sink_key %q 重复", i, sinkKey)
		}
		seen[sinkKey] = struct{}{}
		status := strings.ToLower(strings.TrimSpace(receipt.Status))
		if !audit.ValidCoverageReceiptStatus(status) {
			return nil, fmt.Errorf("coverage[%d].status %q 必须是 scanned|candidate|benign|exempt|missed", i, receipt.Status)
		}
		reason := strings.TrimSpace(receipt.Reason)
		switch status {
		case audit.CoverageStatusCandidate:
			if receipt.FindingID <= 0 {
				return nil, fmt.Errorf("coverage[%d] 状态为 candidate，必须提供 finding_id", i)
			}
		case audit.CoverageStatusExempt:
			if reason == "" {
				return nil, fmt.Errorf("coverage[%d] 状态为 exempt，必须填写 reason", i)
			}
		}
		rowOwner, exists := owner[sinkKey]
		if !exists {
			return nil, fmt.Errorf("coverage[%d].sink_key %q 不在本会话/轮次的覆盖计划中", i, sinkKey)
		}
		if rowOwner == nil || *rowOwner != intentID {
			return nil, fmt.Errorf("coverage[%d].sink_key %q 未分配给意图 %d", i, sinkKey, intentID)
		}
		groupKey := status + "\x00" + reason
		group := groups[groupKey]
		if group == nil {
			group = &auditReceiptGroup{Status: status, Reason: reason}
			groups[groupKey] = group
			order = append(order, groupKey)
		}
		group.SinkKeys = append(group.SinkKeys, sinkKey)
	}
	out := make([]auditReceiptGroup, 0, len(order))
	for _, key := range order {
		out = append(out, *groups[key])
	}
	return out, nil
}

func (d *serverAuditDeps) mergePhaseStats(session *db.AuditSession, phase string, intentID int64, stats map[string]any) error {
	phases, err := d.s.m.pg.ListAuditPhases(session.ID, session.Round)
	if err != nil {
		return err
	}
	merged := map[string]any{}
	for _, p := range phases {
		if p.Phase != phase {
			continue
		}
		if len(p.Stats) > 0 {
			_ = json.Unmarshal(p.Stats, &merged)
		}
		break
	}
	merged["last_intent_id"] = intentID
	merged["last_intent_stats"] = stats
	merged["last_intent_at"] = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("encode phase stats: %w", err)
	}
	return d.s.m.pg.UpdateAuditPhase(session.ID, session.Round, phase, db.AuditPhaseUpdate{
		Stats: raw, SetStats: true,
	})
}

func auditIntentPhase(payload json.RawMessage) string {
	var p struct {
		Audit struct {
			Phase string `json:"phase"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return ""
	}
	return strings.TrimSpace(p.Audit.Phase)
}

func auditIntentFindingIDs(payload json.RawMessage) ([]int64, error) {
	var p struct {
		Audit struct {
			FindingIDs []int64 `json:"finding_ids"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("解析意图 audit.finding_ids 失败: %w", err)
	}
	seen := make(map[int64]struct{}, len(p.Audit.FindingIDs))
	out := make([]int64, 0, len(p.Audit.FindingIDs))
	for _, id := range p.Audit.FindingIDs {
		if id <= 0 {
			return nil, errors.New("audit.finding_ids 必须是正整数")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func auditIntentRound(payload json.RawMessage) int {
	var p struct {
		Audit struct {
			Round int `json:"round"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return 0
	}
	return p.Audit.Round
}

// AssignedCoverage returns the coverage rows currently owned by one intent in
// the session's active round. The worker uses it to discover the sink keys it is
// allowed to report in audit_intent_complete.
func (d *serverAuditDeps) AssignedCoverage(ctx context.Context, taskID, intentID int64) ([]audit.CoverageRow, error) {
	session, err := d.session(taskID)
	if err != nil {
		return nil, err
	}
	if intentID <= 0 {
		return nil, errors.New("intent_id 必须为正整数")
	}
	_, store, err := d.taskAndStore(taskID)
	if err != nil {
		return nil, err
	}
	node, err := store.GetNode(intentID)
	if err != nil {
		return nil, err
	}
	if node == nil || node.Kind != db.KindIntent {
		return nil, fmt.Errorf("意图 %d 不属于任务 %d", intentID, taskID)
	}
	rows, err := d.s.m.pg.ListAuditCoverage(session.ID, session.Round)
	if err != nil {
		return nil, err
	}
	out := make([]audit.CoverageRow, 0)
	for _, row := range rows {
		if row.IntentID == nil || *row.IntentID != intentID {
			continue
		}
		out = append(out, auditCoverageRow(row))
	}
	return out, nil
}

// AssignedFindings returns only the findings explicitly referenced by the
// intent's audit.finding_ids. S5/S8 intents have no coverage rows, so this is
// their authoritative work list. Missing/foreign findings are hard errors.
func (d *serverAuditDeps) AssignedFindings(ctx context.Context, taskID, intentID int64) ([]db.DBFinding, error) {
	if taskID <= 0 || intentID <= 0 {
		return nil, errors.New("task_id 和 intent_id 必须为正整数")
	}
	if _, err := d.session(taskID); err != nil {
		return nil, err
	}
	_, store, err := d.taskAndStore(taskID)
	if err != nil {
		return nil, err
	}
	node, err := store.GetNode(intentID)
	if err != nil {
		return nil, err
	}
	if node == nil || node.Kind != db.KindIntent {
		return nil, fmt.Errorf("意图 %d 不属于任务 %d", intentID, taskID)
	}
	ids, err := auditIntentFindingIDs(node.Payload)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []db.DBFinding{}, nil
	}
	out := make([]db.DBFinding, 0, len(ids))
	for _, findingID := range ids {
		finding, err := d.s.m.pg.GetFinding(findingID)
		if err != nil {
			return nil, fmt.Errorf("读取 finding #%d 失败: %w", findingID, err)
		}
		if finding == nil || finding.TaskID == nil || *finding.TaskID != taskID {
			return nil, fmt.Errorf("finding #%d 不存在或不属于任务 %d", findingID, taskID)
		}
		if finding.NodeID == nil {
			return nil, fmt.Errorf("finding #%d 缺少探索节点，无法派发验证", findingID)
		}
		out = append(out, *finding)
	}
	return out, nil
}

func auditCoverageRow(row db.AuditCoverage) audit.CoverageRow {
	return audit.CoverageRow{
		Kind: row.Kind, Language: row.Language, CWE: row.CWE, Module: row.Module,
		Path: row.Path, Symbol: row.Symbol, SinkKey: row.SinkKey, Status: row.Status,
		Reason: row.Reason, Line: row.Line, Engine: row.Engine,
	}
}

// ClaimAuditCoverage assigns unowned coverage rows to a newly created planner
// intent. All keys are validated against the current round before a single
// ownership UPDATE, so the claim is all-or-nothing for the normal path.
func (d *serverAuditDeps) ClaimAuditCoverage(ctx context.Context, taskID, intentID int64, sinkKeys []string) error {
	if taskID <= 0 || intentID <= 0 {
		return errors.New("task_id 和 intent_id 必须为正整数")
	}
	keys, err := normalizeAuditClaimKeys(sinkKeys)
	if err != nil {
		return err
	}
	session, err := d.session(taskID)
	if err != nil {
		return err
	}
	_, store, err := d.taskAndStore(taskID)
	if err != nil {
		return err
	}
	node, err := store.GetNode(intentID)
	if err != nil {
		return err
	}
	if node == nil || node.Kind != db.KindIntent {
		return fmt.Errorf("意图 %d 不属于任务 %d", intentID, taskID)
	}
	if phase := auditIntentPhase(node.Payload); phase == "" {
		return errors.New("审计意图缺少 audit.phase，无法认领覆盖行")
	}
	if round := auditIntentRound(node.Payload); round != session.Round {
		return fmt.Errorf("意图审计轮次 %d 与当前会话轮次 %d 不一致", round, session.Round)
	}
	rows, err := d.s.m.pg.ListAuditCoverage(session.ID, session.Round)
	if err != nil {
		return err
	}
	if err := validateAuditCoverageClaim(rows, keys); err != nil {
		return err
	}
	if err := d.updateIntentClaimMetadata(ctx, store.ID(), intentID, node.Payload, session.Round, keys); err != nil {
		return err
	}
	assigned, err := d.s.m.pg.AssignAuditCoverage(session.ID, session.Round, keys, intentID)
	if err != nil {
		return err
	}
	if assigned != int64(len(keys)) {
		// The single UPDATE is atomic, but a concurrent owner can still win the
		// unowned-row race. Roll the partial claim back so the intent cannot run
		// with a subset of its declared sinks.
		_, _ = d.s.m.pg.ExecContext(ctx, `
UPDATE audit_coverage SET intent_id=NULL, updated_at=now()
WHERE session_id=$1 AND round=$2 AND intent_id=$3`, session.ID, session.Round, intentID)
		return fmt.Errorf("认领覆盖行不完整：%d/%d", assigned, len(keys))
	}
	return nil
}

func normalizeAuditClaimKeys(keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, errors.New("audit.sink_keys 不能为空")
	}
	if len(keys) > 1000 {
		return nil, errors.New("audit.sink_keys 最多 1000 项")
	}
	out := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, raw := range keys {
		key := strings.TrimSpace(raw)
		if key == "" {
			return nil, errors.New("audit.sink_keys 不能包含空 key")
		}
		if len(key) > 512 {
			return nil, errors.New("audit.sink_keys 单项不能超过 512 字符")
		}
		if strings.IndexFunc(key, unicode.IsControl) >= 0 {
			return nil, errors.New("audit.sink_keys 不能包含控制字符")
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out, nil
}

// validateAuditCoverageClaim rejects any key that is unknown or already owned.
// It is pure so ownership failure modes are unit-testable without PG.
func validateAuditCoverageClaim(rows []db.AuditCoverage, keys []string) error {
	type state struct {
		exists bool
		owned  bool
	}
	index := make(map[string]state, len(rows))
	for i := range rows {
		current := index[rows[i].SinkKey]
		current.exists = true
		if rows[i].IntentID != nil {
			current.owned = true
		}
		index[rows[i].SinkKey] = current
	}
	for _, key := range keys {
		current, ok := index[key]
		if !ok || !current.exists {
			return fmt.Errorf("sink_key %q 不在本会话/轮次的覆盖计划中", key)
		}
		if current.owned {
			return fmt.Errorf("sink_key %q 已被其他意图认领", key)
		}
	}
	return nil
}

func (d *serverAuditDeps) updateIntentClaimMetadata(ctx context.Context, explorationID, intentID int64, payload json.RawMessage, round int, keys []string) error {
	decoded := map[string]any{}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &decoded); err != nil {
			return fmt.Errorf("解析意图 payload 失败: %w", err)
		}
	}
	auditPayload, _ := decoded["audit"].(map[string]any)
	if auditPayload == nil {
		return errors.New("审计意图缺少 audit 对象")
	}
	changed := false
	if phase, _ := auditPayload["phase"].(string); phase != strings.ToUpper(strings.TrimSpace(phase)) {
		auditPayload["phase"] = strings.ToUpper(strings.TrimSpace(phase))
		changed = true
	}
	if existing, _ := auditPayload["round"].(float64); int(existing) != round {
		auditPayload["round"] = round
		changed = true
	}
	if !auditKeysEqual(auditPayload["sink_keys"], keys) {
		auditPayload["sink_keys"] = keys
		changed = true
	}
	if !changed {
		return nil
	}
	decoded["audit"] = auditPayload
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return fmt.Errorf("序列化意图 payload 失败: %w", err)
	}
	res, err := d.s.m.pg.ExecContext(ctx, `
UPDATE exploration_nodes SET payload=$3::jsonb
WHERE id=$1 AND exploration_id=$2 AND kind='intent'`, intentID, explorationID, string(encoded))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("更新意图 audit 元数据失败：意图不存在")
	}
	return nil
}

func auditKeysEqual(raw any, keys []string) bool {
	var existing []string
	switch value := raw.(type) {
	case []string:
		existing = value
	case []any:
		existing = make([]string, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return false
			}
			existing = append(existing, text)
		}
	case nil:
		return len(keys) == 0
	default:
		return false
	}
	if len(existing) != len(keys) {
		return false
	}
	for i := range existing {
		if existing[i] != keys[i] {
			return false
		}
	}
	return true
}

func (d *serverAuditDeps) WriteAuditArtifact(ctx context.Context, taskID int64, relPath string, content []byte) (string, error) {
	if taskID <= 0 {
		return "", errors.New("task_id 必须为正整数")
	}
	if len(content) > agent.AuditArtifactMaxBytes {
		return "", fmt.Errorf("artifact 超过最大大小 %d 字节（本次 %d）", agent.AuditArtifactMaxBytes, len(content))
	}
	cleaned, err := agent.AuditArtifactRelativePath(relPath)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	taskDir := filepath.Join(d.s.m.dir, "tasks", strconv.FormatInt(taskID, 10))
	artifactsDir := filepath.Join(taskDir, "audit", "artifacts")
	if err := os.MkdirAll(artifactsDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 audit/artifacts 失败: %w", err)
	}
	// Resolve symlinks on the root once; every segment below is Lstat-checked so
	// a pre-created symlink cannot redirect the write outside the task directory.
	resolvedTaskDir, err := filepath.EvalSymlinks(taskDir)
	if err != nil {
		return "", fmt.Errorf("解析任务目录失败: %w", err)
	}
	resolvedArtifactsDir, err := filepath.EvalSymlinks(artifactsDir)
	if err != nil {
		return "", fmt.Errorf("解析 audit/artifacts 失败: %w", err)
	}
	if !auditPathWithin(resolvedArtifactsDir, resolvedTaskDir) {
		return "", errors.New("audit/artifacts 解析后逃逸任务目录")
	}

	segments := strings.Split(cleaned, "/")
	current := artifactsDir
	for i, segment := range segments {
		target := filepath.Join(current, segment)
		info, statErr := os.Lstat(target)
		last := i == len(segments)-1
		switch {
		case statErr == nil && info.Mode()&os.ModeSymlink != 0:
			return "", fmt.Errorf("artifact 路径段 %q 是符号链接，拒绝写入", segment)
		case statErr == nil && last && info.IsDir():
			return "", fmt.Errorf("artifact 路径 %q 指向目录，必须写文件", cleaned)
		case statErr == nil && !last && !info.IsDir():
			return "", fmt.Errorf("artifact 路径段 %q 不是目录", segment)
		case statErr != nil && !os.IsNotExist(statErr):
			return "", fmt.Errorf("检查 artifact 路径失败: %w", statErr)
		case statErr != nil && !last:
			if err := os.Mkdir(target, 0o755); err != nil {
				return "", fmt.Errorf("创建 artifact 目录失败: %w", err)
			}
		}
		current = target
	}
	file, err := os.OpenFile(current, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("写入 artifact 失败: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("写入 artifact 失败: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("写入 artifact 失败: %w", err)
	}
	return pathJoinSlash("audit", "artifacts", cleaned), nil
}

func pathJoinSlash(parts ...string) string {
	return strings.TrimPrefix(filepath.ToSlash(filepath.Join(parts...)), "/")
}

func auditPathWithin(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// --- progress / readiness ---

// auditCoverageCandidate is one planner-actionable batch of unowned/planned sink
// sites. The planner copies phase/cwe/language/sink_keys into add_intent.audit.
type auditCoverageCandidate struct {
	Phase      string   `json:"phase"`
	CWE        string   `json:"cwe,omitempty"`
	Language   string   `json:"language,omitempty"`
	Module     string   `json:"module,omitempty"`
	SinkKeys   []string `json:"sink_keys,omitempty"`
	FindingIDs []int64  `json:"finding_ids,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Priority   int      `json:"priority"`
}

// auditFindingCandidate is the minimal finding projection used to dispatch S5
// verification work without inventing coverage keys.
type auditFindingCandidate struct {
	ID       int64
	CWE      string
	Severity string
}

type auditProgressIntent struct {
	ID        int64  `json:"id"`
	Round     int    `json:"round"`
	IntentKey string `json:"intent_key"`
	Origin    string `json:"origin,omitempty"`
	Language  string `json:"language,omitempty"`
	CWE       string `json:"cwe,omitempty"`
	Title     string `json:"title,omitempty"`
	Status    string `json:"status,omitempty"`
	Priority  int    `json:"priority,omitempty"`
}

type auditProgressEngine struct {
	ID          int64  `json:"id"`
	IntentID    *int64 `json:"intent_id,omitempty"`
	Engine      string `json:"engine"`
	JobKind     string `json:"job_kind,omitempty"`
	QueryHash   string `json:"query_hash,omitempty"`
	Status      string `json:"status,omitempty"`
	ResultCount int    `json:"result_count"`
	DurationMS  int64  `json:"duration_ms,omitempty"`
	Error       string `json:"error,omitempty"`
}

type auditProgressEngineCapability struct {
	State         string   `json:"state"`
	Available     bool     `json:"available"`
	Version       string   `json:"version,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	Languages     []string `json:"languages,omitempty"`
	BuildModeNone bool     `json:"build_mode_none,omitempty"`
}

type auditProgressEngineStatus struct {
	Capabilities map[string]auditProgressEngineCapability `json:"capabilities"`
	JobCounts    map[string]auditReportEngineJobCounts    `json:"job_counts"`
	Warnings     []string                                 `json:"warnings,omitempty"`
	Gaps         []string                                 `json:"gaps,omitempty"`
}

// buildAuditProgressEngineStatus projects persisted engine state and job
// outcomes without exposing binary or artifact paths.
func buildAuditProgressEngineStatus(session *db.AuditSession, jobs []db.AuditEngineJob) auditProgressEngineStatus {
	status := auditProgressEngineStatus{
		Capabilities: map[string]auditProgressEngineCapability{},
		JobCounts:    map[string]auditReportEngineJobCounts{},
	}
	if session != nil {
		record := parseAuditEnginesRecord(session.Engines)
		for engine, capability := range record.Capabilities {
			status.Capabilities[engine] = auditProgressEngineCapability{
				State:         auditEngineState(capability, record.Configured[engine]),
				Available:     capability.Available,
				Version:       capability.Version,
				Reason:        capability.Reason,
				Languages:     append([]string(nil), capability.Languages...),
				BuildModeNone: capability.BuildModeNone,
			}
		}
		status.Warnings = append([]string(nil), record.Warnings...)
		status.Gaps = append([]string(nil), record.Gaps...)
	}
	total := auditReportEngineJobCounts{}
	for _, job := range jobs {
		engine := firstNonBlank(strings.TrimSpace(job.Engine), "unknown")
		counts := status.JobCounts[engine]
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
		status.JobCounts[engine] = counts
	}
	status.JobCounts["all"] = total
	return status
}

type auditProgressInput struct {
	Session       *db.AuditSession
	Plan          audit.Plan
	Phases        []db.AuditPhase
	CoverageRows  []db.AuditCoverage
	Intents       []db.AuditDetectionIntent
	IntentSummary map[string]int
	Candidates    []auditCoverageCandidate
	Findings      map[string]int
	FindingsTotal int
	Hypotheses    []db.AuditHypothesis
	Engines       []db.AuditEngineJob
	Ready         bool
	ReadyReason   string
}

// buildAuditProgress is the pure JSON projection used by AuditProgress. Keeping
// it free of DB access makes the gate/coverage shape unit-testable.
func buildAuditProgress(in auditProgressInput) (json.RawMessage, error) {
	if in.Session == nil {
		return nil, errors.New("审计会话不存在")
	}
	session := in.Session
	plan := in.Plan
	if plan.Depth == "" {
		plan.Depth = session.Depth
	}
	if len(plan.Languages) == 0 {
		plan.Languages = append([]string(nil), session.Languages...)
	}
	if plan.PlannedCWEs == nil {
		plan.PlannedCWEs = map[string][]string{}
	}

	// S11 is host-generated; while the audit is running it is necessarily still
	// pending, so Gate-Phase must treat it as satisfied or every progress gate
	// would be permanently false.
	phaseStatuses := auditCompletionPhaseStatuses(in.Phases)
	rows := auditCoverageRows(in.CoverageRows)
	coverage := audit.ComputeCoverage(plan, rows)
	gates := auditGates(plan, phaseStatuses, rows)

	intents := make([]auditProgressIntent, 0, len(in.Intents))
	for _, it := range in.Intents {
		intents = append(intents, auditProgressIntent{
			ID: it.ID, Round: it.Round, IntentKey: it.IntentKey, Origin: it.Origin,
			Language: it.Language, CWE: it.CWE, Title: it.Title, Status: it.Status,
			Priority: it.Priority,
		})
	}
	engines := make([]auditProgressEngine, 0, len(in.Engines))
	for _, job := range in.Engines {
		engines = append(engines, auditProgressEngine{
			ID: job.ID, IntentID: job.IntentID, Engine: job.Engine, JobKind: job.JobKind,
			QueryHash: job.QueryHash, Status: job.Status, ResultCount: job.ResultCount,
			DurationMS: job.DurationMS, Error: job.Error,
		})
	}
	candidates := in.Candidates
	if candidates == nil {
		candidates = []auditCoverageCandidate{}
	}
	findings := in.Findings
	if findings == nil {
		findings = map[string]int{}
	}
	hypotheses := in.Hypotheses
	if hypotheses == nil {
		hypotheses = []db.AuditHypothesis{}
	}
	intentSummary := in.IntentSummary
	if intentSummary == nil {
		intentSummary = map[string]int{}
	}

	sourceRef := sanitizeAuditSourceRef(session.SourceRef, nil)
	sourceLabel := strings.TrimSpace(sourceRef)
	if sourceLabel == "" {
		sourceLabel = sanitizeAuditText(session.SourceType, nil)
	}
	reportReady := auditReportReady(session)
	reportURL := ""
	if reportReady {
		reportURL = "/api/tasks/" + strconv.FormatInt(session.TaskID, 10) + "/audit/report"
	}
	report := map[string]any{
		"session": map[string]any{
			"id": session.ID, "task_id": session.TaskID, "status": session.Status,
			"round": session.Round, "max_rounds": session.MaxRounds,
			"depth": session.Depth, "backend": session.Backend,
			"languages": session.Languages, "source_type": session.SourceType,
			"source_ref": sourceRef, "source_label": sourceLabel,
			"commit_sha":    sanitizeAuditText(session.CommitSHA, nil),
			"repo_asset_id": session.RepoAssetID,
			"started_at":    session.StartedAt, "completed_at": session.CompletedAt,
		},
		"phases":     in.Phases,
		"coverage":   coverage,
		"gates":      gates,
		"intents":    map[string]any{"counts": intentSummary, "detection": intents},
		"candidates": candidates,
		"findings": map[string]any{
			"total":           in.FindingsTotal,
			"by_verification": findings,
		},
		"hypotheses":    hypotheses,
		"engines":       engines,
		"engine_status": buildAuditProgressEngineStatus(session, in.Engines),
		"budget": map[string]any{
			"round": session.Round, "max_rounds": session.MaxRounds,
			"depth": session.Depth, "engines": parseAuditEnginesRecord(session.Engines).Configured,
		},
		"ready_to_complete": in.Ready,
		"ready_reason":      in.ReadyReason,
		"report_ready":      reportReady,
		"report_url":        reportURL,
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("encode audit progress: %w", err)
	}
	return raw, nil
}

func auditPlanFromSession(session *db.AuditSession) audit.Plan {
	plan := audit.Plan{PlannedCWEs: map[string][]string{}}
	if session == nil {
		return plan
	}
	if len(session.Plan) > 0 {
		_ = json.Unmarshal(session.Plan, &plan)
	}
	if plan.Depth == "" {
		plan.Depth = session.Depth
	}
	if len(plan.Languages) == 0 {
		plan.Languages = append([]string(nil), session.Languages...)
	}
	if plan.PlannedCWEs == nil {
		plan.PlannedCWEs = map[string][]string{}
	}
	return plan
}

// auditReportReady reports whether a generated report is available to serve.
// The audit session becomes done/done_with_gaps only after the report has been
// persisted, so this is the completion contract shared by the API and readiness.
func auditReportReady(session *db.AuditSession) bool {
	if session == nil || !db.AuditStatusTerminal(session.Status) {
		return false
	}
	return strings.TrimSpace(session.ReportMD) != ""
}

// auditReadiness is the pure convergence predicate behind ReadyToComplete. A
// done session with a persisted report is ready; gate details live in the
// report. The extra phase/coverage parameters are retained for callers/tests
// that already hold that snapshot, but must not make a generated report
// unprovable.
func auditReadiness(session *db.AuditSession, phases []db.AuditPhase, plan audit.Plan, rows []db.AuditCoverage) (bool, string) {
	if session == nil {
		return false, "审计会话不存在"
	}
	if !db.AuditStatusTerminal(session.Status) {
		return false, fmt.Sprintf("审计会话状态为 %s，尚未收尾", session.Status)
	}
	if strings.TrimSpace(session.ReportMD) == "" {
		return false, "审计报告尚未生成"
	}
	return true, ""
}

func (d *serverAuditDeps) CurrentAuditRound(ctx context.Context, taskID int64) (int, error) {
	session, err := d.session(taskID)
	if err != nil {
		return 0, err
	}
	return session.Round, nil
}

func (d *serverAuditDeps) ReadyToComplete(ctx context.Context, taskID int64) (bool, error) {
	session, err := d.session(taskID)
	if err != nil {
		return false, err
	}
	ready, _ := auditReadiness(session, nil, audit.Plan{}, nil)
	return ready, nil
}

func (d *serverAuditDeps) AuditProgress(ctx context.Context, taskID int64) (json.RawMessage, error) {
	session, err := d.session(taskID)
	if err != nil {
		return nil, err
	}
	phases, err := d.s.m.pg.ListAuditPhases(session.ID, session.Round)
	if err != nil {
		return nil, err
	}
	rows, err := d.s.m.pg.ListAuditCoverage(session.ID, session.Round)
	if err != nil {
		return nil, err
	}
	intents, err := d.s.m.pg.ListAuditDetectionIntents(session.ID, session.Round)
	if err != nil {
		return nil, err
	}
	hypotheses, err := d.s.m.pg.ListAuditHypotheses(session.ID)
	if err != nil {
		return nil, err
	}
	engines, err := d.s.m.pg.ListAuditEngineJobs(session.ID)
	if err != nil {
		return nil, err
	}
	findings, findingsTotal, err := auditFindingCounts(ctx, d.s.m.pg, taskID)
	if err != nil {
		return nil, err
	}
	unverified, err := listAuditUnverifiedFindings(ctx, d.s.m.pg, taskID, 200)
	if err != nil {
		return nil, err
	}
	intentSummary, err := auditIntentSummary(d.s.m.pg, taskID)
	if err != nil {
		return nil, err
	}
	candidates := buildAuditFindingCandidates(unverified, 8, 5)
	candidates = append(candidates, buildAuditCoverageCandidates(rows, 8, 25)...)
	plan := auditPlanFromSession(session)
	ready, reason := auditReadiness(session, phases, plan, rows)
	return buildAuditProgress(auditProgressInput{
		Session: session, Plan: plan, Phases: phases, CoverageRows: rows,
		Intents: intents, IntentSummary: intentSummary, Candidates: candidates,
		Findings: findings, FindingsTotal: findingsTotal,
		Hypotheses: hypotheses, Engines: engines,
		Ready: ready, ReadyReason: reason,
	})
}

func countAuditUnverifiedFindings(ctx context.Context, pg *db.DB, taskID int64) (int, error) {
	var count int
	err := pg.QueryRowContext(ctx, `
SELECT count(*) FROM findings
WHERE task_id=$1
  AND lower(COALESCE(NULLIF(verification, ''), 'unverified')) IN ('candidate', 'unverified')`,
		taskID).Scan(&count)
	return count, err
}

// listAuditUnverifiedFindings returns the planner-actionable unverified finding
// projection. candidate and legacy unverified rows both need S5 verification.
func listAuditUnverifiedFindings(ctx context.Context, pg *db.DB, taskID int64, limit int) ([]auditFindingCandidate, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := pg.QueryContext(ctx, `
SELECT id, COALESCE(cwe_id, ''), COALESCE(severity, '')
FROM findings
WHERE task_id=$1
  AND lower(COALESCE(NULLIF(verification, ''), 'unverified')) IN ('candidate', 'unverified')
ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
         COALESCE(cwe_id, ''), id
LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]auditFindingCandidate, 0)
	for rows.Next() {
		var item auditFindingCandidate
		if err := rows.Scan(&item.ID, &item.CWE, &item.Severity); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// buildAuditFindingCandidates groups unverified findings into bounded S5
// verification batches. Each batch carries one CWE/severity so the planner can
// copy finding_ids verbatim without also having to invent sink keys.
func buildAuditFindingCandidates(findings []auditFindingCandidate, maxBatches, batchSize int) []auditCoverageCandidate {
	if maxBatches <= 0 {
		maxBatches = 8
	}
	if batchSize <= 0 {
		batchSize = 5
	}
	type bucket struct {
		cwe      string
		severity string
		ids      []int64
	}
	buckets := map[string]*bucket{}
	order := make([]string, 0)
	for _, finding := range findings {
		if finding.ID <= 0 {
			continue
		}
		cwe := strings.ToUpper(strings.TrimSpace(finding.CWE))
		severity := strings.ToLower(strings.TrimSpace(finding.Severity))
		key := cwe + "\x00" + severity
		b := buckets[key]
		if b == nil {
			b = &bucket{cwe: cwe, severity: severity}
			buckets[key] = b
			order = append(order, key)
		}
		b.ids = append(b.ids, finding.ID)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := buckets[order[i]], buckets[order[j]]
		ar, br := auditSeverityRank(a.severity), auditSeverityRank(b.severity)
		if ar != br {
			return ar > br
		}
		if a.cwe != b.cwe {
			return a.cwe < b.cwe
		}
		return a.severity < b.severity
	})
	out := make([]auditCoverageCandidate, 0, maxBatches)
	for _, key := range order {
		b := buckets[key]
		sort.Slice(b.ids, func(i, j int) bool { return b.ids[i] < b.ids[j] })
		for start := 0; start < len(b.ids); start += batchSize {
			end := start + batchSize
			if end > len(b.ids) {
				end = len(b.ids)
			}
			out = append(out, auditCoverageCandidate{
				Phase: audit.PhaseVerify, CWE: b.cwe, Severity: b.severity,
				FindingIDs: append([]int64(nil), b.ids[start:end]...),
				Priority:   auditFindingPriority(b.severity),
			})
			if len(out) >= maxBatches {
				return out
			}
		}
	}
	return out
}

func auditSeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func auditFindingPriority(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return 9
	case "medium":
		return 8
	default:
		return 7
	}
}

// auditPhaseStatuses converts DB phase rows and recovers persisted skip reasons
// from the gate/stats JSON. GatePhase requires a reason for skipped/exempt
// required phases.
func auditPhaseStatuses(phases []db.AuditPhase) []audit.PhaseStatus {
	out := make([]audit.PhaseStatus, 0, len(phases))
	for _, p := range phases {
		out = append(out, audit.PhaseStatus{
			Phase: p.Phase, Required: p.Required, Status: p.Status,
			Reason: auditPhaseReason(p),
		})
	}
	return out
}

func auditPhaseReason(phase db.AuditPhase) string {
	for _, raw := range []json.RawMessage{phase.Gate, phase.Stats} {
		if len(raw) == 0 {
			continue
		}
		var value struct {
			Reason      string `json:"reason"`
			SkipReason  string `json:"skip_reason"`
			SkippedNote string `json:"skipped_reason"`
		}
		if json.Unmarshal(raw, &value) != nil {
			continue
		}
		if reason := strings.TrimSpace(value.Reason); reason != "" {
			return reason
		}
		if reason := strings.TrimSpace(value.SkipReason); reason != "" {
			return reason
		}
		if reason := strings.TrimSpace(value.SkippedNote); reason != "" {
			return reason
		}
	}
	return ""
}

func auditCoverageRows(rows []db.AuditCoverage) []audit.CoverageRow {
	out := make([]audit.CoverageRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, audit.CoverageRow{
			Kind: row.Kind, Language: row.Language, CWE: row.CWE, Module: row.Module,
			Path: row.Path, Symbol: row.Symbol, SinkKey: row.SinkKey, Status: row.Status,
			Reason: row.Reason, Line: row.Line, Engine: row.Engine,
		})
	}
	return out
}

func auditGates(plan audit.Plan, phases []audit.PhaseStatus, rows []audit.CoverageRow) map[string]audit.GateResult {
	if plan.Depth == "" {
		plan.Depth = audit.DepthDeep
	}
	return map[string]audit.GateResult{
		"phase":    audit.GatePhase(phases),
		"coverage": audit.GateCoverage(plan, rows, plan.Depth),
		"cwe":      audit.GateCWE(plan, rows),
	}
}

func auditGatesPassed(gates map[string]audit.GateResult) bool {
	if len(gates) == 0 {
		return false
	}
	for _, gate := range gates {
		if !gate.Passed {
			return false
		}
	}
	return true
}

func auditFindingCounts(ctx context.Context, pg *db.DB, taskID int64) (map[string]int, int, error) {
	rows, err := pg.QueryContext(ctx,
		`SELECT COALESCE(NULLIF(verification, ''), 'unverified'), count(*)
		 FROM findings WHERE task_id=$1 GROUP BY 1`, taskID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	counts := map[string]int{}
	total := 0
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, 0, err
		}
		counts[status] = count
		total += count
	}
	return counts, total, rows.Err()
}

func auditIntentSummary(pg *db.DB, taskID int64) (map[string]int, error) {
	pt, err := pg.GetTask(taskID)
	if err != nil {
		return nil, err
	}
	if pt == nil {
		return nil, fmt.Errorf("任务 %d 不存在", taskID)
	}
	nodes, err := pg.Exploration(pt.ExplorationID).ListByKind(db.KindIntent, 10000)
	if err != nil {
		return nil, err
	}
	summary := map[string]int{}
	for _, node := range nodes {
		summary[node.State]++
	}
	return summary, nil
}

// buildAuditCoverageCandidates turns planned/unassigned sink-site coverage into
// bounded S4 batches the planner can dispatch via add_intent.audit.sink_keys.
func buildAuditCoverageCandidates(rows []db.AuditCoverage, maxBatches, batchSize int) []auditCoverageCandidate {
	if maxBatches <= 0 {
		maxBatches = 8
	}
	if batchSize <= 0 {
		batchSize = 25
	}
	type bucket struct {
		language string
		cwe      string
		module   string
		sinkKeys []string
	}
	buckets := map[string]*bucket{}
	order := make([]string, 0)
	for _, row := range rows {
		if strings.ToLower(strings.TrimSpace(row.Kind)) != audit.CoverageKindSinkSite {
			continue
		}
		if row.IntentID != nil {
			continue // already owned by an intent
		}
		status := strings.ToLower(strings.TrimSpace(row.Status))
		if status != audit.CoverageStatusPlanned && status != audit.CoverageStatusMissed {
			continue
		}
		key := row.Language + "\x00" + row.CWE + "\x00" + row.Module
		b := buckets[key]
		if b == nil {
			b = &bucket{language: row.Language, cwe: row.CWE, module: row.Module}
			buckets[key] = b
			order = append(order, key)
		}
		if key := strings.TrimSpace(row.SinkKey); key != "" {
			b.sinkKeys = append(b.sinkKeys, key)
		}
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := buckets[order[i]], buckets[order[j]]
		if a.language != b.language {
			return a.language < b.language
		}
		if a.cwe != b.cwe {
			return a.cwe < b.cwe
		}
		return a.module < b.module
	})
	out := make([]auditCoverageCandidate, 0, maxBatches)
	for _, key := range order {
		b := buckets[key]
		sort.Strings(b.sinkKeys)
		for start := 0; start < len(b.sinkKeys); start += batchSize {
			end := start + batchSize
			if end > len(b.sinkKeys) {
				end = len(b.sinkKeys)
			}
			priority := 8
			out = append(out, auditCoverageCandidate{
				Phase: audit.PhaseDetect, CWE: b.cwe, Language: b.language,
				Module: b.module, SinkKeys: append([]string(nil), b.sinkKeys[start:end]...),
				Priority: priority,
			})
			if len(out) >= maxBatches {
				return out
			}
		}
	}
	return out
}

func (d *serverAuditDeps) session(taskID int64) (*db.AuditSession, error) {
	if d == nil || d.s == nil || d.s.m == nil || d.s.m.pg == nil {
		return nil, errors.New("审计会话存储不可用")
	}
	if taskID <= 0 {
		return nil, errors.New("task_id 必须为正整数")
	}
	session, err := d.s.m.pg.GetAuditSession(taskID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("任务 %d 没有审计会话", taskID)
	}
	return session, nil
}

func (d *serverAuditDeps) taskAndStore(taskID int64) (*db.Task, *db.ExplorationStore, error) {
	pt, err := d.s.m.pg.GetTask(taskID)
	if err != nil {
		return nil, nil, err
	}
	if pt == nil {
		return nil, nil, fmt.Errorf("任务 %d 不存在", taskID)
	}
	return pt, d.s.m.pg.Exploration(pt.ExplorationID), nil
}
