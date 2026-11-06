package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/notify"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrEvidenceConflict = errors.New("流量证据已变更，请刷新后重试")
	ErrFindingNotFound  = errors.New("漏洞不存在")
	ErrEvidenceNotFound = errors.New("流量证据不存在")
)

// This lock covers the evidence filesystem as well as its SQL references. All
// processes sharing the database use it, including readers, exports and GC.
const findingEvidenceLockKey int64 = 7337741004

func (d *DB) WithEvidenceTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, findingEvidenceLockKey); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type TrafficRef struct {
	TrafficID string `json:"traffic_id"`
	Role      string `json:"role"`
	Note      string `json:"note"`
}

func NormalizeTrafficRefs(refs []TrafficRef) ([]TrafficRef, error) {
	out := make([]TrafficRef, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		ref.TrafficID = strings.TrimSpace(ref.TrafficID)
		if ref.TrafficID == "" {
			return nil, errors.New("traffic_id 不能为空")
		}
		if ref.Role == "" {
			ref.Role = "supporting"
		}
		if !ValidTrafficRole(ref.Role) {
			return nil, fmt.Errorf("无效的流量用途 %q", ref.Role)
		}
		if !seen[ref.TrafficID] {
			out = append(out, ref)
			seen[ref.TrafficID] = true
		}
	}
	return out, nil
}

func ValidTrafficRole(role string) bool {
	return role == "baseline" || role == "proof" || role == "verification" || role == "supporting"
}

type TrafficEvidenceSnapshot struct {
	ID              string    `json:"id"`
	SourceTrafficID string    `json:"source_traffic_id"`
	CapturedAt      int64     `json:"captured_at"`
	URL             string    `json:"url"`
	Method          string    `json:"method"`
	Status          int       `json:"status"`
	ContentType     string    `json:"content_type"`
	ReqHead         string    `json:"req_head,omitempty"`
	RespHead        string    `json:"resp_head,omitempty"`
	ReqHash         string    `json:"req_hash"`
	RespHash        string    `json:"resp_hash"`
	ReqLen          int64     `json:"req_len"`
	RespLen         int64     `json:"resp_len"`
	CreatedAt       time.Time `json:"created_at"`
}

type FindingTrafficBinding struct {
	ID         int64                   `json:"id,string"`
	FindingID  int64                   `json:"finding_id,string"`
	SnapshotID string                  `json:"snapshot_id"`
	Role       string                  `json:"role"`
	Note       string                  `json:"note"`
	Position   int                     `json:"position"`
	CreatedAt  time.Time               `json:"created_at"`
	Snapshot   TrafficEvidenceSnapshot `json:"snapshot"`
}

type FindingTraffic struct {
	FindingID     int64                   `json:"finding_id,string"`
	Version       int64                   `json:"version"`
	ReportVersion int64                   `json:"report_version"`
	Bindings      []FindingTrafficBinding `json:"bindings"`
}

type PreparedTrafficEvidence struct {
	Ref      TrafficRef
	Snapshot TrafficEvidenceSnapshot
}

// Normalize makes the snapshot's text columns safe for PostgreSQL. URL and the
// head blocks come straight off the wire, so a target answering with a non-UTF-8
// header (a GBK `Content-Disposition: filename=…`, a NUL byte) would otherwise
// abort the INSERT and roll back the whole finding — losing a confirmed finding
// over a malformed response header. Applied before hashing so the ID always
// matches the bytes that actually land in the table.
func (s TrafficEvidenceSnapshot) Normalize() TrafficEvidenceSnapshot {
	s.SourceTrafficID = utf8Clean(s.SourceTrafficID)
	s.URL = utf8Clean(s.URL)
	s.Method = utf8Clean(s.Method)
	s.ContentType = utf8Clean(s.ContentType)
	s.ReqHead = utf8Clean(s.ReqHead)
	s.RespHead = utf8Clean(s.RespHead)
	return s
}

func TrafficSnapshotID(snapshot TrafficEvidenceSnapshot) string {
	snapshot = snapshot.Normalize()
	snapshot.ID = ""
	snapshot.CreatedAt = time.Time{}
	raw, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// LockTaskEvidenceTx serializes writes with archive queueing (which locks the
// same task row). Once queued, its snapshot must not acquire new evidence.
func LockTaskEvidenceTx(tx *sql.Tx, taskID int64) error {
	if taskID == 0 {
		return nil
	}
	var deleted sql.NullTime
	if err := tx.QueryRow(`SELECT deleted_at FROM tasks WHERE id=$1 FOR UPDATE`, taskID).Scan(&deleted); err != nil {
		return err
	}
	if deleted.Valid {
		return ErrTaskArchiveState
	}
	var state string
	err := tx.QueryRow(`SELECT state FROM task_archives WHERE task_id=$1`, taskID).Scan(&state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && state != ArchiveFailed {
		return ErrTaskArchiveState
	}
	return nil
}

func LockFindingEvidenceTx(tx *sql.Tx, findingID int64, version *int64) error {
	var taskID sql.NullInt64
	if err := tx.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, findingID).Scan(&taskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if err := LockTaskEvidenceTx(tx, taskID.Int64); err != nil {
		return err
	}
	var current int64
	if err := tx.QueryRow(`SELECT evidence_version FROM findings WHERE id=$1 FOR UPDATE`, findingID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if version != nil && *version != current {
		return ErrEvidenceConflict
	}
	return nil
}

func InsertEvidenceSnapshotTx(tx *sql.Tx, s TrafficEvidenceSnapshot) error {
	if s.ID != TrafficSnapshotID(s) {
		return errors.New("证据快照元数据哈希不匹配")
	}
	// The ID was computed over the normalized form; store those same bytes.
	id := s.ID
	s = s.Normalize()
	s.ID = id
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	_, err := tx.Exec(`INSERT INTO traffic_evidence_snapshots
(id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO NOTHING`,
		s.ID, s.SourceTrafficID, s.CapturedAt, s.URL, s.Method, s.Status, s.ContentType, s.ReqHead, s.RespHead, s.ReqHash, s.RespHash, s.ReqLen, s.RespLen, s.CreatedAt)
	return err
}

func AddFindingTrafficTx(tx *sql.Tx, findingID int64, prepared []PreparedTrafficEvidence) error {
	var position int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(position)+1,0) FROM finding_traffic_bindings WHERE finding_id=$1`, findingID).Scan(&position); err != nil {
		return err
	}
	changed := false
	for _, item := range prepared {
		if err := InsertEvidenceSnapshotTx(tx, item.Snapshot); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE traffic_evidence_snapshots SET unreferenced_at=NULL WHERE id=$1`, item.Snapshot.ID); err != nil {
			return err
		}
		res, err := tx.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(finding_id,snapshot_id) DO NOTHING`, findingID, item.Snapshot.ID, item.Ref.Role, item.Ref.Note, position)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n > 0 {
			changed = true
			position++
		}
	}
	if changed {
		return bumpEvidenceVersionTx(tx, findingID)
	}
	return nil
}

func bumpEvidenceVersionTx(tx *sql.Tx, findingID int64) error {
	_, err := tx.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, findingID)
	return err
}

func FindingTrafficTx(tx *sql.Tx, findingID int64) (*FindingTraffic, error) {
	out := &FindingTraffic{FindingID: findingID, Bindings: []FindingTrafficBinding{}}
	if err := tx.QueryRow(`SELECT evidence_version,report_evidence_version FROM findings WHERE id=$1`, findingID).Scan(&out.Version, &out.ReportVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	rows, err := tx.Query(`SELECT b.id,b.finding_id,b.snapshot_id,b.role,b.note,b.position,b.created_at,to_jsonb(s)
FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id WHERE b.finding_id=$1 ORDER BY b.position,b.id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b FindingTrafficBinding
		var raw []byte
		if err := rows.Scan(&b.ID, &b.FindingID, &b.SnapshotID, &b.Role, &b.Note, &b.Position, &b.CreatedAt, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &b.Snapshot); err != nil {
			return nil, err
		}
		out.Bindings = append(out.Bindings, b)
	}
	return out, rows.Err()
}

func (d *DB) GetFindingTraffic(ctx context.Context, findingID int64) (out *FindingTraffic, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = FindingTrafficTx(tx, findingID); return e })
	return
}

func (d *DB) EditFindingTraffic(ctx context.Context, findingID, bindingID, version int64, role, note *string, remove bool, order []int64) error {
	if role != nil && !ValidTrafficRole(*role) {
		return errors.New("无效的流量用途")
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, &version); err != nil {
			return err
		}
		if order != nil {
			current, err := FindingTrafficTx(tx, findingID)
			if err != nil {
				return err
			}
			if len(order) != len(current.Bindings) {
				return ErrEvidenceConflict
			}
			ids := map[int64]bool{}
			for _, b := range current.Bindings {
				ids[b.ID] = true
			}
			for position, id := range order {
				if !ids[id] {
					return ErrEvidenceConflict
				}
				delete(ids, id)
				if _, err := tx.Exec(`UPDATE finding_traffic_bindings SET position=$1 WHERE finding_id=$2 AND id=$3`, position, findingID, id); err != nil {
					return err
				}
			}
		} else {
			var res sql.Result
			var err error
			if remove {
				res, err = tx.Exec(`DELETE FROM finding_traffic_bindings WHERE finding_id=$1 AND id=$2`, findingID, bindingID)
			} else {
				res, err = tx.Exec(`UPDATE finding_traffic_bindings SET role=COALESCE($3,role),note=COALESCE($4,note) WHERE finding_id=$1 AND id=$2`, findingID, bindingID, role, note)
			}
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrEvidenceNotFound
			}
		}
		return bumpEvidenceVersionTx(tx, findingID)
	})
}

type RecordFindingInput struct {
	TaskID, ExplorationID, IntentID                      int64
	VulnClass, Name, Severity, Summary, Evidence, Worker string
	AssetIDs                                             []int64

	// Code-audit fields. They are persisted on both the exploration finding
	// node payload (for the per-task graph view) and the standalone findings row.
	CWEID        string
	CodePath     string
	CodeLine     int
	CodeSymbol   string
	Confidence   float64
	Verification string // defaults to "unverified"
	DedupeKey    string
	CodeEvidence json.RawMessage
	AuditRound   int
	AuditPhase   string
}

type RecordedFinding struct {
	FindingID int64           `json:"finding_id,string"`
	NodeID    int64           `json:"finding_node_id,string"`
	Traffic   *FindingTraffic `json:"traffic"`
	// Duplicate is true when (task_id, dedupe_key) already existed. The returned
	// IDs point at the existing rows; no new node, anchors or notification are
	// created.
	Duplicate bool `json:"duplicate,omitempty"`
}

// CodeFindingInput is the direct-row shape used by AddCodeFinding. CWEID is
// stored as the finding's vulnclass and Title as its display name.
type CodeFindingInput struct {
	TaskID, NodeID                                    int64
	CWEID, Title, Severity, Summary, Evidence, Worker string
	CodePath                                          string
	CodeLine                                          int
	CodeSymbol                                        string
	Confidence                                        float64
	Verification                                      string
	DedupeKey                                         string
	CodeEvidence                                      json.RawMessage
	AuditRound                                        int
	AuditPhase                                        string
	AssetIDs                                          []int64
}

// ctx 由调用方传入本次事务所用的上下文（而非在内部取 context.Background）：
// 事务内新加的推送事件写入同样应受调用方的取消与超时约束。
func RecordFindingTx(ctx context.Context, tx *sql.Tx, in RecordFindingInput, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	if err := LockTaskEvidenceTx(tx, in.TaskID); err != nil {
		return nil, err
	}
	if in.TaskID > 0 {
		var expID int64
		if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, in.TaskID).Scan(&expID); err != nil {
			return nil, err
		}
		if expID != in.ExplorationID {
			return nil, errors.New("漏洞所属任务与探索记录不匹配")
		}
	}
	if in.IntentID > 0 {
		var ok bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent')`, in.IntentID, in.ExplorationID).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("intent_id 必须是本任务的意图（关联任务意图只读）")
		}
	}

	verification := strings.TrimSpace(in.Verification)
	if verification == "" {
		verification = "unverified"
	}
	dedupeKey := codeFindingDedupeKey(in.CWEID, in.CodePath, in.CodeLine, in.CodeSymbol, in.DedupeKey)
	codeEvidence, err := persistedCodeEvidence(in.CodeEvidence)
	if err != nil {
		return nil, err
	}

	// 去重先于建图节点：命中已有 (task_id,dedupe_key) 时只返回既有 finding，
	// 不再新节点、锚点、边或推送，避免同一证据在任务图上重复出现。
	if dedupeKey != "" && in.TaskID > 0 {
		existing, err := duplicateFindingTx(tx, in.TaskID, dedupeKey)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return existing, nil
		}
	}

	payload, err := json.Marshal(map[string]any{
		"vulnclass":     in.VulnClass,
		"name":          in.Name,
		"severity":      in.Severity,
		"summary":       in.Summary,
		"evidence":      map[string]any{"by": in.Worker, "poc": in.Evidence},
		"cwe_id":        in.CWEID,
		"code_path":     in.CodePath,
		"code_line":     in.CodeLine,
		"code_symbol":   in.CodeSymbol,
		"confidence":    in.Confidence,
		"verification":  verification,
		"dedupe_key":    dedupeKey,
		"code_evidence": codeEvidence,
		"audit_round":   in.AuditRound,
		"audit_phase":   in.AuditPhase,
	})
	if err != nil {
		return nil, fmt.Errorf("encode finding payload: %w", err)
	}

	// A unique violation aborts the whole transaction in PostgreSQL. The
	// savepoint lets us roll back the speculative node/anchor/edge work and
	// return the concurrently-created finding as a duplicate. Concurrent
	// writers normally serialize on LockTaskEvidenceTx, so this is a safety net
	// for rows inserted through another path.
	useSavepoint := dedupeKey != "" && in.TaskID > 0
	if useSavepoint {
		if _, err := tx.ExecContext(ctx, `SAVEPOINT record_finding_dedupe`); err != nil {
			return nil, err
		}
	}

	out := &RecordedFinding{}
	if err := tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
VALUES($1,'finding',$2,9,'confirmed',$3) RETURNING id`, in.ExplorationID, string(payload), in.Worker).Scan(&out.NodeID); err != nil {
		return nil, err
	}
	for _, asset := range in.AssetIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, out.NodeID, asset); err != nil {
			return nil, err
		}
	}
	if in.IntentID > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4)`, in.ExplorationID, in.IntentID, RelYields, out.NodeID); err != nil {
			return nil, err
		}
	}
	assets := in.AssetIDs
	if assets == nil {
		assets = []int64{}
	}
	raw, _ := json.Marshal(assets)
	if err := tx.QueryRowContext(ctx, `INSERT INTO findings(task_id,node_id,vulnclass,name,severity,summary,evidence,worker,asset_ids,
cwe_id,code_path,code_line,code_symbol,confidence,verification,dedupe_key,code_evidence,audit_round,audit_phase)
VALUES(NULLIF($1,0),NULLIF($2,0),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING id`,
		in.TaskID, out.NodeID, in.VulnClass, in.Name, in.Severity, in.Summary, in.Evidence, in.Worker, string(raw),
		in.CWEID, in.CodePath, in.CodeLine, in.CodeSymbol, in.Confidence, verification, dedupeKey, string(codeEvidence),
		in.AuditRound, in.AuditPhase).Scan(&out.FindingID); err != nil {
		if useSavepoint && isUniqueViolation(err) {
			if _, rbErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT record_finding_dedupe`); rbErr != nil {
				return nil, rbErr
			}
			if _, relErr := tx.ExecContext(ctx, `RELEASE SAVEPOINT record_finding_dedupe`); relErr != nil {
				return nil, relErr
			}
			existing, selErr := duplicateFindingTx(tx, in.TaskID, dedupeKey)
			if selErr != nil {
				return nil, selErr
			}
			if existing != nil {
				return existing, nil
			}
		}
		return nil, err
	}
	if useSavepoint {
		if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT record_finding_dedupe`); err != nil {
			return nil, err
		}
	}
	// 在**同一事务**里登记一条推送事件：提交即保证「漏洞落库」与「推送任务存在」
	// 原子一致，不存在提交成功却没入队、消息永久丢失的窗口。
	// 这里的失败被隔离在保存点上、不影响漏洞写入（见函数注释），因此忽略返回值。
	RecordNotificationEventTx(ctx, tx, notify.EventFindingCreated, out.FindingID, notify.Snapshot{
		Kind:      notify.EventFindingCreated,
		FindingID: out.FindingID,
		TaskID:    in.TaskID,
		VulnClass: in.VulnClass,
		Name:      in.Name,
		Severity:  in.Severity,
		Summary:   in.Summary,
		AssetIDs:  assets,
	})
	if err := AddFindingTrafficTx(tx, out.FindingID, prepared); err != nil {
		return nil, err
	}
	out.Traffic, err = FindingTrafficTx(tx, out.FindingID)
	return out, err
}

// duplicateFindingTx returns the existing finding for (task_id,dedupe_key), or
// nil when none exists. It locks the row so concurrent duplicate submissions
// observe a stable id/node pair.
func duplicateFindingTx(tx *sql.Tx, taskID int64, dedupeKey string) (*RecordedFinding, error) {
	var id int64
	var nodeID sql.NullInt64
	err := tx.QueryRow(`SELECT id,node_id FROM findings WHERE task_id=$1 AND dedupe_key=$2 FOR UPDATE`, taskID, dedupeKey).Scan(&id, &nodeID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &RecordedFinding{FindingID: id, Duplicate: true}
	if nodeID.Valid {
		out.NodeID = nodeID.Int64
	}
	traffic, err := FindingTrafficTx(tx, id)
	if err != nil {
		if errors.Is(err, ErrFindingNotFound) {
			return out, nil
		}
		return nil, err
	}
	out.Traffic = traffic
	return out, nil
}

// codeFindingDedupeKey returns the server-owned identity for a finding. When any
// code identity field is present the key is always recomputed from the canonical
// CWE/path/line/symbol tuple, so a caller-supplied key (mismatched or empty)
// can never bypass or fragment dedupe. Findings without code identity keep the
// supplied key so legacy pentest recording is unchanged.
func codeFindingDedupeKey(cwe, codePath string, codeLine int, codeSymbol, supplied string) string {
	if strings.TrimSpace(cwe) == "" && strings.TrimSpace(codePath) == "" &&
		codeLine <= 0 && strings.TrimSpace(codeSymbol) == "" {
		return strings.TrimSpace(supplied)
	}
	return audit.DedupeKey(cwe, codePath, codeLine, codeSymbol)
}

func persistedCodeEvidence(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if len(trimmed) > audit.MaxCodeEvidenceBytes {
		return nil, fmt.Errorf("%w: code_evidence %d bytes > %d",
			audit.ErrCodeEvidenceTooLarge, len(trimmed), audit.MaxCodeEvidenceBytes)
	}
	if !json.Valid(trimmed) {
		return nil, errors.New("code_evidence 不是合法 JSON")
	}
	return json.RawMessage(jsonbClean(trimmed)), nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// AddCodeFinding inserts a standalone code-audit finding row directly. Unlike
// RecordFindingTx it does not create an exploration node or a notification; it
// is meant for callers that already own a node (or none). It honors
// (task_id,dedupe_key) and reports duplicate=true with the existing id when the
// key is already present.
func (d *DB) AddCodeFinding(in CodeFindingInput) (id int64, duplicate bool, err error) {
	verification := strings.TrimSpace(in.Verification)
	if verification == "" {
		verification = "unverified"
	}
	dedupeKey := codeFindingDedupeKey(in.CWEID, in.CodePath, in.CodeLine, in.CodeSymbol, in.DedupeKey)
	codeEvidence, err := persistedCodeEvidence(in.CodeEvidence)
	if err != nil {
		return 0, false, err
	}
	aidsJSON, _ := json.Marshal(in.AssetIDs)
	if in.AssetIDs == nil {
		aidsJSON = []byte("[]")
	}

	err = d.WithEvidenceTx(context.Background(), func(tx *sql.Tx) error {
		if err := LockTaskEvidenceTx(tx, in.TaskID); err != nil {
			return err
		}
		insert := func(onConflict string) error {
			q := `INSERT INTO findings(task_id,node_id,vulnclass,name,severity,summary,evidence,worker,asset_ids,
cwe_id,code_path,code_line,code_symbol,confidence,verification,dedupe_key,code_evidence,audit_round,audit_phase)
VALUES(NULLIF($1,0),NULLIF($2,0),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)` + onConflict + ` RETURNING id`
			return tx.QueryRow(q, in.TaskID, in.NodeID, in.CWEID, in.Title, in.Severity, in.Summary, in.Evidence, in.Worker, string(aidsJSON),
				in.CWEID, in.CodePath, in.CodeLine, in.CodeSymbol, in.Confidence, verification, dedupeKey, string(codeEvidence),
				in.AuditRound, in.AuditPhase).Scan(&id)
		}
		if dedupeKey != "" && in.TaskID > 0 {
			insertErr := insert(` ON CONFLICT (task_id, dedupe_key) WHERE dedupe_key <> '' DO NOTHING`)
			if insertErr == nil {
				return nil
			}
			if !errors.Is(insertErr, sql.ErrNoRows) {
				return insertErr
			}
			duplicate = true
			return tx.QueryRow(`SELECT id FROM findings WHERE task_id=$1 AND dedupe_key=$2`, in.TaskID, dedupeKey).Scan(&id)
		}
		return insert("")
	})
	if err != nil {
		return 0, false, err
	}
	return id, duplicate, nil
}

// RecordFinding is the atomic legacy/no-recorder path used by tools and tests.
func (s *ExplorationStore) RecordFinding(ctx context.Context, in RecordFindingInput) (out *RecordedFinding, err error) {
	in.ExplorationID = s.expID
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = RecordFindingTx(ctx, tx, in, nil); return e })
	return
}

func (d *DB) FindingIDByNodeID(nodeID int64) (id int64, err error) {
	err = d.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&id)
	return
}

// PopulateFindingTrafficIDs only enriches already-visible nodes. It performs no
// discovery or ID guessing, and leaves the legacy node ID unchanged.
func (s *ExplorationStore) PopulateFindingTrafficIDs(nodes []*Node) error {
	byID := map[int64]*Node{}
	var args []any
	var placeholders []string
	for _, n := range nodes {
		if n == nil || n.Kind != KindFinding || byID[n.ID] != nil {
			continue
		}
		byID[n.ID] = n
		args = append(args, n.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	if len(args) == 0 {
		return nil
	}
	rows, err := s.db.Query(`SELECT f.id,f.node_id,(SELECT count(*) FROM finding_traffic_bindings b WHERE b.finding_id=f.id) FROM findings f WHERE f.node_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var findingID, nodeID int64
		var count int
		if err := rows.Scan(&findingID, &nodeID, &count); err != nil {
			return err
		}
		n := byID[nodeID]
		n.FindingID, n.FindingNodeID, n.TrafficCount = findingID, nodeID, count
	}
	return rows.Err()
}

func (d *DB) SetFindingReportVersionByNodeID(ctx context.Context, nodeID int64, report string, version *int64) (n int64, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var id int64
		if err := tx.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if err := LockFindingEvidenceTx(tx, id, version); err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE findings SET report=$2,report_evidence_version=COALESCE($3::bigint,CASE WHEN evidence_version=0 THEN 0 ELSE -1 END) WHERE id=$1`, id, report, version)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return
}

// UpdateFindingVerification applies an independent verification verdict to one
// code-audit finding owned by taskID. It updates the standalone findings row
// (verification + code_evidence.verification/confidence) and, when the finding
// has an exploration node, the matching node payload fields so the graph view
// agrees with the findings view. Ownership is enforced in the same transaction;
// a missing finding or a node that does not belong to the task is an error.
func (d *DB) UpdateFindingVerification(ctx context.Context, taskID, findingID int64, verification, method, evidence, altPath string, confidence *float64) error {
	if taskID <= 0 || findingID <= 0 {
		return fmt.Errorf("task_id 和 finding_id 必须为正整数")
	}
	if !audit.ValidVerificationStatus(verification) {
		return fmt.Errorf("未知的 verification 状态 %q", verification)
	}
	if !audit.ValidVerificationMethod(method) {
		return fmt.Errorf("未知的 verification method %q", method)
	}
	if strings.TrimSpace(evidence) == "" {
		return errors.New("verification evidence 不能为空")
	}
	if confidence != nil && (*confidence < 0 || *confidence > 1) {
		return fmt.Errorf("confidence %v 必须在 [0,1] 内", *confidence)
	}

	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var nodeID sql.NullInt64
		var raw []byte
		err := tx.QueryRowContext(ctx,
			`SELECT node_id, code_evidence FROM findings WHERE id=$1 AND task_id=$2 FOR UPDATE`,
			findingID, taskID).Scan(&nodeID, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		if err != nil {
			return err
		}

		codeEvidence := map[string]any{}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &codeEvidence); err != nil {
				return fmt.Errorf("decode finding code_evidence: %w", err)
			}
			if codeEvidence == nil {
				codeEvidence = map[string]any{}
			}
		}
		verdict, _ := codeEvidence["verification"].(map[string]any)
		if verdict == nil {
			verdict = map[string]any{}
		}
		verdict["status"] = verification
		verdict["method"] = method
		verdict["reason"] = strings.TrimSpace(evidence)
		if alt := strings.TrimSpace(altPath); alt != "" {
			verdict["alternative_path"] = alt
		} else {
			delete(verdict, "alternative_path")
		}
		codeEvidence["verification"] = verdict
		if confidence != nil {
			codeEvidence["confidence"] = *confidence
		}
		encoded, err := json.Marshal(codeEvidence)
		if err != nil {
			return fmt.Errorf("encode finding code_evidence: %w", err)
		}
		if confidence != nil {
			_, err = tx.ExecContext(ctx,
				`UPDATE findings SET verification=$3, code_evidence=$4::jsonb, confidence=$5 WHERE id=$1 AND task_id=$2`,
				findingID, taskID, verification, string(jsonbClean(encoded)), *confidence)
		} else {
			_, err = tx.ExecContext(ctx,
				`UPDATE findings SET verification=$3, code_evidence=$4::jsonb WHERE id=$1 AND task_id=$2`,
				findingID, taskID, verification, string(jsonbClean(encoded)))
		}
		if err != nil {
			return err
		}

		if !nodeID.Valid {
			return nil
		}
		var payloadRaw []byte
		err = tx.QueryRowContext(ctx, `
SELECT payload FROM exploration_nodes
WHERE id=$1
  AND exploration_id=(SELECT exploration_id FROM tasks WHERE id=$2)
FOR UPDATE`, nodeID.Int64, taskID).Scan(&payloadRaw)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: finding node %d 不属于任务 %d", ErrFindingNotFound, nodeID.Int64, taskID)
		}
		if err != nil {
			return err
		}
		payload := map[string]any{}
		if len(bytes.TrimSpace(payloadRaw)) > 0 {
			if err := json.Unmarshal(payloadRaw, &payload); err != nil {
				return fmt.Errorf("decode finding node payload: %w", err)
			}
			if payload == nil {
				payload = map[string]any{}
			}
		}
		payload["verification"] = verification
		payload["code_evidence"] = codeEvidence
		if confidence != nil {
			payload["confidence"] = *confidence
		}
		nodeJSON, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode finding node payload: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE exploration_nodes SET payload=$2::jsonb WHERE id=$1`,
			nodeID.Int64, string(jsonbClean(nodeJSON)))
		return err
	})
}

// AttachFindingPOC binds a non-executing PoC artifact to a code-audit finding.
// The method updates both the findings row and its exploration-node payload so
// the graph view and report view stay in sync. Executed is always false: the
// audit worker may write a PoC, but must never run target code.
func (d *DB) AttachFindingPOC(ctx context.Context, taskID, findingID int64, artifactPath, description string) error {
	if taskID <= 0 || findingID <= 0 {
		return fmt.Errorf("task_id 和 finding_id 必须为正整数")
	}
	artifactPath = strings.TrimSpace(artifactPath)
	if artifactPath == "" {
		return errors.New("poc artifact_path 不能为空")
	}
	if normalized := audit.NormalizeCodePath(artifactPath); normalized == "" || normalized != artifactPath {
		return fmt.Errorf("poc artifact_path %q 必须是规范化的相对路径", artifactPath)
	}
	description = strings.TrimSpace(description)
	if description == "" {
		return errors.New("poc description 不能为空")
	}
	poc := audit.POCEvidence{
		Kind: "script", ArtifactPath: artifactPath,
		Description: description, Executed: false,
	}

	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var nodeID sql.NullInt64
		var raw []byte
		err := tx.QueryRowContext(ctx,
			`SELECT node_id, code_evidence FROM findings WHERE id=$1 AND task_id=$2 FOR UPDATE`,
			findingID, taskID).Scan(&nodeID, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		if err != nil {
			return err
		}

		codeEvidence := map[string]any{}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &codeEvidence); err != nil {
				return fmt.Errorf("decode finding code_evidence: %w", err)
			}
			if codeEvidence == nil {
				codeEvidence = map[string]any{}
			}
		}
		codeEvidence["poc"] = poc
		encoded, err := json.Marshal(codeEvidence)
		if err != nil {
			return fmt.Errorf("encode finding code_evidence: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE findings SET code_evidence=$3::jsonb WHERE id=$1 AND task_id=$2`,
			findingID, taskID, string(jsonbClean(encoded))); err != nil {
			return err
		}

		if !nodeID.Valid {
			return nil
		}
		var payloadRaw []byte
		err = tx.QueryRowContext(ctx, `
SELECT payload FROM exploration_nodes
WHERE id=$1
  AND exploration_id=(SELECT exploration_id FROM tasks WHERE id=$2)
FOR UPDATE`, nodeID.Int64, taskID).Scan(&payloadRaw)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: finding node %d 不属于任务 %d", ErrFindingNotFound, nodeID.Int64, taskID)
		}
		if err != nil {
			return err
		}
		payload := map[string]any{}
		if len(bytes.TrimSpace(payloadRaw)) > 0 {
			if err := json.Unmarshal(payloadRaw, &payload); err != nil {
				return fmt.Errorf("decode finding node payload: %w", err)
			}
			if payload == nil {
				payload = map[string]any{}
			}
		}
		payload["code_evidence"] = codeEvidence
		nodeJSON, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode finding node payload: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE exploration_nodes SET payload=$2::jsonb WHERE id=$1`,
			nodeID.Int64, string(jsonbClean(nodeJSON)))
		return err
	})
}
