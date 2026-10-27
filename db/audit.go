package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Code-audit persistence. JSONB columns are written as strings and scanned into
// []byte before being copied into json.RawMessage, so no row buffer is retained.
// languages is a TEXT[]; it is read via array_to_json(languages)::text and
// written via the array literal helper for pgx stdlib compatibility.

// Audit session lifecycle statuses.
const (
	AuditStatusIngest       = "ingest"
	AuditStatusRunning      = "running"
	AuditStatusRoundReview  = "round_review"
	AuditStatusCompleted    = "completed"
	AuditStatusDone         = "done"
	AuditStatusDoneWithGaps = "done_with_gaps"
	AuditStatusFailed       = "failed"
)

// AuditStatusTerminal reports whether status means the audit loop has finished
// (with or without coverage gaps).
func AuditStatusTerminal(status string) bool {
	return status == AuditStatusDone || status == AuditStatusDoneWithGaps
}

// AuditSession is the one-per-task code-audit session row.
type AuditSession struct {
	ID           int64           `json:"id"`
	TaskID       int64           `json:"task_id"`
	Status       string          `json:"status"`
	SourceType   string          `json:"source_type"`
	SourceRef    string          `json:"source_ref"`
	SnapshotPath string          `json:"snapshot_path"`
	CommitSHA    string          `json:"commit_sha"`
	RepoAssetID  *int64          `json:"repo_asset_id,omitempty"`
	Depth        string          `json:"depth"`
	Backend      string          `json:"backend"`
	Languages    []string        `json:"languages"`
	Engines      json.RawMessage `json:"engines"`
	Plan         json.RawMessage `json:"plan"`
	Round        int             `json:"round"`
	MaxRounds    int             `json:"max_rounds"`
	GateResults  json.RawMessage `json:"gate_results"`
	Stats        json.RawMessage `json:"stats"`
	ReportMD     string          `json:"report_md"`
	ReportJSON   json.RawMessage `json:"report_json"`
	StartedAt    *time.Time      `json:"started_at,omitempty"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// AuditPhase records one phase gate for one audit round.
type AuditPhase struct {
	ID          int64           `json:"id"`
	SessionID   int64           `json:"session_id"`
	Round       int             `json:"round"`
	Phase       string          `json:"phase"`
	Required    bool            `json:"required"`
	Status      string          `json:"status"`
	Gate        json.RawMessage `json:"gate"`
	Stats       json.RawMessage `json:"stats"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
}

// AuditPhaseUpdate is a partial phase update. Only fields whose Set* flag is
// true are written; SetStartedAt/SetCompletedAt with a nil time clear the
// column. audit_phases has no updated_at column.
type AuditPhaseUpdate struct {
	Required    bool
	SetRequired bool

	Status    string
	SetStatus bool

	Gate     json.RawMessage
	SetGate  bool
	Stats    json.RawMessage
	SetStats bool

	StartedAt      *time.Time
	CompletedAt    *time.Time
	SetStartedAt   bool
	SetCompletedAt bool
}

// AuditCoverage is one planned/handled unit of audit coverage.
type AuditCoverage struct {
	ID        int64  `json:"id"`
	SessionID int64  `json:"session_id"`
	Round     int    `json:"round"`
	Kind      string `json:"kind"`
	Language  string `json:"language"`
	CWE       string `json:"cwe"`
	Module    string `json:"module"`
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Symbol    string `json:"symbol"`
	SinkKey   string `json:"sink_key"`
	Status    string `json:"status"`
	// IntentID is an audit_detection_intents.id. The additive schema leaves it
	// unconstrained intentionally (coverage may outlive/repoint its intent).
	IntentID  *int64          `json:"intent_id,omitempty"`
	Engine    string          `json:"engine"`
	Evidence  json.RawMessage `json:"evidence"`
	Reason    string          `json:"reason"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// AuditDetectionIntent is a persisted detection task for an audit round.
type AuditDetectionIntent struct {
	ID               int64           `json:"id"`
	SessionID        int64           `json:"session_id"`
	Round            int             `json:"round"`
	IntentKey        string          `json:"intent_key"`
	Origin           string          `json:"origin"`
	Language         string          `json:"language"`
	CWE              string          `json:"cwe"`
	Title            string          `json:"title"`
	QueryKind        string          `json:"query_kind"`
	Sources          json.RawMessage `json:"sources"`
	Sinks            json.RawMessage `json:"sinks"`
	Sanitizers       json.RawMessage `json:"sanitizers"`
	Propagators      json.RawMessage `json:"propagators"`
	Scope            json.RawMessage `json:"scope"`
	Constraints      json.RawMessage `json:"constraints"`
	PreferredEngines json.RawMessage `json:"preferred_engines"`
	Priority         int             `json:"priority"`
	Status           string          `json:"status"`
	Error            string          `json:"error"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// AuditHypothesis is a durable hypothesis tracked across audit rounds.
type AuditHypothesis struct {
	ID            int64           `json:"id"`
	SessionID     int64           `json:"session_id"`
	Round         int             `json:"round"`
	HypothesisKey string          `json:"hypothesis_key"`
	Statement     string          `json:"statement"`
	Status        string          `json:"status"`
	Attempts      json.RawMessage `json:"attempts"`
	Evidence      string          `json:"evidence"`
	Priority      int             `json:"priority"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// AuditRound is the per-round summary and gate decision.
type AuditRound struct {
	ID            int64           `json:"id"`
	SessionID     int64           `json:"session_id"`
	Round         int             `json:"round"`
	NewFindings   int             `json:"new_findings"`
	NewConfirmed  int             `json:"new_confirmed"`
	NewCandidate  int             `json:"new_candidate"`
	TotalFindings int             `json:"total_findings"`
	GateC         string          `json:"gate_c"`
	GateCWE       string          `json:"gate_cwe"`
	GateH         string          `json:"gate_h"`
	GateE         string          `json:"gate_e"`
	GateCoverage  string          `json:"gate_coverage"`
	GateEngine    string          `json:"gate_engine"`
	Decision      string          `json:"decision"`
	Focus         json.RawMessage `json:"focus"`
	TokenUsage    json.RawMessage `json:"token_usage"`
	CreatedAt     time.Time       `json:"created_at"`
}

// AuditEngineJob is one query prepared/validated/run by an analysis engine.
type AuditEngineJob struct {
	ID        int64 `json:"id"`
	SessionID int64 `json:"session_id"`
	// IntentID references audit_detection_intents(id), not audit_coverage.id.
	IntentID     *int64          `json:"intent_id,omitempty"`
	Engine       string          `json:"engine"`
	JobKind      string          `json:"job_kind"`
	QueryHash    string          `json:"query_hash"`
	Status       string          `json:"status"`
	QueryText    string          `json:"query_text"`
	QueryPath    string          `json:"query_path"`
	ArtifactPath string          `json:"artifact_path"`
	ResultCount  int             `json:"result_count"`
	DurationMS   int64           `json:"duration_ms"`
	Error        string          `json:"error"`
	SARIF        json.RawMessage `json:"sarif"`
	Provenance   json.RawMessage `json:"provenance"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// AuditSessionUpdate is a partial session update. Pointer fields apply when
// non-nil; slice/JSON/time fields use their explicit Set* flag, which also
// allows clearing a nullable timestamp by passing a nil value.
type AuditSessionUpdate struct {
	Status       *string
	SourceType   *string
	SourceRef    *string
	SnapshotPath *string
	CommitSHA    *string

	RepoAssetID  *int64
	SetRepoAsset bool

	Depth   *string
	Backend *string

	Languages    []string
	SetLanguages bool

	Engines                                                      json.RawMessage
	Plan                                                         json.RawMessage
	GateResults                                                  json.RawMessage
	Stats                                                        json.RawMessage
	ReportJSON                                                   json.RawMessage
	SetEngines, SetPlan, SetGateResults, SetStats, SetReportJSON bool

	Round     *int
	MaxRounds *int
	ReportMD  *string

	StartedAt      *time.Time
	CompletedAt    *time.Time
	SetStartedAt   bool
	SetCompletedAt bool
}

const auditSessionCols = `id, task_id, status, source_type, source_ref, snapshot_path, commit_sha,
repo_asset_id, depth, backend, array_to_json(languages)::text,
engines, plan, round, max_rounds, gate_results, stats, report_md, report_json,
started_at, completed_at, updated_at`

// auditJSONValue returns raw as a JSONB argument, falling back to the column
// default when the caller supplied no value.
func auditJSONValue(raw json.RawMessage, fallback string) string {
	if len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func decodeAuditLanguages(raw string) ([]string, error) {
	if raw == "" {
		return []string{}, nil
	}
	var langs []string
	if err := json.Unmarshal([]byte(raw), &langs); err != nil {
		return nil, fmt.Errorf("decode audit languages: %w", err)
	}
	if langs == nil {
		langs = []string{}
	}
	return langs, nil
}

func scanAuditSession(sc interface{ Scan(...any) error }) (*AuditSession, error) {
	var s AuditSession
	var languagesJSON string
	var engines, plan, gateResults, stats, reportJSON []byte
	if err := sc.Scan(
		&s.ID, &s.TaskID, &s.Status, &s.SourceType, &s.SourceRef, &s.SnapshotPath,
		&s.CommitSHA, &s.RepoAssetID, &s.Depth, &s.Backend, &languagesJSON,
		&engines, &plan, &s.Round, &s.MaxRounds, &gateResults, &stats,
		&s.ReportMD, &reportJSON, &s.StartedAt, &s.CompletedAt, &s.UpdatedAt,
	); err != nil {
		return nil, err
	}
	langs, err := decodeAuditLanguages(languagesJSON)
	if err != nil {
		return nil, err
	}
	s.Languages = langs
	s.Engines = cloneRawJSON(engines)
	s.Plan = cloneRawJSON(plan)
	s.GateResults = cloneRawJSON(gateResults)
	s.Stats = cloneRawJSON(stats)
	s.ReportJSON = cloneRawJSON(reportJSON)
	return &s, nil
}

// CreateAuditSession inserts the session row and returns the stored row.
func (d *DB) CreateAuditSession(s AuditSession) (*AuditSession, error) {
	if s.Status == "" {
		s.Status = "ingest"
	}
	if s.Depth == "" {
		s.Depth = "deep"
	}
	if s.Backend == "" {
		s.Backend = "codegraph"
	}
	if s.Round == 0 {
		s.Round = 1
	}
	if s.MaxRounds == 0 {
		s.MaxRounds = 5
	}
	row := d.QueryRow(`
INSERT INTO audit_sessions(
    task_id, status, source_type, source_ref, snapshot_path, commit_sha, repo_asset_id,
    depth, backend, languages, engines, plan, round, max_rounds, gate_results, stats,
    report_md, report_json, started_at, completed_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text[],$11::jsonb,$12::jsonb,$13,$14,
    $15::jsonb,$16::jsonb,$17,$18::jsonb,$19,$20)
ON CONFLICT (task_id) DO NOTHING
RETURNING `+auditSessionCols,
		s.TaskID, s.Status, s.SourceType, s.SourceRef, s.SnapshotPath, s.CommitSHA,
		s.RepoAssetID, s.Depth, s.Backend, marshalStringArray(s.Languages),
		auditJSONValue(s.Engines, "{}"), auditJSONValue(s.Plan, "{}"),
		s.Round, s.MaxRounds, auditJSONValue(s.GateResults, "{}"),
		auditJSONValue(s.Stats, "{}"), s.ReportMD, auditJSONValue(s.ReportJSON, "{}"),
		s.StartedAt, s.CompletedAt)
	stored, err := scanAuditSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return d.GetAuditSession(s.TaskID)
	}
	if err != nil {
		return nil, err
	}
	return stored, nil
}

// GetAuditSession returns the session for a task, or (nil, nil) when absent.
func (d *DB) GetAuditSession(taskID int64) (*AuditSession, error) {
	s, err := scanAuditSession(d.QueryRow(`SELECT `+auditSessionCols+` FROM audit_sessions WHERE task_id=$1`, taskID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// UpdateAuditSession applies only the fields explicitly set on upd, always
// bumps updated_at, and returns the updated row. (nil, nil) means no session
// exists for taskID.
func (d *DB) UpdateAuditSession(taskID int64, upd AuditSessionUpdate) (*AuditSession, error) {
	sets := []string{"updated_at=now()"}
	args := make([]any, 0, 12)
	add := func(expr string, value any) {
		args = append(args, value)
		sets = append(sets, fmt.Sprintf(expr, len(args)))
	}

	if upd.Status != nil {
		add("status=$%d", *upd.Status)
	}
	if upd.SourceType != nil {
		add("source_type=$%d", *upd.SourceType)
	}
	if upd.SourceRef != nil {
		add("source_ref=$%d", *upd.SourceRef)
	}
	if upd.SnapshotPath != nil {
		add("snapshot_path=$%d", *upd.SnapshotPath)
	}
	if upd.CommitSHA != nil {
		add("commit_sha=$%d", *upd.CommitSHA)
	}
	if upd.SetRepoAsset {
		if upd.RepoAssetID != nil {
			add("repo_asset_id=$%d", *upd.RepoAssetID)
		} else {
			sets = append(sets, "repo_asset_id=NULL")
		}
	}
	if upd.Depth != nil {
		add("depth=$%d", *upd.Depth)
	}
	if upd.Backend != nil {
		add("backend=$%d", *upd.Backend)
	}
	if upd.SetLanguages {
		add("languages=$%d::text[]", marshalStringArray(upd.Languages))
	}
	if upd.SetEngines {
		add("engines=$%d::jsonb", auditJSONValue(upd.Engines, "{}"))
	}
	if upd.SetPlan {
		add("plan=$%d::jsonb", auditJSONValue(upd.Plan, "{}"))
	}
	if upd.SetGateResults {
		add("gate_results=$%d::jsonb", auditJSONValue(upd.GateResults, "{}"))
	}
	if upd.SetStats {
		add("stats=$%d::jsonb", auditJSONValue(upd.Stats, "{}"))
	}
	if upd.SetReportJSON {
		add("report_json=$%d::jsonb", auditJSONValue(upd.ReportJSON, "{}"))
	}
	if upd.Round != nil {
		add("round=$%d", *upd.Round)
	}
	if upd.MaxRounds != nil {
		add("max_rounds=$%d", *upd.MaxRounds)
	}
	if upd.ReportMD != nil {
		add("report_md=$%d", *upd.ReportMD)
	}
	if upd.SetStartedAt {
		if upd.StartedAt != nil {
			add("started_at=$%d", *upd.StartedAt)
		} else {
			sets = append(sets, "started_at=NULL")
		}
	}
	if upd.SetCompletedAt {
		if upd.CompletedAt != nil {
			add("completed_at=$%d", *upd.CompletedAt)
		} else {
			sets = append(sets, "completed_at=NULL")
		}
	}

	args = append(args, taskID)
	q := fmt.Sprintf(`UPDATE audit_sessions SET %s WHERE task_id=$%d RETURNING %s`,
		strings.Join(sets, ", "), len(args), auditSessionCols)
	s, err := scanAuditSession(d.QueryRow(q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func scanAuditPhase(sc interface{ Scan(...any) error }) (*AuditPhase, error) {
	var p AuditPhase
	var gate, stats []byte
	if err := sc.Scan(&p.ID, &p.SessionID, &p.Round, &p.Phase, &p.Required, &p.Status,
		&gate, &stats, &p.StartedAt, &p.CompletedAt); err != nil {
		return nil, err
	}
	p.Gate = cloneRawJSON(gate)
	p.Stats = cloneRawJSON(stats)
	return &p, nil
}

// InsertAuditPhases inserts phases for a round. Existing (session, round,
// phase) rows are left untouched.
func (d *DB) InsertAuditPhases(sessionID int64, round int, phases []AuditPhase) error {
	if len(phases) == 0 {
		return nil
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, p := range phases {
		status := p.Status
		if status == "" {
			status = "pending"
		}
		// A bool zero value cannot distinguish "unset" from an explicit false,
		// and passing it would bypass the schema's DEFAULT true. Phases are
		// required by default; UpdateAuditPhase can explicitly make one optional.
		required := p.Required
		if !required {
			required = true
		}
		if _, err := tx.Exec(`
INSERT INTO audit_phases(session_id, round, phase, required, status, gate, stats, started_at, completed_at)
VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9)
ON CONFLICT (session_id, round, phase) DO NOTHING`,
			sessionID, round, p.Phase, required, status,
			auditJSONValue(p.Gate, "{}"), auditJSONValue(p.Stats, "{}"),
			p.StartedAt, p.CompletedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListAuditPhases returns a round's phases ordered by phase name.
func (d *DB) ListAuditPhases(sessionID int64, round int) ([]AuditPhase, error) {
	rows, err := d.Query(`
SELECT id, session_id, round, phase, required, status, gate, stats, started_at, completed_at
FROM audit_phases WHERE session_id=$1 AND round=$2 ORDER BY phase`, sessionID, round)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditPhase, 0)
	for rows.Next() {
		p, err := scanAuditPhase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateAuditPhase applies only explicitly set fields to one phase. It is a
// no-op when no field is selected. The table has no updated_at column.
func (d *DB) UpdateAuditPhase(sessionID int64, round int, phase string, upd AuditPhaseUpdate) error {
	sets := make([]string, 0, 6)
	args := make([]any, 0, 9)
	add := func(expr string, value any) {
		args = append(args, value)
		sets = append(sets, fmt.Sprintf(expr, len(args)))
	}
	if upd.SetRequired {
		add("required=$%d", upd.Required)
	}
	if upd.SetStatus {
		add("status=$%d", upd.Status)
	}
	if upd.SetGate {
		add("gate=$%d::jsonb", auditJSONValue(upd.Gate, "{}"))
	}
	if upd.SetStats {
		add("stats=$%d::jsonb", auditJSONValue(upd.Stats, "{}"))
	}
	if upd.SetStartedAt {
		if upd.StartedAt != nil {
			add("started_at=$%d", *upd.StartedAt)
		} else {
			sets = append(sets, "started_at=NULL")
		}
	}
	if upd.SetCompletedAt {
		if upd.CompletedAt != nil {
			add("completed_at=$%d", *upd.CompletedAt)
		} else {
			sets = append(sets, "completed_at=NULL")
		}
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, sessionID, round, phase)
	q := fmt.Sprintf(`UPDATE audit_phases SET %s
WHERE session_id=$%d AND round=$%d AND phase=$%d`,
		strings.Join(sets, ", "), len(args)-2, len(args)-1, len(args))
	_, err := d.Exec(q, args...)
	return err
}

func scanAuditCoverage(sc interface{ Scan(...any) error }) (*AuditCoverage, error) {
	var c AuditCoverage
	var evidence []byte
	if err := sc.Scan(&c.ID, &c.SessionID, &c.Round, &c.Kind, &c.Language, &c.CWE,
		&c.Module, &c.Path, &c.Line, &c.Symbol, &c.SinkKey, &c.Status, &c.IntentID,
		&c.Engine, &evidence, &c.Reason, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	c.Evidence = cloneRawJSON(evidence)
	return &c, nil
}

// UpsertAuditCoverage inserts planned coverage rows. A conflicting row is left
// untouched so a re-plan cannot reset already scanned status.
func (d *DB) UpsertAuditCoverage(rows []AuditCoverage) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, c := range rows {
		status := c.Status
		if status == "" {
			status = "planned"
		}
		if _, err := tx.Exec(`
INSERT INTO audit_coverage(session_id, round, kind, language, cwe, module, path, line,
    symbol, sink_key, status, intent_id, engine, evidence, reason)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15)
ON CONFLICT (session_id, round, kind, sink_key) DO NOTHING`,
			c.SessionID, c.Round, c.Kind, c.Language, c.CWE, c.Module, c.Path, c.Line,
			c.Symbol, c.SinkKey, status, c.IntentID, c.Engine,
			auditJSONValue(c.Evidence, "{}"), c.Reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListAuditCoverage returns a round's coverage ordered for deterministic plans.
func (d *DB) ListAuditCoverage(sessionID int64, round int) ([]AuditCoverage, error) {
	rows, err := d.Query(`
SELECT id, session_id, round, kind, language, cwe, module, path, line, symbol,
       sink_key, status, intent_id, engine, evidence, reason, created_at, updated_at
FROM audit_coverage WHERE session_id=$1 AND round=$2
ORDER BY cwe, path, line, id`, sessionID, round)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditCoverage, 0)
	for rows.Next() {
		c, err := scanAuditCoverage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// MarkAuditCoverage stamps status/reason/intent on the given sink keys in one
// round. An empty sink-key list is a no-op; intentID is an
// audit_detection_intents.id and 0 leaves intent_id NULL.
func (d *DB) MarkAuditCoverage(sessionID int64, round int, sinkKeys []string, status, reason string, intentID int64) error {
	if len(sinkKeys) == 0 {
		return nil
	}
	_, err := d.Exec(`
UPDATE audit_coverage
SET status=$4, reason=$5, intent_id=NULLIF($6::bigint,0), updated_at=now()
WHERE session_id=$1 AND round=$2 AND sink_key=ANY($3::text[])`,
		sessionID, round, marshalStringArray(sinkKeys), status, reason, intentID)
	return err
}

// AssignAuditCoverage assigns currently-unowned coverage rows in one round to an
// intent. Rows already owned by another intent are left untouched; the returned
// count lets the director detect a partial assignment.
func (d *DB) AssignAuditCoverage(sessionID int64, round int, sinkKeys []string, intentID int64) (int64, error) {
	if len(sinkKeys) == 0 {
		return 0, nil
	}
	if intentID <= 0 {
		return 0, errors.New("intent_id 必须为正整数")
	}
	res, err := d.Exec(`
UPDATE audit_coverage
SET intent_id=$4, updated_at=now()
WHERE session_id=$1 AND round=$2 AND sink_key=ANY($3::text[])
  AND intent_id IS NULL`,
		sessionID, round, marshalStringArray(sinkKeys), intentID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// MarkAuditCoverageOwned updates status/reason only for coverage rows owned by
// intentID. It returns the number of rows updated so the caller can reject a
// completion that claimed keys it does not own.
func (d *DB) MarkAuditCoverageOwned(sessionID int64, round int, intentID int64, sinkKeys []string, status, reason string) (int64, error) {
	if len(sinkKeys) == 0 {
		return 0, nil
	}
	if intentID <= 0 {
		return 0, errors.New("intent_id 必须为正整数")
	}
	res, err := d.Exec(`
UPDATE audit_coverage
SET status=$5, reason=$6, updated_at=now()
WHERE session_id=$1 AND round=$2 AND intent_id=$4 AND sink_key=ANY($3::text[])`,
		sessionID, round, marshalStringArray(sinkKeys), intentID, status, reason)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ReleaseAuditCoverage returns incomplete (planned/missed) rows owned by a
// terminal intent to the unowned candidate pool. Completed verdicts
// (scanned/candidate/benign/exempt) stay attached as evidence.
func (d *DB) ReleaseAuditCoverage(sessionID int64, round int, intentID int64) (int64, error) {
	if intentID <= 0 {
		return 0, errors.New("intent_id 必须为正整数")
	}
	res, err := d.Exec(`
UPDATE audit_coverage
SET intent_id=NULL, updated_at=now()
WHERE session_id=$1 AND round=$2 AND intent_id=$3
  AND status IN ('planned','missed')`, sessionID, round, intentID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanAuditDetectionIntent(sc interface{ Scan(...any) error }) (*AuditDetectionIntent, error) {
	var i AuditDetectionIntent
	var sources, sinks, sanitizers, propagators, scope, constraints, preferredEngines []byte
	if err := sc.Scan(&i.ID, &i.SessionID, &i.Round, &i.IntentKey, &i.Origin,
		&i.Language, &i.CWE, &i.Title, &i.QueryKind, &sources, &sinks, &sanitizers,
		&propagators, &scope, &constraints, &preferredEngines, &i.Priority, &i.Status,
		&i.Error, &i.CreatedAt, &i.UpdatedAt); err != nil {
		return nil, err
	}
	i.Sources = cloneRawJSON(sources)
	i.Sinks = cloneRawJSON(sinks)
	i.Sanitizers = cloneRawJSON(sanitizers)
	i.Propagators = cloneRawJSON(propagators)
	i.Scope = cloneRawJSON(scope)
	i.Constraints = cloneRawJSON(constraints)
	i.PreferredEngines = cloneRawJSON(preferredEngines)
	return &i, nil
}

// InsertAuditDetectionIntent upserts one intent by (session, round, key) and
// returns the stored row. Re-running a plan is therefore restart-safe.
func (d *DB) InsertAuditDetectionIntent(i AuditDetectionIntent) (*AuditDetectionIntent, error) {
	if i.QueryKind == "" {
		i.QueryKind = "sink"
	}
	if i.Status == "" {
		i.Status = "planned"
	}
	row := d.QueryRow(`
INSERT INTO audit_detection_intents(session_id, round, intent_key, origin, language, cwe,
    title, query_kind, sources, sinks, sanitizers, propagators, scope, constraints,
    preferred_engines, priority, status, error)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb,$12::jsonb,
    $13::jsonb,$14::jsonb,$15::jsonb,$16,$17,$18)
ON CONFLICT (session_id, round, intent_key) DO UPDATE SET
    origin=EXCLUDED.origin,
    language=EXCLUDED.language,
    cwe=EXCLUDED.cwe,
    title=EXCLUDED.title,
    query_kind=EXCLUDED.query_kind,
    sources=EXCLUDED.sources,
    sinks=EXCLUDED.sinks,
    sanitizers=EXCLUDED.sanitizers,
    propagators=EXCLUDED.propagators,
    scope=EXCLUDED.scope,
    constraints=EXCLUDED.constraints,
    preferred_engines=EXCLUDED.preferred_engines,
    priority=EXCLUDED.priority,
    status=EXCLUDED.status,
    error=EXCLUDED.error,
    updated_at=now()
RETURNING id, session_id, round, intent_key, origin, language, cwe, title, query_kind,
    sources, sinks, sanitizers, propagators, scope, constraints, preferred_engines,
    priority, status, error, created_at, updated_at`,
		i.SessionID, i.Round, i.IntentKey, i.Origin, i.Language, i.CWE, i.Title,
		i.QueryKind, auditJSONValue(i.Sources, "[]"), auditJSONValue(i.Sinks, "[]"),
		auditJSONValue(i.Sanitizers, "[]"), auditJSONValue(i.Propagators, "[]"),
		auditJSONValue(i.Scope, "{}"), auditJSONValue(i.Constraints, "{}"),
		auditJSONValue(i.PreferredEngines, "[]"), i.Priority, i.Status, i.Error)
	return scanAuditDetectionIntent(row)
}

// ListAuditDetectionIntents returns a round's intents in insertion order.
func (d *DB) ListAuditDetectionIntents(sessionID int64, round int) ([]AuditDetectionIntent, error) {
	rows, err := d.Query(`
SELECT id, session_id, round, intent_key, origin, language, cwe, title, query_kind,
       sources, sinks, sanitizers, propagators, scope, constraints, preferred_engines,
       priority, status, error, created_at, updated_at
FROM audit_detection_intents WHERE session_id=$1 AND round=$2 ORDER BY id`, sessionID, round)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditDetectionIntent, 0)
	for rows.Next() {
		i, err := scanAuditDetectionIntent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateAuditDetectionIntentStatus updates a single intent's runtime status and
// error message. Intent identity is (session, round, key).
func (d *DB) UpdateAuditDetectionIntentStatus(sessionID int64, round int, intentKey, status, errMsg string) error {
	_, err := d.Exec(`
UPDATE audit_detection_intents
SET status=$4, error=$5, updated_at=now()
WHERE session_id=$1 AND round=$2 AND intent_key=$3`,
		sessionID, round, intentKey, status, errMsg)
	return err
}

func scanAuditHypothesis(sc interface{ Scan(...any) error }) (*AuditHypothesis, error) {
	var h AuditHypothesis
	var attempts []byte
	if err := sc.Scan(&h.ID, &h.SessionID, &h.Round, &h.HypothesisKey, &h.Statement,
		&h.Status, &attempts, &h.Evidence, &h.Priority, &h.CreatedAt, &h.UpdatedAt); err != nil {
		return nil, err
	}
	h.Attempts = cloneRawJSON(attempts)
	return &h, nil
}

// UpsertAuditHypothesis inserts or updates by (session_id, hypothesis_key).
func (d *DB) UpsertAuditHypothesis(h AuditHypothesis) error {
	if h.Status == "" {
		h.Status = "untested"
	}
	if h.Priority == 0 {
		h.Priority = 5
	}
	_, err := d.Exec(`
INSERT INTO audit_hypotheses(session_id, round, hypothesis_key, statement, status, attempts, evidence, priority)
VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8)
ON CONFLICT (session_id, hypothesis_key) DO UPDATE SET
    round=EXCLUDED.round,
    statement=EXCLUDED.statement,
    status=EXCLUDED.status,
    attempts=EXCLUDED.attempts,
    evidence=EXCLUDED.evidence,
    priority=EXCLUDED.priority,
    updated_at=now()`,
		h.SessionID, h.Round, h.HypothesisKey, h.Statement, h.Status,
		auditJSONValue(h.Attempts, "[]"), h.Evidence, h.Priority)
	return err
}

// ListAuditHypotheses returns all hypotheses for a session in insertion order.
func (d *DB) ListAuditHypotheses(sessionID int64) ([]AuditHypothesis, error) {
	rows, err := d.Query(`
SELECT id, session_id, round, hypothesis_key, statement, status, attempts, evidence,
       priority, created_at, updated_at
FROM audit_hypotheses WHERE session_id=$1 ORDER BY id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditHypothesis, 0)
	for rows.Next() {
		h, err := scanAuditHypothesis(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func scanAuditRound(sc interface{ Scan(...any) error }) (*AuditRound, error) {
	var r AuditRound
	var focus, tokenUsage []byte
	if err := sc.Scan(&r.ID, &r.SessionID, &r.Round, &r.NewFindings, &r.NewConfirmed,
		&r.NewCandidate, &r.TotalFindings, &r.GateC, &r.GateCWE, &r.GateH, &r.GateE,
		&r.GateCoverage, &r.GateEngine, &r.Decision, &focus, &tokenUsage,
		&r.CreatedAt); err != nil {
		return nil, err
	}
	r.Focus = cloneRawJSON(focus)
	r.TokenUsage = cloneRawJSON(tokenUsage)
	return &r, nil
}

// InsertAuditRound writes a round summary idempotently (last write wins).
func (d *DB) InsertAuditRound(r AuditRound) error {
	_, err := d.Exec(`
INSERT INTO audit_rounds(session_id, round, new_findings, new_confirmed, new_candidate,
    total_findings, gate_c, gate_cwe, gate_h, gate_e, gate_coverage, gate_engine,
    decision, focus, token_usage)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb)
ON CONFLICT (session_id, round) DO UPDATE SET
    new_findings=EXCLUDED.new_findings,
    new_confirmed=EXCLUDED.new_confirmed,
    new_candidate=EXCLUDED.new_candidate,
    total_findings=EXCLUDED.total_findings,
    gate_c=EXCLUDED.gate_c,
    gate_cwe=EXCLUDED.gate_cwe,
    gate_h=EXCLUDED.gate_h,
    gate_e=EXCLUDED.gate_e,
    gate_coverage=EXCLUDED.gate_coverage,
    gate_engine=EXCLUDED.gate_engine,
    decision=EXCLUDED.decision,
    focus=EXCLUDED.focus,
    token_usage=EXCLUDED.token_usage`,
		r.SessionID, r.Round, r.NewFindings, r.NewConfirmed, r.NewCandidate,
		r.TotalFindings, r.GateC, r.GateCWE, r.GateH, r.GateE, r.GateCoverage,
		r.GateEngine, r.Decision, auditJSONValue(r.Focus, "{}"),
		auditJSONValue(r.TokenUsage, "{}"))
	return err
}

// ListAuditRounds returns a session's rounds ordered by round number.
func (d *DB) ListAuditRounds(sessionID int64) ([]AuditRound, error) {
	rows, err := d.Query(`
SELECT id, session_id, round, new_findings, new_confirmed, new_candidate, total_findings,
       gate_c, gate_cwe, gate_h, gate_e, gate_coverage, gate_engine, decision, focus,
       token_usage, created_at
FROM audit_rounds WHERE session_id=$1 ORDER BY round`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditRound, 0)
	for rows.Next() {
		r, err := scanAuditRound(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func scanAuditEngineJob(sc interface{ Scan(...any) error }) (*AuditEngineJob, error) {
	var j AuditEngineJob
	var sarif, provenance []byte
	if err := sc.Scan(&j.ID, &j.SessionID, &j.IntentID, &j.Engine, &j.JobKind,
		&j.QueryHash, &j.Status, &j.QueryText, &j.QueryPath, &j.ArtifactPath,
		&j.ResultCount, &j.DurationMS, &j.Error, &sarif, &provenance,
		&j.CreatedAt, &j.UpdatedAt); err != nil {
		return nil, err
	}
	j.SARIF = cloneRawJSON(sarif)
	j.Provenance = cloneRawJSON(provenance)
	return &j, nil
}

// UpsertAuditEngineJob inserts or updates an engine job identified by its
// (session, intent, engine, job kind, query hash) unique key.
func (d *DB) UpsertAuditEngineJob(j AuditEngineJob) error {
	if j.Status == "" {
		j.Status = "pending"
	}
	_, err := d.Exec(`
INSERT INTO audit_engine_jobs(session_id, intent_id, engine, job_kind, query_hash, status,
    query_text, query_path, artifact_path, result_count, duration_ms, error, sarif, provenance)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14::jsonb)
ON CONFLICT (session_id, intent_id, engine, job_kind, query_hash) DO UPDATE SET
    status=EXCLUDED.status,
    query_text=EXCLUDED.query_text,
    query_path=EXCLUDED.query_path,
    artifact_path=EXCLUDED.artifact_path,
    result_count=EXCLUDED.result_count,
    duration_ms=EXCLUDED.duration_ms,
    error=EXCLUDED.error,
    sarif=EXCLUDED.sarif,
    provenance=EXCLUDED.provenance,
    updated_at=now()`,
		j.SessionID, j.IntentID, j.Engine, j.JobKind, j.QueryHash, j.Status,
		j.QueryText, j.QueryPath, j.ArtifactPath, j.ResultCount, j.DurationMS,
		j.Error, auditJSONValue(j.SARIF, "{}"), auditJSONValue(j.Provenance, "{}"))
	return err
}

// ListAuditEngineJobs returns all engine jobs for a session in insertion order.
func (d *DB) ListAuditEngineJobs(sessionID int64) ([]AuditEngineJob, error) {
	rows, err := d.Query(`
SELECT id, session_id, intent_id, engine, job_kind, query_hash, status, query_text,
       query_path, artifact_path, result_count, duration_ms, error, sarif, provenance,
       created_at, updated_at
FROM audit_engine_jobs WHERE session_id=$1 ORDER BY id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditEngineJob, 0)
	for rows.Next() {
		j, err := scanAuditEngineJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
