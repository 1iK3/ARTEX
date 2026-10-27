package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	MaxTaskTemplateNameRunes = 120
	MaxTaskTemplateTextRunes = 16000
)

var (
	ErrTaskTemplateInvalid      = errors.New("invalid task template")
	ErrTaskTemplateNameConflict = errors.New("task template name already exists")
	ErrTaskTemplateNotFound     = errors.New("task template not found")
)

// TaskTemplate is a reusable task preset (description/goal + optional category
// and task-level intercept/allow rules).
type TaskTemplate struct {
	ID             int64                    `json:"id"`
	Name           string                   `json:"name"`
	NKey           string                   `json:"-"`
	Description    string                   `json:"description"`
	Goal           string                   `json:"goal"`
	CategoryID     *int64                   `json:"category_id"`
	InterceptRules []TaskInterceptRuleInput `json:"intercept_rules"`
	Mode           string                   `json:"task_mode"`
	AuditConfig    json.RawMessage          `json:"audit_config"`
	CreatedAt      time.Time                `json:"created_at"`
	UpdatedAt      time.Time                `json:"updated_at"`
}

// TaskTemplateInput is the create/update payload after normalization.
type TaskTemplateInput struct {
	Name           string
	Description    string
	Goal           string
	CategoryID     *int64
	InterceptRules []TaskInterceptRuleInput
	Mode           string
	AuditConfig    json.RawMessage
}

// TaskTemplatePatch changes only fields flagged as set. Name/Description/Goal use
// non-nil pointers; CategoryID/InterceptRules/Mode/AuditConfig use explicit Set
// flags (so a nil CategoryID can mean "clear" when SetCategoryID is true).
type TaskTemplatePatch struct {
	Name              *string
	Description       *string
	Goal              *string
	CategoryID        *int64
	SetCategoryID     bool
	InterceptRules    []TaskInterceptRuleInput
	SetInterceptRules bool
	Mode              *string
	AuditConfig       json.RawMessage
	SetAuditConfig    bool
}

const taskTemplateCols = `id, name, nkey, description, goal, category_id, intercept_rules,
COALESCE(task_mode,'pentest'), COALESCE(audit_config,'{}'::jsonb), created_at, updated_at`

func scanTaskTemplate(row interface{ Scan(...any) error }) (TaskTemplate, error) {
	var t TaskTemplate
	var rulesRaw, auditRaw []byte
	if err := row.Scan(&t.ID, &t.Name, &t.NKey, &t.Description, &t.Goal, &t.CategoryID, &rulesRaw,
		&t.Mode, &auditRaw, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return t, err
	}
	t.InterceptRules = []TaskInterceptRuleInput{}
	if len(rulesRaw) > 0 {
		if err := json.Unmarshal(rulesRaw, &t.InterceptRules); err != nil {
			return t, err
		}
		if t.InterceptRules == nil {
			t.InterceptRules = []TaskInterceptRuleInput{}
		}
	}
	if t.Mode == "" {
		t.Mode = TaskModePentest
	}
	t.AuditConfig = cloneRawJSON(auditRaw)
	if len(t.AuditConfig) == 0 {
		t.AuditConfig = json.RawMessage(`{}`)
	}
	return t, nil
}

// normalizeTaskTemplateMode defaults an empty mode to pentest and rejects
// unknown modes. allowEmpty is true for create/update payloads, false for PATCH
// (where an explicitly empty mode is an error).
func normalizeTaskTemplateMode(mode string, allowEmpty bool) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		if allowEmpty {
			return TaskModePentest, nil
		}
		return "", fmt.Errorf("%w: task_mode is required", ErrTaskTemplateInvalid)
	}
	if !ValidTaskMode(mode) {
		return "", fmt.Errorf("%w: invalid task_mode %q", ErrTaskTemplateInvalid, mode)
	}
	return mode, nil
}

// normalizeTemplateAuditConfig defaults an empty/null config to {} and rejects
// non-object JSON. Audit semantics are validated by the caller (server layer).
func normalizeTemplateAuditConfig(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := []byte(strings.TrimSpace(string(raw)))
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return json.RawMessage(`{}`), nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, fmt.Errorf("%w: audit_config must be a JSON object", ErrTaskTemplateInvalid)
	}
	out := make(json.RawMessage, len(trimmed))
	copy(out, trimmed)
	return out, nil
}

// marshalTemplateRules serializes a template's rule snapshot to JSONB text,
// always producing a JSON array (never null).
func marshalTemplateRules(rules []TaskInterceptRuleInput) ([]byte, error) {
	if rules == nil {
		rules = []TaskInterceptRuleInput{}
	}
	return json.Marshal(rules)
}

// taskTemplateName normalizes display whitespace while preserving the user's case.
func taskTemplateName(name string) string { return strings.Join(strings.Fields(name), " ") }

// taskTemplateNKey is the case-insensitive identity used by the unique index.
func taskTemplateNKey(name string) string { return strings.ToLower(taskTemplateName(name)) }

func normalizeTaskTemplateInput(in TaskTemplateInput) (TaskTemplateInput, string, error) {
	in.Name = taskTemplateName(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	in.Goal = strings.TrimSpace(in.Goal)
	mode, err := normalizeTaskTemplateMode(in.Mode, true)
	if err != nil {
		return in, "", err
	}
	auditConfig, err := normalizeTemplateAuditConfig(in.AuditConfig)
	if err != nil {
		return in, "", err
	}
	in.Mode, in.AuditConfig = mode, auditConfig
	switch {
	case in.Name == "":
		return in, "", fmt.Errorf("%w: name is required", ErrTaskTemplateInvalid)
	case utf8.RuneCountInString(in.Name) > MaxTaskTemplateNameRunes:
		return in, "", fmt.Errorf("%w: name exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateNameRunes)
	case in.Description == "":
		return in, "", fmt.Errorf("%w: description is required", ErrTaskTemplateInvalid)
	case utf8.RuneCountInString(in.Description) > MaxTaskTemplateTextRunes:
		return in, "", fmt.Errorf("%w: description exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
	case in.Goal == "":
		return in, "", fmt.Errorf("%w: goal is required", ErrTaskTemplateInvalid)
	case utf8.RuneCountInString(in.Goal) > MaxTaskTemplateTextRunes:
		return in, "", fmt.Errorf("%w: goal exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
	}
	return in, taskTemplateNKey(in.Name), nil
}

func normalizeTaskTemplatePatch(patch TaskTemplatePatch) (TaskTemplatePatch, *string, error) {
	if patch.Name == nil && patch.Description == nil && patch.Goal == nil && !patch.SetCategoryID &&
		!patch.SetInterceptRules && patch.Mode == nil && !patch.SetAuditConfig {
		return patch, nil, fmt.Errorf("%w: no fields supplied", ErrTaskTemplateInvalid)
	}
	var nkey *string
	if patch.Name != nil {
		name := taskTemplateName(*patch.Name)
		if name == "" {
			return patch, nil, fmt.Errorf("%w: name is required", ErrTaskTemplateInvalid)
		}
		if utf8.RuneCountInString(name) > MaxTaskTemplateNameRunes {
			return patch, nil, fmt.Errorf("%w: name exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateNameRunes)
		}
		key := taskTemplateNKey(name)
		patch.Name = &name
		nkey = &key
	}
	if patch.Description != nil {
		description := strings.TrimSpace(*patch.Description)
		if description == "" {
			return patch, nil, fmt.Errorf("%w: description is required", ErrTaskTemplateInvalid)
		}
		if utf8.RuneCountInString(description) > MaxTaskTemplateTextRunes {
			return patch, nil, fmt.Errorf("%w: description exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
		}
		patch.Description = &description
	}
	if patch.Goal != nil {
		goal := strings.TrimSpace(*patch.Goal)
		if goal == "" {
			return patch, nil, fmt.Errorf("%w: goal is required", ErrTaskTemplateInvalid)
		}
		if utf8.RuneCountInString(goal) > MaxTaskTemplateTextRunes {
			return patch, nil, fmt.Errorf("%w: goal exceeds %d characters", ErrTaskTemplateInvalid, MaxTaskTemplateTextRunes)
		}
		patch.Goal = &goal
	}
	if patch.Mode != nil {
		mode, err := normalizeTaskTemplateMode(*patch.Mode, false)
		if err != nil {
			return patch, nil, err
		}
		patch.Mode = &mode
	}
	if patch.SetAuditConfig {
		auditConfig, err := normalizeTemplateAuditConfig(patch.AuditConfig)
		if err != nil {
			return patch, nil, err
		}
		patch.AuditConfig = auditConfig
	}
	return patch, nkey, nil
}

func taskTemplateUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateTaskTemplate inserts one globally reusable preset.
func (d *DB) CreateTaskTemplate(in TaskTemplateInput) (*TaskTemplate, error) {
	in, nkey, err := normalizeTaskTemplateInput(in)
	if err != nil {
		return nil, err
	}
	rulesJSON, err := marshalTemplateRules(in.InterceptRules)
	if err != nil {
		return nil, err
	}
	t, err := scanTaskTemplate(d.QueryRow(`
INSERT INTO task_templates(name, nkey, description, goal, category_id, intercept_rules, task_mode, audit_config)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
ON CONFLICT (nkey) DO NOTHING
RETURNING `+taskTemplateCols, in.Name, nkey, in.Description, in.Goal, in.CategoryID, rulesJSON,
		in.Mode, string(in.AuditConfig)))
	if err == sql.ErrNoRows {
		return nil, ErrTaskTemplateNameConflict
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTaskTemplates returns the most recently maintained templates first.
func (d *DB) ListTaskTemplates() ([]*TaskTemplate, error) {
	rows, err := d.Query(`SELECT ` + taskTemplateCols + ` FROM task_templates ORDER BY updated_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TaskTemplate{}
	for rows.Next() {
		t, err := scanTaskTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// GetTaskTemplate returns nil when id does not exist.
func (d *DB) GetTaskTemplate(id int64) (*TaskTemplate, error) {
	t, err := scanTaskTemplate(d.QueryRow(`SELECT `+taskTemplateCols+` FROM task_templates WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// UpdateTaskTemplate replaces the editable fields of one preset.
func (d *DB) UpdateTaskTemplate(id int64, in TaskTemplateInput) (*TaskTemplate, error) {
	in, _, err := normalizeTaskTemplateInput(in)
	if err != nil {
		return nil, err
	}
	return d.PatchTaskTemplate(id, TaskTemplatePatch{
		Name: &in.Name, Description: &in.Description, Goal: &in.Goal,
		Mode: &in.Mode, AuditConfig: in.AuditConfig, SetAuditConfig: true,
	})
}

// PatchTaskTemplate atomically changes only the supplied fields. Keeping the
// merge in one UPDATE prevents concurrent disjoint PATCH requests from losing
// each other's changes.
func (d *DB) PatchTaskTemplate(id int64, patch TaskTemplatePatch) (*TaskTemplate, error) {
	patch, nkey, err := normalizeTaskTemplatePatch(patch)
	if err != nil {
		return nil, err
	}
	rulesJSON, err := marshalTemplateRules(patch.InterceptRules)
	if err != nil {
		return nil, err
	}
	auditJSON := patch.AuditConfig
	if len(auditJSON) == 0 {
		auditJSON = json.RawMessage(`{}`)
	}
	t, err := scanTaskTemplate(d.QueryRow(`UPDATE task_templates
SET name=CASE WHEN $2 THEN $3::text ELSE name END,
    nkey=CASE WHEN $2 THEN $4::text ELSE nkey END,
    description=CASE WHEN $5 THEN $6::text ELSE description END,
    goal=CASE WHEN $7 THEN $8::text ELSE goal END,
    category_id=CASE WHEN $9 THEN $10::bigint ELSE category_id END,
    intercept_rules=CASE WHEN $11 THEN $12::jsonb ELSE intercept_rules END,
    task_mode=CASE WHEN $13 THEN $14::text ELSE task_mode END,
    audit_config=CASE WHEN $15 THEN $16::jsonb ELSE audit_config END
WHERE id=$1
RETURNING `+taskTemplateCols,
		id,
		patch.Name != nil, patch.Name, nkey,
		patch.Description != nil, patch.Description,
		patch.Goal != nil, patch.Goal,
		patch.SetCategoryID, patch.CategoryID,
		patch.SetInterceptRules, rulesJSON,
		patch.Mode != nil, patch.Mode,
		patch.SetAuditConfig, string(auditJSON),
	))
	if err == sql.ErrNoRows {
		return nil, ErrTaskTemplateNotFound
	}
	if taskTemplateUniqueViolation(err) {
		return nil, ErrTaskTemplateNameConflict
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteTaskTemplate deletes one preset and reports whether it existed.
func (d *DB) DeleteTaskTemplate(id int64) (bool, error) {
	result, err := d.Exec(`DELETE FROM task_templates WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}
