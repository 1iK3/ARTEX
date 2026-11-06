package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
)

// resolvedTaskMode is the validated mode/audit slice of a task creation request.
type resolvedTaskMode struct {
	Mode        string
	AuditConfig json.RawMessage
	Goal        string
}

// resolveTaskModeOptions validates task_mode + audit config and returns the
// normalized values to persist. It is pure (no Server/DB access) so the create
// and spawn paths share one implementation that can be unit-tested without PG.
//
// A blank goal on a code_audit task gets a deterministic default; pentest goals
// keep the caller's value (blank is allowed, matching the existing API).
func resolveTaskModeOptions(mode string, cfg *audit.Config, goal string, localRoots []string) (resolvedTaskMode, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = db.TaskModePentest
	}
	if !db.ValidTaskMode(mode) {
		return resolvedTaskMode{}, fmt.Errorf("无效的任务模式 %q", mode)
	}
	if mode == db.TaskModePentest {
		if cfg != nil {
			return resolvedTaskMode{}, errors.New("渗透测试任务不支持 audit 配置")
		}
		return resolvedTaskMode{Mode: mode, Goal: goal}, nil
	}
	if cfg == nil {
		return resolvedTaskMode{}, errors.New("代码审计任务缺少 audit 配置")
	}
	normalized := audit.NormalizeConfig(*cfg)
	if err := audit.ValidateConfig(normalized, localRoots); err != nil {
		return resolvedTaskMode{}, fmt.Errorf("审计配置无效: %w", err)
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return resolvedTaskMode{}, fmt.Errorf("序列化审计配置失败: %w", err)
	}
	if strings.TrimSpace(goal) == "" {
		goal = fmt.Sprintf("完成对 %s 的全量深度代码审计", auditSourceLabel(normalized))
	}
	return resolvedTaskMode{Mode: mode, AuditConfig: raw, Goal: goal}, nil
}

func auditSourceLabel(cfg audit.Config) string {
	switch cfg.SourceType {
	case audit.SourceGit:
		return cfg.RepoURL
	case audit.SourceLocal:
		clean := filepath.Clean(strings.TrimSpace(cfg.LocalPath))
		base := filepath.Base(clean)
		if base == "" || base == "." || base == string(filepath.Separator) {
			base = "local-source"
		}
		return "local:" + base
	case audit.SourceZip:
		return "zip:" + cfg.UploadID
	default:
		return cfg.SourceType
	}
}

// decodeAuditConfig decodes an optional audit object from a tool argument.
// Missing and JSON null both mean "not supplied".
func decodeAuditConfig(raw json.RawMessage) (*audit.Config, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil, nil
	}
	var cfg audit.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("audit 配置无效: %w", err)
	}
	return &cfg, nil
}

func taskWorkerConfig(worker *audit.WorkerConfig) (json.RawMessage, error) {
	if worker == nil {
		return nil, nil
	}
	normalized := audit.NormalizeWorkerConfig(worker)
	if err := audit.ValidateWorkerConfig(normalized); err != nil {
		return nil, fmt.Errorf("worker 配置无效: %w", err)
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("序列化 worker 配置失败: %w", err)
	}
	return data, nil
}

// auditConfigIsEmpty reports whether raw is an absent/null/empty JSON object.
// Non-object JSON is rejected.
func auditConfigIsEmpty(raw json.RawMessage) (bool, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return true, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false, errors.New("audit_config 必须是 JSON 对象")
	}
	return len(obj) == 0, nil
}

// templatePatchMode validates an explicitly supplied PATCH task_mode. A present
// null/blank mode is an error: only an absent field may preserve/derive a mode.
func templatePatchMode(raw *string) (string, error) {
	if raw == nil {
		return "", errors.New("task_mode 不能为空")
	}
	mode := strings.ToLower(strings.TrimSpace(*raw))
	if mode == "" {
		return "", errors.New("task_mode 不能为空")
	}
	if !db.ValidTaskMode(mode) {
		return "", fmt.Errorf("无效的任务模式 %q", mode)
	}
	return mode, nil
}

// normalizeTemplateModeConfig validates a task template's mode and audit
// configuration. Pentest templates may carry only an empty config; code_audit
// templates must carry a fully valid audit.Config.
func normalizeTemplateModeConfig(mode string, raw json.RawMessage, localRoots []string) (string, json.RawMessage, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = db.TaskModePentest
	}
	if !db.ValidTaskMode(mode) {
		return "", nil, fmt.Errorf("无效的任务模式 %q", mode)
	}
	if mode == db.TaskModePentest {
		empty, err := auditConfigIsEmpty(raw)
		if err != nil {
			return "", nil, err
		}
		if !empty {
			return "", nil, errors.New("渗透测试模板不支持 audit 配置")
		}
		return mode, json.RawMessage(`{}`), nil
	}
	if empty, _ := auditConfigIsEmpty(raw); empty {
		return "", nil, errors.New("代码审计模板缺少 audit 配置")
	}
	var cfg audit.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", nil, fmt.Errorf("audit_config 无效: %w", err)
	}
	normalized := audit.NormalizeConfig(cfg)
	if err := audit.ValidateConfig(normalized, localRoots); err != nil {
		return "", nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", nil, fmt.Errorf("序列化审计配置失败: %w", err)
	}
	return mode, encoded, nil
}

// parseAuditLocalRoots parses a comma/semicolon separated root list into
// absolute cleaned directories, dropping empty/invalid/duplicate entries.
func parseAuditLocalRoots(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' })
	roots := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		abs, err := filepath.Abs(part)
		if err != nil {
			log.Printf("[audit] 忽略无效的本地审计根目录 %q: %v", part, err)
			continue
		}
		abs = filepath.Clean(abs)
		key := abs
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, abs)
	}
	return roots
}

// auditLocalRoots returns the operator-configured local audit source roots.
// The only configuration source for now is ARTEX_AUDIT_LOCAL_ROOTS (comma or
// semicolon separated); a DB settings key can be layered in later without
// changing callers.
func (s *Server) auditLocalRoots() []string {
	return parseAuditLocalRoots(os.Getenv("ARTEX_AUDIT_LOCAL_ROOTS"))
}

// startCodeAudit hands a code_audit task to the audit director, which performs
// source ingest/profile/plan/prescan/index on first run and then starts the
// shared Engine. The director owns failure reporting and session preservation,
// so this wrapper only logs the returned error.
func (s *Server) startCodeAudit(t *Task) {
	if t == nil {
		return
	}
	if s.auditDirector == nil {
		s.auditDirector = newAuditDirector(s)
	}
	if err := s.auditDirector.Start(s.ctx, t); err != nil {
		log.Printf("[audit] task %s 启动失败: %v", t.ID, err)
	}
}
