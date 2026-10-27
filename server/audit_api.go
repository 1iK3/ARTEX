package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
)

const (
	auditSourceWindowLines  = 200
	auditEngineProbeTimeout = 4 * time.Second
	auditVersionOutputLimit = 200
)

// auditTaskForRequest resolves a code_audit task and rejects non-audit tasks.
func (s *Server) auditTaskForRequest(w http.ResponseWriter, r *http.Request) (*Task, bool) {
	if s == nil || s.m == nil {
		writeErr(w, http.StatusServiceUnavailable, "服务未初始化")
		return nil, false
	}
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return nil, false
	}
	if t.Mode != db.TaskModeCodeAudit {
		writeErr(w, http.StatusBadRequest, "该任务不是代码审计任务")
		return nil, false
	}
	if s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "数据库不可用")
		return nil, false
	}
	return t, true
}

func (s *Server) auditSessionForTask(t *Task) (*db.AuditSession, error) {
	id, err := parseTaskID(t.ID)
	if err != nil {
		return nil, err
	}
	return s.m.pg.GetAuditSession(id)
}

// auditProgress serves the server-computed progress projection. It intentionally
// delegates to the same facade the planner uses, so UI and planner never disagree.
func (s *Server) auditProgress(w http.ResponseWriter, r *http.Request) {
	t, ok := s.auditTaskForRequest(w, r)
	if !ok {
		return
	}
	session, err := s.auditSessionForTask(t)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if session == nil {
		writeErr(w, http.StatusNotFound, "审计会话不存在")
		return
	}
	id, _ := parseTaskID(t.ID)
	raw, err := s.auditDepsFor(t).AuditProgress(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	writeJSON(w, http.StatusOK, raw)
}

// auditReport serves the deterministic generated report. Reports are only
// available after completion (done or done_with_gaps with a non-empty body).
func (s *Server) auditReport(w http.ResponseWriter, r *http.Request) {
	t, ok := s.auditTaskForRequest(w, r)
	if !ok {
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "md"
	}
	if format != "md" && format != "json" {
		writeErr(w, http.StatusBadRequest, "format 必须是 md 或 json")
		return
	}
	session, err := s.auditSessionForTask(t)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if session == nil {
		writeErr(w, http.StatusNotFound, "审计会话不存在")
		return
	}
	if !auditReportReady(session) {
		writeAuditReportNotReady(w, session)
		return
	}
	if format == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `inline; filename="audit-report.md"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(session.ReportMD))
		return
	}
	if len(session.ReportJSON) == 0 || strings.TrimSpace(string(session.ReportJSON)) == "null" {
		writeAuditReportNotReady(w, session)
		return
	}
	writeJSON(w, http.StatusOK, session.ReportJSON)
}

func writeAuditReportNotReady(w http.ResponseWriter, session *db.AuditSession) {
	writeJSON(w, http.StatusConflict, map[string]any{
		"error":        "审计报告尚未生成",
		"status":       session.Status,
		"report_ready": false,
		"gates":        auditReportGateSnapshot(session.GateResults),
		"round":        session.Round,
		"max_rounds":   session.MaxRounds,
	})
}

// auditReportGateSnapshot flattens persisted gate_results to the gates object so
// the not-ready response exposes the same shape as audit_progress.gates.
func auditReportGateSnapshot(raw json.RawMessage) any {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return map[string]any{}
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) == nil {
		if gatesRaw, ok := object["gates"]; ok {
			var gates any
			if json.Unmarshal(gatesRaw, &gates) == nil {
				return gates
			}
		}
	}
	var value any
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	return map[string]any{}
}

// auditSourceFile returns a read-only window from the task's immutable source
// snapshot. The snapshot path itself is never exposed.
func (s *Server) auditSourceFile(w http.ResponseWriter, r *http.Request) {
	t, ok := s.auditTaskForRequest(w, r)
	if !ok {
		return
	}
	session, err := s.auditSessionForTask(t)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if session == nil {
		writeErr(w, http.StatusNotFound, "审计会话不存在")
		return
	}
	root := strings.TrimSpace(session.SnapshotPath)
	if root == "" || !auditSnapshotExists(root) {
		writeErr(w, http.StatusNotFound, "审计源码快照不存在")
		return
	}
	relPath := strings.TrimSpace(r.URL.Query().Get("path"))
	if relPath == "" {
		writeErr(w, http.StatusBadRequest, "path 不能为空")
		return
	}
	line := 1
	if rawLine := strings.TrimSpace(r.URL.Query().Get("line")); rawLine != "" {
		parsed, parseErr := strconv.Atoi(rawLine)
		if parseErr != nil || parsed <= 0 {
			writeErr(w, http.StatusBadRequest, "line 必须是正整数")
			return
		}
		line = parsed
	}
	start, end := auditSourceWindow(line)
	content, totalLines, err := audit.ReadSource(r.Context(), root, relPath, start, end, 0)
	if err != nil {
		if auditSourceNotFound(err) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	actualStart, actualEnd := start, end
	if totalLines <= 0 {
		actualStart, actualEnd = 0, 0
	} else {
		if actualStart > totalLines {
			actualStart = totalLines
		}
		if actualEnd > totalLines {
			actualEnd = totalLines
		}
	}
	cleanPath := audit.NormalizeCodePath(relPath)
	if cleanPath == "" {
		cleanPath = filepath.ToSlash(relPath)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":        cleanPath,
		"start_line":  actualStart,
		"end_line":    actualEnd,
		"total_lines": totalLines,
		"content":     content,
		"language":    audit.LanguageForPath(cleanPath),
	})
}

func auditSourceNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "不存在") || strings.Contains(message, "no such file")
}

// auditCapabilities probes the optional analysis engines and advertises limits.
// Local roots are reduced to basenames so the API never leaks host paths.
func (s *Server) auditCapabilities(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	result := map[string]any{}
	for _, engine := range []string{audit.EngineCodeGraph, audit.EngineCodeQL, audit.EngineJoern} {
		result[engine] = probeAuditEngine(ctx, s.auditEngineBin(engine))
	}
	roots := s.auditLocalRoots()
	names := make([]string, 0, len(roots))
	seen := map[string]struct{}{}
	for _, root := range roots {
		name := filepath.Base(filepath.Clean(root))
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "root"
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	result["local_roots"] = map[string]any{"count": len(roots), "basenames": names}
	result["limits"] = map[string]any{
		"max_source_bytes":       int64(2 << 30),
		"max_files":              200000,
		"max_file_bytes":         int64(10 << 20),
		"max_sink_sites_per_cwe": 2000,
		"max_rounds":             10,
		"depths":                 []string{audit.DepthQuick, audit.DepthStandard, audit.DepthDeep},
	}
	writeJSON(w, http.StatusOK, result)
}

type auditEngineCapability struct {
	Available bool   `json:"available"`
	Path      string `json:"path"`
	Version   string `json:"version"`
}

func probeAuditEngine(ctx context.Context, bin string) auditEngineCapability {
	bin = strings.TrimSpace(bin)
	if bin == "" {
		return auditEngineCapability{Available: false}
	}
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return auditEngineCapability{Available: false}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, auditEngineProbeTimeout)
	defer cancel()
	capability := auditEngineCapability{Available: true, Path: filepath.Base(resolved)}
	for _, args := range [][]string{{"--version"}, {"version"}} {
		cmd := exec.CommandContext(probeCtx, resolved, args...)
		output, runErr := cmd.CombinedOutput()
		if runErr != nil {
			continue
		}
		if version := normalizeAuditVersionOutput(string(output)); version != "" {
			capability.Version = version
			break
		}
	}
	return capability
}

func normalizeAuditVersionOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.Trim(line, "\x00"))
		line = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) && r != '\t' {
				return -1
			}
			return r
		}, line)
		if line == "" {
			continue
		}
		if runes := []rune(line); len(runes) > auditVersionOutputLimit {
			line = string(runes[:auditVersionOutputLimit])
		}
		return line
	}
	return ""
}

// auditEngineBin resolves an operator override for an engine binary. CodeGraph
// keeps its existing env/settings precedence; CodeQL and Joern mirror it.
func (s *Server) auditEngineBin(engine string) string {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case audit.EngineCodeGraph:
		return s.auditCodeGraphBin()
	case audit.EngineCodeQL, audit.EngineJoern:
		name := strings.ToLower(strings.TrimSpace(engine))
		envKey := "ARTEX_" + strings.ToUpper(name) + "_BIN"
		if bin := strings.TrimSpace(os.Getenv(envKey)); bin != "" {
			return bin
		}
		if s != nil && s.m != nil && s.m.pg != nil {
			if bin, ok, err := s.m.pg.GetSetting("audit." + name + "_bin"); err == nil && ok {
				if trimmed := strings.TrimSpace(bin); trimmed != "" {
					return trimmed
				}
			}
		}
		return name
	default:
		return strings.TrimSpace(engine)
	}
}

// auditSourceWindow is kept small and pure for handler tests.
func auditSourceWindow(line int) (int, int) {
	if line <= 0 {
		line = 1
	}
	return line, line + auditSourceWindowLines - 1
}
