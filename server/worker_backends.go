package server

import (
	"net/http"
	"os/exec"

	"github.com/Autumn-27/artex/audit"
)

type workerBackendInfo struct {
	Backend                 string   `json:"backend"`
	Label                   string   `json:"label"`
	Description             string   `json:"description"`
	External                bool     `json:"external"`
	RequiresCommand         bool     `json:"requires_command"`
	Available               bool     `json:"available"`
	Modes                   []string `json:"modes"`
	SuggestedMode           string   `json:"suggested_mode"`
	SuggestedCommand        string   `json:"suggested_command"`
	SuggestedArgs           []string `json:"suggested_args"`
	SuggestedPrivilegedArgs []string `json:"suggested_privileged_args"`
}

func (s *Server) workerBackends(w http.ResponseWriter, _ *http.Request) {
	backends := workerBackendInfos()
	writeJSON(w, http.StatusOK, map[string]any{
		"default_backend": audit.WorkerBackendBuiltin,
		"backends":        backends,
	})
}

func workerBackendInfos() []workerBackendInfo {
	infos := []workerBackendInfo{
		{
			Backend: audit.WorkerBackendBuiltin, Label: "ARTEX 内置 Worker", Description: "使用 ARTEX 静态审计工具面，不执行目标代码。",
			Modes: []string{audit.WorkerModeStatic, audit.WorkerModePrivileged}, SuggestedMode: audit.WorkerModeStatic, Available: true,
		},
		{
			Backend: audit.WorkerBackendCodex, Label: "Codex CLI", Description: "调用本机 Codex 非交互命令，命令模板可按版本调整。",
			External: true, RequiresCommand: true, Modes: []string{audit.WorkerModeStatic, audit.WorkerModePrivileged},
			SuggestedMode: audit.WorkerModeStatic, SuggestedCommand: "codex",
			SuggestedArgs:           []string{"exec", "--skip-git-repo-check", "--sandbox", "read-only", "--output-schema", "{{schema_file}}", "--output-last-message", "{{output_file}}", "{{prompt}}"},
			SuggestedPrivilegedArgs: []string{"exec", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox", "--output-schema", "{{schema_file}}", "--output-last-message", "{{output_file}}", "{{prompt}}"},
		},
		{
			Backend: audit.WorkerBackendOpenCode, Label: "OpenCode CLI", Description: "调用本机 OpenCode 非交互命令，命令模板可按版本调整。",
			External: true, RequiresCommand: true, Modes: []string{audit.WorkerModeStatic, audit.WorkerModePrivileged},
			SuggestedMode: audit.WorkerModeStatic, SuggestedCommand: "opencode",
			SuggestedArgs:           []string{"run", "{{prompt}}"},
			SuggestedPrivilegedArgs: []string{"run", "--auto", "{{prompt}}"},
		},
		{
			Backend: audit.WorkerBackendClaudeCode, Label: "Claude Code CLI", Description: "调用本机 Claude Code 非交互命令，命令模板可按版本调整。",
			External: true, RequiresCommand: true, Modes: []string{audit.WorkerModeStatic, audit.WorkerModePrivileged},
			SuggestedMode: audit.WorkerModeStatic, SuggestedCommand: "claude",
			SuggestedArgs:           []string{"-p", "--permission-mode", "acceptEdits", "{{prompt}}"},
			SuggestedPrivilegedArgs: []string{"-p", "--permission-mode", "bypassPermissions", "{{prompt}}"},
		},
		{
			Backend: audit.WorkerBackendCursor, Label: "Cursor Agent CLI", Description: "调用本机 Cursor Agent 非交互命令，命令模板可按版本调整。",
			External: true, RequiresCommand: true, Modes: []string{audit.WorkerModeStatic, audit.WorkerModePrivileged},
			SuggestedMode: audit.WorkerModeStatic, SuggestedCommand: "cursor-agent",
			SuggestedArgs: []string{"{{input_file}}"},
		},
		{
			Backend: audit.WorkerBackendPi, Label: "Pi CLI", Description: "调用本机 Pi 非交互命令，命令模板可按版本调整。",
			External: true, RequiresCommand: true, Modes: []string{audit.WorkerModeStatic, audit.WorkerModePrivileged},
			SuggestedMode: audit.WorkerModeStatic, SuggestedCommand: "pi",
			SuggestedArgs: []string{"{{input_file}}"},
		},
		{
			Backend: audit.WorkerBackendCustom, Label: "自定义 CLI", Description: "由用户提供 argv 命令模板；不支持 shell 拼接。",
			External: true, RequiresCommand: true, Modes: []string{audit.WorkerModeStatic, audit.WorkerModePrivileged},
			SuggestedMode: audit.WorkerModeStatic, SuggestedArgs: []string{"{{input_file}}"},
		},
	}
	for index := range infos {
		if infos[index].External && infos[index].SuggestedCommand != "" {
			_, err := exec.LookPath(infos[index].SuggestedCommand)
			infos[index].Available = err == nil
		}
	}
	return infos
}
