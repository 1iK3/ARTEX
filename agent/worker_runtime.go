package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	externalWorkerStatusDone     = "done"
	externalWorkerStatusFailed   = "failed"
	externalWorkerStatusTimeout  = "timeout"
	externalWorkerStatusUnparsed = "unparsed"
)

// WorkerRuntime executes one worker intent. It deliberately sits above
// llm.Provider: external coding agents own their tool loop and state.
type WorkerRuntime interface {
	Name() string
	Run(ctx context.Context, req WorkerRequest) (WorkerResult, error)
}

type WorkerRequest struct {
	TaskID       int64
	IntentID     int64
	Name         string
	Prompt       string
	Workspace    string
	SnapshotRoot string
	OutputDir    string
	Privileged   bool
	// Audit selects the code-audit output contract (file/line findings).
	// False keeps the pentest contract, where findings are PoC/evidence based
	// and code locations are optional.
	Audit bool
}

type WorkerResult struct {
	Status    string
	Summary   string
	ExitCode  int
	Duration  time.Duration
	Stderr    string
	RawOutput string
	Findings  []ExternalFinding
	Warnings  []string
}

type ExternalFinding struct {
	Title      string  `json:"title"`
	VulnClass  string  `json:"vuln_class,omitempty"`
	CWEID      string  `json:"cwe_id"`
	Severity   string  `json:"severity"`
	Summary    string  `json:"summary,omitempty"`
	Evidence   string  `json:"evidence,omitempty"`
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Symbol     string  `json:"symbol,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

type CLIRuntimeConfig struct {
	Backend string
	Mode    string
	Command string
	Args    []string
	Cwd     string
	Env     map[string]string
	Timeout time.Duration
}

type CLIRuntime struct {
	config CLIRuntimeConfig
	runner cliRunner
}

func NewCLIRuntime(config CLIRuntimeConfig) *CLIRuntime {
	return newCLIRuntimeWithRunner(config, osCLIRunner{})
}

func newCLIRuntimeWithRunner(config CLIRuntimeConfig, runner cliRunner) *CLIRuntime {
	return &CLIRuntime{config: config, runner: runner}
}

func (r *CLIRuntime) Name() string {
	if r == nil || strings.TrimSpace(r.config.Backend) == "" {
		return "cli"
	}
	return strings.TrimSpace(r.config.Backend)
}

func (r *CLIRuntime) Run(ctx context.Context, req WorkerRequest) (WorkerResult, error) {
	if r == nil || r.runner == nil {
		return WorkerResult{Status: externalWorkerStatusFailed}, errors.New("worker CLI runtime is unavailable")
	}
	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		return WorkerResult{Status: externalWorkerStatusFailed}, fmt.Errorf("create worker output directory: %w", err)
	}
	inputPath := filepath.Join(req.OutputDir, "input.json")
	outputPath := filepath.Join(req.OutputDir, "output.json")
	schemaPath := filepath.Join(req.OutputDir, "output-schema.json")
	if err := writeCLIInput(inputPath, req, outputPath); err != nil {
		return WorkerResult{Status: externalWorkerStatusFailed}, err
	}
	if err := writeCLIOutputSchema(schemaPath, req.Audit); err != nil {
		return WorkerResult{Status: externalWorkerStatusFailed}, err
	}

	command := r.resolve(r.config.Command, req, inputPath, outputPath, schemaPath)
	args := make([]string, 0, len(r.config.Args))
	for _, arg := range r.config.Args {
		args = append(args, r.resolve(arg, req, inputPath, outputPath, schemaPath))
	}
	dir := r.resolve(r.config.Cwd, req, inputPath, outputPath, schemaPath)
	if dir == "" {
		dir = req.Workspace
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if r.config.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, r.config.Timeout)
		defer cancel()
	}
	started := time.Now()
	execution, runErr := r.runner.Run(runCtx, command, args, dir, r.env())
	duration := time.Since(started)
	result := WorkerResult{
		Status:   externalWorkerStatusDone,
		ExitCode: execution.ExitCode,
		Duration: duration,
		Stderr:   execution.Stderr,
	}
	if runErr != nil {
		if errors.Is(runErr, context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			result.Status = externalWorkerStatusTimeout
			return result, fmt.Errorf("worker CLI timeout after %s: %w", r.config.Timeout, runErr)
		}
		result.Status = externalWorkerStatusFailed
		return result, runErr
	}
	if execution.ExitCode != 0 {
		result.Status = externalWorkerStatusFailed
		return result, fmt.Errorf("worker CLI exited with code %d", execution.ExitCode)
	}

	raw := strings.TrimSpace(execution.Stdout)
	if data, err := os.ReadFile(outputPath); err == nil && strings.TrimSpace(string(data)) != "" {
		raw = strings.TrimSpace(string(data))
	}
	result.RawOutput = raw
	parsed, parseErr := parseCLIOutput(raw)
	if parseErr != nil {
		result.Status = externalWorkerStatusUnparsed
		result.Warnings = append(result.Warnings, "worker CLI output was not valid JSON")
		return result, nil
	}
	if strings.TrimSpace(parsed.Status) != "" {
		result.Status = strings.TrimSpace(parsed.Status)
	}
	if result.Status == "" {
		result.Status = externalWorkerStatusDone
	}
	result.Summary = strings.TrimSpace(parsed.Summary)
	result.Findings = append([]ExternalFinding(nil), parsed.Findings...)
	result.Warnings = append(result.Warnings, parsed.Notes...)
	return result, nil
}

type cliOutput struct {
	Status   string            `json:"status"`
	Summary  string            `json:"summary"`
	Findings []ExternalFinding `json:"findings"`
	Notes    []string          `json:"notes"`
}

func parseCLIOutput(raw string) (cliOutput, error) {
	var parsed cliOutput
	if err := json.Unmarshal([]byte(normalizeCLIJSON(raw)), &parsed); err == nil && strings.TrimSpace(parsed.Status) != "" && strings.TrimSpace(parsed.Summary) != "" {
		return parsed, nil
	}

	// Some agents (notably Claude Code with --output-format json) wrap the
	// requested JSON contract in their own result envelope. Unwrap one level so
	// a compliant final answer is still parsed instead of becoming "unparsed".
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Output json.RawMessage `json:"output"`
		Text   json.RawMessage `json:"text"`
	}
	if err := json.Unmarshal([]byte(normalizeCLIJSON(raw)), &envelope); err != nil {
		return parsed, err
	}
	for _, candidate := range []json.RawMessage{envelope.Result, envelope.Output, envelope.Text} {
		if len(candidate) == 0 {
			continue
		}
		value := string(candidate)
		var text string
		if err := json.Unmarshal(candidate, &text); err == nil {
			value = text
		}
		if err := json.Unmarshal([]byte(normalizeCLIJSON(value)), &parsed); err == nil {
			return parsed, nil
		}
	}
	return parsed, errors.New("worker CLI output does not contain the JSON contract")
}

func normalizeCLIJSON(raw string) string {
	value := strings.TrimSpace(raw)
	if !strings.HasPrefix(value, "```") {
		return value
	}
	if index := strings.Index(value, "\n"); index >= 0 {
		value = value[index+1:]
	}
	value = strings.TrimSpace(value)
	return strings.TrimSuffix(value, "```")
}

func cliFindingExample(audit bool) map[string]any {
	if audit {
		return map[string]any{
			"title": "string", "cwe_id": "CWE-89", "severity": "high",
			"summary": "string", "evidence": "string", "file": "relative/path.go",
			"line": 1, "symbol": "FunctionName", "confidence": 0.75,
		}
	}
	return map[string]any{
		"title": "Login endpoint SQL injection", "vuln_class": "SQL Injection",
		"cwe_id": "CWE-89", "severity": "high", "summary": "string",
		"evidence": "reproduction command plus the decisive output lines",
		"confidence": 0.75,
	}
}

func writeCLIOutputSchema(path string, audit bool) error {
	findingRequired := []string{"title", "cwe_id", "severity", "file", "line"}
	if !audit {
		findingRequired = []string{"title", "severity", "summary"}
	}
	cweID := map[string]any{"type": "string", "minLength": 1}
	file := map[string]any{"type": "string", "minLength": 1}
	if !audit {
		cweID = map[string]any{"type": "string"}
		file = map[string]any{"type": "string"}
	}
	schema := map[string]any{
		"$schema":              "http://json-schema.org/draft-07/schema#",
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"status", "summary"},
		"properties": map[string]any{
			"status":  map[string]any{"type": "string", "enum": []string{"done", "failed", "timeout"}},
			"summary": map[string]any{"type": "string", "minLength": 1},
			"findings": map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": false, "required": findingRequired, "properties": map[string]any{
				"title":      map[string]any{"type": "string", "minLength": 1},
				"vuln_class": map[string]any{"type": "string"},
				"cwe_id":     cweID,
				"severity":   map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low"}},
				"summary":    map[string]any{"type": "string"},
				"evidence":   map[string]any{"type": "string"},
				"file":       file,
				"line":       map[string]any{"type": "integer", "minimum": 1},
				"symbol":     map[string]any{"type": "string"},
				"confidence": map[string]any{"type": "number", "minimum": 0, "maximum": 1},
			}}},
			"notes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
	}
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeCLIInput(path string, req WorkerRequest, outputPath string) error {
	findingExample := cliFindingExample(req.Audit)
	taskMode := "code_audit"
	if !req.Audit {
		taskMode = "pentest"
		findingExample = map[string]any{
			"title": "Login endpoint SQL injection", "vuln_class": "SQL Injection",
			"cwe_id": "CWE-89", "severity": "high", "summary": "string",
			"evidence": "reproduction command plus the decisive output lines",
			"confidence": 0.75,
		}
	}
	payload := map[string]any{
		"task_id":       req.TaskID,
		"intent_id":     req.IntentID,
		"worker":        req.Name,
		"prompt":        "Use your native tools as needed to complete this request. When finished, return only a JSON object matching output_contract; do not write to output_path.\n\n" + req.Prompt,
		"workspace":     req.Workspace,
		"snapshot_root": req.SnapshotRoot,
		"output_path":   outputPath,
		"task_mode":     taskMode,
		"output_contract": map[string]any{
			"status":  "done|failed|timeout",
			"summary": "string",
			"findings": []map[string]any{findingExample},
			"notes": []string{"string"},
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (r *CLIRuntime) resolve(value string, req WorkerRequest, inputPath, outputPath, schemaPath string) string {
	replacements := []string{
		"{{task_id}}", strconv.FormatInt(req.TaskID, 10),
		"{{intent_id}}", strconv.FormatInt(req.IntentID, 10),
		"{{workspace}}", req.Workspace,
		"{{snapshot_root}}", req.SnapshotRoot,
		"{{prompt}}", req.Prompt,
		"{{input_file}}", inputPath,
		"{{output_file}}", outputPath,
		"{{schema_file}}", schemaPath,
	}
	for i := 0; i+1 < len(replacements); i += 2 {
		value = strings.ReplaceAll(value, replacements[i], replacements[i+1])
	}
	return value
}

func (r *CLIRuntime) env() []string {
	out := append([]string(nil), os.Environ()...)
	keys := make([]string, 0, len(r.config.Env))
	for key := range r.config.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, key+"="+r.config.Env[key])
	}
	return out
}

type cliExecution struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type cliRunner interface {
	Run(ctx context.Context, command string, args []string, dir string, env []string) (cliExecution, error)
}

type osCLIRunner struct{}

func (osCLIRunner) Run(ctx context.Context, command string, args []string, dir string, env []string) (cliExecution, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = dir
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	return cliExecution{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitCode}, err
}
