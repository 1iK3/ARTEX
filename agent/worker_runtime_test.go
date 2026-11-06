package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

type fakeCLIRunner struct {
	command string
	args    []string
	dir     string
	env     []string

	stdout   string
	stderr   string
	exitCode int
	err      error
}

func (f *fakeCLIRunner) Run(ctx context.Context, command string, args []string, dir string, env []string) (cliExecution, error) {
	f.command, f.args, f.dir, f.env = command, append([]string(nil), args...), dir, append([]string(nil), env...)
	return cliExecution{Stdout: f.stdout, Stderr: f.stderr, ExitCode: f.exitCode}, f.err
}

func newTestCLIRuntime(t *testing.T, runner *fakeCLIRunner) *CLIRuntime {
	t.Helper()
	return newCLIRuntimeWithRunner(CLIRuntimeConfig{
		Backend: "codex",
		Mode:    "privileged",
		Command: "fake-codex",
		Args:    []string{"exec", "{{input_file}}", "{{output_file}}"},
		Cwd:     "{{workspace}}",
		Env:     map[string]string{"NO_COLOR": "1"},
		Timeout: time.Second,
	}, runner)
}

func newTestWorkerRequest(t *testing.T) WorkerRequest {
	t.Helper()
	workspace := t.TempDir()
	return WorkerRequest{
		TaskID:       42,
		IntentID:     77,
		Name:         "work#1",
		Prompt:       "audit the repository",
		Workspace:    workspace,
		SnapshotRoot: workspace,
		OutputDir:    filepath.Join(workspace, "audit", "workers", "77"),
	}
}

func TestCLIRuntimeResolvesPlaceholders(t *testing.T) {
	runner := &fakeCLIRunner{}
	runtime := newTestCLIRuntime(t, runner)
	req := newTestWorkerRequest(t)

	_, err := runtime.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if runner.command != "fake-codex" {
		t.Fatalf("command = %q", runner.command)
	}
	if runner.dir != req.Workspace {
		t.Fatalf("dir = %q, want %q", runner.dir, req.Workspace)
	}
	if len(runner.args) != 3 || !strings.HasSuffix(runner.args[1], "input.json") || !strings.HasSuffix(runner.args[2], "output.json") {
		t.Fatalf("args = %#v", runner.args)
	}
	if !containsEnv(runner.env, "NO_COLOR=1") {
		t.Fatalf("env = %#v", runner.env)
	}
}

func TestCLIRuntimeWritesAndResolvesOutputSchema(t *testing.T) {
	runner := &fakeCLIRunner{stdout: `{"status":"done","summary":"schema enforced"}`}
	runtime := newCLIRuntimeWithRunner(CLIRuntimeConfig{
		Backend: "codex",
		Mode:    "privileged",
		Command: "codex",
		Args: []string{
			"exec",
			"--output-schema",
			"{{schema_file}}",
			"--output-last-message",
			"{{output_file}}",
			"{{input_file}}",
		},
		Cwd: "{{workspace}}",
	}, runner)
	req := newTestWorkerRequest(t)

	result, err := runtime.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "done" {
		t.Fatalf("result = %+v", result)
	}
	if len(runner.args) != 6 || !strings.HasSuffix(runner.args[2], "output-schema.json") || !strings.HasSuffix(runner.args[4], "output.json") || !strings.HasSuffix(runner.args[5], "input.json") {
		t.Fatalf("args = %#v", runner.args)
	}
	schema, err := os.ReadFile(filepath.Join(req.OutputDir, "output-schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var parsed struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	if len(parsed.Required) == 0 {
		t.Fatalf("schema has no required fields: %s", schema)
	}
}

func TestCLIOutputSchemaPentestContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output-schema.json")
	if err := writeCLIOutputSchema(path, false); err != nil {
		t.Fatalf("writeCLIOutputSchema() error = %v", err)
	}
	var schema struct {
		Properties struct {
			Findings struct {
				Items struct {
					Required   []string `json:"required"`
					Properties map[string]struct {
						MinLength *int `json:"minLength"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"findings"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(mustRead(t, path), &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	items := schema.Properties.Findings.Items
	if strings.Join(items.Required, ",") != "title,severity,summary" {
		t.Fatalf("pentest findings required = %v", items.Required)
	}
	if _, ok := items.Properties["vuln_class"]; !ok {
		t.Fatalf("pentest findings schema missing vuln_class: %v", items.Properties)
	}
	if file, ok := items.Properties["file"]; !ok || file.MinLength != nil {
		t.Fatalf("pentest file must stay optional: %#v", items.Properties["file"])
	}
}

func TestCLIOutputSchemaAuditContractKeepsCodeFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output-schema.json")
	if err := writeCLIOutputSchema(path, true); err != nil {
		t.Fatalf("writeCLIOutputSchema() error = %v", err)
	}
	var schema struct {
		Properties struct {
			Findings struct {
				Items struct {
					Required   []string `json:"required"`
					Properties map[string]struct {
						MinLength *int `json:"minLength"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"findings"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(mustRead(t, path), &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	items := schema.Properties.Findings.Items
	if strings.Join(items.Required, ",") != "title,cwe_id,severity,file,line" {
		t.Fatalf("audit findings required = %v", items.Required)
	}
	if file := items.Properties["file"]; file.MinLength == nil {
		t.Fatalf("audit file must stay required (minLength): %#v", file)
	}
}

func TestCLIInputPentestContract(t *testing.T) {
	req := newTestWorkerRequest(t)
	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		t.Fatalf("create output dir: %v", err)
	}
	path := filepath.Join(req.OutputDir, "input.json")
	if err := writeCLIInput(path, req, filepath.Join(req.OutputDir, "output.json")); err != nil {
		t.Fatalf("writeCLIInput() error = %v", err)
	}
	var payload struct {
		TaskMode string         `json:"task_mode"`
		Contract map[string]any `json:"output_contract"`
	}
	if err := json.Unmarshal(mustRead(t, path), &payload); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	if payload.TaskMode != "pentest" {
		t.Fatalf("task_mode = %q, want pentest", payload.TaskMode)
	}
	findings, _ := payload.Contract["findings"].([]any)
	if len(findings) == 0 {
		t.Fatalf("output_contract missing findings example: %#v", payload.Contract)
	}
	example, _ := findings[0].(map[string]any)
	if _, ok := example["vuln_class"]; !ok {
		t.Fatalf("pentest findings example missing vuln_class: %#v", example)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func TestCLIInputPromptRequestsJSONOnlyResponse(t *testing.T) {
	req := newTestWorkerRequest(t)
	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		t.Fatalf("create output dir: %v", err)
	}
	path := filepath.Join(req.OutputDir, "input.json")
	if err := writeCLIInput(path, req, filepath.Join(req.OutputDir, "output.json")); err != nil {
		t.Fatalf("writeCLIInput() error = %v", err)
	}
	var payload struct {
		Prompt string `json:"prompt"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	if !strings.Contains(payload.Prompt, "When finished, return only a JSON object") || !strings.Contains(payload.Prompt, req.Prompt) {
		t.Fatalf("prompt = %q, want JSON-only instruction plus original prompt", payload.Prompt)
	}
}

func containsEnv(env []string, want string) bool {
	for _, item := range env {
		if item == want {
			return true
		}
	}
	return false
}

func TestCLIRuntimeParsesJSONOutput(t *testing.T) {
	runner := &fakeCLIRunner{stdout: `{"status":"done","summary":"found one issue","findings":[{"title":"SQL injection","cwe_id":"CWE-89","severity":"high","evidence":"unsafe query","file":"src/main.go","line":12}]}`}
	runtime := newTestCLIRuntime(t, runner)
	req := newTestWorkerRequest(t)

	result, err := runtime.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "done" || result.Summary != "found one issue" {
		t.Fatalf("result = %+v", result)
	}
	if len(result.Findings) != 1 || result.Findings[0].Title != "SQL injection" || result.Findings[0].Line != 12 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	input, err := os.ReadFile(filepath.Join(req.OutputDir, "input.json"))
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(input, &payload); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	prompt, _ := payload["prompt"].(string)
	if !strings.Contains(prompt, req.Prompt) {
		t.Fatalf("prompt = %q, want %q", prompt, req.Prompt)
	}
}

func TestCLIRuntimeResolvesPromptPlaceholder(t *testing.T) {
	runner := &fakeCLIRunner{stdout: `{"status":"done","summary":"prompt resolved"}`}
	runtime := newCLIRuntimeWithRunner(CLIRuntimeConfig{
		Backend: "opencode",
		Mode:    "privileged",
		Command: "opencode",
		Args:    []string{"run", "--auto", "{{prompt}}"},
		Cwd:     "{{workspace}}",
	}, runner)
	req := newTestWorkerRequest(t)

	if _, err := runtime.Run(context.Background(), req); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(runner.args) != 3 || runner.args[2] != req.Prompt {
		t.Fatalf("args = %#v, want prompt in final argv", runner.args)
	}
}

func TestCLIRuntimeParsesWrappedJSONOutput(t *testing.T) {
	inner := `{"status":"done","summary":"wrapped result"}`
	wrapped := `{"subtype":"success","result":"` + strings.ReplaceAll(inner, `"`, `\"`) + `"}`
	runner := &fakeCLIRunner{stdout: wrapped}
	runtime := newTestCLIRuntime(t, runner)

	result, err := runtime.Run(context.Background(), newTestWorkerRequest(t))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "done" || result.Summary != "wrapped result" {
		t.Fatalf("result = %+v", result)
	}
}

func TestCLIRuntimeNonzeroExit(t *testing.T) {
	runner := &fakeCLIRunner{exitCode: 2, stderr: "boom", err: errors.New("exit status 2")}
	runtime := newTestCLIRuntime(t, runner)

	result, err := runtime.Run(context.Background(), newTestWorkerRequest(t))
	if err == nil || !strings.Contains(err.Error(), "exit status 2") {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "failed" || result.ExitCode != 2 || result.Stderr != "boom" {
		t.Fatalf("result = %+v", result)
	}
}

func TestCLIRuntimeInvalidJSONIsUnparsed(t *testing.T) {
	runner := &fakeCLIRunner{stdout: "not json"}
	runtime := newTestCLIRuntime(t, runner)

	result, err := runtime.Run(context.Background(), newTestWorkerRequest(t))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != "unparsed" || len(result.Warnings) == 0 || result.RawOutput != "not json" {
		t.Fatalf("result = %+v", result)
	}
}

func TestCLIRuntimeTimeout(t *testing.T) {
	runner := &fakeCLIRunner{err: context.DeadlineExceeded}
	runtime := newTestCLIRuntime(t, runner)

	_, err := runtime.Run(context.Background(), newTestWorkerRequest(t))
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("Run() error = %v", err)
	}
}

type fakeWorkerRuntime struct {
	req    WorkerRequest
	result WorkerResult
	err    error
}

func (f *fakeWorkerRuntime) Name() string { return "codex" }

func (f *fakeWorkerRuntime) Run(ctx context.Context, req WorkerRequest) (WorkerResult, error) {
	f.req = req
	return f.result, f.err
}

type fakeExternalAuditDeps struct {
	AuditDeps
	inputs []db.RecordFindingInput
}

func (f *fakeExternalAuditDeps) ReportCodeFinding(ctx context.Context, in db.RecordFindingInput) (*db.RecordedFinding, error) {
	f.inputs = append(f.inputs, in)
	return &db.RecordedFinding{FindingID: int64(len(f.inputs)), NodeID: int64(len(f.inputs))}, nil
}

func TestWorkerExternalRuntimeRecordsCandidateFinding(t *testing.T) {
	workspace := t.TempDir()
	runtime := &fakeWorkerRuntime{result: WorkerResult{
		Status:  "done",
		Summary: "external audit complete",
		Findings: []ExternalFinding{{
			Title:      "SQL injection",
			CWEID:      "CWE-89",
			Severity:   "high",
			Summary:    "unsafe query",
			Evidence:   "query concatenation",
			File:       "src/main.go",
			Line:       12,
			Symbol:     "handler",
			Confidence: 0.9,
		}},
	}}
	deps := &fakeExternalAuditDeps{}
	worker := &Worker{
		externalRuntime: runtime,
		auditDeps:       deps,
		auditMode:       true,
		agentKey:        "code_worker",
		workDir:         workspace,
		auditSourceRoot: workspace,
	}
	intent := &db.Node{ID: 77, Kind: "intent", Payload: json.RawMessage(`"audit source"`)}

	reason, writes, err := worker.execute(context.Background(), "work#1", 42, nil, nil, intent, nil, func(db.Activity) {}, nil, nil, "", "")
	if err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	if reason != harness.ReasonCompleted {
		t.Fatalf("reason = %v, want completed", reason)
	}
	if writes.Findings != 1 {
		t.Fatalf("writes = %+v, want one finding", writes)
	}
	if len(deps.inputs) != 1 {
		t.Fatalf("recorded findings = %d", len(deps.inputs))
	}
	input := deps.inputs[0]
	if input.Verification != audit.VerificationCandidate {
		t.Fatalf("verification = %q, want candidate", input.Verification)
	}
	if input.CodePath != "src/main.go" || input.CodeLine != 12 || input.CodeSymbol != "handler" {
		t.Fatalf("input = %+v", input)
	}
	if runtime.req.Prompt == "" || runtime.req.Workspace != workspace || runtime.req.IntentID != 77 {
		t.Fatalf("request = %+v", runtime.req)
	}
}

func TestWorkerExternalRuntimeFollowsConfiguredPrivilege(t *testing.T) {
	for _, tt := range []struct {
		name       string
		privileged bool
	}{
		{name: "static", privileged: false},
		{name: "privileged", privileged: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			workspace := t.TempDir()
			runtime := &fakeWorkerRuntime{result: WorkerResult{Status: "done", Summary: "external audit complete"}}
			worker := &Worker{
				externalRuntime: runtime,
				auditMode:       true,
				agentKey:        "code_worker",
				workDir:         workspace,
				auditSourceRoot: workspace,
			}
			worker.SetExternalRuntimePrivileged(tt.privileged)
			intent := &db.Node{ID: 78, Kind: "intent", Payload: json.RawMessage(`"audit source"`)}

			_, _, err := worker.execute(context.Background(), "work#1", 42, nil, nil, intent, nil, func(db.Activity) {}, nil, nil, "", "")
			if err != nil {
				t.Fatalf("execute() error = %v", err)
			}
			if runtime.req.Privileged != tt.privileged {
				t.Fatalf("request privilege = %v, want %v", runtime.req.Privileged, tt.privileged)
			}
		})
	}
}

type fakeFindingRecorder struct {
	inputs []db.RecordFindingInput
}

func (f *fakeFindingRecorder) Record(_ context.Context, in db.RecordFindingInput, _ []db.TrafficRef) (*db.RecordedFinding, error) {
	f.inputs = append(f.inputs, in)
	return &db.RecordedFinding{FindingID: int64(len(f.inputs)), NodeID: int64(len(f.inputs))}, nil
}

func TestWorkerExternalPentestRuntimeRecordsFactAndFinding(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("external pentest recorder", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "probe the login form"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(intentID)
	if err != nil || intent == nil {
		t.Fatalf("GetNode(%d) = %v, %v", intentID, intent, err)
	}

	runtime := &fakeWorkerRuntime{result: WorkerResult{
		Status:    "done",
		Summary:   "login probes complete",
		RawOutput: "curl -s http://target/login\n200 OK",
		Findings: []ExternalFinding{
			{Title: "Login SQL injection", VulnClass: "SQL Injection", Severity: "HIGH", Summary: "sqli confirmed", Evidence: "curl ' OR '1'='1 accepted"},
			{Title: "Bad severity finding", Severity: "catastrophic", Summary: "dropped"},
		},
	}}
	recorder := &fakeFindingRecorder{}
	workDir := t.TempDir()
	worker := &Worker{externalRuntime: runtime, findingRecorder: recorder, agentKey: "worker", workDir: workDir}

	var activities []db.Activity
	reason, writes, err := worker.execute(context.Background(), "work#1", task.ID, nil, store, intent, nil, func(a db.Activity) { activities = append(activities, a) }, nil, nil, "", "")
	if err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	if reason != harness.ReasonCompleted {
		t.Fatalf("reason = %v", reason)
	}
	if writes.Facts != 1 || writes.Findings != 1 {
		t.Fatalf("writes = %+v, want one fact and one finding", writes)
	}
	if runtime.req.Audit {
		t.Fatalf("request audit flag = true, want pentest")
	}
	if !strings.Contains(runtime.req.Prompt, "授权渗透测试平台") || !strings.Contains(runtime.req.Prompt, "probe the login form") || !strings.Contains(runtime.req.Prompt, `"status"`) {
		t.Fatalf("prompt = %q", runtime.req.Prompt)
	}
	expectedWorkspace := filepath.Join(workDir, "tasks", strconv.FormatInt(task.ID, 10), "i"+strconv.FormatInt(intentID, 10))
	if runtime.req.Workspace != expectedWorkspace {
		t.Fatalf("workspace = %q, want %q", runtime.req.Workspace, expectedWorkspace)
	}
	if runtime.req.OutputDir != filepath.Join(expectedWorkspace, "worker-cli") {
		t.Fatalf("output dir = %q", runtime.req.OutputDir)
	}
	if len(recorder.inputs) != 1 {
		t.Fatalf("recorded findings = %d", len(recorder.inputs))
	}
	input := recorder.inputs[0]
	if input.TaskID != task.ID || input.IntentID != intentID || input.Severity != "high" || input.VulnClass != "SQL Injection" || input.Worker != "work#1" {
		t.Fatalf("finding input = %+v", input)
	}
	facts, err := store.ListByKind(db.KindFact, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, fact := range facts {
		if fact.Origin == "work#1" && strings.Contains(string(fact.Payload), "login probes complete") {
			found = true
		}
	}
	if !found {
		t.Fatalf("recorded fact not found: %+v", facts)
	}
	edges, err := store.EdgesTouching([]int64{intentID})
	if err != nil {
		t.Fatal(err)
	}
	linked := false
	for _, edge := range edges {
		if edge.Rel == db.RelYields && edge.From == intentID {
			linked = true
		}
	}
	if !linked {
		t.Fatalf("intent->fact edge not found: %+v", edges)
	}
	if len(activities) != 1 || activities[0].Summary != "login probes complete" || activities[0].NodeID == nil || *activities[0].NodeID != intentID {
		t.Fatalf("activities = %+v", activities)
	}
	if !strings.Contains(activities[0].Detail, "跳过无效外部 finding") {
		t.Fatalf("activity detail missing skip warning: %q", activities[0].Detail)
	}
}
