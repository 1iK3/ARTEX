package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkerBackendsHandler(t *testing.T) {
	server := &Server{}
	request := httptest.NewRequest(http.MethodGet, "/api/worker-backends", nil)
	recorder := httptest.NewRecorder()

	server.workerBackends(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		DefaultBackend string `json:"default_backend"`
		Backends       []struct {
			Backend                 string   `json:"backend"`
			Label                   string   `json:"label"`
			External                bool     `json:"external"`
			RequiresCommand         bool     `json:"requires_command"`
			Modes                   []string `json:"modes"`
			SuggestedMode           string   `json:"suggested_mode"`
			Command                 string   `json:"suggested_command"`
			Args                    []string `json:"suggested_args"`
			SuggestedPrivilegedArgs []string `json:"suggested_privileged_args"`
		} `json:"backends"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.DefaultBackend != "builtin" || len(response.Backends) != 7 {
		t.Fatalf("response = %+v", response)
	}
	want := []string{"builtin", "codex", "opencode", "claudecode", "cursor", "pi", "custom"}
	for index, backend := range want {
		if response.Backends[index].Backend != backend {
			t.Fatalf("backend[%d] = %q, want %q", index, response.Backends[index].Backend, backend)
		}
	}
	builtin := response.Backends[0]
	if builtin.External || builtin.RequiresCommand || builtin.SuggestedMode != "static" {
		t.Fatalf("builtin backend = %+v", builtin)
	}
	for _, backend := range response.Backends[1:] {
		if !backend.External || !backend.RequiresCommand || backend.SuggestedMode != "static" {
			t.Fatalf("external backend = %+v", backend)
		}
		if len(backend.Modes) != 2 || backend.Modes[0] != "static" || backend.Modes[1] != "privileged" {
			t.Fatalf("modes = %+v", backend.Modes)
		}
		if backend.Backend != "custom" && (backend.Command == "" || len(backend.Args) == 0) {
			t.Fatalf("known backend lacks a command template: %+v", backend)
		}
	}
	codexArgs := strings.Join(response.Backends[1].Args, " ")
	if !strings.Contains(codexArgs, "--skip-git-repo-check") {
		t.Fatalf("codex args must run outside git repositories (pentest workspaces): %v", response.Backends[1].Args)
	}
	if !strings.Contains(codexArgs, "--output-schema {{schema_file}} --output-last-message {{output_file}} {{prompt}}") {
		t.Fatalf("codex args must enforce the output schema: %v", response.Backends[1].Args)
	}
	codexPrivilegedArgs := strings.Join(response.Backends[1].SuggestedPrivilegedArgs, " ")
	if !strings.Contains(codexPrivilegedArgs, "--skip-git-repo-check") {
		t.Fatalf("codex privileged args must run outside git repositories: %v", response.Backends[1].SuggestedPrivilegedArgs)
	}
	if !strings.Contains(codexPrivilegedArgs, "--dangerously-bypass-approvals-and-sandbox") {
		t.Fatalf("codex privileged args = %v", response.Backends[1].SuggestedPrivilegedArgs)
	}
}

func TestWorkerBackendsRouteRequiresAuth(t *testing.T) {
	server := &Server{}
	handler := server.Handler()
	request := httptest.NewRequest(http.MethodGet, "/api/worker-backends", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "codex") {
		t.Fatalf("unauthenticated response leaked backend catalog: %s", recorder.Body.String())
	}
}
