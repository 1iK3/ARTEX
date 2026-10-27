package engines

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/audit"
)

const sarifWithCodeFlow = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "CodeQL", "rules": [{
      "id": "java/sql-injection",
      "name": "SQL injection",
      "properties": {"tags": ["security", "external/cwe/cwe-089"]}
    }]}},
    "results": [{
      "ruleId": "java/sql-injection",
      "level": "error",
      "message": {"text": "This SQL query depends on a user-supplied value."},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "src/main/java/App.java"},
          "region": {"startLine": 42, "startColumn": 7}
        },
        "logicalLocations": [{"name": "find", "fullyQualifiedName": "App.find"}]
      }],
      "codeFlows": [{"threadFlows": [{"locations": [
        {"location": {
          "physicalLocation": {"artifactLocation": {"uri": "src/main/java/Controller.java"}, "region": {"startLine": 10}},
          "logicalLocations": [{"name": "Controller.search"}],
          "message": {"text": "source"}
        }},
        {"location": {
          "physicalLocation": {"artifactLocation": {"uri": "src/main/java/App.java"}, "region": {"startLine": 42}},
          "logicalLocations": [{"name": "Statement.executeQuery"}],
          "message": {"text": "sink"}
        }}
      ]}]}],
      "partialFingerprints": {"primaryLocationLineHash": "abc"}
    }]
  }]
}`

const sarifSinkOnly = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "java/sink"}]}},
    "results": [{
      "ruleId": "java/sink",
      "level": "warning",
      "message": {"text": "dangerous call"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "src/main/java/App.java"},
        "region": {"startLine": 9, "startColumn": 3}
      }}]
    }]
  }]
}`

func TestCodeQLProbe(t *testing.T) {
	fake := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		switch {
		case len(args) == 1 && args[0] == "version":
			return "CodeQL command-line toolchain release 2.20.4.", "", nil
		case len(args) == 2 && args[0] == "resolve" && args[1] == "languages":
			return `java
javascript
python
go
cpp`, "", nil
		case len(args) >= 2 && args[0] == "resolve" && args[1] == "packs":
			return `codeql/java-all@9.2.0: (library)
codeql/javascript-all@2.10.4: (library)
codeql/python-all@7.2.8: (library)`, "", nil
		default:
			return "", "", fmt.Errorf("unexpected args %v", args)
		}
	}}
	searchRoot := t.TempDir()
	runner := &CodeQLRunner{Bin: "codeql", WorkDir: t.TempDir(), SearchPath: searchRoot, execFn: fake.run}
	capability, err := runner.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !capability.Available {
		t.Fatalf("capability unavailable: %+v", capability)
	}
	if capability.Version != "2.20.4" {
		t.Errorf("version = %q", capability.Version)
	}
	packCall, ok := fake.find("codeql", "resolve", "packs")
	if !ok {
		t.Fatalf("resolve packs not called: %+v", fake.snapshot())
	}
	additional := ""
	for _, arg := range packCall.Args {
		if strings.HasPrefix(arg, "--additional-packs=") {
			additional = arg
		}
	}
	if !strings.Contains(additional, searchRoot) {
		t.Errorf("SearchPath was not honored in additional packs: %q", additional)
	}
	if home, err := os.UserHomeDir(); err == nil && !strings.Contains(additional, filepath.Join(home, ".codeql", "packages")) {
		t.Errorf("pack cache root missing from additional packs: %q", additional)
	}
	if !capability.BuildModeNone {
		t.Error("BuildModeNone = false")
	}
	for _, want := range []string{audit.Java, audit.Python, audit.JavaScript, audit.TypeScript} {
		if !containsString(capability.Languages, want) {
			t.Errorf("languages %v missing %s", capability.Languages, want)
		}
	}
	for _, missing := range []string{audit.Go, audit.CPP} {
		if containsString(capability.Languages, missing) {
			t.Errorf("language %s should be unavailable without its query pack: %v", missing, capability.Languages)
		}
	}
}

func TestCodeQLProbeFailures(t *testing.T) {
	missing := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		return "", "", exec.ErrNotFound
	}}
	runner := &CodeQLRunner{Bin: "codeql", execFn: missing.run}
	capability, err := runner.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe missing binary returned error: %v", err)
	}
	if capability.Available || capability.Reason != "binary_missing" {
		t.Fatalf("missing binary capability = %+v", capability)
	}

	noPacks := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		switch {
		case len(args) == 1 && args[0] == "version":
			return "CodeQL 2.20.4", "", nil
		case len(args) == 2 && args[0] == "resolve" && args[1] == "languages":
			return "java", "", nil
		case len(args) >= 2 && args[0] == "resolve" && args[1] == "packs":
			return "", "", nil
		}
		return "", "", nil
	}}
	runner = &CodeQLRunner{Bin: "codeql", execFn: noPacks.run}
	capability, err = runner.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe no packs: %v", err)
	}
	if capability.Available || capability.Reason != "query_pack_missing" {
		t.Fatalf("no packs capability = %+v", capability)
	}

	resolveFailed := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		if len(args) == 1 && args[0] == "version" {
			return "CodeQL 2.20.4", "", nil
		}
		return "", "boom", errors.New("resolve failed")
	}}
	runner = &CodeQLRunner{Bin: "codeql", execFn: resolveFailed.run}
	capability, err = runner.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe resolve failure: %v", err)
	}
	if capability.Available || capability.Reason != "language_resolve_failed" {
		t.Fatalf("resolve failure capability = %+v", capability)
	}
}

func TestCodeQLPrepare(t *testing.T) {
	workDir := t.TempDir()
	sourceRoot := t.TempDir()
	fake := &fakeExec{}
	runner := &CodeQLRunner{Bin: "codeql", WorkDir: workDir, execFn: fake.run}
	prepared, err := runner.Prepare(context.Background(), SourceRef{Root: sourceRoot}, []string{audit.Java, audit.Python}, PrepareOptions{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(prepared.Paths) != 2 || prepared.Paths[audit.Java] == "" || prepared.Paths[audit.Python] == "" {
		t.Fatalf("prepared paths = %+v", prepared.Paths)
	}
	if prepared.BuildModes[audit.Java] != "none" || prepared.BuildModes[audit.Python] != "none" {
		t.Errorf("build modes = %+v", prepared.BuildModes)
	}
	calls := fake.snapshot()
	if len(calls) != 2 {
		t.Fatalf("database create calls = %d, want 2: %+v", len(calls), calls)
	}
	for _, call := range calls {
		if len(call.Args) < 2 || call.Args[0] != "database" || call.Args[1] != "create" {
			t.Fatalf("unexpected call args: %v", call.Args)
		}
		if !hasArg(call.Args, "--build-mode=none") {
			t.Errorf("missing --build-mode=none: %v", call.Args)
		}
		if !hasArg(call.Args, "--source-root="+sourceRoot) {
			t.Errorf("missing source root: %v", call.Args)
		}
		if !hasArg(call.Args, "--overwrite") {
			t.Errorf("missing --overwrite: %v", call.Args)
		}
	}
	javaCall, ok := fake.find("codeql", "database", "create")
	if !ok || !hasArg(javaCall.Args, "--language=java") {
		t.Errorf("Java database create args = %v", javaCall.Args)
	}
	relative, err := filepath.Rel(workDir, prepared.Paths[audit.Java])
	if err != nil || strings.HasPrefix(relative, "..") {
		t.Errorf("database path escapes work dir: %q (%v)", prepared.Paths[audit.Java], err)
	}
}

func TestCodeQLPrepareUnsupportedBuild(t *testing.T) {
	runner := &CodeQLRunner{Bin: "codeql", WorkDir: t.TempDir(), execFn: (&fakeExec{}).run}
	prepared, err := runner.Prepare(context.Background(), SourceRef{Root: t.TempDir()}, []string{audit.CPP}, PrepareOptions{})
	if err == nil || !errors.Is(err, ErrUnsupportedBuildRequired) || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("cpp prepare error = %v", err)
	}
	if !strings.Contains(prepared.Unsupported[audit.CPP], "unsupported_build_required") {
		t.Errorf("cpp unsupported reason = %q", prepared.Unsupported[audit.CPP])
	}

	prebuilt := t.TempDir()
	runner = &CodeQLRunner{Bin: "codeql", WorkDir: t.TempDir(), DBPath: prebuilt, execFn: (&fakeExec{}).run}
	prepared, err = runner.Prepare(context.Background(), SourceRef{Root: t.TempDir()}, []string{audit.CPP}, PrepareOptions{})
	if err != nil {
		t.Fatalf("cpp prepare with prebuilt: %v", err)
	}
	if prepared.Paths[audit.CPP] != prebuilt || prepared.BuildModes[audit.CPP] != "prebuilt" {
		t.Errorf("prebuilt result = %+v", prepared)
	}

	mixedRunner := &CodeQLRunner{Bin: "codeql", WorkDir: t.TempDir(), execFn: (&fakeExec{}).run}
	mixed, err := mixedRunner.Prepare(context.Background(), SourceRef{Root: t.TempDir()}, []string{audit.Java, audit.CPP}, PrepareOptions{})
	if err != nil {
		t.Fatalf("mixed prepare: %v", err)
	}
	if mixed.Paths[audit.Java] == "" || mixed.Unsupported[audit.CPP] == "" {
		t.Errorf("mixed prepare result = %+v", mixed)
	}

	unknown, err := mixedRunner.Prepare(context.Background(), SourceRef{Root: t.TempDir()}, []string{audit.Rust}, PrepareOptions{})
	if err == nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("rust prepare error = %v", err)
	}
	if unknown.Unsupported[audit.Rust] != "language_not_supported" {
		t.Errorf("rust unsupported reason = %q", unknown.Unsupported[audit.Rust])
	}

	noSource, err := mixedRunner.Prepare(context.Background(), SourceRef{}, []string{audit.Java}, PrepareOptions{})
	if err == nil || !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("missing source error = %v", err)
	}
	if noSource.Unsupported[audit.Java] != "source_root_required" {
		t.Errorf("missing source reason = %q", noSource.Unsupported[audit.Java])
	}
}

func TestCodeQLValidateWritesQueryAndQlpacks(t *testing.T) {
	workDir := t.TempDir()
	fake := packAwareCodeQLExec(nil)
	runner := &CodeQLRunner{Bin: "codeql", WorkDir: workDir, execFn: fake.run}
	q := mustRender(t, EngineCodeQL, testJavaTaintIntent())
	if err := runner.Validate(context.Background(), q); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	queryDir := filepath.Join(workDir, "queries", "codeql", safeEngineID(q.ID))
	if _, err := os.Stat(filepath.Join(queryDir, "query.ql")); err != nil {
		t.Errorf("query file missing: %v", err)
	}
	qlpack, err := os.ReadFile(filepath.Join(queryDir, "qlpack.yml"))
	if err != nil {
		t.Errorf("qlpack missing: %v", err)
	}
	if !strings.Contains(string(qlpack), `codeql/java-all: "9.2.0"`) {
		t.Errorf("qlpack dependency is not pinned: %s", qlpack)
	}
	call, ok := fake.find("codeql", "query", "compile")
	if !ok {
		t.Fatalf("query compile was not executed: %+v", fake.snapshot())
	}
	if !strings.HasSuffix(call.Args[len(call.Args)-1], "query.ql") {
		t.Errorf("compile query arg = %v", call.Args)
	}
	if !hasArgPrefix(call.Args, "--additional-packs=") {
		t.Errorf("compile args lack additional packs: %v", call.Args)
	}
}

func TestCodeQLValidateFailures(t *testing.T) {
	q := mustRender(t, EngineCodeQL, testJavaTaintIntent())

	packMissing := packAwareCodeQLExec(func(ctx context.Context, args []string) (string, string, error) {
		return "", "Could not resolve query pack codeql/java-all", errors.New("exit status 2")
	})
	runner := &CodeQLRunner{Bin: "codeql", WorkDir: t.TempDir(), execFn: packMissing.run}
	if err := runner.Validate(context.Background(), q); !errors.Is(err, ErrCapability) {
		t.Fatalf("missing pack error = %v, want ErrCapability", err)
	}

	missingBinary := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		return "", "", exec.ErrNotFound
	}}
	runner = &CodeQLRunner{Bin: "codeql", WorkDir: t.TempDir(), execFn: missingBinary.run}
	if err := runner.Validate(context.Background(), q); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing binary error = %v, want ErrUnavailable", err)
	}

	runner = &CodeQLRunner{Bin: "codeql", WorkDir: t.TempDir(), execFn: (&fakeExec{}).run}
	if err := runner.Validate(context.Background(), QuerySpec{Engine: EngineCodeQL, Language: audit.Java}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("empty query error = %v", err)
	}
	unsupported := q
	unsupported.Language = audit.Rust
	if err := runner.Validate(context.Background(), unsupported); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported language error = %v", err)
	}
	wrongEngine := q
	wrongEngine.Engine = EngineJoern
	if err := runner.Validate(context.Background(), wrongEngine); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("wrong engine error = %v", err)
	}
}

func TestCodeQLValidatePathSafety(t *testing.T) {
	workDir := t.TempDir()
	runner := &CodeQLRunner{Bin: "codeql", WorkDir: workDir, execFn: packAwareCodeQLExec(nil).run}
	q := mustRender(t, EngineCodeQL, testJavaTaintIntent())
	q.ID = "../../escape"
	if err := runner.Validate(context.Background(), q); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	expectedDir := filepath.Join(workDir, "queries", "codeql", "escape")
	if _, err := os.Stat(filepath.Join(expectedDir, "query.ql")); err != nil {
		t.Fatalf("sanitized query path not used: %v", err)
	}
}

func TestCodeQLRunSARIFFixture(t *testing.T) {
	workDir := t.TempDir()
	database := t.TempDir()
	fake := packAwareCodeQLExec(func(ctx context.Context, args []string) (string, string, error) {
		if len(args) >= 2 && args[0] == "database" && args[1] == "analyze" {
			output := ""
			for _, arg := range args {
				if strings.HasPrefix(arg, "--output=") {
					output = strings.TrimPrefix(arg, "--output=")
				}
			}
			if output == "" {
				return "", "", errors.New("missing --output")
			}
			return "", "", os.WriteFile(output, []byte(sarifWithCodeFlow), 0o600)
		}
		return "", "", fmt.Errorf("unexpected call: %v", args)
	})
	runner := &CodeQLRunner{Bin: "codeql", WorkDir: workDir, RAMMB: 4096, execFn: fake.run}
	q := mustRender(t, EngineCodeQL, testJavaTaintIntent())
	q.ArtifactPath = database
	findings, err := runner.Run(context.Background(), q)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Confidence != 0.75 || finding.Severity != audit.SeverityHigh {
		t.Errorf("finding confidence/severity = %v/%q", finding.Confidence, finding.Severity)
	}
	if finding.CWE != "CWE-89" || finding.Language != audit.Java || finding.QueryID != q.ID {
		t.Errorf("finding meta = %+v", finding)
	}
	if finding.Source == nil || finding.Source.Path != "src/main/java/Controller.java" || finding.Source.Line != 10 {
		t.Errorf("source = %+v", finding.Source)
	}
	if finding.Sink == nil || finding.Sink.Path != "src/main/java/App.java" || finding.Sink.Line != 42 {
		t.Errorf("sink = %+v", finding.Sink)
	}
	if len(finding.Trace) != 2 {
		t.Errorf("trace = %+v", finding.Trace)
	}
	if finding.RawRef != "sarif:java/sql-injection:0" {
		t.Errorf("raw ref = %q", finding.RawRef)
	}
	analyze, ok := fake.find("codeql", "database", "analyze")
	if !ok {
		t.Fatalf("analyze not called: %+v", fake.snapshot())
	}
	for _, want := range []string{"--format=sarif-latest", "--ram=4096", "--threads=0"} {
		if !hasArg(analyze.Args, want) {
			t.Errorf("analyze args missing %q: %v", want, analyze.Args)
		}
	}
	if !hasArgPrefix(analyze.Args, "--additional-packs=") {
		t.Errorf("analyze args lack additional packs: %v", analyze.Args)
	}
	if analyze.Args[len(analyze.Args)-2] != database {
		t.Errorf("database arg = %q, want %q", analyze.Args[len(analyze.Args)-2], database)
	}
	outputArg := ""
	for _, arg := range analyze.Args {
		if strings.HasPrefix(arg, "--output=") {
			outputArg = strings.TrimPrefix(arg, "--output=")
		}
	}
	relative, relErr := filepath.Rel(workDir, outputArg)
	if relErr != nil || strings.HasPrefix(relative, "..") {
		t.Errorf("SARIF output escapes work dir: %q (%v)", outputArg, relErr)
	}
}

func TestCodeQLRunFailuresAndTimeout(t *testing.T) {
	workDir := t.TempDir()
	runner := &CodeQLRunner{Bin: "codeql", WorkDir: workDir, execFn: (&fakeExec{}).run}
	q := mustRender(t, EngineCodeQL, testJavaTaintIntent())
	if _, err := runner.Run(context.Background(), q); !errors.Is(err, ErrMissingArtifact) {
		t.Fatalf("missing database error = %v", err)
	}

	q.ArtifactPath = t.TempDir()
	failing := packAwareCodeQLExec(func(ctx context.Context, args []string) (string, string, error) {
		if len(args) >= 2 && args[0] == "database" && args[1] == "analyze" {
			return "", "analysis failed", errors.New("exit status 1")
		}
		return "", "", nil
	})
	runner.execFn = failing.run
	if _, err := runner.Run(context.Background(), q); err == nil || !strings.Contains(err.Error(), "analysis failed") {
		t.Fatalf("analyze failure error = %v", err)
	}

	slow := packAwareCodeQLExec(func(ctx context.Context, args []string) (string, string, error) {
		if len(args) >= 2 && args[0] == "database" && args[1] == "analyze" {
			<-ctx.Done()
			return "", "", ctx.Err()
		}
		return "", "", nil
	})
	runner.execFn = slow.run
	runner.Timeout = 20 * time.Millisecond
	if _, err := runner.Run(context.Background(), q); !errors.Is(err, ErrTimeout) {
		t.Fatalf("timeout error = %v, want ErrTimeout", err)
	}
}

func TestParseSARIFInfersSymbolWithoutLogicalLocations(t *testing.T) {
	const fixture = `{
	  "version": "2.1.0",
	  "runs": [{
	    "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "artex/test/sqli"}]}},
	    "results": [{
	      "ruleId": "artex/test/sqli",
	      "level": "error",
	      "message": {"text": "Artex CWE-89 taint reaches sink (execute, executeQuery)"},
	      "locations": [{"physicalLocation": {
	        "artifactLocation": {"uri": "App.java"},
	        "region": {"startLine": 10, "startColumn": 28}
	      }}],
	      "codeFlows": [{"threadFlows": [{"locations": [
	        {"location": {
	          "physicalLocation": {"artifactLocation": {"uri": "App.java"}, "region": {"startLine": 9, "startColumn": 16}},
	          "message": {"text": "getParameter(...) : String"}
	        }},
	        {"location": {
	          "physicalLocation": {"artifactLocation": {"uri": "App.java"}, "region": {"startLine": 10, "startColumn": 28}},
	          "message": {"text": "... + ..."}
	        }}
	      ]}]}]
	    }]
	  }]
	}`
	findings, err := ParseSARIF([]byte(fixture), FindingMeta{
		QueryID: "qs-real", CWE: "CWE-89", Language: audit.Java,
		SinkSymbols: []string{"execute", "executeQuery"},
	})
	if err != nil {
		t.Fatalf("ParseSARIF: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	finding := findings[0]
	if finding.Location.Symbol != "executeQuery" {
		t.Errorf("location symbol = %q, want inferred executeQuery", finding.Location.Symbol)
	}
	if finding.Sink == nil || finding.Sink.Symbol != "executeQuery" {
		t.Errorf("sink = %+v", finding.Sink)
	}
	if finding.Source == nil || finding.Source.Symbol != "getParameter" {
		t.Errorf("source = %+v", finding.Source)
	}
	if finding.Payload["symbol"] != "executeQuery" {
		t.Errorf("payload symbol = %v", finding.Payload["symbol"])
	}
	if finding.Confidence != 0.75 || len(finding.Trace) != 2 {
		t.Errorf("confidence/trace = %v/%+v", finding.Confidence, finding.Trace)
	}
}

func TestParseSARIFSinkOnlyFallbackSymbol(t *testing.T) {
	findings, err := ParseSARIF([]byte(sarifSinkOnly), FindingMeta{CWE: "CWE-89", Language: audit.Java})
	if err != nil {
		t.Fatalf("ParseSARIF: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	if findings[0].Location.Symbol == "" || findings[0].Sink == nil || findings[0].Sink.Symbol == "" {
		t.Errorf("sink-only finding lost its symbol fallback: %+v", findings[0])
	}
	if findings[0].Payload["symbol"] == "" {
		t.Errorf("payload symbol is empty: %+v", findings[0].Payload)
	}
}

func TestParseSARIF(t *testing.T) {
	findings, err := ParseSARIF([]byte(sarifWithCodeFlow), FindingMeta{
		QueryID:  "qs-test",
		Language: audit.Java,
	})
	if err != nil {
		t.Fatalf("ParseSARIF: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	finding := findings[0]
	if finding.Engine != EngineCodeQL || finding.QueryID != "qs-test" || finding.CWE != "CWE-89" {
		t.Errorf("finding identity = %+v", finding)
	}
	if finding.Message != "This SQL query depends on a user-supplied value." {
		t.Errorf("message = %q", finding.Message)
	}
	if finding.Severity != audit.SeverityHigh || finding.Confidence != 0.75 {
		t.Errorf("severity/confidence = %q/%v", finding.Severity, finding.Confidence)
	}
	if finding.Location.Path != "src/main/java/App.java" || finding.Location.Line != 42 || finding.Location.Symbol != "App.find" {
		t.Errorf("location = %+v", finding.Location)
	}
	if finding.Source == nil || finding.Source.Symbol != "Controller.search" {
		t.Errorf("source = %+v", finding.Source)
	}
	if finding.Sink == nil || finding.Sink.Symbol != "Statement.executeQuery" {
		t.Errorf("sink = %+v", finding.Sink)
	}
	if len(finding.Trace) != 2 || finding.Trace[0].Line != 10 || finding.Trace[1].Line != 42 {
		t.Errorf("trace = %+v", finding.Trace)
	}
	if finding.Payload["start_column"] != 7 {
		t.Errorf("start column payload = %v", finding.Payload["start_column"])
	}
	if finding.RawRef != "sarif:java/sql-injection:0" {
		t.Errorf("raw ref = %q", finding.RawRef)
	}

	sinkOnly, err := ParseSARIF([]byte(sarifSinkOnly), FindingMeta{
		CWE: "CWE-89", Language: audit.Java,
	})
	if err != nil {
		t.Fatalf("ParseSARIF sink-only: %v", err)
	}
	if len(sinkOnly) != 1 {
		t.Fatalf("sink-only findings = %d", len(sinkOnly))
	}
	if sinkOnly[0].Confidence != 0.45 || sinkOnly[0].Source != nil || sinkOnly[0].Sink == nil {
		t.Errorf("sink-only finding = %+v", sinkOnly[0])
	}
	if sinkOnly[0].Severity != audit.SeverityMedium {
		t.Errorf("warning severity mapping = %q", sinkOnly[0].Severity)
	}

	missing, err := ParseSARIF([]byte(`{"runs":[{"results":[{"message":{"text":"bare result"}}]}]}`), FindingMeta{})
	if err != nil {
		t.Fatalf("ParseSARIF missing fields: %v", err)
	}
	if len(missing) != 1 || missing[0].RawRef != "sarif:unknown:0" || missing[0].Location.Path != "" {
		t.Errorf("missing-field finding = %+v", missing)
	}

	if _, err := ParseSARIF([]byte(`{not json`), FindingMeta{}); err == nil {
		t.Fatal("malformed SARIF should error")
	}
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

const codeQLJavaPackOutput = "codeql/java-all@9.2.0: (library) C:/packs/qlpack.yml"

func packAwareCodeQLExec(analyze func(ctx context.Context, args []string) (string, string, error)) *fakeExec {
	return &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		if len(args) >= 2 && args[0] == "resolve" && args[1] == "packs" {
			return codeQLJavaPackOutput, "", nil
		}
		if analyze != nil {
			return analyze(ctx, args)
		}
		return "", "", nil
	}}
}

func hasArgPrefix(args []string, prefix string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return true
		}
	}
	return false
}
