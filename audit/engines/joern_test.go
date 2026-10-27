package engines

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/audit"
)

func TestJoernProbe(t *testing.T) {
	fake := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		switch {
		case name == "joern" && hasArg(args, "--help"):
			return "Joern 4.0.112 Usage: joern [options]", "", nil
		case name == "joern-parse" && hasArg(args, "--help"):
			return "Usage: joern-parse <source> --output <cpg>", "", nil
		default:
			return "", "", errors.New("unexpected command")
		}
	}}
	runner := &JoernRunner{Bin: "joern", ParseBin: "joern-parse", WorkDir: t.TempDir(), execFn: fake.run}
	capability, err := runner.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !capability.Available || capability.Version != "4.0.112" || !capability.BuildModeNone {
		t.Fatalf("capability = %+v", capability)
	}
	for _, want := range []string{audit.Java, audit.Python, audit.JavaScript, audit.TypeScript, audit.Go, audit.C, audit.CPP} {
		if !containsString(capability.Languages, want) {
			t.Errorf("languages %v missing %s", capability.Languages, want)
		}
	}

	missing := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		return "", "", exec.ErrNotFound
	}}
	runner = &JoernRunner{Bin: "joern", ParseBin: "joern-parse", execFn: missing.run}
	capability, err = runner.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe missing: %v", err)
	}
	if capability.Available || capability.Reason != "binary_missing" {
		t.Fatalf("missing capability = %+v", capability)
	}

	parseMissing := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		if name == "joern" && hasArg(args, "--help") {
			return "Joern 4.0.112 Usage: joern [options]", "", nil
		}
		return "", "", exec.ErrNotFound
	}}
	runner = &JoernRunner{Bin: "joern", ParseBin: "joern-parse", execFn: parseMissing.run}
	capability, err = runner.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe parse missing: %v", err)
	}
	if capability.Available || capability.Reason != "parse_binary_missing" {
		t.Fatalf("parse missing capability = %+v", capability)
	}
}

func TestJoernPrepare(t *testing.T) {
	workDir := t.TempDir()
	sourceRoot := t.TempDir()
	fake := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		for index, arg := range args {
			if arg == "--output" && index+1 < len(args) {
				if err := os.WriteFile(args[index+1], []byte("cpg-content"), 0o600); err != nil {
					return "", "", err
				}
				return "parsed", "", nil
			}
		}
		return "", "", errors.New("missing --output")
	}}
	runner := &JoernRunner{Bin: "joern", ParseBin: "joern-parse", WorkDir: workDir, execFn: fake.run}
	prepared, err := runner.Prepare(context.Background(), SourceRef{Root: sourceRoot}, []string{audit.Java, audit.Python}, PrepareOptions{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(prepared.Languages) != 2 {
		t.Fatalf("prepared = %+v", prepared)
	}
	if prepared.Paths[audit.Java] != prepared.Paths[audit.Python] || prepared.Paths[audit.Java] == "" {
		t.Errorf("paths = %+v", prepared.Paths)
	}
	if prepared.BuildModes[audit.Java] != "parse" {
		t.Errorf("build mode = %q", prepared.BuildModes[audit.Java])
	}
	if _, err := os.Stat(prepared.Paths[audit.Java]); err != nil {
		t.Errorf("CPG missing: %v", err)
	}
	call, ok := fake.find("joern-parse")
	if !ok {
		t.Fatalf("joern-parse not called: %+v", fake.snapshot())
	}
	if len(call.Args) < 1 || call.Args[0] != sourceRoot {
		t.Errorf("parse args = %v", call.Args)
	}
	if !hasArg(call.Args, "--output") {
		t.Errorf("parse args missing --output: %v", call.Args)
	}

	failing := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		return "", "parse exploded", errors.New("exit status 1")
	}}
	runner = &JoernRunner{Bin: "joern", ParseBin: "joern-parse", WorkDir: t.TempDir(), execFn: failing.run}
	failedPrepared, err := runner.Prepare(context.Background(), SourceRef{Root: sourceRoot}, []string{audit.Java}, PrepareOptions{})
	if err == nil {
		t.Fatal("parse failure should return an error")
	}
	if !strings.Contains(failedPrepared.Unsupported[audit.Java], "joern_parse_failed") {
		t.Errorf("unsupported reason = %q", failedPrepared.Unsupported[audit.Java])
	}

	cpgPath := filepath.Join(t.TempDir(), "prebuilt.bin")
	if err := os.WriteFile(cpgPath, []byte("prebuilt-cpg"), 0o600); err != nil {
		t.Fatal(err)
	}
	prebuiltExec := &fakeExec{}
	runner = &JoernRunner{Bin: "joern", ParseBin: "joern-parse", WorkDir: t.TempDir(), CPGPath: cpgPath, execFn: prebuiltExec.run}
	prepared, err = runner.Prepare(context.Background(), SourceRef{Root: sourceRoot}, []string{audit.Java}, PrepareOptions{})
	if err != nil {
		t.Fatalf("prebuilt Prepare: %v", err)
	}
	if prepared.Paths[audit.Java] != cpgPath {
		t.Errorf("prebuilt path = %q", prepared.Paths[audit.Java])
	}
	if prebuiltExec.count() != 0 {
		t.Errorf("prebuilt prepare executed commands: %+v", prebuiltExec.snapshot())
	}

	unsupported, err := runner.Prepare(context.Background(), SourceRef{Root: sourceRoot}, []string{audit.Rust}, PrepareOptions{})
	if err == nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("rust prepare error = %v", err)
	}
	if unsupported.Unsupported[audit.Rust] != "language_not_supported" {
		t.Errorf("rust unsupported = %q", unsupported.Unsupported[audit.Rust])
	}

	runner = &JoernRunner{Bin: "joern", ParseBin: "joern-parse", WorkDir: t.TempDir(), execFn: (&fakeExec{}).run}
	if _, err := runner.Prepare(context.Background(), SourceRef{}, []string{audit.Java}, PrepareOptions{}); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("missing source error = %v", err)
	}
}

func TestJoernValidate(t *testing.T) {
	runner := &JoernRunner{Bin: "joern", ParseBin: "joern-parse", WorkDir: t.TempDir(), execFn: (&fakeExec{}).run}
	q := mustRender(t, EngineJoern, testJavaTaintIntent())
	if err := runner.Validate(context.Background(), q); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	importQuery := q
	importQuery.QueryText += "\nimport sys.process._"
	if err := runner.Validate(context.Background(), importQuery); !errors.Is(err, ErrForbiddenQuery) {
		t.Errorf("import query error = %v", err)
	}

	runtimeQuery := q
	runtimeQuery.QueryText += "\nval runtimeProbe = Runtime.getRuntime"
	if err := runner.Validate(context.Background(), runtimeQuery); !errors.Is(err, ErrForbiddenQuery) {
		t.Errorf("runtime query error = %v", err)
	}

	stringQuery := q
	stringQuery.QueryText += "\nval artexDummy = cpg.call.filter(c => c.name.matches(\".*import.*\"))"
	if err := runner.Validate(context.Background(), stringQuery); err != nil {
		t.Errorf("forbidden token inside a string literal should be data: %v", err)
	}

	freeForm := q
	freeForm.Template = "joern/java/custom"
	if err := runner.Validate(context.Background(), freeForm); !errors.Is(err, ErrForbiddenQuery) {
		t.Errorf("free-form query error = %v", err)
	}

	llmQuery := q
	llmQuery.GeneratedBy = "llm"
	if err := runner.Validate(context.Background(), llmQuery); !errors.Is(err, ErrForbiddenQuery) {
		t.Errorf("llm query error = %v", err)
	}

	triple := q
	triple.QueryText += "\nval s = \"\"\"import sys.process\"\"\""
	if err := runner.Validate(context.Background(), triple); !errors.Is(err, ErrForbiddenQuery) {
		t.Errorf("triple-quoted string error = %v", err)
	}

	interpolated := q
	interpolated.QueryText += "\nval bad = s\"${sys.process}\""
	if err := runner.Validate(context.Background(), interpolated); !errors.Is(err, ErrForbiddenQuery) {
		t.Errorf("interpolated string error = %v", err)
	}

	sandboxed := &JoernRunner{Bin: "joern", SandboxCmd: "bwrap --ro-bind / /", WorkDir: t.TempDir(), execFn: (&fakeExec{}).run}
	if err := sandboxed.Validate(context.Background(), freeForm); err != nil {
		t.Errorf("sandboxed free-form validation: %v", err)
	}
	if err := sandboxed.Validate(context.Background(), importQuery); err != nil {
		t.Errorf("sandboxed import validation: %v", err)
	}

	empty := q
	empty.QueryText = ""
	if err := runner.Validate(context.Background(), empty); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("empty query error = %v", err)
	}
	control := q
	control.QueryText = "val x = 1\x00"
	if err := runner.Validate(context.Background(), control); !errors.Is(err, ErrForbiddenQuery) {
		t.Errorf("control character error = %v", err)
	}
	wrongEngine := q
	wrongEngine.Engine = EngineCodeQL
	if err := runner.Validate(context.Background(), wrongEngine); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("wrong engine error = %v", err)
	}
}

func TestJoernRun(t *testing.T) {
	workDir := t.TempDir()
	cpgPath := filepath.Join(t.TempDir(), "cpg.bin")
	if err := os.WriteFile(cpgPath, []byte("cpg-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout := "Joern log line\n" + JoernJSONMarker + ` [{
		"file":"src/main/java/App.java",
		"line":42,
		"column":7,
		"symbol":"executeQuery",
		"cwe":"CWE-89",
		"message":"tainted flow reaches query",
		"confidence":0.65,
		"trace":[
			{"file":"src/main/java/Controller.java","line":10,"symbol":"getParameter"},
			{"file":"src/main/java/App.java","line":42,"symbol":"executeQuery"}
		]
	}]`
	fake := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		return stdout, "", nil
	}}
	runner := &JoernRunner{Bin: "joern", ParseBin: "joern-parse", WorkDir: workDir, execFn: fake.run}
	q := mustRender(t, EngineJoern, testJavaTaintIntent())
	q.ArtifactPath = cpgPath
	findings, err := runner.Run(context.Background(), q)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	finding := findings[0]
	if finding.Engine != EngineJoern || finding.QueryID != q.ID || finding.CWE != "CWE-89" || finding.Language != audit.Java {
		t.Errorf("finding identity = %+v", finding)
	}
	if finding.Location.Path != "src/main/java/App.java" || finding.Location.Line != 42 || finding.Location.Symbol != "executeQuery" {
		t.Errorf("location = %+v", finding.Location)
	}
	if finding.Source == nil || finding.Source.Line != 10 || finding.Sink == nil || finding.Sink.Line != 42 {
		t.Errorf("source/sink = %+v / %+v", finding.Source, finding.Sink)
	}
	if len(finding.Trace) != 2 || finding.Confidence != 0.65 {
		t.Errorf("trace/confidence = %+v / %v", finding.Trace, finding.Confidence)
	}
	if finding.RawRef != "joern:"+q.ID+":0" {
		t.Errorf("raw ref = %q", finding.RawRef)
	}
	wrapperPath := filepath.Join(workDir, "queries", "joern", safeEngineID(q.ID), "query.sc")
	data, err := os.ReadFile(wrapperPath)
	if err != nil {
		t.Fatalf("wrapper missing: %v", err)
	}
	wrapper := string(data)
	if !strings.Contains(wrapper, JoernJSONMarker) || !strings.Contains(wrapper, "CpgLoader.load") || !strings.Contains(wrapper, "artexSources") {
		t.Errorf("wrapper content unexpected:\n%s", wrapper)
	}
	call, ok := fake.find("joern")
	if !ok {
		t.Fatalf("joern not invoked: %+v", fake.snapshot())
	}
	if !hasArg(call.Args, "--script") || !hasArg(call.Args, wrapperPath) {
		t.Errorf("joern args = %v", call.Args)
	}
}

func TestJoernRunOutputHandling(t *testing.T) {
	workDir := t.TempDir()
	cpgPath := filepath.Join(t.TempDir(), "cpg.bin")
	if err := os.WriteFile(cpgPath, []byte("cpg"), 0o600); err != nil {
		t.Fatal(err)
	}
	q := mustRender(t, EngineJoern, testJavaTaintIntent())
	q.ArtifactPath = cpgPath

	empty := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		return "", "", nil
	}}
	runner := &JoernRunner{Bin: "joern", WorkDir: workDir, execFn: empty.run}
	findings, err := runner.Run(context.Background(), q)
	if err != nil {
		t.Fatalf("empty output: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("empty output findings = %+v", findings)
	}

	noMarker := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		return "joern chattered but produced no result", "", nil
	}}
	runner.execFn = noMarker.run
	if _, err := runner.Run(context.Background(), q); err == nil || !strings.Contains(err.Error(), JoernJSONMarker) {
		t.Fatalf("missing marker error = %v", err)
	}

	badJSON := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		return JoernJSONMarker + " [", "", nil
	}}
	runner.execFn = badJSON.run
	if _, err := runner.Run(context.Background(), q); err == nil {
		t.Fatal("malformed JSON should error")
	}

	ndjson := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		return JoernJSONMarker + ` {"file":"a.java","line":1,"symbol":"firstSink"} {"file":"b.java","line":2,"symbol":"secondSink"}`, "", nil
	}}
	runner.execFn = ndjson.run
	findings, err = runner.Run(context.Background(), q)
	if err != nil {
		t.Fatalf("ndjson output: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("ndjson findings = %d", len(findings))
	}

	missingCPG := q
	missingCPG.ArtifactPath = ""
	runner = &JoernRunner{Bin: "joern", WorkDir: workDir, execFn: empty.run}
	if _, err := runner.Run(context.Background(), missingCPG); !errors.Is(err, ErrMissingArtifact) {
		t.Fatalf("missing CPG error = %v", err)
	}
}

func TestJoernRunTimeoutAndSandbox(t *testing.T) {
	workDir := t.TempDir()
	cpgPath := filepath.Join(t.TempDir(), "cpg.bin")
	if err := os.WriteFile(cpgPath, []byte("cpg"), 0o600); err != nil {
		t.Fatal(err)
	}
	q := mustRender(t, EngineJoern, testJavaTaintIntent())
	q.ArtifactPath = cpgPath

	slow := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		<-ctx.Done()
		return "", "", ctx.Err()
	}}
	runner := &JoernRunner{Bin: "joern", WorkDir: workDir, Timeout: 20 * time.Millisecond, execFn: slow.run}
	if _, err := runner.Run(context.Background(), q); !errors.Is(err, ErrTimeout) {
		t.Fatalf("timeout error = %v", err)
	}

	sandboxed := &fakeExec{fn: func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		return "", "", nil
	}}
	runner = &JoernRunner{
		Bin: "joern", WorkDir: workDir, SandboxCmd: "bwrap --ro-bind / /", execFn: sandboxed.run,
	}
	if _, err := runner.Run(context.Background(), q); err != nil {
		t.Fatalf("sandboxed Run: %v", err)
	}
	call, ok := sandboxed.find("bwrap")
	if !ok {
		t.Fatalf("sandbox command not used: %+v", sandboxed.snapshot())
	}
	if !hasArg(call.Args, "--ro-bind") || !hasArg(call.Args, "joern") || !hasArg(call.Args, "--script") {
		t.Errorf("sandbox args = %v", call.Args)
	}
}

func TestParseJoernOutputMarkerInStderr(t *testing.T) {
	rows, err := parseJoernOutput("log only", JoernJSONMarker+` {"file":"a.java","line":3,"symbol":"sink"}`)
	if err != nil {
		t.Fatalf("parseJoernOutput: %v", err)
	}
	if len(rows) != 1 || rows[0].File != "a.java" || rows[0].Line != 3 {
		t.Errorf("rows = %+v", rows)
	}
}
