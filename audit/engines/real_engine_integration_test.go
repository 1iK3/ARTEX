package engines

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/audit"
)

const realJavaFixture = `public class App {
  static class Request {
    String getParameter(String name) { return ""; }
  }
  static class Statement {
    void executeQuery(String sql) { }
  }
  void search(Request request, Statement statement) {
    String q = request.getParameter("q");
    statement.executeQuery("SELECT * FROM users WHERE name = '" + q + "'");
  }
}
`

func realJavaIntent(kind string) DetectionIntent {
	return DetectionIntent{
		ID:         "real-java-" + kind,
		Origin:     OriginSinkRule,
		Language:   audit.Java,
		CWE:        "CWE-89",
		Title:      "SQL Injection real fixture",
		QueryKind:  kind,
		Sources:    []Pattern{{Pattern: "getParameter", Match: MatchMethodCall}},
		Sinks:      []Pattern{{Pattern: "executeQuery", Match: MatchMethodCall}},
		Sanitizers: []Pattern{{Pattern: "setString", Match: MatchMethodCall}},
		Constraints: Constraints{
			MaxResults: 50,
		},
		PreferredEngines: []string{EngineCodeQL, EngineJoern},
	}
}

func realEngineExec(t *testing.T) ExecFunc {
	t.Helper()
	return func(ctx context.Context, name string, args []string, dir string) (string, string, error) {
		stdout, stderr, err := runExec(ctx, name, args, dir)
		t.Logf("ENGINE EXEC: %s %s (dir=%s)\nSTDOUT:\n%s\nSTDERR:\n%s\nERR:%v",
			name, strings.Join(args, " "), dir, truncateEngineLog(stdout), truncateEngineLog(stderr), err)
		return stdout, stderr, err
	}
}

func truncateEngineLog(value string) string {
	const limit = 4000
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}

func logRealFindings(t *testing.T, label string, findings []EngineFinding) {
	t.Helper()
	for index, finding := range findings {
		source := "<nil>"
		if finding.Source != nil {
			source = finding.Source.Path + ":" + finding.Source.Symbol
		}
		sink := "<nil>"
		if finding.Sink != nil {
			sink = finding.Sink.Path + ":" + finding.Sink.Symbol
		}
		t.Logf("%s finding[%d] path=%s line=%d symbol=%q source=%s sink=%s confidence=%v raw=%s message=%q",
			label, index, finding.Location.Path, finding.Location.Line, finding.Location.Symbol,
			source, sink, finding.Confidence, finding.RawRef, finding.Message)
	}
}

func writeRealJavaFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "App.java"), []byte(realJavaFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func codeQLIntegrationBinary(t *testing.T) string {
	t.Helper()
	if bin := strings.TrimSpace(os.Getenv("ARTEX_CODEQL_BIN")); bin != "" {
		return bin
	}
	if bin, err := exec.LookPath("codeql"); err == nil {
		return bin
	}
	for _, candidate := range []string{
		`D:\tools\codeql-win64\codeql\codeql`,
		`D:\tools\codeql-win64\codeql\codeql.exe`,
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	t.Skip("codeql binary is not installed")
	return ""
}

func codeQLIntegrationSearchPath(t *testing.T) string {
	t.Helper()
	if path := strings.TrimSpace(os.Getenv("ARTEX_CODEQL_SEARCH_PATH")); path != "" {
		return path
	}
	if home, err := os.UserHomeDir(); err == nil {
		cache := filepath.Join(home, ".codeql", "packages")
		if info, err := os.Stat(filepath.Join(cache, "codeql", "java-all")); err == nil && info.IsDir() {
			return cache
		}
	}
	return ""
}

func joernIntegrationBins(t *testing.T) (string, string) {
	t.Helper()
	bin := strings.TrimSpace(os.Getenv("ARTEX_JOERN_BIN"))
	parse := strings.TrimSpace(os.Getenv("ARTEX_JOERN_PARSE_BIN"))
	if bin == "" {
		candidates := []string{
			`D:\tools\joern\joern-cli\joern`,
			`D:\tools\joern\joern-cli\joern.bat`,
		}
		for _, candidate := range candidates {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				bin = candidate
				break
			}
		}
	}
	if parse == "" {
		candidates := []string{
			`D:\tools\joern\joern-cli\joern-parse`,
			`D:\tools\joern\joern-cli\joern-parse.bat`,
		}
		for _, candidate := range candidates {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				parse = candidate
				break
			}
		}
	}
	if bin == "" {
		t.Skip("joern binary is not installed")
	}
	if parse == "" {
		t.Skip("joern-parse binary is not installed")
	}
	return bin, parse
}

func assertRealJavaFinding(t *testing.T, label, kind string, wantConfidence float64, findings []EngineFinding) {
	t.Helper()
	if len(findings) == 0 {
		t.Fatalf("%s produced no findings", label)
	}
	finding := findings[0]
	if finding.CWE != "CWE-89" || finding.Language != audit.Java {
		t.Fatalf("%s finding identity = %+v", label, finding)
	}
	if filepath.ToSlash(finding.Location.Path) != "App.java" {
		t.Fatalf("%s location path = %q, want App.java", label, finding.Location.Path)
	}
	if finding.Location.Line != 10 {
		t.Fatalf("%s sink line = %d, want 10", label, finding.Location.Line)
	}
	if !strings.EqualFold(finding.Location.Symbol, "executeQuery") {
		t.Fatalf("%s sink symbol = %q, want executeQuery", label, finding.Location.Symbol)
	}
	if finding.Sink == nil || !strings.EqualFold(finding.Sink.Symbol, "executeQuery") {
		t.Fatalf("%s sink node = %+v", label, finding.Sink)
	}
	if kind == QueryKindTaint {
		if finding.Source == nil || finding.Source.Line != 9 {
			t.Fatalf("%s source node = %+v, want line 9", label, finding.Source)
		}
	}
	if finding.Confidence != wantConfidence {
		t.Fatalf("%s confidence = %v, want %v", label, finding.Confidence, wantConfidence)
	}
}

func TestRealCodeQLJavaTaintAndSinkQueries(t *testing.T) {
	if os.Getenv("ARTEX_ENGINE_INTEGRATION") != "1" {
		t.Skip("set ARTEX_ENGINE_INTEGRATION=1 to run real-engine integration tests")
	}
	bin := codeQLIntegrationBinary(t)
	searchPath := codeQLIntegrationSearchPath(t)
	if searchPath == "" {
		t.Skip("CodeQL java-all pack cache is not installed")
	}
	sourceRoot := writeRealJavaFixture(t)
	workDir := t.TempDir()
	runner := NewCodeQLRunner(bin, workDir)
	runner.SearchPath = searchPath
	runner.RAMMB = 2048
	runner.Timeout = 4 * time.Minute
	runner.execFn = realEngineExec(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	autoRunner := NewCodeQLRunner(bin, workDir)
	autoRunner.Timeout = time.Minute
	autoCapability, autoErr := autoRunner.Probe(ctx)
	if autoErr != nil {
		t.Fatalf("CodeQL cache auto-probe: %v", autoErr)
	}
	if !autoCapability.Available {
		t.Fatalf("CodeQL pack cache was not auto-detected: %+v", autoCapability)
	}
	t.Logf("CodeQL pack cache auto-detected (%s): %v", autoCapability.Version, autoCapability.Languages)

	capability, err := runner.Probe(ctx)
	if err != nil {
		t.Fatalf("CodeQL probe: %v", err)
	}
	if !capability.Available {
		if capability.Reason == "binary_missing" || capability.Reason == "query_pack_missing" {
			t.Skipf("CodeQL unavailable: %s", capability.Reason)
		}
		t.Fatalf("CodeQL probe failed: %+v", capability)
	}
	prepared, err := runner.Prepare(ctx, SourceRef{Root: sourceRoot, Languages: []string{audit.Java}}, []string{audit.Java}, PrepareOptions{WorkDir: workDir, Timeout: runner.Timeout, RAMMB: 2048})
	if err != nil {
		t.Fatalf("CodeQL prepare: %v", err)
	}
	t.Logf("CodeQL %s prepared %s", capability.Version, prepared.Paths[audit.Java])

	for _, kind := range []string{QueryKindTaint, QueryKindSink} {
		intent := realJavaIntent(kind)
		query, err := Render(EngineCodeQL, intent)
		if err != nil {
			t.Fatalf("CodeQL render %s: %v", kind, err)
		}
		if err := runner.Validate(ctx, query); err != nil {
			t.Fatalf("CodeQL validate %s: %v", kind, err)
		}
		findings, err := runner.Run(ctx, query)
		if err != nil {
			t.Fatalf("CodeQL run %s: %v", kind, err)
		}
		t.Logf("CodeQL %s query %s produced %d finding(s)", kind, query.ID, len(findings))
		logRealFindings(t, "CodeQL "+kind, findings)
		confidence := 0.45
		if kind == QueryKindTaint {
			confidence = 0.75
		}
		assertRealJavaFinding(t, "CodeQL "+kind, kind, confidence, findings)
	}
}

func TestRealJoernJavaTaintAndSinkQueries(t *testing.T) {
	if os.Getenv("ARTEX_ENGINE_INTEGRATION") != "1" {
		t.Skip("set ARTEX_ENGINE_INTEGRATION=1 to run real-engine integration tests")
	}
	bin, parse := joernIntegrationBins(t)
	sourceRoot := writeRealJavaFixture(t)
	workDir := t.TempDir()
	runner := NewJoernRunner(bin, parse, workDir)
	runner.Timeout = 3 * time.Minute
	runner.execFn = realEngineExec(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	capability, err := runner.Probe(ctx)
	if err != nil {
		t.Fatalf("Joern probe: %v", err)
	}
	if !capability.Available {
		if capability.Reason == "binary_missing" || capability.Reason == "parse_binary_missing" {
			t.Skipf("Joern unavailable: %s", capability.Reason)
		}
		t.Fatalf("Joern probe failed (check JAVA_HOME/JDK 17): %+v", capability)
	}
	prepared, err := runner.Prepare(ctx, SourceRef{Root: sourceRoot, Languages: []string{audit.Java}}, []string{audit.Java}, PrepareOptions{WorkDir: workDir, Timeout: runner.Timeout})
	if err != nil {
		t.Fatalf("Joern prepare: %v", err)
	}
	t.Logf("Joern %s prepared %s", capability.Version, prepared.Paths[audit.Java])

	for _, kind := range []string{QueryKindTaint, QueryKindSink} {
		intent := realJavaIntent(kind)
		query, err := Render(EngineJoern, intent)
		if err != nil {
			t.Fatalf("Joern render %s: %v", kind, err)
		}
		if err := runner.Validate(ctx, query); err != nil {
			t.Fatalf("Joern validate %s: %v", kind, err)
		}
		findings, err := runner.Run(ctx, query)
		if err != nil {
			t.Fatalf("Joern run %s: %v", kind, err)
		}
		t.Logf("Joern %s query %s produced %d finding(s)", kind, query.ID, len(findings))
		logRealFindings(t, "Joern "+kind, findings)
		confidence := 0.5
		if kind == QueryKindTaint {
			confidence = 0.65
		}
		assertRealJavaFinding(t, "Joern "+kind, kind, confidence, findings)
	}
}
