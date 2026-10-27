package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func prescanPlan(language string, cwes ...string) Plan {
	return Plan{
		Languages:   []string{language},
		PlannedCWEs: map[string][]string{language: cwes},
		Modules:     []string{},
		EntryPoints: []string{},
	}
}

func TestPrescanJavaSQLSink(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "src", "main", "java", "A.java"), `package demo;
class A {
  void q() throws Exception {
    stmt.executeQuery(q);
  }
}
`)
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	registry := mustLoadRegistry(t)
	plan := prescanPlan(Java, "CWE-89")

	result, err := Prescan(root, profile, plan, registry, PrescanLimits{})
	if err != nil {
		t.Fatalf("Prescan: %v", err)
	}
	if len(result.Sites) != 1 {
		t.Fatalf("sites = %+v, want one", result.Sites)
	}
	site := result.Sites[0]
	if site.Language != Java || site.CWE != "CWE-89" || site.Path != "src/main/java/A.java" || site.Line != 4 || site.Symbol != "executeQuery" {
		t.Fatalf("site = %+v", site)
	}
	sum := sha256.Sum256([]byte("java|CWE-89|src/main/java/A.java|4|executeQuery"))
	wantKey := hex.EncodeToString(sum[:])
	if site.SinkKey != wantKey {
		t.Fatalf("SinkKey = %q, want %q", site.SinkKey, wantKey)
	}
	if len(site.SinkKey) != 64 {
		t.Fatalf("SinkKey length = %d", len(site.SinkKey))
	}

	again, err := Prescan(root, profile, plan, registry, PrescanLimits{})
	if err != nil {
		t.Fatalf("Prescan again: %v", err)
	}
	if len(again.Sites) != 1 || again.Sites[0].SinkKey != site.SinkKey {
		t.Fatalf("second scan differs: %+v", again.Sites)
	}
}

func TestPrescanPythonEval(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "app.py"), "value = 1\nresult = eval(user_input)\n")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prescan(root, profile, prescanPlan(Python, "CWE-94"), mustLoadRegistry(t), PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 {
		t.Fatalf("sites = %+v, want one eval site", result.Sites)
	}
	if got := result.Sites[0]; got.Symbol != "eval" || got.Line != 2 || got.Path != "app.py" || got.CWE != "CWE-94" {
		t.Fatalf("site = %+v", got)
	}
}

func TestPrescanJavaScriptChildProcessExec(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "app.js"), "child_process.exec(cmd);\n")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prescan(root, profile, prescanPlan(JavaScript, "CWE-78"), mustLoadRegistry(t), PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 {
		t.Fatalf("sites = %+v, want one exec site", result.Sites)
	}
	if got := result.Sites[0]; got.Symbol != "exec" || got.Line != 1 || got.CWE != "CWE-78" {
		t.Fatalf("site = %+v", got)
	}
}

func TestPrescanFiltersShortAndGenericSymbols(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "A.java"), "get();\nab();\nsourceSym();\ndangerousCall();\nopen();\nrun();\n")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	registry := Registry{Sinks: map[string][]SinkDefinition{
		Java: {
			{CWEID: "CWE-999", Symbol: "x.get", Kind: "sink"},
			{CWEID: "CWE-999", Symbol: "x.ab", Kind: "sink"},
			{CWEID: "CWE-999", Symbol: "x.sourceSym", Kind: "source"},
			{CWEID: "CWE-999", Symbol: "x.dangerousCall", Kind: "sink"},
			{CWEID: "CWE-999", Symbol: "x.open", Kind: "sink"},
			{CWEID: "CWE-999", Symbol: "x.run", Kind: "sink"},
		},
	}}
	result, err := Prescan(root, profile, prescanPlan(Java, "CWE-999"), registry, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 || result.Sites[0].Symbol != "dangerousCall" {
		t.Fatalf("sites = %+v, want one dangerousCall", result.Sites)
	}
	if result.Stats.SkippedSymbols != 4 {
		t.Fatalf("SkippedSymbols = %d, want 4", result.Stats.SkippedSymbols)
	}
}

func TestPrescanSymbolsAreCappedWithStats(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "A.java"), "danger000();\ndanger200();\n")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	definitions := make([]SinkDefinition, 0, 201)
	for i := 0; i < 201; i++ {
		definitions = append(definitions, SinkDefinition{
			CWEID:  "CWE-999",
			Symbol: fmt.Sprintf("x.danger%03d", i),
			Kind:   "sink",
		})
	}
	registry := Registry{Sinks: map[string][]SinkDefinition{Java: definitions}}
	result, err := Prescan(root, profile, prescanPlan(Java, "CWE-999"), registry, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 || result.Sites[0].Symbol != "danger000" {
		t.Fatalf("sites = %+v, want only danger000", result.Sites)
	}
	if len(result.Stats.TruncatedCWEs) != 1 || result.Stats.TruncatedCWEs[0] != "java|CWE-999" {
		t.Fatalf("TruncatedCWEs = %v", result.Stats.TruncatedCWEs)
	}
}

func TestPrescanSiteCapPerCWE(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "A.java"), "stmt.executeQuery(q1);\nstmt.executeQuery(q2);\nstmt.executeQuery(q3);\n")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prescan(root, profile, prescanPlan(Java, "CWE-89"), mustLoadRegistry(t), PrescanLimits{MaxSitesPerCWE: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 2 {
		t.Fatalf("sites = %+v, want two", result.Sites)
	}
	if result.Sites[0].Line != 1 || result.Sites[1].Line != 2 {
		t.Fatalf("site lines = %d,%d, want 1,2", result.Sites[0].Line, result.Sites[1].Line)
	}
	if !equalStrings(result.Stats.SiteCapCWEs, []string{"java|CWE-89"}) {
		t.Fatalf("SiteCapCWEs = %v, want [java|CWE-89]", result.Stats.SiteCapCWEs)
	}
}

func TestPrescanExcludesTestsVendorAndGenerated(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "src", "main", "java", "A.java"), "stmt.executeQuery(q);\n")
	writeAuditTestFile(t, filepath.Join(root, "src", "test", "java", "ATest.java"), "stmt.executeQuery(q);\n")
	writeAuditTestFile(t, filepath.Join(root, "vendor", "V.java"), "stmt.executeQuery(q);\n")
	writeAuditTestFile(t, filepath.Join(root, "node_modules", "N.java"), "stmt.executeQuery(q);\n")

	registry := mustLoadRegistry(t)
	plan := prescanPlan(Java, "CWE-89")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prescan(root, profile, plan, registry, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 || result.Sites[0].Path != "src/main/java/A.java" {
		t.Fatalf("default sites = %+v, want only main source", result.Sites)
	}

	profile, err = ProfileSource(root, PrescanLimits{IncludeTests: true, IncludeVendor: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err = Prescan(root, profile, plan, registry, PrescanLimits{IncludeTests: true, IncludeVendor: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 3 {
		t.Fatalf("include sites = %+v, want main/test/vendor", result.Sites)
	}
	for _, site := range result.Sites {
		if strings.Contains(site.Path, "node_modules") {
			t.Fatalf("node_modules must always be excluded: %+v", site)
		}
	}
}

func TestPrescanSkipsBinaryMinifiedAndLargeFiles(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "app.js"), "child_process.exec(cmd);\n")
	writeAuditTestFile(t, filepath.Join(root, "app.min.js"), "child_process.exec(cmd);\n")
	writeAuditTestFile(t, filepath.Join(root, "binary.java"), "stmt.executeQuery(q);\x00hidden\n")
	writeAuditTestFile(t, filepath.Join(root, "large.java"), "stmt.executeQuery(q);\n"+strings.Repeat("x", 1000))
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	// Java CWE-89: binary and oversized Java files are skipped; app.js is not a
	// Java file. app.min.js is skipped for the JavaScript pass.
	result, err := Prescan(root, profile, prescanPlan(Java, "CWE-89"), mustLoadRegistry(t), PrescanLimits{MaxFileBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 0 {
		t.Fatalf("java sites = %+v, want none", result.Sites)
	}
	result, err = Prescan(root, profile, prescanPlan(JavaScript, "CWE-78"), mustLoadRegistry(t), PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 || result.Sites[0].Path != "app.js" {
		t.Fatalf("js sites = %+v, want only app.js", result.Sites)
	}
}

func TestPrescanMaxFilesIsDeterministic(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "a.java"), "stmt.executeQuery(q);\n")
	writeAuditTestFile(t, filepath.Join(root, "b.java"), "stmt.executeQuery(q);\n")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prescan(root, profile, prescanPlan(Java, "CWE-89"), mustLoadRegistry(t), PrescanLimits{MaxFiles: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 || result.Sites[0].Path != "a.java" {
		t.Fatalf("sites = %+v, want a.java only", result.Sites)
	}
	if !result.Stats.FileLimitReached {
		t.Fatalf("FileLimitReached = false, want true")
	}
}

func TestPrescanRecordsBinaryMinifiedAndLargeSkips(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "app.min.js"), "child_process.exec(cmd);\n")
	writeAuditTestFile(t, filepath.Join(root, "binary.java"), "stmt.executeQuery(q);"+string([]byte{0})+"\n")
	writeAuditTestFile(t, filepath.Join(root, "large.java"), "stmt.executeQuery(q);\n"+strings.Repeat("x", 200))
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		Languages: []string{Java, JavaScript},
		PlannedCWEs: map[string][]string{
			Java:       {"CWE-89"},
			JavaScript: {"CWE-78"},
		},
	}
	result, err := Prescan(root, profile, plan, mustLoadRegistry(t), PrescanLimits{MaxFileBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.SkippedBinaryOrMinified != 2 {
		t.Fatalf("SkippedBinaryOrMinified = %d, want 2", result.Stats.SkippedBinaryOrMinified)
	}
	if result.Stats.SkippedLargeFiles != 1 {
		t.Fatalf("SkippedLargeFiles = %d, want 1", result.Stats.SkippedLargeFiles)
	}
}

func TestPrescanRecordsLongLinesAndContinues(t *testing.T) {
	root := t.TempDir()
	longLine := strings.Repeat("x", prescanMaxLineBytes+1)
	writeAuditTestFile(t, filepath.Join(root, "A.java"), longLine+"\nstmt.executeQuery(q);\n")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prescan(root, profile, prescanPlan(Java, "CWE-89"), mustLoadRegistry(t), PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.SkippedLongLines != 1 {
		t.Fatalf("SkippedLongLines = %d, want 1", result.Stats.SkippedLongLines)
	}
	if len(result.Sites) != 1 || result.Sites[0].Line != 2 {
		t.Fatalf("sites = %+v, want one site on line 2 after the long line", result.Sites)
	}
}

func TestPrescanLanguageWithoutSinks(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "main.go"), "package main\nfunc main() { execQuery() }\n")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prescan(root, profile, prescanPlan(Go, "CWE-89"), mustLoadRegistry(t), PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Sites == nil || len(result.Sites) != 0 {
		t.Fatalf("Go sites = %+v, want non-nil empty (registry has no Go sink table)", result.Sites)
	}
}

func TestPrescanEmptyPlanAndMissingRoot(t *testing.T) {
	root := t.TempDir()
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prescan(root, profile, Plan{}, mustLoadRegistry(t), PrescanLimits{})
	if err != nil {
		t.Fatalf("Prescan empty: %v", err)
	}
	if result.Sites == nil || len(result.Sites) != 0 {
		t.Fatalf("empty sites = %+v", result.Sites)
	}
	if _, err := Prescan(filepath.Join(root, "missing"), profile, Plan{}, mustLoadRegistry(t), PrescanLimits{}); err == nil {
		t.Fatal("expected missing root error")
	}
}

func TestPrescanDedupesRepeatedMatchesOnLine(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "app.js"), "child_process.exec(cmd); exec(cmd);\n")
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prescan(root, profile, prescanPlan(JavaScript, "CWE-78"), mustLoadRegistry(t), PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 {
		t.Fatalf("sites = %+v, want one deduped line site", result.Sites)
	}
}

func TestPrescanCRLFLineNumbers(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "A.java")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("class A {\r\n  void q() {\r\n    stmt.executeQuery(q);\r\n  }\r\n}\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prescan(root, profile, prescanPlan(Java, "CWE-89"), mustLoadRegistry(t), PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 || result.Sites[0].Line != 3 {
		t.Fatalf("sites = %+v, want line 3", result.Sites)
	}
}

func TestSinkKeyForMatchesPrescanSite(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "src", "main", "java", "A.java"), `package demo;
class A {
  void q() throws Exception {
    stmt.executeQuery(q);
  }
}
`)
	profile, err := ProfileSource(root, PrescanLimits{})
	if err != nil {
		t.Fatalf("ProfileSource: %v", err)
	}
	result, err := Prescan(root, profile, prescanPlan(Java, "CWE-89"), mustLoadRegistry(t), PrescanLimits{})
	if err != nil {
		t.Fatalf("Prescan: %v", err)
	}
	if len(result.Sites) != 1 {
		t.Fatalf("sites = %+v, want one", result.Sites)
	}
	site := result.Sites[0]
	key := SinkKeyFor(site.Language, site.CWE, site.Path, site.Line, site.Symbol)
	if key != site.SinkKey {
		t.Fatalf("SinkKeyFor = %q, prescan key = %q", key, site.SinkKey)
	}
	if key == "" || len(key) != 64 {
		t.Fatalf("SinkKeyFor length = %d, want 64", len(key))
	}
}
