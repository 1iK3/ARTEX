package audit

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func validConfirmedEvidence() CodeEvidence {
	return CodeEvidence{
		CWEID:      "CWE-89",
		Title:      "SQL injection in UserDao.find",
		Severity:   SeverityHigh,
		Confidence: 0.86,
		Verification: Verification{
			Status:           VerificationConfirmed,
			Method:           MethodTaintTrace,
			AlternativePath:  "UserController.search -> UserDao.find",
			DesignValidation: DesignValidationRealVuln,
		},
		Location: CodeLocation{Path: "src/UserDao.java", Line: 42, EndLine: 44, Symbol: "UserDao.find"},
		Source: &CodeLocation{
			Path: "src/UserController.java", Line: 23, Symbol: "HttpServletRequest.getParameter",
		},
		Sink: &CodeLocation{
			Path: "src/UserDao.java", Line: 42, Symbol: "Statement.executeQuery",
			API: "java.sql.Statement.executeQuery",
		},
		Trace: []TraceStep{
			{Path: "src/UserController.java", Line: 23, Symbol: "UserController.search", Note: "entry"},
			{Path: "src/UserDao.java", Line: 42, Symbol: "UserDao.find", Note: "sink"},
		},
		Sanitizers: []SanitizerVerdict{{Symbol: "PreparedStatement.setString", Verdict: SanitizerMissing}},
		Reachability: &Reachability{
			Reachable: true, EntryPoint: "GET /search", AuthRequired: false, AuthStateRecorded: true,
		},
		Analysis: Analysis{Phase: "S5", Round: 1, Backend: "codegraph"},
	}
}

func TestCodeEvidenceValidation(t *testing.T) {
	if err := ValidateCodeEvidence(validConfirmedEvidence()); err != nil {
		t.Fatalf("valid confirmed evidence rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CodeEvidence)
		want   string
	}{
		{"missing source", func(ev *CodeEvidence) { ev.Source = nil }, "requires source"},
		{"missing sink", func(ev *CodeEvidence) { ev.Sink = nil }, "requires sink"},
		{"missing trace", func(ev *CodeEvidence) { ev.Trace = nil }, "trace step"},
		{"missing sanitizers", func(ev *CodeEvidence) { ev.Sanitizers = nil }, "sanitizer"},
		{"unknown sanitizer verdict", func(ev *CodeEvidence) { ev.Sanitizers[0].Verdict = "unknown" }, "verdict"},
		{"empty sanitizer symbol", func(ev *CodeEvidence) { ev.Sanitizers[0].Symbol = " " }, "sanitizers[0].symbol"},
		{"low confidence", func(ev *CodeEvidence) { ev.Confidence = 0.49 }, "confidence >= 0.5"},
		{"no reachability", func(ev *CodeEvidence) { ev.Reachability = nil }, "reachable"},
		{"unreachable", func(ev *CodeEvidence) { ev.Reachability.Reachable = false }, "reachable"},
		{"no entry point", func(ev *CodeEvidence) { ev.Reachability.EntryPoint = " " }, "entry_point"},
		{"auth state not recorded", func(ev *CodeEvidence) { ev.Reachability.AuthStateRecorded = false }, "auth_state_recorded"},
		{"no cross check", func(ev *CodeEvidence) { ev.Verification.AlternativePath = "" }, "alternative path or engine"},
		{"engine without design validation", func(ev *CodeEvidence) {
			ev.Verification.AlternativePath = ""
			ev.Verification.DesignValidation = ""
			ev.Engines = []EngineEvidence{{Name: "codeql", Confidence: 0.7, RawRef: "sarif://run/1"}}
		}, "design_validation"},
		{"bad design validation", func(ev *CodeEvidence) { ev.Verification.DesignValidation = "by_design" }, "design_validation"},
		{"missing method", func(ev *CodeEvidence) { ev.Verification.Method = "" }, "verification.method"},
		{"unknown method", func(ev *CodeEvidence) { ev.Verification.Method = "vibes" }, "unknown verification method"},
		{"unknown status", func(ev *CodeEvidence) { ev.Verification.Status = "verified" }, "unknown verification status"},
		{"unknown severity", func(ev *CodeEvidence) { ev.Severity = "severe" }, "unknown severity"},
		{"bad cwe", func(ev *CodeEvidence) { ev.CWEID = "89" }, "cwe_id"},
		{"confidence above one", func(ev *CodeEvidence) { ev.Confidence = 1.1 }, "within [0,1]"},
		{"nan confidence", func(ev *CodeEvidence) { ev.Confidence = math.NaN() }, "within [0,1]"},
		{"empty title", func(ev *CodeEvidence) { ev.Title = "  " }, "title"},
		{"zero location line", func(ev *CodeEvidence) { ev.Location.Line = 0 }, "location.line"},
		{"empty location symbol", func(ev *CodeEvidence) { ev.Location.Symbol = "" }, "location.symbol"},
		{"absolute location path", func(ev *CodeEvidence) { ev.Location.Path = "/etc/passwd" }, "must be relative"},
		{"escaping location path", func(ev *CodeEvidence) { ev.Location.Path = "src/../../etc/passwd" }, "escapes"},
		{"windows drive path", func(ev *CodeEvidence) { ev.Location.Path = `C:\repo\A.java` }, "must be relative"},
		{"trace path escape", func(ev *CodeEvidence) { ev.Trace[0].Path = "../outside.java" }, "escapes"},
		{"trace zero line", func(ev *CodeEvidence) { ev.Trace[0].Line = 0 }, "trace[0].line"},
		{"empty engine name", func(ev *CodeEvidence) { ev.Engines = []EngineEvidence{{Confidence: 0.5}} }, "engines[0].name"},
		{"engine without raw ref", func(ev *CodeEvidence) { ev.Engines = []EngineEvidence{{Name: "joern"}} }, "engines[0].raw_ref"},
		{"engine confidence", func(ev *CodeEvidence) {
			ev.Engines = []EngineEvidence{{Name: "joern", Confidence: 2, RawRef: "joern://cpg/1"}}
		}, "within [0,1]"},
		{"absolute poc path", func(ev *CodeEvidence) {
			ev.POC = &POCEvidence{Kind: "script", ArtifactPath: "/tmp/poc.py"}
		}, "must be relative"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := validConfirmedEvidence()
			tc.mutate(&ev)
			err := ValidateCodeEvidence(ev)
			if err == nil {
				t.Fatalf("expected validation error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestCodeEvidenceStatusRules(t *testing.T) {
	// Confirmed source/sink may be symbol-only (the location carries the file).
	ev := validConfirmedEvidence()
	ev.Source = &CodeLocation{Symbol: "getParameter"}
	ev.Sink = &CodeLocation{Symbol: "executeQuery"}
	if err := ValidateCodeEvidence(ev); err != nil {
		t.Fatalf("symbol-only source/sink rejected: %v", err)
	}

	// Medium confirmed does not need reachability/design validation.
	ev = validConfirmedEvidence()
	ev.Severity = SeverityMedium
	ev.Confidence = 0.6
	ev.Verification.AlternativePath = ""
	ev.Verification.DesignValidation = ""
	ev.Reachability = nil
	if err := ValidateCodeEvidence(ev); err != nil {
		t.Fatalf("medium confirmed rejected: %v", err)
	}

	// Critical confirmed may satisfy the cross-check with engine evidence, but
	// each engine hit must carry both a name and a raw reference.
	ev = validConfirmedEvidence()
	ev.Severity = SeverityCritical
	ev.Verification.AlternativePath = ""
	ev.Engines = []EngineEvidence{{Name: "codeql", QueryID: "qs-1", Confidence: 0.75, RawRef: "sarif://run/7"}}
	if err := ValidateCodeEvidence(ev); err != nil {
		t.Fatalf("critical confirmed with engine evidence rejected: %v", err)
	}
	ev.Engines = []EngineEvidence{{Name: "codeql", QueryID: "qs-1", Confidence: 0.75}}
	if err := ValidateCodeEvidence(ev); err == nil {
		t.Fatal("engine evidence without raw_ref must not corroborate a finding")
	}

	// High confirmed requires an explicit entry point and recorded auth state.
	ev = validConfirmedEvidence()
	ev.Reachability.EntryPoint = ""
	if err := ValidateCodeEvidence(ev); err == nil {
		t.Fatal("high confirmed without an entry point must be rejected")
	}
	ev = validConfirmedEvidence()
	ev.Reachability.AuthStateRecorded = false
	if err := ValidateCodeEvidence(ev); err == nil {
		t.Fatal("high confirmed without a recorded auth state must be rejected")
	}

	// Unverified/candidate may omit the method; other statuses may not.
	candidate := validConfirmedEvidence()
	candidate.Verification = Verification{Status: VerificationCandidate}
	if err := ValidateCodeEvidence(candidate); err != nil {
		t.Fatalf("candidate without method rejected: %v", err)
	}
	if err := ValidateCodeEvidence(candidate, VerificationRefuted); err == nil {
		t.Fatal("refuted status without a method must be rejected")
	}
	refuted := candidate
	refuted.Verification = Verification{Status: VerificationRefuted, Method: MethodManual}
	if err := ValidateCodeEvidence(refuted); err != nil {
		t.Fatalf("refuted evidence with manual method rejected: %v", err)
	}
	designIntent := candidate
	designIntent.Verification = Verification{Status: VerificationDesignIntent, Method: MethodDesignValidation}
	if err := ValidateCodeEvidence(designIntent); err != nil {
		t.Fatalf("design_intent evidence rejected: %v", err)
	}

	// The status parameter overrides the embedded status for the confirmed bar.
	if err := ValidateCodeEvidenceFor(candidate, VerificationConfirmed); err == nil {
		t.Fatal("status override to confirmed must require source/sink/trace")
	}
	if err := ValidateCodeEvidenceFor(validConfirmedEvidence(), VerificationCandidate); err != nil {
		t.Fatalf("status override to candidate rejected: %v", err)
	}
}

func TestCodeEvidenceEnums(t *testing.T) {
	for _, severity := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if !ValidSeverity(severity) {
			t.Errorf("severity %q should be valid", severity)
		}
	}
	for _, severity := range []string{"", "info", "HIGH"} {
		if ValidSeverity(severity) {
			t.Errorf("severity %q should be invalid", severity)
		}
	}
	for _, status := range []string{
		VerificationUnverified, VerificationCandidate, VerificationConfirmed,
		VerificationRefuted, VerificationDesignIntent,
	} {
		if !ValidVerificationStatus(status) {
			t.Errorf("status %q should be valid", status)
		}
	}
	for _, status := range []string{"", "verified", "confirmed "} {
		if ValidVerificationStatus(status) {
			t.Errorf("status %q should be invalid", status)
		}
	}
	for _, method := range []string{
		MethodTaintTrace, MethodAlternativePath, MethodCrossEngine,
		MethodDesignValidation, MethodManual,
	} {
		if !ValidVerificationMethod(method) {
			t.Errorf("method %q should be valid", method)
		}
	}
	for _, method := range []string{"", "taint", "manual "} {
		if ValidVerificationMethod(method) {
			t.Errorf("method %q should be invalid", method)
		}
	}
	for _, verdict := range []string{SanitizerPresent, SanitizerMissing, SanitizerInsufficient} {
		if !ValidSanitizerVerdict(verdict) {
			t.Errorf("verdict %q should be valid", verdict)
		}
	}
	for _, verdict := range []string{"", "unknown", "Present"} {
		if ValidSanitizerVerdict(verdict) {
			t.Errorf("verdict %q should be invalid", verdict)
		}
	}
}

func TestDedupeKey(t *testing.T) {
	k1 := DedupeKey("CWE-89", "/a/../src/A.java", 42, "java.sql.Statement.executeQuery")
	k2 := DedupeKey("CWE-89", "src/A.java", 42, "executeQuery")
	if k1 != k2 {
		t.Fatalf("equivalent findings produced different keys: %q != %q", k1, k2)
	}
	if want := "CWE-89|src/A.java|42|executeQuery"; k1 != want {
		t.Fatalf("key = %q, want %q", k1, want)
	}

	k3 := DedupeKey(" CWE-79 ", `src\view\Page.cs`, 7, " System.Web.HttpUtility.HtmlEncode (string) ")
	if want := "CWE-79|src/view/Page.cs|7|HtmlEncode"; k3 != want {
		t.Fatalf("key = %q, want %q", k3, want)
	}

	// DedupeKey canonicalizes absolute/drive/escaping paths so the same file
	// cannot mint multiple keys.
	for _, path := range []string{
		`C:\repo\src\A.java`, "/repo/./src/A.java", "repo/src/../src/A.java",
	} {
		if got := DedupeKey("CWE-89", path, 42, "executeQuery"); got != "CWE-89|repo/src/A.java|42|executeQuery" {
			t.Fatalf("DedupeKey(%q) = %q, want canonical repo/src/A.java key", path, got)
		}
	}

	// Case is significant (symbols are case-sensitive).
	if DedupeKey("CWE-89", "src/A.java", 42, "ExecuteQuery") ==
		DedupeKey("CWE-89", "src/A.java", 42, "executeQuery") {
		t.Fatal("dedupe key must preserve symbol case")
	}
}

func TestShortSymbol(t *testing.T) {
	tests := map[string]string{
		"java.sql.Statement.executeQuery":         "Statement.executeQuery",
		"java.sql.Statement.executeQuery(String)": "Statement.executeQuery",
		"UserDao.find":                    "UserDao.find",
		" executeQuery() ":                "executeQuery",
		"a.b.c.d":                         "c.d",
		"Foo.Bar.baz ( int x, String y )": "Bar.baz",
		"outer(inner(x))":                 "outer",
		"":                                "",
		"   ":                             "",
	}
	for in, want := range tests {
		if got := ShortSymbol(in); got != want {
			t.Errorf("ShortSymbol(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeCodePath(t *testing.T) {
	tests := map[string]string{
		"/a/../src/A.java": "src/A.java",
		`src\main\A.java`:  "src/main/A.java",
		`a\b`:              "a/b",
		"./src/A.java":     "src/A.java",
		"./a/../b":         "b",
		"a/./b":            "a/b",
		"":                 "",
		".":                "",
		`C:\repo\A.java`:   "repo/A.java",
		`C:/repo/A.java`:   "repo/A.java",
		"/etc/passwd":      "etc/passwd",
		"../outside.java":  "outside.java",
		"a/../../b":        "b",
		"..":               "",
	}
	for in, want := range tests {
		if got := NormalizeCodePath(in); got != want {
			t.Errorf("NormalizeCodePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeCodePathStrict(t *testing.T) {
	valid := map[string]string{
		`a\b`:             "a/b",
		"./a/../b":        "b",
		`src\main\A.java`: "src/main/A.java",
		"src/./A.java":    "src/A.java",
	}
	for in, want := range valid {
		got, err := normalizeCodePath(in)
		if err != nil {
			t.Errorf("normalizeCodePath(%q) rejected: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeCodePath(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{
		`C:\x`, `C:/x`, "c:foo/bar", "/etc/passwd", `\\server\share\x`,
		"../outside.java", "a/../../b", ".", "",
	} {
		if got, err := normalizeCodePath(in); err == nil {
			t.Errorf("normalizeCodePath(%q) = %q, want rejection", in, got)
		}
	}
}

func TestCodeEvidenceMarshal(t *testing.T) {
	ev := validConfirmedEvidence()
	raw, err := MarshalCodeEvidence(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got CodeEvidence
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("marshaled evidence is not valid JSON: %v", err)
	}
	if got.Version != CodeEvidenceVersion {
		t.Fatalf("version = %d, want %d", got.Version, CodeEvidenceVersion)
	}
	if want := "CWE-89|src/UserDao.java|42|executeQuery"; got.DedupeKey != want {
		t.Fatalf("dedupe key = %q, want %q", got.DedupeKey, want)
	}

	// A caller-supplied key is never trusted: it is always replaced by the
	// canonical server key derived from CWE/path/line/sink symbol.
	ev.DedupeKey = "CWE-79|somewhere/else.go|1|nothing"
	raw, err = MarshalCodeEvidence(ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if want := "CWE-89|src/UserDao.java|42|executeQuery"; got.DedupeKey != want {
		t.Fatalf("supplied dedupe key survived: %q, want %q", got.DedupeKey, want)
	}

	// The key is derived from the canonicalized path and sink symbol.
	ev = validConfirmedEvidence()
	ev.Location.Path = `src\..\src\UserDao.java`
	ev.Sink.Symbol = "java.sql.Statement.executeQuery(String)"
	raw, err = MarshalCodeEvidence(ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if want := "CWE-89|src/UserDao.java|42|executeQuery"; got.DedupeKey != want {
		t.Fatalf("canonical dedupe key = %q, want %q", got.DedupeKey, want)
	}

	// Oversized evidence is rejected rather than silently truncated.
	ev = validConfirmedEvidence()
	ev.Impact = strings.Repeat("x", MaxCodeEvidenceBytes+1)
	_, err = MarshalCodeEvidence(ev)
	if !errors.Is(err, ErrCodeEvidenceTooLarge) {
		t.Fatalf("oversized evidence error = %v, want ErrCodeEvidenceTooLarge", err)
	}
}
