package engines

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/audit"
)

func testRegistry() audit.Registry {
	return audit.Registry{
		CWE: []audit.CWEDefinition{
			{ID: "CWE-89", Name: "SQL Injection", Priority: "P0"},
			{ID: "CWE-78", Name: "OS Command Injection", Priority: "P0"},
			{ID: "CWE-22", Name: "Path Traversal", Priority: "P0"},
		},
		Sinks: map[string][]audit.SinkDefinition{
			audit.Java: {
				{CWEID: "CWE-89", Symbol: "java.sql.Statement.executeQuery", Kind: "sink", Description: "raw query"},
				{CWEID: "CWE-89", Symbol: "java.sql.Statement.executeQuery", Kind: "sink", Description: "duplicate"},
				{CWEID: "CWE-89", Symbol: "java.sql.Statement.executeQuery(String)", Kind: "sink", Description: "query with signature"},
				{CWEID: "CWE-89", Symbol: "org.example.query.runQuery(java.lang.String)", Kind: "sink", Description: "dotted signature"},
				{CWEID: "CWE-89", Symbol: "java.sql.Statement.execute", Kind: "sink", Description: "raw execute"},
				{CWEID: "CWE-89", Symbol: "get", Kind: "sink", Description: "short generic"},
				{CWEID: "CWE-89", Symbol: "org.example.read", Kind: "sink", Description: "generic read"},
				{CWEID: "CWE-89", Symbol: "a.b", Kind: "sink", Description: "too short"},
				{CWEID: "CWE-89", Symbol: "java.sql.PreparedStatement.setString", Kind: "sanitizer", Description: "bound parameter"},
				{CWEID: "CWE-78", Symbol: "java.lang.Runtime.exec", Kind: "sink", Description: "runtime exec"},
				{CWEID: "*", Symbol: "javax.servlet.http.HttpServletRequest.getParameter", Kind: "source", Description: "request parameter"},
				{CWEID: "*", Symbol: "javax.servlet.http.HttpServletRequest.getHeader", Kind: "source", Description: "request header"},
				{CWEID: "*", Symbol: "java.lang.System.getenv", Kind: "source", Description: "environment variable"},
				{CWEID: "*", Symbol: "flask.request.args", Kind: "source", Description: "broad request args"},
				{CWEID: "*", Symbol: "req.query", Kind: "source", Description: "broad request query"},
				{CWEID: "*", Symbol: "org.example.web.getDottedParam(java.lang.String)", Kind: "source", Description: "dotted source signature"},
				{CWEID: "*", Symbol: "get", Kind: "source", Description: "short generic source"},
			},
		},
	}
}

func TestBuildDetectionIntentsFromRegistry(t *testing.T) {
	plan := audit.Plan{
		Languages: []string{audit.Java},
		PlannedCWEs: map[string][]string{
			audit.Java: {"CWE-89", "CWE-78", "CWE-22"},
		},
		Modules: []string{"user-service"},
	}
	intents, err := BuildDetectionIntents(plan, testRegistry())
	if err != nil {
		t.Fatalf("BuildDetectionIntents: %v", err)
	}
	if len(intents) != 2 {
		t.Fatalf("intent count = %d, want 2 (CWE-22 has no sinks): %+v", len(intents), intents)
	}
	first, second := intents[0], intents[1]
	if first.CWE != "CWE-78" || second.CWE != "CWE-89" {
		t.Fatalf("priority order = %s, %s; want CWE-78 then CWE-89", first.CWE, second.CWE)
	}
	if first.Priority <= second.Priority {
		t.Fatalf("P0 priority order not descending: %d <= %d", first.Priority, second.Priority)
	}

	sql := second
	if sql.Origin != OriginSinkRule {
		t.Errorf("origin = %q, want %q", sql.Origin, OriginSinkRule)
	}
	if sql.QueryKind != QueryKindTaint {
		t.Errorf("query kind = %q, want taint", sql.QueryKind)
	}
	if sql.Title == "" || !strings.Contains(sql.Title, "SQL Injection") {
		t.Errorf("title = %q, want SQL Injection label", sql.Title)
	}
	if sql.Constraints.MaxResults != 200 || sql.Constraints.SeverityMin != "medium" {
		t.Errorf("constraints = %+v", sql.Constraints)
	}
	if len(sql.PreferredEngines) != 3 {
		t.Errorf("preferred engines = %v", sql.PreferredEngines)
	}
	if len(sql.Scope.Paths) != 0 || len(sql.Scope.Modules) != 1 || sql.Scope.Modules[0] != "user-service" {
		t.Errorf("scope = %+v", sql.Scope)
	}
	if !hasPattern(sql.Sinks, "executeQuery", MatchMethodCall) || !hasPattern(sql.Sinks, "execute", MatchMethodCall) {
		t.Errorf("sinks = %+v, want executeQuery and execute", sql.Sinks)
	}
	if !hasPattern(sql.Sinks, "runQuery", MatchMethodCall) {
		t.Errorf("dotted call signature was not reduced to runQuery: %+v", sql.Sinks)
	}
	for _, unwanted := range []string{"get", "read", "b"} {
		if hasPattern(sql.Sinks, unwanted, MatchMethodCall) {
			t.Errorf("generic/short sink %q was not filtered: %+v", unwanted, sql.Sinks)
		}
	}
	if countPattern(sql.Sinks, "executeQuery") != 1 {
		t.Errorf("executeQuery was not deduplicated: %+v", sql.Sinks)
	}
	if !hasPattern(sql.Sources, "getParameter", MatchMethodCall) ||
		!hasPattern(sql.Sources, "getHeader", MatchMethodCall) ||
		!hasPattern(sql.Sources, "getenv", MatchMethodCall) ||
		!hasPattern(sql.Sources, "getDottedParam", MatchMethodCall) {
		t.Errorf("sources = %+v", sql.Sources)
	}
	if hasPattern(sql.Sources, "get", MatchMethodCall) {
		t.Errorf("short source was not filtered: %+v", sql.Sources)
	}
	for _, broad := range []string{"args", "query"} {
		if hasPattern(sql.Sources, broad, MatchMethodCall) {
			t.Errorf("broad source %q was not filtered: %+v", broad, sql.Sources)
		}
	}
	if !hasPattern(sql.Sanitizers, "setString", MatchMethodCall) {
		t.Errorf("sanitizers = %+v", sql.Sanitizers)
	}
	if len(first.Sanitizers) != 0 {
		t.Errorf("CWE-78 sanitizers = %+v, want none", first.Sanitizers)
	}

	again, err := BuildDetectionIntents(plan, testRegistry())
	if err != nil {
		t.Fatalf("BuildDetectionIntents repeat: %v", err)
	}
	if len(again) != len(intents) || again[0].ID != intents[0].ID || again[1].ID != intents[1].ID {
		t.Fatalf("intent IDs are not stable: %+v vs %+v", intents, again)
	}
}

func TestBuildDetectionIntentsFrameworkTaint(t *testing.T) {
	frameworks := json.RawMessage(`[{
		"name": "gin",
		"sources": [
			{"name": "request", "pattern": "r.FormValue"},
			{"name": "header", "pattern": "GetHeader|Header"}
		],
		"sinks": [
			{"name": "database-sql", "pattern": "Query|Exec|ExecContext"}
		],
		"source_sink_pairs": [
			{"source": "request", "sink": "database-sql", "cwe": "CWE-89"}
		]
	}]`)
	registry := audit.Registry{
		CWE: []audit.CWEDefinition{{ID: "CWE-89", Name: "SQL Injection"}},
		Sinks: map[string][]audit.SinkDefinition{
			audit.Go: {},
		},
		Taint: map[string][]audit.TaintRegistry{
			audit.Go: {{RegistryName: "go-frameworks", Language: audit.Go, Frameworks: frameworks}},
		},
	}
	plan := audit.Plan{
		Languages:   []string{audit.Go},
		PlannedCWEs: map[string][]string{audit.Go: {"CWE-89"}},
	}
	intents, err := BuildDetectionIntents(plan, registry)
	if err != nil {
		t.Fatalf("BuildDetectionIntents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("intent count = %d, want 1: %+v", len(intents), intents)
	}
	intent := intents[0]
	if intent.QueryKind != QueryKindTaint {
		t.Errorf("query kind = %q, want taint", intent.QueryKind)
	}
	if !hasPattern(intent.Sources, "FormValue", MatchMethodCall) {
		t.Errorf("framework source was not extracted: %+v", intent.Sources)
	}
	for _, sink := range []string{"Query", "Exec", "ExecContext"} {
		if !hasPattern(intent.Sinks, sink, MatchMethodCall) {
			t.Errorf("framework sink %q missing: %+v", sink, intent.Sinks)
		}
	}
	if !hasPattern(intent.Sinks, "Query|Exec|ExecContext", MatchRegex) {
		t.Errorf("raw framework regex pattern missing: %+v", intent.Sinks)
	}
	if hasPattern(intent.Sources, "GetHeader", MatchMethodCall) {
		t.Errorf("unpaired framework source should not be added: %+v", intent.Sources)
	}
}

func TestBuildDetectionIntentsEmbeddedRegistry(t *testing.T) {
	registry, err := audit.LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	plan := audit.Plan{
		Languages: []string{audit.Java, audit.Python},
		PlannedCWEs: map[string][]string{
			audit.Java:   {"CWE-89"},
			audit.Python: {"CWE-89"},
		},
		Modules: []string{"service"},
	}
	intents, err := BuildDetectionIntents(plan, registry)
	if err != nil {
		t.Fatalf("BuildDetectionIntents: %v", err)
	}
	if len(intents) == 0 {
		t.Fatal("embedded registry produced no intents")
	}
	seen := make(map[string]struct{}, len(intents))
	for _, intent := range intents {
		if len(intent.Sinks) == 0 {
			t.Errorf("intent %s has no sinks", intent.ID)
		}
		if intent.QueryKind != QueryKindTaint && intent.QueryKind != QueryKindSink {
			t.Errorf("intent %s query kind = %q", intent.ID, intent.QueryKind)
		}
		if _, exists := seen[intent.ID]; exists {
			t.Errorf("duplicate intent ID %s", intent.ID)
		}
		seen[intent.ID] = struct{}{}
	}
}

func TestBuildDetectionIntentsMalformedTaintRegistry(t *testing.T) {
	registry := audit.Registry{
		CWE: []audit.CWEDefinition{{ID: "CWE-89", Name: "SQL Injection"}},
		Sinks: map[string][]audit.SinkDefinition{
			audit.Java: {{CWEID: "CWE-89", Symbol: "java.sql.Statement.executeQuery", Kind: "sink"}},
		},
		Taint: map[string][]audit.TaintRegistry{
			audit.Java: {{RegistryName: "broken", Language: audit.Java, Frameworks: json.RawMessage(`{not json`)}},
		},
	}
	plan := audit.Plan{
		Languages:   []string{audit.Java},
		PlannedCWEs: map[string][]string{audit.Java: {"CWE-89"}},
	}
	if _, err := BuildDetectionIntents(plan, registry); err == nil {
		t.Fatal("expected malformed taint registry error")
	}
}

func TestBuildDetectionIntentsNonP0PlanOrder(t *testing.T) {
	registry := audit.Registry{
		CWE: []audit.CWEDefinition{{ID: "CWE-1001", Name: "First"}, {ID: "CWE-1000", Name: "Second"}},
		Sinks: map[string][]audit.SinkDefinition{
			audit.Java: {
				{CWEID: "CWE-1001", Symbol: "org.example.alphaSink", Kind: "sink"},
				{CWEID: "CWE-1000", Symbol: "org.example.betaSink", Kind: "sink"},
			},
		},
	}
	plan := audit.Plan{
		Languages:   []string{audit.Java},
		PlannedCWEs: map[string][]string{audit.Java: {"CWE-1001", "CWE-1000"}},
	}
	intents, err := BuildDetectionIntents(plan, registry)
	if err != nil {
		t.Fatalf("BuildDetectionIntents: %v", err)
	}
	if len(intents) != 2 {
		t.Fatalf("intent count = %d, want 2", len(intents))
	}
	if intents[0].CWE != "CWE-1001" || intents[1].CWE != "CWE-1000" {
		t.Fatalf("non-P0 plan order = %s, %s", intents[0].CWE, intents[1].CWE)
	}
	if intents[0].Priority <= intents[1].Priority {
		t.Fatalf("non-P0 priorities = %d, %d", intents[0].Priority, intents[1].Priority)
	}
}

func TestFrameworkSourceBroadPatterns(t *testing.T) {
	if got := appendFrameworkPatterns(nil, "fw", "source", "broad", "args"); len(got) != 0 {
		t.Fatalf("bare broad source pattern was retained: %+v", got)
	}
	patterns := appendFrameworkPatterns(nil, "fw", "source", "request", "request.args")
	if !hasPattern(patterns, "request.args", MatchRegex) {
		t.Errorf("qualified framework source pattern missing: %+v", patterns)
	}
	if hasPattern(patterns, "args", MatchMethodCall) {
		t.Errorf("broad framework method source was retained: %+v", patterns)
	}
}

func TestShortPatternSymbol(t *testing.T) {
	cases := map[string]string{
		"java.sql.Statement.executeQuery(java.lang.String)": "executeQuery",
		"django.db.connection.cursor().execute":             "execute",
		"QProcess::start":                                   "start",
		"system(":                                           "system",
		"org.example.query.runQuery(java.lang.String)":      "runQuery",
	}
	for raw, want := range cases {
		got, ok := shortPatternSymbol(raw)
		if !ok || got != want {
			t.Errorf("shortPatternSymbol(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
	if _, ok := shortPatternSymbol("get"); ok {
		t.Error("generic name get should be filtered")
	}
	if _, ok := shortPatternSymbol("a.b"); ok {
		t.Error("short name b should be filtered")
	}
}

func hasPattern(patterns []Pattern, value, match string) bool {
	for _, pattern := range patterns {
		if pattern.Pattern == value && pattern.Match == match {
			return true
		}
	}
	return false
}

func countPattern(patterns []Pattern, value string) int {
	count := 0
	for _, pattern := range patterns {
		if pattern.Pattern == value {
			count++
		}
	}
	return count
}
