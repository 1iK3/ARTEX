package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/audit/engines"
	"github.com/Autumn-27/artex/db"
)

func TestAuditEngineFindingsToSitesMatchPrescanKeys(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "A.java"),
		[]byte("class A {\n  void q() throws Exception {\n    stmt.executeQuery(q);\n  }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := audit.ProfileSource(root, audit.PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := audit.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	plan := audit.Plan{
		Languages: []string{audit.Java}, PlannedCWEs: map[string][]string{audit.Java: {"CWE-89"}},
	}
	prescan, err := audit.Prescan(root, profile, plan, registry, audit.PrescanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(prescan.Sites) != 1 {
		t.Fatalf("prescan sites = %+v, want one", prescan.Sites)
	}
	prescanSite := prescan.Sites[0]
	intent := engines.DetectionIntent{ID: "intent-1", Language: prescanSite.Language, CWE: prescanSite.CWE}
	findings := []engines.EngineFinding{
		{
			Engine: "codeql", Confidence: 0.8,
			Location: audit.CodeLocation{
				Path: prescanSite.Path, Line: prescanSite.Line,
				Symbol: "java.sql.Statement." + prescanSite.Symbol,
			},
			Payload: map[string]any{
				"intent_id": "intent-1",
				"engines": []map[string]any{
					{"name": "codeql", "confidence": 0.8, "raw_ref": "sarif:rule:0"},
				},
			},
		},
		{
			Engine: "joern", Confidence: 0.6,
			Location: audit.CodeLocation{
				Path: strings.ReplaceAll(prescanSite.Path, "/", "\\"),
				Line: prescanSite.Line, Symbol: prescanSite.Symbol,
			},
			Sink: &audit.CodeLocation{
				Path: prescanSite.Path, Line: prescanSite.Line, Symbol: prescanSite.Symbol,
			},
			Payload: map[string]any{"intent_id": "intent-1"},
		},
		{
			// CWE and language fall back to the intent; line is missing, so the
			// finding must be discarded rather than fabricated into coverage.
			Engine: "codeql", Confidence: 0.7,
			Location: audit.CodeLocation{Path: prescanSite.Path, Symbol: prescanSite.Symbol},
			Payload:  map[string]any{"intent_id": "intent-1"},
		},
	}
	sites, evidence := auditEngineSinkSites(findings, []engines.DetectionIntent{intent}, root)
	if len(sites) != 1 {
		t.Fatalf("sites = %+v, want one", sites)
	}
	site := sites[0]
	if site.SinkKey != prescanSite.SinkKey {
		t.Fatalf("engine SinkKey = %q, prescan SinkKey = %q", site.SinkKey, prescanSite.SinkKey)
	}
	if site.Path != prescanSite.Path || site.Line != prescanSite.Line ||
		site.Symbol != prescanSite.Symbol || site.Language != prescanSite.Language ||
		site.CWE != prescanSite.CWE {
		t.Fatalf("site = %+v, prescan = %+v", site, prescanSite)
	}
	entry, ok := evidence[prescanSite.SinkKey]
	if !ok {
		t.Fatalf("evidence missing for %s: %+v", prescanSite.SinkKey, evidence)
	}
	if entry.Engine != "codeql" || entry.Confidence != 0.8 {
		t.Fatalf("evidence = %+v, want codeql/0.8", entry)
	}
	if entry.Engines["codeql"] != 0.8 || entry.Engines["joern"] != 0.6 {
		t.Fatalf("per-engine evidence = %+v", entry.Engines)
	}

	// A correlated finding's boosted finding-level confidence must not overwrite
	// the individual engines' payload confidences.
	correlated := engines.EngineFinding{
		Engine: "codeql", Confidence: 0.85,
		Payload: map[string]any{
			"engines": []map[string]any{
				{"name": "codeql", "confidence": 0.75},
				{"name": "joern", "confidence": 0.65},
			},
		},
	}
	correlatedEvidence := auditEngineFindingEvidence(correlated)
	if correlatedEvidence["codeql"] != 0.75 || correlatedEvidence["joern"] != 0.65 {
		t.Fatalf("correlated per-engine evidence = %+v", correlatedEvidence)
	}
}

func TestMergeAuditSinkSitesAndEngineCoverageEvidence(t *testing.T) {
	prescanKey := audit.SinkKeyFor(audit.Java, "CWE-89", "src/A.java", 4, "executeQuery")
	engineOnlyKey := audit.SinkKeyFor(audit.Java, "CWE-89", "src/B.java", 9, "query")
	prescanSite := audit.SinkSite{
		Language: audit.Java, CWE: "CWE-89", Path: "src/A.java", Line: 4,
		Symbol: "executeQuery", SinkKey: prescanKey,
	}
	duplicateEngineSite := prescanSite
	duplicateEngineSite.Line = 4
	engineOnlySite := audit.SinkSite{
		Language: audit.Java, CWE: "CWE-89", Path: "src/B.java", Line: 9,
		Symbol: "query", SinkKey: engineOnlyKey,
	}
	evidence := map[string]auditEngineSiteEvidence{
		prescanKey: {Engine: "codeql", Confidence: 0.8, Engines: map[string]float64{"codeql": 0.8}},
		engineOnlyKey: {
			Engine: "codeql", Confidence: 0.6,
			Engines: map[string]float64{"codeql": 0.6, "joern": 0.5},
		},
	}
	merged := mergeAuditSinkSites(
		[]audit.SinkSite{prescanSite},
		[]audit.SinkSite{duplicateEngineSite, engineOnlySite},
		evidence,
	)
	if len(merged.Sites) != 2 {
		t.Fatalf("merged sites = %+v, want two", merged.Sites)
	}
	if merged.Sites[0].SinkKey != prescanKey || merged.Sites[1].SinkKey != engineOnlyKey {
		t.Fatalf("merged order = %+v", merged.Sites)
	}
	if _, ok := merged.EngineOnly[prescanKey]; ok {
		t.Fatal("prescan duplicate must not be engine-only")
	}
	if _, ok := merged.EngineOnly[engineOnlyKey]; !ok {
		t.Fatal("engine-only site was not recorded")
	}

	plan := audit.Plan{
		Languages:   []string{audit.Java},
		Modules:     []string{"src", "other"},
		PlannedCWEs: map[string][]string{audit.Java: {"CWE-89", "CWE-79"}},
	}
	rows := auditPlanCoverageRows(7, plan, merged.Sites, audit.EngineCodeGraph)
	rows = applyAuditEngineCoverageEvidence(rows, merged)
	rows = applyAuditNoSinkCoverageExemptions(rows, merged.Sites)

	byKey := map[string]db.AuditCoverage{}
	for _, row := range rows {
		byKey[row.SinkKey] = row
	}
	prescanRow := byKey[prescanKey]
	if prescanRow.Engine != audit.EngineCodeGraph {
		t.Fatalf("prescan row engine = %q, want codegraph", prescanRow.Engine)
	}
	var prescanEvidence map[string]any
	if err := json.Unmarshal(prescanRow.Evidence, &prescanEvidence); err != nil {
		t.Fatalf("prescan evidence: %v", err)
	}
	if prescanEvidence["origin"] != "prescan+engine" || prescanEvidence["engine"] != "codeql" {
		t.Fatalf("prescan evidence = %+v", prescanEvidence)
	}
	engineRow := byKey[engineOnlyKey]
	if engineRow.Engine != "codeql+joern" {
		t.Fatalf("engine-only stamp = %q, want codeql+joern", engineRow.Engine)
	}
	var engineEvidence map[string]any
	if err := json.Unmarshal(engineRow.Evidence, &engineEvidence); err != nil {
		t.Fatalf("engine evidence: %v", err)
	}
	if engineEvidence["origin"] != "engine" || engineEvidence["engine"] != "codeql" ||
		engineEvidence["confidence"] != 0.6 {
		t.Fatalf("engine evidence = %+v", engineEvidence)
	}

	for _, row := range rows {
		switch {
		case row.Kind == audit.CoverageKindCWE && row.CWE == "CWE-89":
			if row.Status != audit.CoverageStatusPlanned {
				t.Fatalf("CWE-89 row was exempted despite engine-only sites: %+v", row)
			}
		case row.Kind == audit.CoverageKindCWE && row.CWE == "CWE-79":
			if row.Status != audit.CoverageStatusExempt {
				t.Fatalf("CWE-79 row without sinks = %+v", row)
			}
		case row.Kind == audit.CoverageKindModule && row.Module == "src":
			if row.Status != audit.CoverageStatusPlanned {
				t.Fatalf("module with engine-only site was exempted: %+v", row)
			}
		case row.Kind == audit.CoverageKindModule && row.Module == "other":
			if row.Status != audit.CoverageStatusExempt {
				t.Fatalf("module without sinks = %+v", row)
			}
		}
	}
}

func TestAuditEngineRecordRedactionReportAndProgress(t *testing.T) {
	snapshot := `C:\secret-artex\work\tasks\42\audit\source`
	workDir := filepath.Join(snapshot, "engines")
	record := auditEnginesRecord{
		Configured: map[string]string{"codegraph": "required", "codeql": "auto", "joern": "off"},
		Capabilities: map[string]engines.Capability{
			"codeql": {
				Available: true, Version: "2.25.5", Path: `C:\tools\codeql\codeql.exe`,
				Languages: []string{audit.Java}, BuildModeNone: true,
			},
			"joern": {Available: false, Reason: "binary_missing", Path: `C:\tools\joern\joern.bat`},
		},
		Prepared: map[string]engines.Prepared{
			"codeql": {
				Languages:   []string{audit.Java},
				Paths:       map[string]string{audit.Java: `C:\secret-artex\work\tasks\42\audit\engines\db`},
				BuildModes:  map[string]string{audit.Java: "none"},
				Unsupported: map[string]string{audit.Go: "unsupported_build_required"},
				Warnings:    []string{"prepared under " + snapshot},
			},
		},
		Warnings: []string{"probe failed at " + workDir},
		Gaps:     []string{"joern unavailable under " + snapshot},
	}
	sanitized := sanitizeAuditEnginesRecord(record, auditEngineRedactPaths(snapshot, workDir))
	raw, err := json.Marshal(sanitized)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-artex") {
		t.Fatalf("session engines JSON leaked a host path: %s", raw)
	}
	parsed := parseAuditEnginesRecord(raw)
	if parsed.Capabilities["codeql"].Path != "codeql.exe" {
		t.Fatalf("capability path = %q, want basename", parsed.Capabilities["codeql"].Path)
	}
	if parsed.Prepared["codeql"].Paths[audit.Java] != "db" {
		t.Fatalf("prepared path = %q, want basename", parsed.Prepared["codeql"].Paths[audit.Java])
	}
	if parsed.Configured["codeql"] != "auto" {
		t.Fatalf("configured = %+v", parsed.Configured)
	}
	withTimeout := auditEngineJSONWithWarnings(raw, nil, []string{"engine timeout"})
	withTimeoutRecord := parseAuditEnginesRecord(withTimeout)
	if len(withTimeoutRecord.Warnings) != len(parsed.Warnings)+1 {
		t.Fatalf("timeout warning was not merged: %+v", withTimeoutRecord.Warnings)
	}
	// Adding the same warning twice must stay idempotent across preflight retries.
	withTimeoutAgain := parseAuditEnginesRecord(auditEngineJSONWithWarnings(withTimeout, nil, []string{"engine timeout"}))
	if len(withTimeoutAgain.Warnings) != len(withTimeoutRecord.Warnings) {
		t.Fatalf("warning merge is not idempotent: %+v", withTimeoutAgain.Warnings)
	}

	session := &db.AuditSession{
		ID: 7, TaskID: 42, Status: db.AuditStatusRunning, Round: 1, MaxRounds: 3,
		Depth: audit.DepthStandard, Backend: audit.EngineCodeGraph,
		Languages: []string{audit.Java}, Engines: raw,
	}
	jobs := []db.AuditEngineJob{
		{ID: 1, Engine: "codeql", JobKind: "run", Status: "done", ResultCount: 2},
		{ID: 2, Engine: "codeql", JobKind: "run", Status: "failed"},
		{ID: 3, Engine: "joern", JobKind: "run", Status: "skipped"},
	}
	reportEngines := buildAuditReportEngines(session, jobs, auditEngineRedactPaths(snapshot, workDir))
	if reportEngines.Capabilities["codeql"].State != "ready" {
		t.Fatalf("report capability = %+v", reportEngines.Capabilities["codeql"])
	}
	if reportEngines.Capabilities["joern"].State != "disabled" {
		t.Fatalf("report joern = %+v", reportEngines.Capabilities["joern"])
	}
	if reportEngines.Prepared["codeql"].Unsupported[audit.Go] == "" {
		t.Fatalf("report prepared gap lost: %+v", reportEngines.Prepared["codeql"])
	}
	joinedGaps := strings.Join(reportEngines.Gaps, "\n")
	if !strings.Contains(joinedGaps, "binary_missing") && !strings.Contains(joinedGaps, "joern unavailable") {
		t.Fatalf("report gaps lack unavailable reason: %v", reportEngines.Gaps)
	}
	if !strings.Contains(joinedGaps, "codeql 引擎有 1 个失败任务") {
		t.Fatalf("report gaps lack failed-job count: %v", reportEngines.Gaps)
	}

	plan := audit.Plan{
		Depth: audit.DepthStandard, Languages: []string{audit.Java},
		PlannedCWEs: map[string][]string{audit.Java: {"CWE-89"}},
	}
	progressRaw, err := buildAuditProgress(auditProgressInput{
		Session: session, Plan: plan, Engines: jobs,
	})
	if err != nil {
		t.Fatal(err)
	}
	var progress map[string]any
	if err := json.Unmarshal(progressRaw, &progress); err != nil {
		t.Fatal(err)
	}
	status, ok := progress["engine_status"].(map[string]any)
	if !ok {
		t.Fatalf("progress engine_status = %T", progress["engine_status"])
	}
	capabilities := status["capabilities"].(map[string]any)
	codeQL := capabilities["codeql"].(map[string]any)
	if codeQL["state"] != "ready" || codeQL["version"] != "2.25.5" {
		t.Fatalf("progress capability = %+v", codeQL)
	}
	if _, leaked := codeQL["path"]; leaked {
		t.Fatalf("progress capability leaked path: %+v", codeQL)
	}
	counts := status["job_counts"].(map[string]any)
	if counts["all"].(map[string]any)["total"] != float64(3) ||
		counts["all"].(map[string]any)["skipped"] != float64(1) ||
		counts["codeql"].(map[string]any)["failed"] != float64(1) {
		t.Fatalf("progress job counts = %+v", counts)
	}
	budgetEngines := progress["budget"].(map[string]any)["engines"].(map[string]any)
	if budgetEngines["codeql"] != "auto" || budgetEngines["joern"] != "off" {
		t.Fatalf("progress budget engines = %+v", budgetEngines)
	}
	for _, forbidden := range []string{"secret-artex", "snapshot_path"} {
		if strings.Contains(string(progressRaw), forbidden) {
			t.Fatalf("progress leaked %q: %s", forbidden, progressRaw)
		}
	}
}

func TestAuditEngineModesAndTimeout(t *testing.T) {
	enabled := enabledAuditEngines(audit.Config{Engines: map[string]string{
		"codeql": "auto", "joern": "off",
	}})
	if len(enabled) != 1 || enabled[0] != audit.EngineCodeQL {
		t.Fatalf("enabled engines = %v", enabled)
	}
	if got := enabledAuditEngines(audit.Config{Engines: map[string]string{"codeql": "", "joern": "auto"}}); len(got) != 1 || got[0] != audit.EngineJoern {
		t.Fatalf("empty mode must skip, enabled = %v", got)
	}
	if got := enabledAuditEngines(audit.Config{}); len(got) != 0 {
		t.Fatalf("no configured engines = %v", got)
	}
	if got := auditEngineTimeout(audit.Config{}); got.Seconds() != auditEngineDefaultSeconds {
		t.Fatalf("default engine timeout = %s", got)
	}
	if got := auditEngineTimeout(audit.Config{Budgets: map[string]any{"max_engine_seconds": float64(42)}}); got.Seconds() != 42 {
		t.Fatalf("configured engine timeout = %s", got)
	}
	if got := auditEngineTimeout(audit.Config{Budgets: map[string]any{"max_engine_seconds": float64(999999999)}}); got.Seconds() != auditEngineMaxSeconds {
		t.Fatalf("capped engine timeout = %s", got)
	}
}

func TestAuditEngineSinkSitesSymbolAndPathFallbacks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	intent := engines.DetectionIntent{ID: "intent-path", Language: audit.Java, CWE: "CWE-89"}
	findings := []engines.EngineFinding{
		{
			Engine: "codeql", CWE: "CWE-89", Language: audit.Java,
			Location: audit.CodeLocation{Path: "src/A.java", Line: 10},
			Payload:  map[string]any{"intent_id": "intent-path", "symbol": "executeQuery"},
		},
		{
			Engine: "joern", CWE: "CWE-89", Language: audit.Java,
			Location: audit.CodeLocation{Path: "src/B.java", Line: 11},
			Message:  "dangerous call to executeQuery()",
			Payload:  map[string]any{"intent_id": "intent-path"},
		},
		{
			Engine: "codeql", CWE: "CWE-89", Language: audit.Java,
			Location: audit.CodeLocation{Path: filepath.Join(root, "src", "C.java"), Line: 12, Symbol: "exec"},
			Payload:  map[string]any{"intent_id": "intent-path"},
		},
		{
			Engine: "joern", CWE: "CWE-89", Language: audit.Java,
			Location: audit.CodeLocation{Path: "../outside.java", Line: 13, Symbol: "exec"},
			Payload:  map[string]any{"intent_id": "intent-path"},
		},
		{
			Engine: "joern", CWE: "CWE-89", Language: audit.Java,
			Location: audit.CodeLocation{Path: filepath.Join(outside, "Outside.java"), Line: 14, Symbol: "exec"},
			Payload:  map[string]any{"intent_id": "intent-path"},
		},
	}
	sites, _ := auditEngineSinkSites(findings, []engines.DetectionIntent{intent}, root)
	if len(sites) != 3 {
		t.Fatalf("sites = %+v, want 3 confined findings", sites)
	}
	byPath := make(map[string]audit.SinkSite, len(sites))
	for _, site := range sites {
		byPath[site.Path] = site
	}
	if site, ok := byPath["src/A.java"]; !ok || site.Symbol != "executeQuery" {
		t.Errorf("payload symbol fallback missing: %+v", sites)
	}
	if site, ok := byPath["src/B.java"]; !ok || site.Symbol != "executeQuery" {
		t.Errorf("message symbol fallback missing: %+v", sites)
	}
	if site, ok := byPath["src/C.java"]; !ok || site.Symbol != "exec" {
		t.Errorf("absolute in-root path was not relativized: %+v", sites)
	}
	for _, leaked := range []string{"../outside.java", filepath.Join(outside, "Outside.java")} {
		for _, site := range sites {
			if strings.Contains(filepath.ToSlash(site.Path), filepath.ToSlash(leaked)) {
				t.Errorf("out-of-root path was retained: %+v", site)
			}
		}
	}
}

func TestAuditEngineJobResultCountsUsePayloadEngines(t *testing.T) {
	findings := []engines.EngineFinding{
		{
			Engine: "codeql", Confidence: 0.85,
			Payload: map[string]any{
				"intent_id": "intent-1",
				"engines": []map[string]any{
					{"name": "codeql", "confidence": 0.75},
					{"name": "joern", "confidence": 0.65},
				},
			},
		},
		{Engine: "codeql", Payload: map[string]any{"intent_id": "intent-1"}},
	}
	counts := auditEngineJobResultCounts(findings)
	if counts["codeql\x00intent-1"] != 2 {
		t.Errorf("codeql count = %d, want 2: %+v", counts["codeql\x00intent-1"], counts)
	}
	if counts["joern\x00intent-1"] != 1 {
		t.Errorf("joern count = %d, want 1: %+v", counts["joern\x00intent-1"], counts)
	}
}

func TestAuditEngineErrorsRedactHostRoots(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		t.Skip("user home unavailable")
	}
	snapshot := filepath.Join(t.TempDir(), "snapshot")
	workDir := filepath.Join(snapshot, "engines")
	redactions := auditEngineRedactPaths(snapshot, workDir)
	redactions = auditEngineAddRedaction(redactions, `D:\tools\codeql-win64\codeql`)
	redactions = auditEngineAddRedaction(redactions, `D:\tools\joern\joern-cli`)
	message := "failed under " + filepath.Join(home, ".codeql", "packages") +
		" temp=" + os.TempDir() +
		" tool=" + `D:\tools\codeql-win64\codeql\codeql.exe` +
		" joern=" + `D:\tools\joern\joern-cli\joern.bat` +
		" snapshot=" + snapshot
	sanitized := sanitizeAuditText(message, redactions)
	for _, forbidden := range []string{home, os.TempDir(), `D:\tools\codeql-win64`, `D:\tools\joern`} {
		if strings.Contains(sanitized, forbidden) {
			t.Fatalf("sanitized error leaked %q: %s", forbidden, sanitized)
		}
	}
	for _, p := range redactions {
		if strings.Contains(p, "secret-artex") {
			t.Fatalf("unexpected redaction root: %s", p)
		}
	}
	engineSanitized := engines.RedactEngineText(message)
	if strings.Contains(engineSanitized, home) || strings.Contains(engineSanitized, "AppData") {
		t.Fatalf("engine error redaction leaked host path: %s", engineSanitized)
	}
}
