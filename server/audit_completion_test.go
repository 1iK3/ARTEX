package server

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/audit/engines"
	"github.com/Autumn-27/artex/db"
)

func TestDecideAuditCompletion(t *testing.T) {
	tests := []struct {
		name       string
		active     int
		unverified int
		gates      bool
		atMax      bool
		zeroStreak int
		candidates bool
		phase      bool
		want       auditCompletionDecision
	}{
		{"active work waits", 1, 0, true, true, 0, true, false, auditDecisionWait},
		{"unverified requests S5", 0, 2, true, true, 0, true, false, auditDecisionRequestVerification},
		{"gates pass completes", 0, 0, true, false, 0, false, false, auditDecisionComplete},
		{"max rounds forces gaps", 0, 0, false, true, 0, true, true, auditDecisionCompleteWithGaps},
		{"zero streak converges", 0, 0, false, false, 2, true, true, auditDecisionCompleteWithGaps},
		{"single zero round retries", 0, 0, false, false, 1, true, false, auditDecisionRetryCoverage},
		{"coverage candidates retry", 0, 0, false, false, 0, true, false, auditDecisionRetryCoverage},
		{"deep phase candidates wait", 0, 0, false, false, 0, false, true, auditDecisionWait},
		{"no candidates forces gaps", 0, 0, false, false, 0, false, false, auditDecisionCompleteWithGaps},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := decideAuditCompletion(tc.active, tc.unverified, tc.gates, tc.atMax, tc.zeroStreak, tc.candidates, tc.phase)
			if got != tc.want {
				t.Fatalf("decision = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSummarizeAuditIntents(t *testing.T) {
	node := func(phase string, round int, state string) *db.Node {
		payload, _ := json.Marshal(map[string]any{"audit": map[string]any{"phase": phase, "round": round}})
		return &db.Node{Kind: db.KindIntent, State: state, Payload: payload}
	}
	intents := []*db.Node{
		node(audit.PhaseDetect, 1, "done"),
		node(audit.PhaseVerify, 1, "running"),
		node(audit.PhaseDesign, 1, "paused"),
		node(audit.PhaseLogic, 1, "future_state"),
		node(audit.PhaseDetect, 2, "open"),   // wrong round
		node("", 1, "open"),                  // not an audit intent
		node(audit.PhaseDepth, 1, "deleted"), // retracted
		node(audit.PhasePoC, 1, "blocked"),
	}
	active, byPhase := summarizeAuditIntents(intents, 1)
	if active != 3 {
		t.Fatalf("active = %d, want 3 (running/paused/unknown)", active)
	}
	if byPhase[audit.PhaseDetect] != 1 || byPhase[audit.PhaseVerify] != 1 ||
		byPhase[audit.PhaseDesign] != 1 || byPhase[audit.PhaseLogic] != 1 ||
		byPhase[audit.PhasePoC] != 1 || byPhase[audit.PhaseDepth] != 0 {
		t.Fatalf("phase counts = %#v", byPhase)
	}
}

func TestAuditPhaseSkipReasonSatisfiesGate(t *testing.T) {
	gateJSON := json.RawMessage(`{"reason":"no_targets","skipped_by":"audit_director"}`)
	phases := []db.AuditPhase{
		{Phase: audit.PhaseIngest, Required: true, Status: "done"},
		{Phase: audit.PhaseProfile, Required: true, Status: "done"},
		{Phase: audit.PhaseSurface, Required: true, Status: "done"},
		{Phase: audit.PhaseDataFlow, Required: true, Status: "skipped", Gate: gateJSON},
		{Phase: audit.PhaseDetect, Required: true, Status: "done"},
		{Phase: audit.PhaseVerify, Required: true, Status: "skipped", Gate: gateJSON},
		{Phase: audit.PhaseDesign, Required: true, Status: "skipped", Gate: gateJSON},
		{Phase: audit.PhaseReport, Required: true, Status: "done"},
	}
	statuses := auditPhaseStatuses(phases)
	gate := audit.GatePhase(statuses)
	if !gate.Passed {
		t.Fatalf("skipped phases with reasons must pass Gate-Phase: %+v", gate)
	}

	phases[3].Gate = nil
	if gate := audit.GatePhase(auditPhaseStatuses(phases)); gate.Passed {
		t.Fatal("skipped phase without a reason must fail Gate-Phase")
	}
}

func TestAuditCompletionPhaseStatusesTreatsS11AsSatisfied(t *testing.T) {
	phases := []db.AuditPhase{
		{Phase: audit.PhaseIngest, Required: true, Status: "done"},
		{Phase: audit.PhaseProfile, Required: true, Status: "done"},
		{Phase: audit.PhaseSurface, Required: true, Status: "done"},
		{Phase: audit.PhaseDetect, Required: true, Status: "done"},
		{Phase: audit.PhaseReport, Required: true, Status: "pending"},
	}
	if gate := audit.GatePhase(auditPhaseStatuses(phases)); gate.Passed {
		t.Fatal("pending S11 must fail the raw phase gate")
	}
	statuses := auditCompletionPhaseStatuses(phases)
	gate := audit.GatePhase(statuses)
	if !gate.Passed {
		t.Fatalf("completion phase status should treat S11 as satisfied: %+v", gate)
	}
	if phases[4].Status != "pending" {
		t.Fatal("completion helper must not mutate the persisted phase row")
	}
}

func TestAuditGatesPassedAndGapSummary(t *testing.T) {
	passed := map[string]audit.GateResult{
		"phase": {Name: "Gate-Phase", Passed: true},
		"cwe":   {Name: "Gate-CWE", Passed: true},
	}
	if !auditGatesPassed(passed) {
		t.Fatal("all-pass gates reported failure")
	}
	passed["coverage"] = audit.GateResult{Name: "Gate-Coverage", Passed: false, Reason: "sink coverage 0.50 below threshold 0.95"}
	if summary := auditGateGapSummary(passed); !strings.Contains(summary, "Gate-Coverage") ||
		!strings.Contains(summary, "below threshold") {
		t.Fatalf("gap summary = %q", summary)
	}
	if auditGatesPassed(nil) {
		t.Fatal("empty gates must not count as passed")
	}
}

func TestBuildAuditFindingCandidates(t *testing.T) {
	findings := []auditFindingCandidate{
		{ID: 1, CWE: "CWE-89", Severity: "high"},
		{ID: 2, CWE: "CWE-89", Severity: "high"},
		{ID: 3, CWE: "CWE-89", Severity: "high"},
		{ID: 4, CWE: "CWE-89", Severity: "high"},
		{ID: 5, CWE: "CWE-89", Severity: "high"},
		{ID: 6, CWE: "CWE-89", Severity: "high"},
		{ID: 7, CWE: "CWE-79", Severity: "medium"},
		{ID: 8, CWE: "CWE-78", Severity: "critical"},
		{ID: 0, CWE: "CWE-89", Severity: "high"},
	}
	candidates := buildAuditFindingCandidates(findings, 8, 5)
	if len(candidates) != 4 {
		t.Fatalf("candidates = %+v, want 4 (critical, high batch 1, high batch 2, medium)", candidates)
	}
	if candidates[0].Phase != audit.PhaseVerify || candidates[0].CWE != "CWE-78" ||
		candidates[0].Severity != "critical" || candidates[0].Priority != 9 ||
		len(candidates[0].FindingIDs) != 1 || candidates[0].FindingIDs[0] != 8 {
		t.Fatalf("critical candidate = %+v", candidates[0])
	}
	if candidates[1].CWE != "CWE-89" || len(candidates[1].FindingIDs) != 5 ||
		candidates[1].FindingIDs[0] != 1 || candidates[1].FindingIDs[4] != 5 {
		t.Fatalf("first high batch = %+v", candidates[1])
	}
	if len(candidates[2].FindingIDs) != 1 || candidates[2].FindingIDs[0] != 6 {
		t.Fatalf("second high batch = %+v", candidates[2])
	}
	if candidates[3].CWE != "CWE-79" || candidates[3].Priority != 8 {
		t.Fatalf("medium candidate = %+v", candidates[3])
	}
	if len(candidates[0].SinkKeys) != 0 {
		t.Fatal("finding candidates must not invent sink keys")
	}
	limited := buildAuditFindingCandidates(findings, 2, 5)
	if len(limited) != 2 {
		t.Fatalf("max batches not applied: %+v", limited)
	}
}

func TestBuildAuditPhaseCandidatesForDeepChain(t *testing.T) {
	plan := audit.Plan{
		Depth: audit.DepthDeep, Languages: []string{"java"}, Modules: []string{"src"},
	}
	phases := []db.AuditPhase{
		{Phase: audit.PhaseDataFlow, Required: true, Status: "pending"},
		{Phase: audit.PhaseLogic, Required: true, Status: "pending"},
		{Phase: audit.PhaseOdinDeep, Required: true, Status: "pending"},
		{Phase: audit.PhaseDesign, Required: true, Status: "pending"},
		{Phase: audit.PhaseDepth, Required: true, Status: "pending"},
		{Phase: audit.PhasePoC, Required: true, Status: "pending"},
		{Phase: audit.PhaseReport, Required: true, Status: "pending"},
	}
	confirmed := []auditFindingCandidate{
		{ID: 1, CWE: "CWE-89", Severity: "high"},
		{ID: 2, CWE: "CWE-78", Severity: "critical"},
		{ID: 3, CWE: "CWE-79", Severity: "low"},
	}
	candidates := buildAuditPhaseCandidates(plan, phases, confirmed)
	byPhase := make(map[string][]auditCoverageCandidate)
	for _, candidate := range candidates {
		byPhase[candidate.Phase] = append(byPhase[candidate.Phase], candidate)
	}
	for _, phase := range []string{
		audit.PhaseDataFlow, audit.PhaseLogic, audit.PhaseOdinDeep,
		audit.PhaseDesign, audit.PhaseDepth, audit.PhasePoC,
	} {
		if len(byPhase[phase]) == 0 {
			t.Fatalf("%s has no actionable candidate: %+v", phase, candidates)
		}
	}
	if len(byPhase[audit.PhaseReport]) != 0 {
		t.Fatalf("S11 must stay host-owned: %+v", byPhase[audit.PhaseReport])
	}
	for _, phase := range []string{audit.PhaseDataFlow, audit.PhaseLogic, audit.PhaseOdinDeep, audit.PhaseDepth} {
		if byPhase[phase][0].Language != "java" {
			t.Fatalf("%s candidate language = %q, want java", phase, byPhase[phase][0].Language)
		}
	}
	for _, phase := range []string{audit.PhaseDesign, audit.PhasePoC} {
		got := byPhase[phase][0].FindingIDs
		if len(got) != 2 || got[0] != 2 || got[1] != 1 {
			t.Fatalf("%s finding_ids = %v, want [2 1]", phase, got)
		}
	}

	phases[0].Status = "done"
	quick := buildAuditPhaseCandidates(audit.Plan{Depth: audit.DepthQuick, Languages: []string{"go"}}, phases, nil)
	for _, candidate := range quick {
		if candidate.Phase == audit.PhaseDataFlow {
			t.Fatalf("completed S3 must not be re-dispatched: %+v", quick)
		}
	}
}

func TestBuildAuditCoverageCandidatesIncludesS3EntryPoints(t *testing.T) {
	rows := []db.AuditCoverage{
		{Kind: audit.CoverageKindEntryPoint, Language: "go", CWE: "CWE-89", Module: "api",
			Path: "api/handler.go", Symbol: "Handle", SinkKey: "entry:api/handler.go:Handle",
			Status: audit.CoverageStatusPlanned},
		{Kind: audit.CoverageKindSinkSite, Language: "go", CWE: "CWE-89", Module: "api",
			Path: "api/db.go", Symbol: "Query", SinkKey: "sink:api/db.go:Query",
			Status: audit.CoverageStatusPlanned},
	}
	candidates := buildAuditCoverageCandidates(rows, 8, 25)
	if len(candidates) != 2 {
		t.Fatalf("candidates = %+v, want one S3 and one S4 batch", candidates)
	}
	if candidates[0].Phase != audit.PhaseDataFlow || candidates[0].Language != "go" ||
		candidates[0].Module != "api" || len(candidates[0].SinkKeys) != 1 ||
		candidates[0].SinkKeys[0] != "entry:api/handler.go:Handle" {
		t.Fatalf("S3 entry-point candidate = %+v", candidates[0])
	}
	if candidates[1].Phase != audit.PhaseDetect || len(candidates[1].SinkKeys) != 1 ||
		candidates[1].SinkKeys[0] != "sink:api/db.go:Query" {
		t.Fatalf("S4 sink candidate = %+v", candidates[1])
	}
}

func TestAuditPlanCoverageRowsIncludesPlannedEntryPoints(t *testing.T) {
	plan := audit.Plan{
		Depth: audit.DepthDeep, Languages: []string{"go"},
		PlannedCWEs: map[string][]string{"go": {"CWE-89"}},
		EntryPoints: []string{"api.Handle", "worker.Run"},
	}
	rows := auditPlanCoverageRows(91, plan, nil, "codegraph")
	entries := make([]db.AuditCoverage, 0, 2)
	for _, row := range rows {
		if row.Kind == audit.CoverageKindEntryPoint {
			entries = append(entries, row)
		}
	}
	if len(entries) != 2 {
		t.Fatalf("entry-point rows = %+v, want 2", entries)
	}
	for _, row := range entries {
		if row.SessionID != 91 || row.Round != 1 || row.Language != "go" ||
			row.Status != audit.CoverageStatusPlanned || row.Symbol == "" ||
			row.SinkKey != "entry:"+row.Symbol {
			t.Fatalf("planned entry-point row = %+v", row)
		}
	}
	if entries[0].Symbol != "api.Handle" || entries[1].Symbol != "worker.Run" {
		t.Fatalf("entry-point order = [%s %s]", entries[0].Symbol, entries[1].Symbol)
	}
}

func TestAuditGatesIncludeHypothesisAndEngineDiscipline(t *testing.T) {
	plan := audit.Plan{Depth: audit.DepthDeep}
	attempts, err := json.Marshal(make([]map[string]any, 3))
	if err != nil {
		t.Fatal(err)
	}
	engineRecord := auditEnginesRecord{
		Configured: map[string]string{audit.EngineCodeGraph: "required"},
		Capabilities: map[string]engines.Capability{
			audit.EngineCodeGraph: {Available: false, Reason: "not installed"},
		},
	}
	gates := auditGates(
		plan, nil, nil,
		[]db.AuditHypothesis{{Status: "testing", Attempts: attempts}},
		0,
		[]db.AuditEngineJob{{Engine: audit.EngineCodeGraph, Status: "failed"}},
		engineRecord,
	)
	if gate := gates["hypothesis"]; gate.Passed {
		t.Fatalf("Gate-H passed for a testing hypothesis at attempt limit: %+v", gate)
	}
	if gate := gates["engine"]; gate.Passed {
		t.Fatalf("Gate-Engine passed with required engine missing and failed job: %+v", gate)
	}

	engineRecord.Capabilities[audit.EngineCodeGraph] = engines.Capability{Available: true}
	gates = auditGates(plan, nil, nil, nil, 0, nil, engineRecord)
	if gate := gates["hypothesis"]; !gate.Passed {
		t.Fatalf("Gate-H failed without hypotheses: %+v", gate)
	}
	if gate := gates["engine"]; !gate.Passed {
		t.Fatalf("Gate-Engine failed with required engine ready: %+v", gate)
	}

	healthy := make([]db.AuditEngineJob, 0, 10)
	for i := 0; i < 8; i++ {
		healthy = append(healthy, db.AuditEngineJob{Engine: audit.EngineCodeGraph, Status: "done"})
	}
	atThreshold := append([]db.AuditEngineJob(nil), healthy...)
	atThreshold = append(atThreshold,
		db.AuditEngineJob{Engine: audit.EngineCodeGraph, Status: "failed"},
		db.AuditEngineJob{Engine: audit.EngineCodeGraph, Status: "failed"},
	)
	gates = auditGates(audit.Plan{Depth: audit.DepthDeep}, nil, nil, nil, 0, atThreshold, engineRecord)
	if gate := gates["engine"]; !gate.Passed {
		t.Fatalf("Gate-Engine failed at the 0.80 success threshold: %+v", gate)
	}

	belowThreshold := append([]db.AuditEngineJob(nil), healthy[:7]...)
	belowThreshold = append(belowThreshold,
		db.AuditEngineJob{Engine: audit.EngineCodeGraph, Status: "failed"},
		db.AuditEngineJob{Engine: audit.EngineCodeGraph, Status: "failed"},
		db.AuditEngineJob{Engine: audit.EngineCodeGraph, Status: "failed"},
	)
	gates = auditGates(audit.Plan{Depth: audit.DepthDeep}, nil, nil, nil, 0, belowThreshold, engineRecord)
	gate := gates["engine"]
	if gate.Passed {
		t.Fatalf("Gate-Engine passed below the 0.80 success threshold: %+v", gate)
	}
	details, _ := gate.Details["success_rate"].(float64)
	if details < 0.69 || details > 0.71 {
		t.Fatalf("Gate-Engine success rate = %v, want 0.70", gate.Details["success_rate"])
	}
	if outcome := auditEngineGateOutcome(atThreshold); outcome != "pass" {
		t.Fatalf("round Gate-Engine outcome at threshold = %q, want pass", outcome)
	}
	if outcome := auditEngineGateOutcome(belowThreshold); outcome != "degraded" {
		t.Fatalf("round Gate-Engine outcome below threshold = %q, want degraded", outcome)
	}
}

func TestAuditGatesScoreHypothesisQualityAndPivot(t *testing.T) {
	plan := audit.Plan{Depth: audit.DepthDeep}
	engineRecord := auditEnginesRecord{}
	oneAttempt := json.RawMessage(`[{"action":"attempt","outcome":"failed"}]`)

	gates := auditGates(plan, nil, nil, nil, 0, nil, engineRecord)
	gate := gates["hypothesis"]
	if !gate.Passed || gate.Details["score"] == nil {
		t.Fatalf("Gate-H without findings/hypotheses should pass with a score: %+v", gate)
	}

	gates = auditGates(plan, nil, nil, nil, 2, nil, engineRecord)
	gate = gates["hypothesis"]
	if gate.Passed {
		t.Fatalf("Gate-H passed with findings but no hypotheses: %+v", gate)
	}
	if !strings.Contains(gate.Reason, "findings_without_hypotheses") {
		t.Fatalf("Gate-H reason lacks findings violation: %+v", gate)
	}

	refuted := []db.AuditHypothesis{
		{HypothesisKey: "one", Status: "refuted", Attempts: oneAttempt},
		{HypothesisKey: "two", Status: "refuted", Attempts: oneAttempt},
		{HypothesisKey: "three", Status: "refuted", Attempts: oneAttempt},
	}
	gates = auditGates(plan, nil, nil, refuted, 3, nil, engineRecord)
	gate = gates["hypothesis"]
	if gate.Passed || !strings.Contains(gate.Reason, "pivot_gap") {
		t.Fatalf("Gate-H should fail after three refuted hypotheses without a pivot: %+v", gate)
	}

	pivoted := append(append([]db.AuditHypothesis(nil), refuted...),
		db.AuditHypothesis{HypothesisKey: "new-direction", Status: "confirmed", Attempts: oneAttempt},
	)
	gates = auditGates(plan, nil, nil, pivoted, 3, nil, engineRecord)
	gate = gates["hypothesis"]
	if !gate.Passed {
		t.Fatalf("Gate-H failed after a pivot: %+v", gate)
	}
	score, _ := gate.Details["score"].(float64)
	if score < 62 || score > 63 {
		t.Fatalf("Gate-H score = %v, want 62.5 (warning below 70)", gate.Details["score"])
	}
	if warning, _ := gate.Details["warning"].(bool); !warning {
		t.Fatalf("Gate-H should warn below score 70: %+v", gate)
	}
	if outcome := auditHypothesisRoundOutcome(gate); outcome != "warn" {
		t.Fatalf("round Gate-H outcome = %q, want warn", outcome)
	}
}

func TestAuditNoSinkExemptionsMakeGoGatesPass(t *testing.T) {
	plan := audit.Plan{
		Depth: audit.DepthQuick, Languages: []string{"go"},
		PlannedCWEs: map[string][]string{"go": {"CWE-89", "CWE-79"}},
		Modules:     []string{"cmd"},
	}
	rows := applyAuditNoSinkCoverageExemptions(auditPlanCoverageRows(1, plan, nil, "fallback"), nil)
	for _, row := range rows {
		if row.Kind == audit.CoverageKindCWE || row.Kind == audit.CoverageKindModule {
			if row.Status != audit.CoverageStatusExempt || !audit.ValidExemptionReason(row.Reason) {
				t.Fatalf("unsunk %s row was not exempted: %+v", row.Kind, row)
			}
		}
	}
	converted := auditCoverageRows(rows)
	if gate := audit.GateCWE(plan, converted); !gate.Passed {
		t.Fatalf("Gate-CWE should pass for a Go plan with no registry sinks: %+v", gate)
	}
	if gate := audit.GateCoverage(plan, converted, plan.Depth); !gate.Passed {
		t.Fatalf("Gate-Coverage should pass for a Go plan with no registry sinks: %+v", gate)
	}
}

func TestAuditWithSinkSitesStillRequiresReceipts(t *testing.T) {
	plan := audit.Plan{
		Depth: audit.DepthQuick, Languages: []string{"java"},
		PlannedCWEs: map[string][]string{"java": {"CWE-89"}},
		Modules:     []string{"src"},
	}
	sites := []audit.SinkSite{{
		Language: "java", CWE: "CWE-89", Path: "src/UserDao.java",
		Symbol: "Statement.executeQuery", SinkKey: "sink-java-1", Line: 42,
	}}
	rows := applyAuditNoSinkCoverageExemptions(auditPlanCoverageRows(1, plan, sites, "codegraph"), sites)
	for _, row := range rows {
		if row.Kind == audit.CoverageKindCWE {
			if row.Status != audit.CoverageStatusPlanned {
				t.Fatalf("CWE with sink sites must not be exempted: %+v", row)
			}
		}
		if row.Kind == audit.CoverageKindModule && row.Status != audit.CoverageStatusPlanned {
			t.Fatalf("module with sink sites must not be exempted: %+v", row)
		}
	}
	converted := auditCoverageRows(rows)
	if gate := audit.GateCWE(plan, converted); gate.Passed {
		t.Fatal("Gate-CWE passed without any covered Java sink receipt")
	}
	if gate := audit.GateCoverage(plan, converted, plan.Depth); gate.Passed {
		t.Fatal("Gate-Coverage passed without any covered Java sink receipt")
	}
	for i := range rows {
		if rows[i].Kind == audit.CoverageKindSinkSite {
			rows[i].Status = audit.CoverageStatusScanned
		}
	}
	converted = auditCoverageRows(rows)
	if gate := audit.GateCWE(plan, converted); !gate.Passed {
		t.Fatalf("covered sink receipt did not satisfy Gate-CWE: %+v", gate)
	}
	if gate := audit.GateCoverage(plan, converted, plan.Depth); !gate.Passed {
		t.Fatalf("covered sink receipt did not satisfy Gate-Coverage: %+v", gate)
	}
}

func TestAuditSkipReason(t *testing.T) {
	targetless := audit.Plan{PlannedCWEs: map[string][]string{}}
	for _, phase := range []string{audit.PhaseProfile, audit.PhaseSurface, audit.PhaseDataFlow, audit.PhaseVerify, audit.PhaseLogic, audit.PhaseDesign, audit.PhasePoC} {
		reason, ok := auditSkipReason(phase, 0, targetless, nil)
		if !ok || reason != "no_targets" {
			t.Fatalf("%s skip = %q/%v", phase, reason, ok)
		}
	}
	if reason, ok := auditSkipReason(audit.PhaseDetect, 0, targetless, nil); !ok || reason != "no_sinks" {
		t.Fatalf("S4 no sinks skip = %q/%v", reason, ok)
	}
	if _, ok := auditSkipReason(audit.PhaseIngest, 0, targetless, nil); ok {
		t.Fatal("S0 must never be skipped")
	}
	if _, ok := auditSkipReason(audit.PhaseReport, 0, targetless, nil); ok {
		t.Fatal("S11 must never be skipped")
	}

	withTarget := audit.Plan{
		Languages: []string{"go"}, PlannedCWEs: map[string][]string{"go": {"CWE-89"}},
	}
	for _, phase := range []string{audit.PhaseProfile, audit.PhaseSurface} {
		if _, ok := auditSkipReason(phase, 0, withTarget, nil); ok {
			t.Fatalf("%s must remain pending while the plan has targets", phase)
		}
	}
	if _, ok := auditSkipReason(audit.PhaseVerify, 1, withTarget, nil); ok {
		t.Fatal("phase with an intent must not be skipped")
	}
	sinkRows := []db.AuditCoverage{{Kind: audit.CoverageKindSinkSite, SinkKey: "s", Status: audit.CoverageStatusPlanned}}
	if _, ok := auditSkipReason(audit.PhaseDetect, 0, withTarget, sinkRows); ok {
		t.Fatal("S4 must remain pending while sink-site rows exist")
	}
	entryRows := []db.AuditCoverage{{Kind: audit.CoverageKindEntryPoint, SinkKey: "entry", Status: audit.CoverageStatusPlanned}}
	if _, ok := auditSkipReason(audit.PhaseDataFlow, 0, withTarget, entryRows); ok {
		t.Fatal("S3 must remain pending while entry-point coverage rows exist")
	}
}

func TestBuildAuditProgressTreatsS11AsSatisfied(t *testing.T) {
	session := &db.AuditSession{
		ID: 1, TaskID: 2, Status: db.AuditStatusRunning, Round: 1, MaxRounds: 1,
		Depth: audit.DepthQuick, Languages: []string{"go"},
	}
	plan := audit.Plan{Depth: audit.DepthQuick, Languages: []string{"go"}, PlannedCWEs: map[string][]string{"go": nil}}
	phases := []db.AuditPhase{
		{Phase: audit.PhaseIngest, Required: true, Status: "done"},
		{Phase: audit.PhaseProfile, Required: true, Status: "done"},
		{Phase: audit.PhaseSurface, Required: true, Status: "done"},
		{Phase: audit.PhaseDetect, Required: true, Status: "done"},
		{Phase: audit.PhaseReport, Required: true, Status: "pending"},
	}
	raw, err := buildAuditProgress(auditProgressInput{Session: session, Plan: plan, Phases: phases})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Gates map[string]audit.GateResult `json:"gates"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Gates["phase"].Passed {
		t.Fatalf("progress Gate-Phase should treat pending S11 as satisfied: %+v", out.Gates["phase"])
	}
}

func TestAuditCompletionWatchdogStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var checks atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchAuditCompletion(ctx, 2*time.Millisecond, func() bool { return false }, func() { checks.Add(1) })
	}()
	waitForAtomic(t, &checks, 1)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not stop after context cancellation")
	}
	stopped := checks.Load()
	time.Sleep(20 * time.Millisecond)
	if checks.Load() != stopped {
		t.Fatal("watchdog kept checking after cancellation")
	}
}

func TestAuditCompletionWatchdogStopsOnTerminalTask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var checks atomic.Int32
	var terminal atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchAuditCompletion(ctx, 2*time.Millisecond, terminal.Load, func() { checks.Add(1) })
	}()
	waitForAtomic(t, &checks, 1)
	terminal.Store(true)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not stop after task became terminal")
	}
}

func waitForAtomic(t *testing.T, value *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for value.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("watchdog never ran (checks=%d)", value.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBuildAuditProgressIncludesVerificationCandidates(t *testing.T) {
	session := &db.AuditSession{
		ID: 1, TaskID: 2, Status: db.AuditStatusRunning, Round: 1, MaxRounds: 2,
		Depth: audit.DepthQuick, Languages: []string{"go"},
	}
	plan := audit.Plan{Depth: audit.DepthQuick, Languages: []string{"go"}, PlannedCWEs: map[string][]string{"go": nil}}
	findings := buildAuditFindingCandidates([]auditFindingCandidate{{ID: 10, CWE: "CWE-89", Severity: "high"}}, 8, 5)
	raw, err := buildAuditProgress(auditProgressInput{
		Session: session, Plan: plan, Candidates: findings,
		Findings: map[string]int{"candidate": 1}, FindingsTotal: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Candidates []auditCoverageCandidate `json:"candidates"`
		ReportURL  string                   `json:"report_url"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Candidates) != 1 || out.Candidates[0].Phase != audit.PhaseVerify ||
		len(out.Candidates[0].FindingIDs) != 1 || out.Candidates[0].FindingIDs[0] != 10 ||
		out.Candidates[0].CWE != "CWE-89" || out.Candidates[0].Severity != "high" {
		t.Fatalf("candidates = %+v", out.Candidates)
	}
	if out.ReportURL != "" {
		t.Fatalf("report_url must be empty before completion: %q", out.ReportURL)
	}
}

func TestBuildAuditProgressIncludesEngineVisibility(t *testing.T) {
	session := &db.AuditSession{
		ID: 1, TaskID: 2, Status: db.AuditStatusRunning, Round: 1, MaxRounds: 1,
		Depth: audit.DepthQuick, Languages: []string{"go"},
		Engines: json.RawMessage(`{
			"intent_analysis": {
				"recognition_source": "fallback",
				"model": "test-model",
				"prompt_version": "v1",
				"raw_output_hash": "raw-hash",
				"repair_attempts": 1,
				"fallback": true,
				"error": "provider timeout",
				"query_gaps": ["LLM 意图识别失败，已回退确定性 sink 意图"]
			},
			"gaps": ["CodeQL unavailable"]
		}`),
	}
	intentID := int64(11)
	raw, err := buildAuditProgress(auditProgressInput{
		Session: session,
		Plan:    audit.Plan{Depth: audit.DepthQuick, Languages: []string{"go"}, PlannedCWEs: map[string][]string{"go": nil}},
		Engines: []db.AuditEngineJob{{
			ID: 7, IntentID: &intentID, Engine: "codeql", JobKind: "run",
			QueryHash: "query-hash", Status: "done", ResultCount: 3, DurationMS: 1250,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		EngineStatus struct {
			IntentAnalysis *auditIntentAnalysisRecord            `json:"intent_analysis"`
			JobCounts      map[string]auditReportEngineJobCounts `json:"job_counts"`
			Gaps           []string                              `json:"gaps"`
		} `json:"engine_status"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	analysis := out.EngineStatus.IntentAnalysis
	if analysis == nil {
		t.Fatal("engine_status.intent_analysis is missing")
	}
	if analysis.RecognitionSource != "fallback" || analysis.Model != "test-model" ||
		analysis.PromptVersion != "v1" || analysis.RawOutputHash != "raw-hash" ||
		analysis.RepairAttempts != 1 || !analysis.Fallback ||
		len(analysis.QueryGaps) != 1 {
		t.Fatalf("intent analysis = %+v", analysis)
	}
	if out.EngineStatus.JobCounts["codeql"].Done != 1 {
		t.Fatalf("job counts = %+v", out.EngineStatus.JobCounts)
	}
	if len(out.EngineStatus.Gaps) != 1 || out.EngineStatus.Gaps[0] != "CodeQL unavailable" {
		t.Fatalf("engine gaps = %+v", out.EngineStatus.Gaps)
	}
}

func TestBuildAuditProgressIncludesCoverageDetail(t *testing.T) {
	session := &db.AuditSession{
		ID: 1, TaskID: 2, Status: db.AuditStatusRunning, Round: 1, MaxRounds: 1,
		Depth: audit.DepthQuick, Languages: []string{"go"},
	}
	plan := audit.Plan{Depth: audit.DepthQuick, Languages: []string{"go"}, PlannedCWEs: map[string][]string{"go": {"CWE-79"}}}
	rows := []db.AuditCoverage{
		{Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-89", SinkKey: "cwe:go:CWE-89", Status: audit.CoverageStatusScanned},
		{Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-79", SinkKey: "cwe:go:CWE-79", Status: audit.CoverageStatusMissed, Reason: "not reached"},
		{Kind: audit.CoverageKindSinkSite, Language: "go", CWE: "CWE-79", Module: "internal/pay", Path: "internal/pay/db.go", Line: 42, SinkKey: "sink:db", Status: audit.CoverageStatusPlanned},
		{Kind: audit.CoverageKindSinkSite, Language: "go", CWE: "CWE-79", Module: "internal/pay", Path: "internal/pay/exempt.go", Line: 8, SinkKey: "sink:exempt", Status: audit.CoverageStatusExempt, Reason: "not approved"},
	}
	raw, err := buildAuditProgress(auditProgressInput{Session: session, Plan: plan, CoverageRows: rows})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		CoverageDetail struct {
			Rows          []auditReportGapRow `json:"rows"`
			UncoveredCWEs []string            `json:"uncovered_cwes"`
		} `json:"coverage_detail"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.CoverageDetail.Rows) != 3 {
		t.Fatalf("coverage detail rows = %+v", out.CoverageDetail.Rows)
	}
	if out.CoverageDetail.Rows[0].Status != audit.CoverageStatusMissed ||
		out.CoverageDetail.Rows[0].Kind != audit.CoverageKindCWE ||
		out.CoverageDetail.Rows[0].CWE != "CWE-79" {
		t.Fatalf("first coverage row = %+v", out.CoverageDetail.Rows[0])
	}
	if out.CoverageDetail.Rows[1].Path != "internal/pay/db.go" || out.CoverageDetail.Rows[1].Line != 42 {
		t.Fatalf("second coverage row = %+v", out.CoverageDetail.Rows[1])
	}
	if out.CoverageDetail.Rows[2].Status != audit.CoverageStatusExempt || out.CoverageDetail.Rows[2].Reason != "not approved" {
		t.Fatalf("third coverage row = %+v", out.CoverageDetail.Rows[2])
	}
	if len(out.CoverageDetail.UncoveredCWEs) != 1 || out.CoverageDetail.UncoveredCWEs[0] != "go|CWE-79" {
		t.Fatalf("uncovered cwes = %+v", out.CoverageDetail.UncoveredCWEs)
	}
}
