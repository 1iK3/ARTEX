package audit

import (
	"fmt"
	"strings"
	"testing"
)

func TestComputeCoverage(t *testing.T) {
	plan := Plan{
		Languages: []string{Java, Python},
		PlannedCWEs: map[string][]string{
			Java:   {"CWE-89", "CWE-78", "CWE-89"},
			Python: {"CWE-22"},
		},
		Modules:     []string{"api", "worker"},
		EntryPoints: []string{"api.Handler", "worker.Run"},
	}
	rows := []CoverageRow{
		{Kind: CoverageKindCWE, Language: Java, CWE: "CWE-89", Status: CoverageStatusScanned},
		{Kind: CoverageKindCWE, Language: "JAVA", CWE: "CWE-78", Status: CoverageStatusExempt, Reason: "no_sinks: fixture"},
		{Kind: CoverageKindCWE, Language: Python, CWE: "CWE-22", Status: CoverageStatusMissed},
		{Kind: CoverageKindSinkSite, Module: "api", Status: CoverageStatusScanned},
		{Kind: CoverageKindSinkSite, Module: "api", Status: CoverageStatusCandidate},
		{Kind: CoverageKindSinkSite, Module: "api", Status: CoverageStatusBenign},
		{Kind: CoverageKindSinkSite, Module: "worker", Status: CoverageStatusMissed},
		{Kind: CoverageKindModule, Module: "api", Status: CoverageStatusScanned},
		{Kind: CoverageKindModule, Module: "worker", Status: CoverageStatusPlanned},
		{Kind: CoverageKindEntryPoint, Symbol: "api.Handler", Status: CoverageStatusScanned},
		{Kind: CoverageKindEntryPoint, Symbol: "worker.Run", Status: CoverageStatusPlanned},
		{Kind: "source", Status: CoverageStatusScanned},
	}

	counts := ComputeCoverage(plan, rows)
	if counts.PlannedCWE != 3 || counts.CoveredCWE != 2 {
		t.Fatalf("CWE planned/covered = %d/%d, want 3/2", counts.PlannedCWE, counts.CoveredCWE)
	}
	if counts.CWE < 0.66 || counts.CWE > 0.67 {
		t.Fatalf("CWE coverage = %f, want ~0.6667", counts.CWE)
	}
	if counts.PlannedSites != 4 || counts.CoveredSites != 3 || counts.SinkSites != 0.75 {
		t.Fatalf("sites = planned %d covered %d ratio %f, want 4/3/0.75", counts.PlannedSites, counts.CoveredSites, counts.SinkSites)
	}
	if counts.PlannedModules != 2 || counts.CoveredModules != 1 || counts.Modules != 0.5 {
		t.Fatalf("modules = planned %d covered %d ratio %f, want 2/1/0.5", counts.PlannedModules, counts.CoveredModules, counts.Modules)
	}
	if counts.PlannedEntries != 2 || counts.CoveredEntries != 1 || counts.EntryPoints != 0.5 {
		t.Fatalf("entries = planned %d covered %d ratio %f, want 2/1/0.5", counts.PlannedEntries, counts.CoveredEntries, counts.EntryPoints)
	}
}

func TestComputeCoverageModuleFallbackAndEntryIdentifiers(t *testing.T) {
	plan := Plan{
		Modules:     []string{"a", "b"},
		EntryPoints: []string{"p", "q", "r"},
	}
	rows := []CoverageRow{
		{Kind: CoverageKindSinkSite, Module: "a", Status: CoverageStatusScanned},
		{Kind: CoverageKindCWE, Module: "b", Status: CoverageStatusCandidate},
		{Kind: CoverageKindEntryPoint, Path: "p", Status: CoverageStatusScanned},
		{Kind: CoverageKindEntryPoint, SinkKey: "q", Status: CoverageStatusBenign},
		{Kind: CoverageKindEntryPoint, Symbol: "r", Status: CoverageStatusMissed},
		{Kind: CoverageKindEntryPoint, Symbol: "not-planned", Status: CoverageStatusScanned},
	}
	counts := ComputeCoverage(plan, rows)
	if counts.PlannedModules != 2 || counts.CoveredModules != 2 || counts.Modules != 1 {
		t.Fatalf("modules = %d/%d/%f, want 2/2/1", counts.PlannedModules, counts.CoveredModules, counts.Modules)
	}
	if counts.PlannedEntries != 3 || counts.CoveredEntries != 2 || counts.EntryPoints < 0.66 || counts.EntryPoints > 0.67 {
		t.Fatalf("entries = %d/%d/%f, want 3/2/~0.6667", counts.PlannedEntries, counts.CoveredEntries, counts.EntryPoints)
	}
	if counts.PlannedCWE != 0 || counts.CWE != 1 {
		t.Fatalf("CWE zero denominator = %d/%f, want 0/1", counts.PlannedCWE, counts.CWE)
	}
}

func TestComputeCoverageModuleRowsAreAddedToDenominator(t *testing.T) {
	plan := Plan{Modules: []string{"a"}}
	rows := []CoverageRow{
		{Kind: CoverageKindModule, Module: "b", Status: CoverageStatusPlanned},
		{Kind: CoverageKindSinkSite, Module: "a", Status: CoverageStatusScanned},
	}
	counts := ComputeCoverage(plan, rows)
	if counts.PlannedModules != 2 || counts.CoveredModules != 1 || counts.Modules != 0.5 {
		t.Fatalf("modules = %d/%d/%f, want 2/1/0.5", counts.PlannedModules, counts.CoveredModules, counts.Modules)
	}
}

func TestComputeCoverageZeroDenominators(t *testing.T) {
	plan := Plan{Languages: []string{Go}, PlannedCWEs: map[string][]string{Go: {}}}
	counts := ComputeCoverage(plan, nil)
	if counts.PlannedCWE != 0 || counts.CWE != 1 {
		t.Fatalf("CWE = %d/%f", counts.PlannedCWE, counts.CWE)
	}
	if counts.PlannedSites != 0 || counts.SinkSites != 1 {
		t.Fatalf("sites = %d/%f", counts.PlannedSites, counts.SinkSites)
	}
	if counts.PlannedModules != 0 || counts.Modules != 1 {
		t.Fatalf("modules = %d/%f", counts.PlannedModules, counts.Modules)
	}
	if counts.PlannedEntries != 0 || counts.EntryPoints != 1 {
		t.Fatalf("entries = %d/%f", counts.PlannedEntries, counts.EntryPoints)
	}
}

func TestThresholds(t *testing.T) {
	tests := []struct {
		depth string
		want  CoverageThresholds
	}{
		{DepthQuick, CoverageThresholds{CWE: 1.0, SinkSites: 0.90, Modules: 0.80, EntryPoints: 0.80}},
		{DepthStandard, CoverageThresholds{CWE: 1.0, SinkSites: 0.95, Modules: 0.95, EntryPoints: 0.95}},
		{DepthDeep, CoverageThresholds{CWE: 1.0, SinkSites: 1.0, Modules: 1.0, EntryPoints: 1.0}},
		{"", CoverageThresholds{CWE: 1.0, SinkSites: 1.0, Modules: 1.0, EntryPoints: 1.0}},
		{"unknown", CoverageThresholds{CWE: 1.0, SinkSites: 1.0, Modules: 1.0, EntryPoints: 1.0}},
	}
	for _, tc := range tests {
		if got := Thresholds(tc.depth); got != tc.want {
			t.Errorf("Thresholds(%q) = %+v, want %+v", tc.depth, got, tc.want)
		}
	}
}

func gateCoverageFixture() (Plan, []CoverageRow) {
	plan := Plan{
		PlannedCWEs: map[string][]string{Java: {"CWE-89", "CWE-78"}},
		Modules:     []string{"m0", "m1", "m2", "m3", "m4"},
		EntryPoints: []string{"e0", "e1", "e2", "e3", "e4"},
	}
	rows := []CoverageRow{
		{Kind: CoverageKindCWE, Language: Java, CWE: "CWE-89", Status: CoverageStatusScanned},
		{Kind: CoverageKindCWE, Language: Java, CWE: "CWE-78", Status: CoverageStatusScanned},
	}
	for i := 0; i < 10; i++ {
		status := CoverageStatusScanned
		module := fmt.Sprintf("m%d", i%4)
		if i == 9 {
			status = CoverageStatusMissed
			module = "m4"
		}
		rows = append(rows, CoverageRow{
			Kind:   CoverageKindSinkSite,
			Module: module,
			Status: status,
		})
	}
	for i := 0; i < 5; i++ {
		status := CoverageStatusScanned
		if i == 4 {
			status = CoverageStatusMissed
		}
		rows = append(rows, CoverageRow{
			Kind:   CoverageKindEntryPoint,
			Symbol: fmt.Sprintf("e%d", i),
			Status: status,
		})
	}
	return plan, rows
}

func TestGateCoverageThresholds(t *testing.T) {
	plan, rows := gateCoverageFixture()

	quick := GateCoverage(plan, rows, DepthQuick)
	if quick.Name != "Gate-Coverage" || !quick.Passed {
		t.Fatalf("quick gate = %+v, want pass", quick)
	}
	if quick.Details == nil {
		t.Fatal("quick gate details are nil")
	}
	quickCounts, ok := quick.Details["counts"].(CoverageCounts)
	if !ok {
		t.Fatalf("details counts type = %T", quick.Details["counts"])
	}
	if quickCounts.SinkSites != 0.9 || quickCounts.Modules != 0.8 || quickCounts.EntryPoints != 0.8 {
		t.Fatalf("quick counts = %+v", quickCounts)
	}

	standard := GateCoverage(plan, rows, DepthStandard)
	if standard.Passed {
		t.Fatalf("standard gate = %+v, want fail", standard)
	}
	failed, ok := standard.Details["failed"].([]string)
	if !ok || len(failed) == 0 {
		t.Fatalf("standard failed details = %#v", standard.Details["failed"])
	}
	if !strings.Contains(strings.Join(failed, "; "), "sink") {
		t.Fatalf("failed details = %v, want sink gap", failed)
	}

	deep := GateCoverage(plan, rows, DepthDeep)
	if deep.Passed {
		t.Fatalf("deep gate = %+v, want fail", deep)
	}
}

func TestGateCoverageExemptionsAndEmptyPlan(t *testing.T) {
	plan := Plan{PlannedCWEs: map[string][]string{Java: {"CWE-89"}}}
	rows := []CoverageRow{{
		Kind: CoverageKindCWE, Language: Java, CWE: "CWE-89", Status: CoverageStatusExempt, Reason: "generated_code: generated sources",
	}}
	result := GateCoverage(plan, rows, DepthDeep)
	if !result.Passed {
		t.Fatalf("exempt gate = %+v, want pass", result)
	}
	exemptions, ok := result.Details["exemptions"].([]CoverageRow)
	if !ok || len(exemptions) != 1 || exemptions[0].Reason != "generated_code: generated sources" {
		t.Fatalf("exemptions details = %#v", result.Details["exemptions"])
	}

	empty := GateCoverage(Plan{}, nil, DepthDeep)
	if !empty.Passed {
		t.Fatalf("empty plan gate = %+v, want pass", empty)
	}
}

func TestGateCWEPass(t *testing.T) {
	plan := Plan{
		Languages: []string{Java, Python},
		PlannedCWEs: map[string][]string{
			Java:   {"CWE-89"},
			Python: {"CWE-22"},
		},
	}
	rows := []CoverageRow{
		{Kind: CoverageKindCWE, Language: "JAVA", CWE: "CWE-89", Status: CoverageStatusScanned},
		{Kind: CoverageKindCWE, Language: Python, CWE: "CWE-22", Status: CoverageStatusExempt, Reason: "no_sinks"},
	}
	result := GateCWE(plan, rows)
	if result.Name != "Gate-CWE" || !result.Passed {
		t.Fatalf("gate = %+v, want pass", result)
	}
	if noPlan, _ := result.Details["no_plan"].(bool); noPlan {
		t.Fatalf("no_plan = true in non-empty plan: %+v", result.Details)
	}
}

func TestGateCWEFailsMissingPairs(t *testing.T) {
	plan := Plan{
		PlannedCWEs: map[string][]string{
			Java:   {"CWE-89", "CWE-78"},
			Python: {"CWE-22"},
		},
	}
	rows := []CoverageRow{
		{Kind: CoverageKindCWE, Language: Java, CWE: "CWE-89", Status: CoverageStatusScanned},
		{Kind: CoverageKindCWE, Language: Java, CWE: "CWE-78", Status: CoverageStatusMissed},
		{Kind: CoverageKindCWE, Language: Python, CWE: "CWE-22", Status: CoverageStatusPlanned},
	}
	result := GateCWE(plan, rows)
	if result.Passed {
		t.Fatalf("gate = %+v, want fail", result)
	}
	missing, ok := result.Details["missing"].([]string)
	if !ok {
		t.Fatalf("missing type = %T", result.Details["missing"])
	}
	want := []string{"java|CWE-78", "python|CWE-22"}
	if !equalStrings(missing, want) {
		t.Fatalf("missing = %v, want %v", missing, want)
	}
	if planned, _ := result.Details["planned"].(int); planned != 3 {
		t.Fatalf("planned = %v, want 3", result.Details["planned"])
	}
	if covered, _ := result.Details["covered"].(int); covered != 1 {
		t.Fatalf("covered = %v, want 1", result.Details["covered"])
	}
}

func TestGateCWELanguageGapAndNoPlan(t *testing.T) {
	plan := Plan{
		Languages: []string{Java, "ruby"},
		PlannedCWEs: map[string][]string{
			Java:   {"CWE-89"},
			"ruby": {},
		},
	}
	rows := []CoverageRow{
		{Kind: CoverageKindCWE, Language: Java, CWE: "CWE-89", Status: CoverageStatusScanned},
	}
	result := GateCWE(plan, rows)
	if !result.Passed {
		t.Fatalf("gate = %+v, want pass with language gap details", result)
	}
	gaps, ok := result.Details["language_gaps"].([]string)
	if !ok || !equalStrings(gaps, []string{"ruby"}) {
		t.Fatalf("language_gaps = %#v", result.Details["language_gaps"])
	}

	noPlan := GateCWE(Plan{Languages: []string{Go}, PlannedCWEs: map[string][]string{Go: {}}}, nil)
	if !noPlan.Passed {
		t.Fatalf("no-plan gate = %+v, want pass", noPlan)
	}
	if noPlanFlag, _ := noPlan.Details["no_plan"].(bool); !noPlanFlag {
		t.Fatalf("no_plan = %#v, want true", noPlan.Details["no_plan"])
	}
	if gaps, _ := noPlan.Details["language_gaps"].([]string); !equalStrings(gaps, []string{Go}) {
		t.Fatalf("no-plan language_gaps = %#v", noPlan.Details["language_gaps"])
	}

	empty := GateCWE(Plan{}, nil)
	if !empty.Passed {
		t.Fatalf("empty plan gate = %+v", empty)
	}
}

func TestGatePhase(t *testing.T) {
	phases := []PhaseStatus{
		{Phase: PhaseIngest, Required: true, Status: CoverageStatusScanned}, // arbitrary statuses are phase gaps
		{Phase: PhaseProfile, Required: true, Status: "done"},
		{Phase: PhaseSurface, Required: true, Status: "skipped", Reason: "not applicable"},
		{Phase: PhaseDataFlow, Required: true, Status: "exempt", Reason: "no entry"},
		{Phase: PhaseDetect, Required: false, Status: "failed"},
	}
	result := GatePhase(phases)
	if result.Name != "Gate-Phase" || result.Passed {
		t.Fatalf("gate = %+v, want fail because scanned is not a phase state", result)
	}
	failed, _ := result.Details["failed"].([]string)
	if !equalStrings(failed, []string{PhaseIngest}) {
		t.Fatalf("failed = %v, want [S0]", failed)
	}

	phases = []PhaseStatus{
		{Phase: PhaseIngest, Required: true, Status: "done"},
		{Phase: PhaseProfile, Required: true, Status: "skipped", Reason: "no profile work"},
		{Phase: PhaseSurface, Required: true, Status: "exempt", Reason: "no entries"},
		{Phase: PhaseDetect, Required: false, Status: "failed"},
	}
	result = GatePhase(phases)
	if !result.Passed {
		t.Fatalf("gate = %+v, want pass; optional failed phases are ignored", result)
	}

	missing := GatePhase([]PhaseStatus{
		{Phase: PhaseIngest, Required: true, Status: ""},
		{Phase: PhaseProfile, Required: true, Status: "running"},
	})
	if missing.Passed {
		t.Fatalf("missing gate = %+v, want fail", missing)
	}
	missingList, _ := missing.Details["missing"].([]string)
	failedList, _ := missing.Details["failed"].([]string)
	if !equalStrings(missingList, []string{PhaseIngest}) {
		t.Fatalf("missing = %v, want [S0]", missingList)
	}
	if !equalStrings(failedList, []string{PhaseProfile}) {
		t.Fatalf("failed = %v, want [S1]", failedList)
	}

	if empty := GatePhase(nil); !empty.Passed {
		t.Fatalf("empty gate = %+v, want pass", empty)
	}
}

func TestGatePhaseRequiresReasonsAndRetryLimit(t *testing.T) {
	noReason := GatePhase([]PhaseStatus{
		{Phase: PhaseProfile, Required: true, Status: "skipped"},
	})
	if noReason.Passed {
		t.Fatalf("skipped without reason gate = %+v, want fail", noReason)
	}
	missingReasons, _ := noReason.Details["missing_reasons"].([]string)
	if !equalStrings(missingReasons, []string{PhaseProfile}) {
		t.Fatalf("missing_reasons = %v", missingReasons)
	}

	tooMany := GatePhase([]PhaseStatus{
		{Phase: PhaseIngest, Required: true, Status: "done", Attempts: 3},
	})
	if tooMany.Passed {
		t.Fatalf("attempts gate = %+v, want fail", tooMany)
	}
	attempts, _ := tooMany.Details["too_many_attempts"].([]string)
	if !equalStrings(attempts, []string{PhaseIngest}) {
		t.Fatalf("too_many_attempts = %v", attempts)
	}

	atLimit := GatePhase([]PhaseStatus{
		{Phase: PhaseIngest, Required: true, Status: "done", Attempts: 2},
	})
	if !atLimit.Passed {
		t.Fatalf("attempts at retry limit = %+v, want pass", atLimit)
	}

	optional := GatePhase([]PhaseStatus{
		{Phase: PhaseIngest, Required: true, Status: "done"},
		{Phase: PhaseDetect, Required: false, Status: "skipped", Attempts: 9},
	})
	if !optional.Passed {
		t.Fatalf("optional failed phase must not block: %+v", optional)
	}
}

func TestCoverageCoveredStatusBoundaries(t *testing.T) {
	plan := Plan{PlannedCWEs: map[string][]string{Java: {"CWE-89"}}}
	tests := []struct {
		status  string
		reason  string
		covered bool
		invalid int
	}{
		{CoverageStatusScanned, "", true, 0},
		{CoverageStatusCandidate, "", true, 0},
		{CoverageStatusBenign, "", true, 0},
		{CoverageStatusExempt, "generated_code: generated parser", true, 0},
		{CoverageStatusExempt, "", false, 1},
		{CoverageStatusExempt, "made_up_reason", false, 1},
		{CoverageStatusPlanned, "", false, 0},
		{CoverageStatusMissed, "", false, 0},
		{"unknown", "", false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.status+"_"+tc.reason, func(t *testing.T) {
			rows := []CoverageRow{{
				Kind: CoverageKindCWE, Language: Java, CWE: "CWE-89", Status: tc.status, Reason: tc.reason,
			}}
			counts := ComputeCoverage(plan, rows)
			wantCovered := 0
			if tc.covered {
				wantCovered = 1
			}
			if counts.CoveredCWE != wantCovered || counts.InvalidExemptions != tc.invalid {
				t.Fatalf("counts = %+v, want covered=%d invalid=%d", counts, wantCovered, tc.invalid)
			}
		})
	}
}

func TestValidExemptionCategories(t *testing.T) {
	valid := []string{
		"language_not_applicable",
		"no_sinks",
		"no_sinks: no dangerous API in module",
		"INDEX_UNAVAILABLE",
		"budget_exhausted: round budget",
		"generated_code",
		"test_code: fixtures",
		"unsupported_engine: codeql missing",
	}
	for _, reason := range valid {
		if !validExemptionReason(reason) {
			t.Errorf("validExemptionReason(%q) = false, want true", reason)
		}
	}
	invalid := []string{
		"", "not reachable", "generated_codex", "no_sinks because no API",
		"unknown_category: detail", "no_sinks:",
	}
	for _, reason := range invalid {
		if validExemptionReason(reason) {
			t.Errorf("validExemptionReason(%q) = true, want false", reason)
		}
	}
}

func TestGateCoverageInvalidExemptionFails(t *testing.T) {
	for _, reason := range []string{"", "made_up_reason"} {
		result := GateCoverage(Plan{}, []CoverageRow{{
			Kind: CoverageKindCWE, Language: Java, CWE: "CWE-89", Status: CoverageStatusExempt, Reason: reason,
		}}, DepthDeep)
		if result.Passed {
			t.Fatalf("reason %q: gate = %+v, want failure", reason, result)
		}
		counts, ok := result.Details["counts"].(CoverageCounts)
		if !ok || counts.InvalidExemptions != 1 {
			t.Fatalf("reason %q: counts = %#v", reason, result.Details["counts"])
		}
	}
}

func TestGateCWEInvalidExemptionDoesNotCover(t *testing.T) {
	plan := Plan{PlannedCWEs: map[string][]string{Java: {"CWE-89"}}}
	result := GateCWE(plan, []CoverageRow{{
		Kind: CoverageKindCWE, Language: Java, CWE: "CWE-89", Status: CoverageStatusExempt, Reason: "made_up_reason",
	}})
	if result.Passed {
		t.Fatalf("gate = %+v, want failure for invalid exemption", result)
	}
	missing, _ := result.Details["missing"].([]string)
	if !equalStrings(missing, []string{"java|CWE-89"}) {
		t.Fatalf("missing = %v", missing)
	}
}
