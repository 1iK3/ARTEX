package audit

import (
	"fmt"
	"sort"
	"strings"
)

const (
	coverageEpsilon          = 1e-9
	maxRequiredPhaseAttempts = 2
)

// GateCoverage checks the deterministic coverage ledger against the depth
// thresholds. Exempt rows count as covered but are listed in Details.
func GateCoverage(plan Plan, rows []CoverageRow, depth string) GateResult {
	depth = normalizeDepthValue(depth)
	if !validDepth(depth) {
		depth = DepthDeep
	}
	counts := ComputeCoverage(plan, rows)
	thresholds := Thresholds(depth)

	type dimension struct {
		name      string
		coverage  float64
		threshold float64
	}
	dimensions := []dimension{
		{name: "cwe", coverage: counts.CWE, threshold: thresholds.CWE},
		{name: "sink_site", coverage: counts.SinkSites, threshold: thresholds.SinkSites},
		{name: "module", coverage: counts.Modules, threshold: thresholds.Modules},
		{name: "entry_point", coverage: counts.EntryPoints, threshold: thresholds.EntryPoints},
	}
	failed := make([]string, 0)
	for _, dim := range dimensions {
		if dim.coverage+coverageEpsilon < dim.threshold {
			failed = append(failed, fmt.Sprintf("%s coverage %.4f below threshold %.2f", dim.name, dim.coverage, dim.threshold))
		}
	}
	if counts.InvalidExemptions > 0 {
		failed = append(failed, fmt.Sprintf("%d invalid exemption reason(s)", counts.InvalidExemptions))
	}

	exemptions := make([]CoverageRow, 0)
	for _, row := range rows {
		if normalizeCoverageStatus(row.Status) == CoverageStatusExempt {
			exemptions = append(exemptions, row)
		}
	}

	passed := len(failed) == 0
	reason := "coverage thresholds met"
	if !passed {
		reason = strings.Join(failed, "; ")
	}
	return GateResult{
		Name:   "Gate-Coverage",
		Passed: passed,
		Reason: reason,
		Details: map[string]any{
			"depth":      depth,
			"counts":     counts,
			"thresholds": thresholds,
			"exemptions": exemptions,
			"failed":     failed,
		},
	}
}

// GateCWE verifies that every planned language+CWE pair has at least one
// covered or exempt row. A language with an empty CWE plan is surfaced as a
// language_gap; the director decides whether that gap is acceptable.
func GateCWE(plan Plan, rows []CoverageRow) GateResult {
	pairs := plannedCWEPairs(plan)
	languageGaps := plannedLanguageGaps(plan)

	covered := make(map[string]struct{})
	for _, row := range rows {
		if !isCoveredRow(row) {
			continue
		}
		language := coverageLanguage(row.Language)
		cwe := strings.ToUpper(strings.TrimSpace(row.CWE))
		if language == "" || cwe == "" {
			continue
		}
		covered[coveragePairKey(language, cwe)] = struct{}{}
	}

	missing := make([]string, 0)
	for _, pair := range pairs {
		if _, ok := covered[coveragePairKey(pair.Language, pair.CWE)]; !ok {
			missing = append(missing, pair.Language+"|"+pair.CWE)
		}
	}
	sort.Strings(missing)

	noPlan := len(pairs) == 0
	passed := len(missing) == 0
	reason := "all planned CWEs have coverage"
	switch {
	case noPlan:
		reason = "no planned CWEs"
	case !passed:
		reason = fmt.Sprintf("%d of %d planned CWEs lack coverage", len(missing), len(pairs))
	}

	return GateResult{
		Name:   "Gate-CWE",
		Passed: passed,
		Reason: reason,
		Details: map[string]any{
			"planned":       len(pairs),
			"covered":       len(pairs) - len(missing),
			"missing":       missing,
			"language_gaps": languageGaps,
			"no_plan":       noPlan,
		},
	}
}

// PhaseStatus is one phase's status for Gate-Phase. Attempts counts failed
// execution attempts for the phase in the current round.
type PhaseStatus struct {
	Phase    string `json:"phase"`
	Required bool   `json:"required"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Attempts int    `json:"attempts,omitempty"`
}

// GatePhase requires every required phase to be done, skipped, or exempt.
// Skipped/exempt required phases need a non-empty reason, and a required phase
// with more than maxRequiredPhaseAttempts attempts fails the gate. Optional
// phase failures do not block.
func GatePhase(phases []PhaseStatus) GateResult {
	required := make([]string, 0)
	failed := make([]string, 0)
	missing := make([]string, 0)
	missingReasons := make([]string, 0)
	tooManyAttempts := make([]string, 0)
	markFailed := func(id string) {
		for _, existing := range failed {
			if existing == id {
				return
			}
		}
		failed = append(failed, id)
	}

	for _, phase := range phases {
		if !phase.Required {
			continue
		}
		id := strings.TrimSpace(phase.Phase)
		if id == "" {
			id = "<unnamed>"
		}
		required = append(required, id)
		status := normalizeCoverageStatus(phase.Status)
		switch status {
		case "":
			missing = append(missing, id)
		case "done":
			// Satisfied.
		case "skipped", "exempt":
			if strings.TrimSpace(phase.Reason) == "" {
				markFailed(id)
				missingReasons = append(missingReasons, id)
			}
		default:
			markFailed(id)
		}
		if phase.Attempts > maxRequiredPhaseAttempts {
			tooManyAttempts = append(tooManyAttempts, id)
			markFailed(id)
		}
	}

	passed := len(failed) == 0 && len(missing) == 0
	reason := "all required phases satisfied"
	if !passed {
		reason = fmt.Sprintf("%d required phase(s) failed, %d missing", len(failed), len(missing))
	}
	if len(required) == 0 {
		reason = "no required phases"
	}
	return GateResult{
		Name:   "Gate-Phase",
		Passed: passed,
		Reason: reason,
		Details: map[string]any{
			"required":          required,
			"failed":            failed,
			"missing":           missing,
			"missing_reasons":   missingReasons,
			"too_many_attempts": tooManyAttempts,
			"retry_limit":       maxRequiredPhaseAttempts,
		},
	}
}
