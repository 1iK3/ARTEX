package audit

import (
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Coverage row kinds and statuses persisted in audit_coverage.
const (
	CoverageKindCWE        = "cwe"
	CoverageKindSinkSite   = "sink_site"
	CoverageKindModule     = "module"
	CoverageKindEntryPoint = "entry_point"

	CoverageStatusPlanned   = "planned"
	CoverageStatusScanned   = "scanned"
	CoverageStatusCandidate = "candidate"
	CoverageStatusBenign    = "benign"
	CoverageStatusExempt    = "exempt"
	CoverageStatusMissed    = "missed"
)

// CoverageReceipt is one sink/module verdict submitted by an audit worker when
// it completes an intent. The server validates that SinkKey belongs to the
// intent's assigned coverage set before persisting the receipt.
type CoverageReceipt struct {
	SinkKey   string         `json:"sink_key"`
	Status    string         `json:"status"`
	Reason    string         `json:"reason,omitempty"`
	FindingID int64          `json:"finding_id,omitempty"`
	Evidence  map[string]any `json:"evidence,omitempty"`
}

// ValidCoverageReceiptStatus reports whether status is one an intent completion
// receipt may carry. "planned" is deliberately excluded: workers report what
// they observed, not future work.
func ValidCoverageReceiptStatus(status string) bool {
	switch normalizeCoverageStatus(status) {
	case CoverageStatusScanned, CoverageStatusCandidate, CoverageStatusBenign,
		CoverageStatusExempt, CoverageStatusMissed:
		return true
	}
	return false
}

// ValidExemptionReason reports whether reason is an approved exemption category
// (optionally with a ": detail" suffix). Gate-Coverage counts only these.
func ValidExemptionReason(reason string) bool {
	return validExemptionReason(reason)
}

// CoverageRow mirrors one audit_coverage row for the pure coverage and gate
// calculations. It intentionally has no DB dependency.
type CoverageRow struct {
	Kind     string `json:"kind"`
	Language string `json:"language,omitempty"`
	CWE      string `json:"cwe,omitempty"`
	Module   string `json:"module,omitempty"`
	Path     string `json:"path,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
	SinkKey  string `json:"sink_key,omitempty"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Line     int    `json:"line,omitempty"`
	Engine   string `json:"engine,omitempty"`
}

// CoverageCounts is the denominator/coverage ledger for one audit round.
// Percentages are 1.0 when the corresponding denominator is zero.
type CoverageCounts struct {
	CWE               float64 `json:"cwe"`
	SinkSites         float64 `json:"sink_sites"`
	Modules           float64 `json:"modules"`
	EntryPoints       float64 `json:"entry_points"`
	PlannedCWE        int     `json:"planned_cwe"`
	CoveredCWE        int     `json:"covered_cwe"`
	PlannedSites      int     `json:"planned_sites"`
	CoveredSites      int     `json:"covered_sites"`
	PlannedModules    int     `json:"planned_modules"`
	CoveredModules    int     `json:"covered_modules"`
	PlannedEntries    int     `json:"planned_entries"`
	CoveredEntries    int     `json:"covered_entries"`
	InvalidExemptions int     `json:"invalid_exemptions"`
}

// CoverageThresholds are the minimum per-dimension ratios for a depth.
type CoverageThresholds struct {
	CWE         float64 `json:"cwe"`
	SinkSites   float64 `json:"sink_sites"`
	Modules     float64 `json:"modules"`
	EntryPoints float64 `json:"entry_points"`
}

// GateResult is a machine-readable gate outcome. Details must stay JSON
// serializable because it is persisted in audit_phases/audit_rounds.
type GateResult struct {
	Name    string         `json:"name"`
	Passed  bool           `json:"passed"`
	Reason  string         `json:"reason"`
	Details map[string]any `json:"details,omitempty"`
}

type plannedCWEPair struct {
	Language string
	CWE      string
}

// ComputeCoverage computes the per-round coverage ledger. Exempt rows count as
// covered; planned and missed rows do not.
//
// Module denominator entries are the union of plan.Modules and module-kind
// coverage rows. A module is covered by a covered module row or by a covered
// sink/CWE row in that module. Planned entry points are matched against the
// symbol, path, or sink_key of a covered entry_point row. Exempt rows are
// covered only when Reason starts with an approved exemption category.
func ComputeCoverage(plan Plan, rows []CoverageRow) CoverageCounts {
	var counts CoverageCounts

	pairs := plannedCWEPairs(plan)
	counts.PlannedCWE = len(pairs)

	plannedModules := make(map[string]struct{})
	for _, module := range plan.Modules {
		if normalized := normalizeCoverageModule(module); normalized != "" {
			plannedModules[normalized] = struct{}{}
		}
	}
	for _, row := range rows {
		if coverageKind(row.Kind) == CoverageKindModule {
			if module := normalizeCoverageModule(row.Module); module != "" {
				plannedModules[module] = struct{}{}
			}
		}
	}

	plannedEntries := make(map[string]struct{})
	for _, entry := range plan.EntryPoints {
		if normalized := normalizeEntryIdent(entry); normalized != "" {
			plannedEntries[normalized] = struct{}{}
		}
	}

	coveredCWEs := make(map[string]struct{})
	coveredModules := make(map[string]struct{})
	coveredEntries := make(map[string]struct{})

	for _, row := range rows {
		kind := coverageKind(row.Kind)
		status := normalizeCoverageStatus(row.Status)
		if status == CoverageStatusExempt && !validExemptionReason(row.Reason) {
			counts.InvalidExemptions++
		}
		covered := isCoveredRow(row)

		if cwe := strings.ToUpper(strings.TrimSpace(row.CWE)); cwe != "" && covered {
			language := coverageLanguage(row.Language)
			if language != "" {
				coveredCWEs[coveragePairKey(language, cwe)] = struct{}{}
			}
		}

		if kind == CoverageKindSinkSite {
			counts.PlannedSites++
			if covered {
				counts.CoveredSites++
			}
		}

		if !covered {
			continue
		}
		module := normalizeCoverageModule(row.Module)
		switch kind {
		case CoverageKindModule:
			if module != "" {
				coveredModules[module] = struct{}{}
			}
		case CoverageKindSinkSite, CoverageKindCWE:
			if module != "" {
				coveredModules[module] = struct{}{}
			}
		case CoverageKindEntryPoint:
			for _, candidate := range []string{row.Symbol, row.Path, row.SinkKey} {
				entry := normalizeEntryIdent(candidate)
				if entry == "" {
					continue
				}
				if _, planned := plannedEntries[entry]; planned {
					coveredEntries[entry] = struct{}{}
				}
			}
		}
	}

	for _, pair := range pairs {
		if _, ok := coveredCWEs[coveragePairKey(pair.Language, pair.CWE)]; ok {
			counts.CoveredCWE++
		}
	}
	for module := range plannedModules {
		if _, ok := coveredModules[module]; ok {
			counts.CoveredModules++
		}
	}
	for entry := range plannedEntries {
		if _, ok := coveredEntries[entry]; ok {
			counts.CoveredEntries++
		}
	}

	counts.PlannedModules = len(plannedModules)
	counts.PlannedEntries = len(plannedEntries)
	counts.CWE = coverageRatio(counts.CoveredCWE, counts.PlannedCWE)
	counts.SinkSites = coverageRatio(counts.CoveredSites, counts.PlannedSites)
	counts.Modules = coverageRatio(counts.CoveredModules, counts.PlannedModules)
	counts.EntryPoints = coverageRatio(counts.CoveredEntries, counts.PlannedEntries)
	return counts
}

// Thresholds returns the per-depth Gate-Coverage thresholds. Empty and
// unknown depths fall back to deep.
func Thresholds(depth string) CoverageThresholds {
	switch normalizeDepthValue(depth) {
	case DepthQuick:
		return CoverageThresholds{CWE: 1.0, SinkSites: 0.90, Modules: 0.80, EntryPoints: 0.80}
	case DepthStandard:
		return CoverageThresholds{CWE: 1.0, SinkSites: 0.95, Modules: 0.95, EntryPoints: 0.95}
	default:
		return CoverageThresholds{CWE: 1.0, SinkSites: 1.0, Modules: 1.0, EntryPoints: 1.0}
	}
}

func coverageRatio(covered, planned int) float64 {
	if planned == 0 {
		return 1.0
	}
	return float64(covered) / float64(planned)
}

func plannedCWEPairs(plan Plan) []plannedCWEPair {
	seen := make(map[string]struct{})
	pairs := make([]plannedCWEPair, 0)
	for rawLanguage, cwes := range plan.PlannedCWEs {
		language := coverageLanguage(rawLanguage)
		if language == "" {
			continue
		}
		for _, rawCWE := range cwes {
			cwe := strings.ToUpper(strings.TrimSpace(rawCWE))
			if cwe == "" {
				continue
			}
			key := coveragePairKey(language, cwe)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			pairs = append(pairs, plannedCWEPair{Language: language, CWE: cwe})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Language != pairs[j].Language {
			return pairs[i].Language < pairs[j].Language
		}
		if cweNumber(pairs[i].CWE) != cweNumber(pairs[j].CWE) {
			return cweNumber(pairs[i].CWE) < cweNumber(pairs[j].CWE)
		}
		return pairs[i].CWE < pairs[j].CWE
	})
	return pairs
}

func plannedLanguageGaps(plan Plan) []string {
	counts := make(map[string]int)
	languages := make(map[string]struct{})
	for _, pair := range plannedCWEPairs(plan) {
		counts[pair.Language]++
		languages[pair.Language] = struct{}{}
	}
	for _, raw := range plan.Languages {
		language := coverageLanguage(raw)
		if language != "" {
			languages[language] = struct{}{}
		}
	}
	for raw := range plan.PlannedCWEs {
		language := coverageLanguage(raw)
		if language != "" {
			languages[language] = struct{}{}
		}
	}
	gaps := make([]string, 0)
	for language := range languages {
		if counts[language] == 0 {
			gaps = append(gaps, language)
		}
	}
	sort.Strings(gaps)
	return gaps
}

func coveragePairKey(language, cwe string) string {
	return language + "\x00" + cwe
}

func coverageLanguage(language string) string {
	language = strings.TrimSpace(language)
	if language == "" {
		return ""
	}
	if normalized := NormalizeLanguage(language); normalized != "" {
		return normalized
	}
	return strings.ToLower(language)
}

func coverageKind(kind string) string {
	return strings.ToLower(strings.TrimSpace(kind))
}

func normalizeCoverageStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

var validExemptionCategories = map[string]struct{}{
	"language_not_applicable": {},
	"no_sinks":                {},
	"index_unavailable":       {},
	"budget_exhausted":        {},
	"generated_code":          {},
	"test_code":               {},
	"unsupported_engine":      {},
}

// validExemptionReason accepts "category" or "category: detail", matching the
// exemption categories documented in the fusion design.
func validExemptionReason(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	if reason == "" {
		return false
	}
	if _, ok := validExemptionCategories[reason]; ok {
		return true
	}
	colon := strings.IndexByte(reason, ':')
	if colon <= 0 {
		return false
	}
	category := strings.TrimSpace(reason[:colon])
	detail := strings.TrimSpace(reason[colon+1:])
	if detail == "" {
		return false
	}
	_, ok := validExemptionCategories[category]
	return ok
}

func isCoveredRow(row CoverageRow) bool {
	switch normalizeCoverageStatus(row.Status) {
	case CoverageStatusScanned, CoverageStatusCandidate, CoverageStatusBenign:
		return true
	case CoverageStatusExempt:
		return validExemptionReason(row.Reason)
	default:
		return false
	}
}

func normalizeCoverageModule(module string) string {
	module = strings.TrimSpace(filepath.ToSlash(module))
	if module == "" {
		return ""
	}
	cleaned := path.Clean(module)
	if cleaned == "." && module != "." {
		return ""
	}
	return cleaned
}

func normalizeEntryIdent(entry string) string {
	return strings.TrimSpace(filepath.ToSlash(entry))
}
