package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Audit phases. They mirror the Omni-Audit S0-S11 pipeline.
const (
	PhaseIngest   = "S0"
	PhaseProfile  = "S1"
	PhaseSurface  = "S2"
	PhaseDataFlow = "S3"
	PhaseDetect   = "S4"
	PhaseVerify   = "S5"
	PhaseLogic    = "S6"
	PhaseOdinDeep = "S7"
	PhaseDesign   = "S8"
	PhaseDepth    = "S9"
	PhasePoC      = "S10"
	PhaseReport   = "S11"
)

// CoreCWE is the fixed 26-CWE core scope for quick and standard audits.
var CoreCWE = []string{
	"CWE-78", "CWE-94", "CWE-22", "CWE-918", "CWE-502",
	"CWE-79", "CWE-89", "CWE-611", "CWE-327", "CWE-287",
	"CWE-798", "CWE-434", "CWE-347", "CWE-295", "CWE-352",
	"CWE-862", "CWE-639", "CWE-470", "CWE-601", "CWE-1321",
	"CWE-93", "CWE-940", "CWE-119", "CWE-134", "CWE-416",
	"CWE-415",
}

// PhasePlan is one phase in the deterministic audit matrix.
type PhasePlan struct {
	Phase     string   `json:"phase"`
	Required  bool     `json:"required"`
	DependsOn []string `json:"depends_on"`
}

// Plan is the deterministic output consumed by the audit director and
// coverage gates. PlannedCWEs is keyed by canonical language.
type Plan struct {
	Depth       string              `json:"depth"`
	MaxRounds   int                 `json:"max_rounds"`
	Languages   []string            `json:"languages"`
	PlannedCWEs map[string][]string `json:"planned_cwes"`
	Phases      []PhasePlan         `json:"phases"`
	Modules     []string            `json:"modules"`
	EntryPoints []string            `json:"entry_points"`
}

var phaseOrder = []string{
	PhaseIngest,
	PhaseProfile,
	PhaseSurface,
	PhaseDataFlow,
	PhaseDetect,
	PhaseVerify,
	PhaseLogic,
	PhaseOdinDeep,
	PhaseDesign,
	PhaseDepth,
	PhasePoC,
	PhaseReport,
}

var phaseDependencies = map[string][]string{
	PhaseIngest:   {},
	PhaseProfile:  {PhaseIngest},
	PhaseSurface:  {PhaseProfile},
	PhaseDataFlow: {PhaseSurface},
	PhaseDetect:   {PhaseProfile},
	PhaseVerify:   {PhaseDetect},
	PhaseLogic:    {PhaseSurface, PhaseVerify},
	PhaseOdinDeep: {PhaseVerify},
	PhaseDesign:   {PhaseVerify, PhaseOdinDeep},
	PhaseDepth:    {PhaseDesign},
	PhasePoC:      {PhaseDesign, PhaseDepth},
	PhaseReport:   {PhaseIngest, PhaseProfile, PhaseSurface, PhaseDataFlow, PhaseDetect, PhaseVerify, PhaseLogic, PhaseOdinDeep, PhaseDesign, PhaseDepth, PhasePoC},
}

// BuildPlan turns a profile and frozen task config into a deterministic audit
// plan. Unknown CWEs are retained for explicit scope; unsupported languages
// receive an empty CWE list so the director can record a language gap.
func BuildPlan(profile Profile, cfg Config, reg Registry) (Plan, error) {
	depth := normalizeDepthValue(cfg.Depth)
	if depth == "" {
		depth = DepthDeep
	}
	if !validDepth(depth) {
		return Plan{}, fmt.Errorf("无效的 depth %q（quick|standard|deep）", cfg.Depth)
	}

	languages := planLanguages(cfg.Languages, profile.Languages)
	if len(languages) == 0 {
		return Plan{}, errors.New("无法确定审计语言（请配置 languages 或在源码中提供可识别文件）")
	}

	cwes, err := plannedCWEIDs(cfg, languages, reg)
	if err != nil {
		return Plan{}, err
	}
	planned := make(map[string][]string, len(languages))
	for _, language := range languages {
		planned[language] = cloneStrings(cwes[language])
		if planned[language] == nil {
			planned[language] = []string{}
		}
	}

	rounds := cfg.MaxRounds
	if rounds <= 0 {
		rounds = roundsForDepth(depth)
	}

	return Plan{
		Depth:       depth,
		MaxRounds:   rounds,
		Languages:   cloneStrings(languages),
		PlannedCWEs: planned,
		Phases:      buildPhases(depth),
		Modules:     cloneStrings(profile.Modules),
		EntryPoints: []string{},
	}, nil
}

func planLanguages(configured, fromProfile []string) []string {
	source := configured
	if len(source) == 0 {
		source = fromProfile
	}
	out := make([]string, 0, len(source))
	seen := make(map[string]struct{}, len(source))
	for _, raw := range source {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		language := NormalizeLanguage(raw)
		if language == "" {
			language = strings.ToLower(raw)
		}
		if _, ok := seen[language]; ok {
			continue
		}
		seen[language] = struct{}{}
		out = append(out, language)
	}
	return out
}

func plannedCWEIDs(cfg Config, languages []string, reg Registry) (map[string][]string, error) {
	scope := strings.ToLower(strings.TrimSpace(cfg.CWEScope))
	if scope == "" {
		scope = CWEScopeCore
	}
	out := make(map[string][]string, len(languages))

	switch scope {
	case CWEScopeCore:
		core := cloneStrings(CoreCWE)
		sortCWEIDs(core)
		for _, language := range languages {
			out[language] = cloneStrings(core)
		}
	case CWEScopeExplicit:
		explicit, err := normalizeExplicitCWEIDs(cfg.CWEIDs)
		if err != nil {
			return nil, err
		}
		for _, language := range languages {
			out[language] = cloneStrings(explicit)
		}
	case CWEScopeFull:
		for _, language := range languages {
			ids, err := fullCWEIDs(language, reg)
			if err != nil {
				return nil, err
			}
			out[language] = ids
		}
	default:
		return nil, fmt.Errorf("无效的 cwe_scope %q（core|full|explicit）", cfg.CWEScope)
	}
	return out, nil
}

func normalizeExplicitCWEIDs(raw []string) ([]string, error) {
	ids := normalizeCWEIDs(raw)
	if len(ids) == 0 {
		return nil, errors.New("cwe_scope=explicit 时必须提供 cwe_ids")
	}
	for _, id := range ids {
		if !cweIDPattern.MatchString(id) {
			return nil, fmt.Errorf("无效的 CWE 编号 %q（应形如 CWE-89）", id)
		}
	}
	sortCWEIDs(ids)
	return ids, nil
}

// fullCWEIDs builds deep scope from the CWE table, sink definitions, Odin
// rules, and framework taint registries. Taint CWEs are collected by
// recursively scanning the framework JSON for cwe/cweId/cwe_id string fields;
// this is a deliberate heuristic because the registry schema is intentionally
// open-ended and owned by Omni-Audit.
func fullCWEIDs(language string, reg Registry) ([]string, error) {
	seen := make(map[string]struct{})
	add := func(id string) {
		if cweIDPattern.MatchString(id) {
			seen[id] = struct{}{}
		}
	}

	for _, definition := range reg.CWEsFor(language) {
		add(definition.ID)
	}
	for _, definition := range reg.SinksFor(language) {
		add(definition.CWEID)
	}
	for _, rule := range reg.OdinRulesFor(language) {
		add(rule.CWE)
	}
	for _, taint := range reg.TaintsFor(language) {
		if err := collectTaintCWEs(taint.Frameworks, seen, 0); err != nil {
			name := strings.TrimSpace(taint.RegistryName)
			if name == "" {
				name = language
			}
			return nil, fmt.Errorf("decode taint registry %q: %w", name, err)
		}
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sortCWEIDs(ids)
	return ids, nil
}

func collectTaintCWEs(raw json.RawMessage, seen map[string]struct{}, depth int) error {
	if len(raw) == 0 || depth > 64 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	collectTaintCWEValue(decoded, seen, depth)
	return nil
}

func collectTaintCWEValue(value any, seen map[string]struct{}, depth int) {
	if depth > 64 {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			switch strings.ToLower(key) {
			case "cwe", "cweid", "cwe_id":
				if id, ok := nested.(string); ok && cweIDPattern.MatchString(id) {
					seen[id] = struct{}{}
				}
			}
			collectTaintCWEValue(nested, seen, depth+1)
		}
	case []any:
		for _, nested := range typed {
			collectTaintCWEValue(nested, seen, depth+1)
		}
	}
}

func sortCWEIDs(ids []string) {
	sort.Slice(ids, func(i, j int) bool {
		left, right := cweNumber(ids[i]), cweNumber(ids[j])
		if left != right {
			return left < right
		}
		return ids[i] < ids[j]
	})
}

func cweNumber(id string) int {
	number, err := strconv.Atoi(strings.TrimPrefix(id, "CWE-"))
	if err != nil {
		return int(^uint(0) >> 1)
	}
	return number
}

func buildPhases(depth string) []PhasePlan {
	included := make(map[string]bool, len(phaseOrder))
	for _, phase := range phaseOrder {
		switch depth {
		case DepthQuick, DepthStandard:
			if phase == PhaseOdinDeep || phase == PhaseDepth {
				continue
			}
		}
		included[phase] = true
	}

	phases := make([]PhasePlan, 0, len(included))
	for _, phase := range phaseOrder {
		if !included[phase] {
			continue
		}
		required := true
		if depth == DepthQuick {
			switch phase {
			case PhaseDataFlow, PhaseLogic, PhasePoC:
				required = false
			}
		}
		dependencies := make([]string, 0, len(phaseDependencies[phase]))
		for _, dependency := range phaseDependencies[phase] {
			if included[dependency] {
				dependencies = append(dependencies, dependency)
			}
		}
		phases = append(phases, PhasePlan{
			Phase:     phase,
			Required:  required,
			DependsOn: dependencies,
		})
	}
	return phases
}
