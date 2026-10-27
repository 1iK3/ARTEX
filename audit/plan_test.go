package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func planPhase(t *testing.T, plan Plan, id string) PhasePlan {
	t.Helper()
	for _, phase := range plan.Phases {
		if phase.Phase == id {
			return phase
		}
	}
	t.Fatalf("plan has no phase %s", id)
	return PhasePlan{}
}

func phaseIDs(plan Plan) []string {
	ids := make([]string, 0, len(plan.Phases))
	for _, phase := range plan.Phases {
		ids = append(ids, phase.Phase)
	}
	return ids
}

func TestCoreCWEList(t *testing.T) {
	if len(CoreCWE) != 26 {
		t.Fatalf("CoreCWE length = %d, want 26", len(CoreCWE))
	}
	seen := make(map[string]bool)
	required := map[string]bool{
		"CWE-78": true, "CWE-94": true, "CWE-22": true, "CWE-918": true,
		"CWE-502": true, "CWE-79": true, "CWE-89": true, "CWE-611": true,
		"CWE-327": true, "CWE-287": true, "CWE-798": true, "CWE-434": true,
		"CWE-347": true, "CWE-295": true, "CWE-352": true, "CWE-862": true,
		"CWE-639": true, "CWE-470": true, "CWE-601": true, "CWE-1321": true,
		"CWE-93": true, "CWE-940": true, "CWE-119": true, "CWE-134": true,
		"CWE-416": true, "CWE-415": true,
	}
	for _, cwe := range CoreCWE {
		if !cweIDPattern.MatchString(cwe) {
			t.Errorf("invalid CoreCWE entry %q", cwe)
		}
		if seen[cwe] {
			t.Errorf("duplicate CoreCWE entry %q", cwe)
		}
		seen[cwe] = true
	}
	for cwe := range required {
		if !seen[cwe] {
			t.Errorf("CoreCWE missing %s", cwe)
		}
	}
}

func TestBuildPlanCoreQuick(t *testing.T) {
	registry := mustLoadRegistry(t)
	profile := Profile{Languages: []string{Java, Python}, Modules: []string{"src"}}
	plan, err := BuildPlan(profile, Config{Depth: DepthQuick, CWEScope: CWEScopeCore}, registry)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if plan.Depth != DepthQuick || plan.MaxRounds != 1 {
		t.Fatalf("depth/rounds = %s/%d, want quick/1", plan.Depth, plan.MaxRounds)
	}
	if !equalStrings(plan.Languages, []string{Java, Python}) {
		t.Fatalf("Languages = %v, want [java python]", plan.Languages)
	}
	if len(plan.PlannedCWEs) != 2 {
		t.Fatalf("PlannedCWEs = %v, want two languages", plan.PlannedCWEs)
	}
	for _, language := range plan.Languages {
		cwes := plan.PlannedCWEs[language]
		if len(cwes) != 26 {
			t.Fatalf("%s CWEs = %v, want 26", language, cwes)
		}
		if !isSortedUniqueCWEs(cwes) {
			t.Fatalf("%s CWEs are not sorted/unique: %v", language, cwes)
		}
		for _, core := range CoreCWE {
			if !containsString(cwes, core) {
				t.Errorf("%s plan missing %s", language, core)
			}
		}
	}
	if !equalStrings(plan.Modules, []string{"src"}) {
		t.Fatalf("Modules = %v, want [src]", plan.Modules)
	}
	if plan.EntryPoints == nil || len(plan.EntryPoints) != 0 {
		t.Fatalf("EntryPoints = %v, want non-nil empty", plan.EntryPoints)
	}

	wantPhases := []string{"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S8", "S10", "S11"}
	if !equalStrings(phaseIDs(plan), wantPhases) {
		t.Fatalf("phases = %v, want %v", phaseIDs(plan), wantPhases)
	}
	required := map[string]bool{
		"S0": true, "S1": true, "S2": true, "S3": false, "S4": true,
		"S5": true, "S6": false, "S8": true, "S10": false, "S11": true,
	}
	for _, phase := range plan.Phases {
		if phase.Required != required[phase.Phase] {
			t.Errorf("phase %s required = %v, want %v", phase.Phase, phase.Required, required[phase.Phase])
		}
	}
	wantDeps := map[string][]string{
		"S0":  {},
		"S1":  {"S0"},
		"S2":  {"S1"},
		"S3":  {"S2"},
		"S4":  {"S1"},
		"S5":  {"S4"},
		"S6":  {"S2", "S5"},
		"S8":  {"S5"},
		"S10": {"S8"},
		"S11": {"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S8", "S10"},
	}
	for id, deps := range wantDeps {
		got := planPhase(t, plan, id).DependsOn
		if !equalStrings(got, deps) {
			t.Errorf("phase %s deps = %v, want %v", id, got, deps)
		}
	}
}

func TestBuildPlanStandardAndDeep(t *testing.T) {
	registry := mustLoadRegistry(t)
	profile := Profile{Languages: []string{Go}}

	standard, err := BuildPlan(profile, Config{Depth: DepthStandard, CWEScope: CWEScopeCore}, registry)
	if err != nil {
		t.Fatalf("BuildPlan standard: %v", err)
	}
	if standard.MaxRounds != 3 {
		t.Fatalf("standard rounds = %d, want 3", standard.MaxRounds)
	}
	wantIncluded := []string{"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S8", "S10", "S11"}
	if !equalStrings(phaseIDs(standard), wantIncluded) {
		t.Fatalf("standard phases = %v, want %v", phaseIDs(standard), wantIncluded)
	}
	for _, phase := range standard.Phases {
		if !phase.Required {
			t.Errorf("standard phase %s should be required", phase.Phase)
		}
	}
	if deps := planPhase(t, standard, "S8").DependsOn; !equalStrings(deps, []string{"S5"}) {
		t.Errorf("standard S8 deps = %v, want [S5]", deps)
	}
	if deps := planPhase(t, standard, "S10").DependsOn; !equalStrings(deps, []string{"S8"}) {
		t.Errorf("standard S10 deps = %v, want [S8]", deps)
	}

	deep, err := BuildPlan(profile, Config{Depth: DepthDeep, CWEScope: CWEScopeCore}, registry)
	if err != nil {
		t.Fatalf("BuildPlan deep: %v", err)
	}
	if deep.MaxRounds != 5 {
		t.Fatalf("deep rounds = %d, want 5", deep.MaxRounds)
	}
	wantDeep := []string{"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11"}
	if !equalStrings(phaseIDs(deep), wantDeep) {
		t.Fatalf("deep phases = %v, want %v", phaseIDs(deep), wantDeep)
	}
	for _, phase := range deep.Phases {
		if !phase.Required {
			t.Errorf("deep phase %s should be required", phase.Phase)
		}
	}
	if deps := planPhase(t, deep, "S8").DependsOn; !equalStrings(deps, []string{"S5", "S7"}) {
		t.Errorf("deep S8 deps = %v, want [S5 S7]", deps)
	}
	if deps := planPhase(t, deep, "S10").DependsOn; !equalStrings(deps, []string{"S8", "S9"}) {
		t.Errorf("deep S10 deps = %v, want [S8 S9]", deps)
	}
	if deps := planPhase(t, deep, "S11").DependsOn; !equalStrings(deps, []string{"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10"}) {
		t.Errorf("deep S11 deps = %v", deps)
	}
}

func TestBuildPlanPhasesAreAcyclic(t *testing.T) {
	registry := mustLoadRegistry(t)
	for _, depth := range []string{DepthQuick, DepthStandard, DepthDeep} {
		plan, err := BuildPlan(Profile{Languages: []string{Java}}, Config{Depth: depth, CWEScope: CWEScopeCore}, registry)
		if err != nil {
			t.Fatalf("BuildPlan(%s): %v", depth, err)
		}
		seen := make(map[string]bool)
		for _, phase := range plan.Phases {
			for _, dep := range phase.DependsOn {
				if !seen[dep] {
					t.Errorf("%s phase %s depends on %s, which is absent or later", depth, phase.Phase, dep)
				}
			}
			seen[phase.Phase] = true
		}
	}
}

func TestBuildPlanDefaultDepthAndRoundsOverride(t *testing.T) {
	registry := mustLoadRegistry(t)
	plan, err := BuildPlan(Profile{Languages: []string{Java}}, Config{CWEScope: CWEScopeCore}, registry)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if plan.Depth != DepthDeep || plan.MaxRounds != 5 {
		t.Fatalf("default depth/rounds = %s/%d, want deep/5", plan.Depth, plan.MaxRounds)
	}

	plan, err = BuildPlan(Profile{Languages: []string{Java}}, Config{Depth: DepthStandard, MaxRounds: 7, CWEScope: CWEScopeCore}, registry)
	if err != nil {
		t.Fatalf("BuildPlan override: %v", err)
	}
	if plan.MaxRounds != 7 {
		t.Fatalf("rounds override = %d, want 7", plan.MaxRounds)
	}
}

func TestBuildPlanLanguageAliases(t *testing.T) {
	registry := mustLoadRegistry(t)
	plan, err := BuildPlan(
		Profile{Languages: []string{Java}},
		Config{Depth: DepthQuick, CWEScope: CWEScopeCore, Languages: []string{" Js ", "node", "TS", "python", "python", ""}},
		registry,
	)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	want := []string{JavaScript, TypeScript, Python}
	if !equalStrings(plan.Languages, want) {
		t.Fatalf("Languages = %v, want %v", plan.Languages, want)
	}
	if len(plan.PlannedCWEs) != len(want) {
		t.Fatalf("PlannedCWEs keys = %v", plan.PlannedCWEs)
	}
	for _, language := range want {
		if len(plan.PlannedCWEs[language]) != 26 {
			t.Errorf("%s CWEs = %v", language, plan.PlannedCWEs[language])
		}
	}
}

func TestBuildPlanLanguagesFallBackToProfile(t *testing.T) {
	registry := mustLoadRegistry(t)
	profile := Profile{Languages: []string{Python, Go}, Modules: []string{"app", "cmd"}}
	plan, err := BuildPlan(profile, Config{Depth: DepthQuick, CWEScope: CWEScopeCore}, registry)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if !equalStrings(plan.Languages, []string{Python, Go}) {
		t.Fatalf("Languages = %v, want profile order [python go]", plan.Languages)
	}
	if !equalStrings(plan.Modules, []string{"app", "cmd"}) {
		t.Fatalf("Modules = %v", plan.Modules)
	}
	profile.Modules[0] = "mutated"
	if plan.Modules[0] != "app" {
		t.Fatal("plan.Modules aliases profile storage")
	}
}

func TestBuildPlanExplicitScope(t *testing.T) {
	registry := mustLoadRegistry(t)
	plan, err := BuildPlan(
		Profile{Languages: []string{Java}},
		Config{Depth: DepthStandard, CWEScope: CWEScopeExplicit, CWEIDs: []string{"cwe-89", "CWE-78", " CWE-89 ", "CWE-1321"}},
		registry,
	)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	want := []string{"CWE-78", "CWE-89", "CWE-1321"}
	if !equalStrings(plan.PlannedCWEs[Java], want) {
		t.Fatalf("explicit CWEs = %v, want %v", plan.PlannedCWEs[Java], want)
	}

	invalid := []Config{
		{Depth: DepthStandard, CWEScope: CWEScopeExplicit},
		{Depth: DepthStandard, CWEScope: CWEScopeExplicit, CWEIDs: []string{"CWE-X"}},
		{Depth: DepthStandard, CWEScope: "bogus"},
	}
	for _, cfg := range invalid {
		if _, err := BuildPlan(Profile{Languages: []string{Java}}, cfg, registry); err == nil {
			t.Errorf("BuildPlan(%+v) = nil error, want error", cfg)
		}
	}
}

func TestBuildPlanEmptyLanguages(t *testing.T) {
	registry := mustLoadRegistry(t)
	for _, profile := range []Profile{{}, {Languages: []string{"", "   "}}} {
		_, err := BuildPlan(profile, Config{Depth: DepthQuick, CWEScope: CWEScopeCore}, registry)
		if err == nil {
			t.Fatal("expected empty languages error")
		}
		if !strings.Contains(err.Error(), "无法确定审计语言") {
			t.Fatalf("error = %v, want 无法确定审计语言", err)
		}
	}
}

func TestBuildPlanFullScopeTaintExtraction(t *testing.T) {
	registry := Registry{
		CWE: []CWEDefinition{
			{ID: "CWE-89", ApplicableLanguages: []string{"java"}},
			{ID: "CWE-79", ApplicableLanguages: []string{"java"}},
		},
		Sinks: map[string][]SinkDefinition{
			"java": {
				{CWEID: "CWE-89", Symbol: "executeQuery", Kind: "sink"},
				{CWEID: "CWE-22", Symbol: "readFile", Kind: "sink"},
				{CWEID: "*", Symbol: "wildcard", Kind: "sink"},
				{CWEID: "", Symbol: "none", Kind: "sink"},
			},
		},
		OdinRules: []OdinRule{
			{CWE: "CWE-94", Languages: []string{"java"}},
			{CWE: "not-a-cwe", Languages: []string{"java"}},
		},
		Taint: map[string][]TaintRegistry{
			"java": {{
				RegistryName: "synthetic",
				Language:     "java",
				Frameworks: json.RawMessage(`{
					"name": "framework",
					"pairs": [
						{"cwe": "CWE-502"},
						{"cweId": "CWE-918"},
						{"cwe_id": "CWE-78"},
						{"cwe": "junk"},
						{"nested": {"cwe": "CWE-79"}},
						{"cwe": 22}
					]
				}`),
			}},
		},
	}

	plan, err := BuildPlan(Profile{Languages: []string{Java}}, Config{Depth: DepthDeep, CWEScope: CWEScopeFull}, registry)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	want := []string{"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502", "CWE-918"}
	if !equalStrings(plan.PlannedCWEs[Java], want) {
		t.Fatalf("full CWEs = %v, want %v", plan.PlannedCWEs[Java], want)
	}
}

func TestBuildPlanFullScopeRealRegistry(t *testing.T) {
	registry := mustLoadRegistry(t)
	plan, err := BuildPlan(Profile{Languages: []string{Java}}, Config{Depth: DepthDeep, CWEScope: CWEScopeFull}, registry)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	cwes := plan.PlannedCWEs[Java]
	if len(cwes) <= 100 {
		t.Fatalf("Java full CWE count = %d, want >100", len(cwes))
	}
	if !isSortedUniqueCWEs(cwes) {
		t.Fatal("full CWEs are not sorted and unique")
	}
	for _, want := range []string{"CWE-15", "CWE-89", "CWE-94", "CWE-918"} {
		if !containsString(cwes, want) {
			t.Errorf("full Java CWEs missing %s", want)
		}
	}
	if containsString(cwes, "*") {
		t.Fatal("wildcard CWE must be skipped")
	}
}

func TestBuildPlanFullScopeLanguageWithoutCWEs(t *testing.T) {
	plan, err := BuildPlan(Profile{Languages: []string{"ruby"}}, Config{Depth: DepthDeep, CWEScope: CWEScopeFull}, Registry{})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	cwes, ok := plan.PlannedCWEs["ruby"]
	if !ok {
		t.Fatalf("PlannedCWEs missing ruby: %v", plan.PlannedCWEs)
	}
	if cwes == nil || len(cwes) != 0 {
		t.Fatalf("ruby CWEs = %v, want non-nil empty", cwes)
	}
	if !equalStrings(plan.Languages, []string{"ruby"}) {
		t.Fatalf("Languages = %v", plan.Languages)
	}
}

func TestBuildPlanMalformedTaintIsActionable(t *testing.T) {
	registry := Registry{
		Taint: map[string][]TaintRegistry{
			"java": {{Frameworks: json.RawMessage(`{not-json`)}},
		},
	}
	_, err := BuildPlan(Profile{Languages: []string{Java}}, Config{Depth: DepthDeep, CWEScope: CWEScopeFull}, registry)
	if err == nil {
		t.Fatal("expected malformed taint error")
	}
}

func isSortedUniqueCWEs(cwes []string) bool {
	seen := make(map[string]bool, len(cwes))
	for i, cwe := range cwes {
		if !cweIDPattern.MatchString(cwe) {
			return false
		}
		if seen[cwe] {
			return false
		}
		seen[cwe] = true
		if i > 0 && cweNumber(cwe) < cweNumber(cwes[i-1]) {
			return false
		}
		if i > 0 && cweNumber(cwe) == cweNumber(cwes[i-1]) && cwe < cwes[i-1] {
			return false
		}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
