package audit

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const wantRegistrySource = "Omni-Audit@f439e2d"

func mustLoadRegistry(t *testing.T) Registry {
	t.Helper()
	registry, err := LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return registry
}

func TestRegistryLoads(t *testing.T) {
	registry := mustLoadRegistry(t)

	if len(registry.CWE) < 20 {
		t.Fatalf("expected CWE definitions, got %d", len(registry.CWE))
	}
	if len(registry.OdinRules) < 100 {
		t.Fatalf("expected Odin rules, got %d", len(registry.OdinRules))
	}
	if len(registry.Sinks) == 0 {
		t.Fatal("expected sink definitions")
	}
	if len(registry.Taint) == 0 {
		t.Fatal("expected taint registries")
	}

	javaSinks := registry.SinksFor(Java)
	if len(javaSinks) == 0 {
		t.Fatal("expected Java sink definitions")
	}
	for _, sink := range javaSinks {
		if sink.CWEID == "" || sink.Symbol == "" || sink.Kind == "" {
			t.Fatalf("malformed sink: %+v", sink)
		}
	}
}

func TestRegistryProvenance(t *testing.T) {
	registry := mustLoadRegistry(t)
	if registry.Source != wantRegistrySource {
		t.Fatalf("source = %q, want %q; regenerate with the exporter after updating the expected source", registry.Source, wantRegistrySource)
	}
	if strings.HasSuffix(registry.Source, "-dirty") {
		t.Fatalf("source %q is dirty; regenerate from a clean shared tree", registry.Source)
	}
}

func TestRegistryCWEsAreUnique(t *testing.T) {
	registry := mustLoadRegistry(t)

	seen := make(map[string]string, len(registry.CWE))
	for _, definition := range registry.CWE {
		if previous, ok := seen[definition.ID]; ok {
			t.Errorf("duplicate CWE %s: kept %s and %s", definition.ID, previous, definition.Priority)
			continue
		}
		seen[definition.ID] = definition.Priority
	}
	if len(seen) != len(registry.CWE) {
		t.Fatalf("CWE count %d does not match unique IDs %d", len(registry.CWE), len(seen))
	}
	if priority := seen["CWE-918"]; priority != "P0" {
		t.Fatalf("CWE-918 priority = %q, want P0 (duplicate P2 must be dropped)", priority)
	}
}

func TestRegistrySectionsAndLanguages(t *testing.T) {
	registry := mustLoadRegistry(t)

	wantLanguages := []string{Java, Python, JavaScript, TypeScript, Go, Rust, C, CPP}
	if got := Languages(); !slices.Equal(got, wantLanguages) {
		t.Fatalf("Languages() = %v, want %v", got, wantLanguages)
	}

	// Every canonical language has taint data. Go is a supported language but
	// Omni-Audit has no deterministic Go sink table. Rust has sinks and taint
	// data, but the source CWE table has no rust entries; assert that so the
	// README caveat cannot silently go stale.
	for _, language := range wantLanguages {
		if language == Rust {
			if got := len(registry.CWEsFor(Rust)); got != 0 {
				t.Errorf("CWEsFor(rust) = %d, want 0; update the README if the source gains rust CWEs", got)
			}
		} else if len(registry.CWEsFor(language)) == 0 {
			t.Errorf("expected CWE definitions for %q", language)
		}
		if len(registry.TaintsFor(language)) == 0 {
			t.Errorf("expected taint registries for %q", language)
		}
		// Odin rules tagged nodejs apply to both JavaScript and TypeScript.
		if len(registry.OdinRulesFor(language)) == 0 {
			t.Errorf("expected Odin rules for %q", language)
		}
		if language == Go {
			if registry.HasSinks(language) {
				t.Errorf("expected no Go sink table")
			}
			if sinks := registry.SinksFor(language); len(sinks) != 0 {
				t.Errorf("SinksFor(%q) returned %d sinks, want 0", language, len(sinks))
			}
			continue
		}
		if !registry.HasSinks(language) {
			t.Errorf("expected sink definitions for %q", language)
		}
		if len(registry.SinksFor(language)) == 0 {
			t.Errorf("SinksFor(%q) returned no sinks", language)
		}
	}

	if len(registry.Sinks) != len(wantLanguages)-1 {
		t.Fatalf("sink languages = %d, want %d", len(registry.Sinks), len(wantLanguages)-1)
	}
}

func TestSinksForTable(t *testing.T) {
	registry := mustLoadRegistry(t)

	tests := []struct {
		name      string
		language  string
		canonical string
		wantEmpty bool
	}{
		{name: "canonical java", language: Java, canonical: Java},
		{name: "case insensitive", language: "JAVA", canonical: Java},
		{name: "trimmed", language: " java ", canonical: Java},
		{name: "javascript", language: JavaScript, canonical: JavaScript},
		{name: "js alias", language: "js", canonical: JavaScript},
		{name: "node alias", language: "node", canonical: JavaScript},
		{name: "nodejs alias", language: "nodejs", canonical: JavaScript},
		{name: "node.js alias", language: "node.js", canonical: JavaScript},
		{name: "typescript", language: TypeScript, canonical: TypeScript},
		{name: "ts alias", language: "ts", canonical: TypeScript},
		{name: "rust", language: Rust, canonical: Rust},
		{name: "c", language: C, canonical: C},
		{name: "cpp", language: CPP, canonical: CPP},
		{name: "c++ alias", language: "c++", canonical: CPP},
		{name: "cxx alias", language: "cxx", canonical: CPP},
		{name: "go has no sink table", language: Go, canonical: Go, wantEmpty: true},
		{name: "golang has no sink table", language: "golang", canonical: Go, wantEmpty: true},
		{name: "unknown", language: "ruby", wantEmpty: true},
		{name: "empty", language: "", wantEmpty: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := registry.SinksFor(tc.language)
			if got == nil {
				t.Fatalf("SinksFor(%q) returned nil; want non-nil slice", tc.language)
			}
			if tc.wantEmpty {
				if len(got) != 0 {
					t.Fatalf("SinksFor(%q) returned %d sinks, want none", tc.language, len(got))
				}
				if registry.HasSinks(tc.language) {
					t.Fatalf("HasSinks(%q) = true, want false", tc.language)
				}
				return
			}

			want := registry.Sinks[tc.canonical]
			if len(want) == 0 {
				t.Fatalf("test setup: no sinks for canonical language %q", tc.canonical)
			}
			if len(got) != len(want) {
				t.Fatalf("SinksFor(%q) returned %d sinks, want %d", tc.language, len(got), len(want))
			}
			if got[0].Symbol != want[0].Symbol {
				t.Fatalf("SinksFor(%q) first symbol = %q, want %q", tc.language, got[0].Symbol, want[0].Symbol)
			}
			if !registry.HasSinks(tc.language) {
				t.Fatalf("HasSinks(%q) = false, want true", tc.language)
			}
		})
	}
}

func TestCWEsForTable(t *testing.T) {
	registry := mustLoadRegistry(t)

	tests := []struct {
		name      string
		language  string
		sameAs    string
		wantEmpty bool
	}{
		{name: "canonical java", language: Java, sameAs: Java},
		{name: "case insensitive", language: "Java", sameAs: Java},
		{name: "nodejs as javascript", language: "nodejs", sameAs: JavaScript},
		{name: "node alias", language: "node", sameAs: JavaScript},
		{name: "js alias", language: "js", sameAs: JavaScript},
		{name: "ts alias", language: "ts", sameAs: TypeScript},
		{name: "go", language: Go, sameAs: Go},
		{name: "c++ alias", language: "c++", sameAs: CPP},
		{name: "cxx alias", language: "cxx", sameAs: CPP},
		{name: "unknown", language: "ruby", wantEmpty: true},
		{name: "empty", language: "", wantEmpty: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := registry.CWEsFor(tc.language)
			if got == nil {
				t.Fatalf("CWEsFor(%q) returned nil; want non-nil slice", tc.language)
			}
			if tc.wantEmpty {
				if len(got) != 0 {
					t.Fatalf("CWEsFor(%q) returned %d CWEs, want none", tc.language, len(got))
				}
				return
			}

			want := registry.CWEsFor(tc.sameAs)
			if len(want) == 0 {
				t.Fatalf("test setup: no CWEs for canonical language %q", tc.sameAs)
			}
			if len(got) != len(want) {
				t.Fatalf("CWEsFor(%q) returned %d CWEs, want %d", tc.language, len(got), len(want))
			}
			for i := range got {
				if got[i].ID != want[i].ID {
					t.Fatalf("CWEsFor(%q)[%d] = %s, want %s", tc.language, i, got[i].ID, want[i].ID)
				}
			}

			canonical := NormalizeLanguage(tc.sameAs)
			for _, definition := range got {
				if !languageMatches(definition.ApplicableLanguages, canonical) {
					t.Errorf("CWEsFor(%q) returned %s without applicable language %q", tc.language, definition.ID, canonical)
				}
			}
		})
	}
}

func TestCWEsForSynthetic(t *testing.T) {
	registry := Registry{CWE: []CWEDefinition{
		{ID: "CWE-1", ApplicableLanguages: []string{"java", "java"}},
		{ID: "CWE-2", ApplicableLanguages: []string{"nodejs"}},
		{ID: "CWE-3", ApplicableLanguages: []string{"javascript"}},
		{ID: "CWE-4", ApplicableLanguages: []string{"ruby"}},
	}}

	tests := []struct {
		name     string
		language string
		want     []string
	}{
		{name: "duplicate language entries", language: Java, want: []string{"CWE-1"}},
		{name: "nodejs matches javascript", language: "nodejs", want: []string{"CWE-2", "CWE-3"}},
		{name: "javascript matches nodejs", language: JavaScript, want: []string{"CWE-2", "CWE-3"}},
		{name: "unknown data language", language: "ruby", want: nil},
		{name: "unknown requested language", language: "unknown", want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := registry.CWEsFor(tc.language)
			if got == nil {
				t.Fatalf("CWEsFor(%q) returned nil; want non-nil slice", tc.language)
			}
			ids := make([]string, len(got))
			for i, definition := range got {
				ids[i] = definition.ID
			}
			if !slices.Equal(ids, tc.want) {
				t.Fatalf("CWEsFor(%q) = %v, want %v", tc.language, ids, tc.want)
			}
		})
	}
}

func TestRegistryRepresentativeEntries(t *testing.T) {
	registry := mustLoadRegistry(t)

	var sqlInjection *CWEDefinition
	for i := range registry.CWE {
		if registry.CWE[i].ID == "CWE-89" {
			sqlInjection = &registry.CWE[i]
			break
		}
	}
	if sqlInjection == nil {
		t.Fatal("CWE-89 not found")
	}
	if sqlInjection.Name != "SQL Injection" || sqlInjection.Priority != "P0" || sqlInjection.Channel != "code" {
		t.Fatalf("unexpected CWE-89: %+v", *sqlInjection)
	}
	if !languageMatches(sqlInjection.ApplicableLanguages, Java) {
		t.Fatalf("CWE-89 does not apply to Java: %v", sqlInjection.ApplicableLanguages)
	}

	var jdbcSink *SinkDefinition
	var servletSource *SinkDefinition
	for i := range registry.Sinks[Java] {
		sink := &registry.Sinks[Java][i]
		switch sink.Symbol {
		case "java.sql.Statement.executeQuery":
			jdbcSink = sink
		case "javax.servlet.http.HttpServletRequest.getParameter":
			servletSource = sink
		}
	}
	if jdbcSink == nil || jdbcSink.Kind != "sink" || jdbcSink.CWEID != "CWE-89" {
		t.Fatalf("unexpected JDBC sink: %+v", jdbcSink)
	}
	if servletSource == nil || servletSource.Kind != "source" || servletSource.CWEID != "*" {
		t.Fatalf("unexpected servlet source: %+v", servletSource)
	}

	var sqlRule *OdinRule
	for i := range registry.OdinRules {
		if registry.OdinRules[i].CWE == "CWE-89" {
			sqlRule = &registry.OdinRules[i]
			break
		}
	}
	if sqlRule == nil {
		t.Fatal("Odin CWE-89 rule not found")
	}
	if sqlRule.Name != "SQL注入" || sqlRule.Severity != "critical" {
		t.Fatalf("unexpected Odin CWE-89 rule: %+v", *sqlRule)
	}
	if sqlRule.TraceHint == "" || sqlRule.Category == "" {
		t.Fatalf("Odin rule is missing traceHint/category: %+v", *sqlRule)
	}
	if !slices.Contains(sqlRule.Languages, "nodejs") {
		t.Fatalf("Odin CWE-89 languages = %v, want nodejs", sqlRule.Languages)
	}
}

func TestTaintContract(t *testing.T) {
	registry := mustLoadRegistry(t)

	for _, language := range Languages() {
		registries := registry.TaintsFor(language)
		if len(registries) == 0 {
			t.Errorf("expected taint registries for %q", language)
			continue
		}
		// C and C++ share the C++ taint registry, and JavaScript and TypeScript
		// share the Node registry, so their language field records the source
		// registry rather than the key it was exported under.
		wantRegistryLanguage := language
		switch language {
		case TypeScript:
			wantRegistryLanguage = JavaScript
		case C:
			wantRegistryLanguage = CPP
		}
		for _, taint := range registries {
			if taint.RegistryName == "" {
				t.Errorf("%s taint registry has empty registry_name", language)
			}
			if got := NormalizeLanguage(taint.Language); got != wantRegistryLanguage {
				t.Errorf("%s taint registry language = %q (normalized %q), want %q", language, taint.Language, got, wantRegistryLanguage)
			}

			var frameworks []struct {
				Name            string          `json:"name"`
				Category        string          `json:"category"`
				Sources         json.RawMessage `json:"sources"`
				Sinks           json.RawMessage `json:"sinks"`
				SourceSinkPairs json.RawMessage `json:"source_sink_pairs"`
			}
			if err := json.Unmarshal(taint.Frameworks, &frameworks); err != nil {
				t.Errorf("%s taint frameworks are invalid JSON: %v", language, err)
				continue
			}
			if len(frameworks) == 0 {
				t.Errorf("%s taint registry has no frameworks", language)
				continue
			}
			for _, framework := range frameworks {
				if framework.Name == "" || framework.Category == "" {
					t.Errorf("%s framework is missing name/category", language)
				}
				if len(framework.Sources) == 0 || len(framework.Sinks) == 0 || len(framework.SourceSinkPairs) == 0 {
					t.Errorf("%s framework %q has empty source/sink/pair data", language, framework.Name)
				}
			}
		}
	}

	java := registry.TaintsFor(Java)
	if len(java) != 1 || java[0].RegistryName != "Java 框架污点注册表" {
		t.Fatalf("unexpected Java taint registries: %+v", java)
	}
	if got, want := len(registry.TaintsFor("js")), len(registry.TaintsFor(JavaScript)); got != want {
		t.Fatalf("TaintsFor(js) = %d, want %d", got, want)
	}
	if got := registry.TaintsFor("ruby"); got == nil || len(got) != 0 {
		t.Fatalf("TaintsFor(unknown) = %v, want non-nil empty slice", got)
	}
}

func TestOdinRulesFor(t *testing.T) {
	registry := mustLoadRegistry(t)

	nodeRules := registry.OdinRulesFor("nodejs")
	if len(nodeRules) == 0 {
		t.Fatal("expected Odin rules for nodejs")
	}
	t.Logf("matched %d nodejs rules for javascript and typescript", len(nodeRules))

	typescriptRules := registry.OdinRulesFor(TypeScript)
	if len(typescriptRules) == 0 {
		t.Fatal("expected Odin rules for typescript")
	}

	// All rule languages that normalize to JavaScript apply to both JavaScript
	// and TypeScript (the current source tags them as "nodejs").
	sameRules := []struct {
		name     string
		language string
	}{
		{name: "javascript", language: JavaScript},
		{name: "js alias", language: "js"},
		{name: "typescript", language: TypeScript},
		{name: "ts alias", language: "ts"},
	}
	for _, tc := range sameRules {
		rules := registry.OdinRulesFor(tc.language)
		if len(rules) == 0 {
			t.Fatalf("expected Odin rules for %q", tc.language)
		}
		if !reflect.DeepEqual(rules, nodeRules) {
			t.Fatalf("OdinRulesFor(%q) content differs from OdinRulesFor(nodejs) (%d vs %d rules)", tc.language, len(rules), len(nodeRules))
		}
	}

	for _, rule := range nodeRules {
		if !odinLanguageMatches(rule.Languages, JavaScript) {
			t.Errorf("Odin rule %s does not match javascript: %v", rule.CWE, rule.Languages)
		}
	}

	found := false
	for _, rule := range typescriptRules {
		if rule.CWE == "CWE-89" && rule.Name == "SQL注入" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected TypeScript-relevant Odin CWE-89 rule from nodejs")
	}

	if got := registry.OdinRulesFor("unknown"); got == nil || len(got) != 0 {
		t.Fatalf("OdinRulesFor(unknown) = %v, want non-nil empty slice", got)
	}
}

func TestNormalizeLanguage(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "java", input: "java", want: Java},
		{name: "java uppercase", input: "JAVA", want: Java},
		{name: "python trimmed", input: " python ", want: Python},
		{name: "py alias", input: "py", want: Python},
		{name: "javascript", input: "javascript", want: JavaScript},
		{name: "js alias", input: "js", want: JavaScript},
		{name: "node alias", input: "node", want: JavaScript},
		{name: "nodejs alias", input: "nodejs", want: JavaScript},
		{name: "node.js alias", input: "node.js", want: JavaScript},
		{name: "typescript", input: "typescript", want: TypeScript},
		{name: "ts alias", input: "ts", want: TypeScript},
		{name: "tsx alias", input: "tsx", want: TypeScript},
		{name: "go", input: "go", want: Go},
		{name: "golang alias", input: "golang", want: Go},
		{name: "rust", input: "rust", want: Rust},
		{name: "rs alias", input: "rs", want: Rust},
		{name: "c", input: "c", want: C},
		{name: "c uppercase", input: "C", want: C},
		{name: "cpp", input: "cpp", want: CPP},
		{name: "c++ alias", input: "c++", want: CPP},
		{name: "cxx alias", input: "cxx", want: CPP},
		{name: "cc alias", input: "cc", want: CPP},
		{name: "unknown", input: "ruby", want: ""},
		{name: "empty", input: "", want: ""},
		{name: "blank", input: "   ", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeLanguage(tc.input); got != tc.want {
				t.Fatalf("NormalizeLanguage(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestLanguagesReturnsCopy(t *testing.T) {
	languages := Languages()
	if len(languages) == 0 {
		t.Fatal("Languages() returned no languages")
	}
	languages[0] = "mutated"
	if got := Languages()[0]; got != Java {
		t.Fatalf("Languages() cache was mutated: %q", got)
	}
}

func TestDecodeRegistryMalformed(t *testing.T) {
	t.Run("syntax error", func(t *testing.T) {
		registry, err := decodeRegistry([]byte("{"))
		if err == nil {
			t.Fatal("expected decode error")
		}
		if !strings.Contains(err.Error(), "decode audit registry") {
			t.Fatalf("error lacks context: %v", err)
		}
		assertZeroRegistry(t, registry)
	})

	t.Run("wrong taint shape returns zero registry", func(t *testing.T) {
		payload := []byte(`{
			"source": "Omni-Audit@test",
			"cwe": [{"id": "CWE-1"}],
			"sinks": {"java": [{"symbol": "x"}]},
			"odin_rules": [{"cwe": "CWE-1"}],
			"taint": {"java": {"registry_name": "x"}}
		}`)
		registry, err := decodeRegistry(payload)
		if err == nil {
			t.Fatal("expected taint shape decode error")
		}
		assertZeroRegistry(t, registry)
	})
}

func assertZeroRegistry(t *testing.T, registry Registry) {
	t.Helper()
	if registry.Source != "" || registry.CWE != nil || registry.Sinks != nil || registry.OdinRules != nil || registry.Taint != nil {
		t.Fatalf("expected zero registry on error, got %+v", registry)
	}
}

func TestLoadRegistryReturnsDeepCopy(t *testing.T) {
	// Decode a value that shares nothing with the loader cache.
	want, err := decodeRegistry(registryJSON)
	if err != nil {
		t.Fatalf("decode embedded registry: %v", err)
	}

	mutated := mustLoadRegistry(t)
	if len(mutated.CWE) == 0 || len(mutated.CWE[0].ApplicableLanguages) == 0 {
		t.Fatal("test setup: expected CWE definitions with languages")
	}
	if len(mutated.Sinks[Java]) == 0 {
		t.Fatal("test setup: expected Java sinks")
	}
	if len(mutated.OdinRules) == 0 || len(mutated.OdinRules[0].Languages) == 0 {
		t.Fatal("test setup: expected Odin rules with languages")
	}
	if len(mutated.Taint[Java]) == 0 || len(mutated.Taint[Java][0].Frameworks) == 0 {
		t.Fatal("test setup: expected Java taint frameworks")
	}

	mutated.CWE[0].Name = "mutated"
	mutated.CWE[0].ApplicableLanguages[0] = "mutated"
	mutated.CWE = mutated.CWE[:0]
	mutated.Sinks[Java][0].Symbol = "mutated"
	delete(mutated.Sinks, Java)
	mutated.OdinRules[0].Name = "mutated"
	mutated.OdinRules[0].Languages[0] = "mutated"
	mutated.OdinRules = mutated.OdinRules[:0]
	mutated.Taint[Java][0].RegistryName = "mutated"
	mutated.Taint[Java][0].Frameworks[0] = 'X'
	delete(mutated.Taint, Java)

	fresh := mustLoadRegistry(t)
	if !reflect.DeepEqual(fresh, want) {
		t.Fatal("mutating a loaded registry affected a later load")
	}
}

func TestLoadRegistryDecodeErrorIsNotCached(t *testing.T) {
	registryMu.Lock()
	originalJSON := registryJSON
	registryJSON = []byte("{")
	registryCache = nil
	registryMu.Unlock()

	t.Cleanup(func() {
		registryMu.Lock()
		registryJSON = originalJSON
		registryCache = nil
		registryMu.Unlock()
	})

	for attempt := 1; attempt <= 2; attempt++ {
		registry, err := LoadRegistry()
		if err == nil {
			t.Fatalf("attempt %d: expected load error", attempt)
		}
		if !strings.Contains(err.Error(), "load embedded audit registry") {
			t.Fatalf("attempt %d: error lacks context: %v", attempt, err)
		}
		assertZeroRegistry(t, registry)

		registryMu.Lock()
		cached := registryCache
		registryMu.Unlock()
		if cached != nil {
			t.Fatalf("attempt %d: failed decode populated the cache", attempt)
		}
	}

	// Restoring valid data must allow a successful load, proving the earlier
	// errors were not cached.
	registryMu.Lock()
	registryJSON = originalJSON
	registryMu.Unlock()
	registry, err := LoadRegistry()
	if err != nil {
		t.Fatalf("load after restoring valid registry: %v", err)
	}
	if registry.Source != wantRegistrySource {
		t.Fatalf("source after restoring valid registry = %q", registry.Source)
	}
}

func TestAccessorsReturnCopies(t *testing.T) {
	registry := mustLoadRegistry(t)

	sinks := registry.SinksFor(Java)
	if len(sinks) == 0 {
		t.Fatal("expected Java sinks")
	}
	originalSymbol := sinks[0].Symbol
	sinks[0].Symbol = "mutated"
	if got := registry.SinksFor(Java)[0].Symbol; got != originalSymbol {
		t.Fatalf("SinksFor exposed cache: symbol = %q, want %q", got, originalSymbol)
	}

	cwes := registry.CWEsFor(Java)
	if len(cwes) == 0 || len(cwes[0].ApplicableLanguages) == 0 {
		t.Fatal("expected CWEs with applicable languages")
	}
	originalLanguage := cwes[0].ApplicableLanguages[0]
	cwes[0].ApplicableLanguages[0] = "mutated"
	if got := registry.CWEsFor(Java)[0].ApplicableLanguages[0]; got != originalLanguage {
		t.Fatalf("CWEsFor exposed cache: language = %q, want %q", got, originalLanguage)
	}

	rules := registry.OdinRulesFor(JavaScript)
	if len(rules) == 0 || len(rules[0].Languages) == 0 {
		t.Fatal("expected Odin rules with languages")
	}
	originalRuleLanguage := rules[0].Languages[0]
	rules[0].Languages[0] = "mutated"
	if got := registry.OdinRulesFor(JavaScript)[0].Languages[0]; got != originalRuleLanguage {
		t.Fatalf("OdinRulesFor exposed cache: language = %q, want %q", got, originalRuleLanguage)
	}

	taints := registry.TaintsFor(Java)
	if len(taints) == 0 || len(taints[0].Frameworks) == 0 {
		t.Fatal("expected Java taint frameworks")
	}
	originalByte := taints[0].Frameworks[0]
	taints[0].Frameworks[0] = 'X'
	if got := registry.TaintsFor(Java)[0].Frameworks[0]; got != originalByte {
		t.Fatalf("TaintsFor exposed cache: first byte = %q, want %q", got, originalByte)
	}
}
