// Package audit provides code-audit data and orchestration primitives.
package audit

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

// registryJSON is generated from Omni-Audit by
// Omni-Audit/scripts/export-artex-audit-data.mts. Do not hand-edit.
//
//go:embed data/audit-registry.json
var registryJSON []byte

var (
	registryMu    sync.Mutex
	registryCache *Registry
)

// decodeRegistry decodes a registry payload. It returns a zero Registry on
// any error so callers never observe partially populated data.
func decodeRegistry(data []byte) (Registry, error) {
	var registry Registry
	if err := json.Unmarshal(data, &registry); err != nil {
		return Registry{}, fmt.Errorf("decode audit registry: %w", err)
	}
	return registry, nil
}

// cloneRegistry returns a deep copy of registry so callers cannot mutate the
// cached value through maps, slices, or raw JSON.
func cloneRegistry(source Registry) Registry {
	clone := Registry{Source: source.Source}

	if source.CWE != nil {
		clone.CWE = make([]CWEDefinition, len(source.CWE))
		for i, definition := range source.CWE {
			clone.CWE[i] = definition
			clone.CWE[i].ApplicableLanguages = cloneStrings(definition.ApplicableLanguages)
		}
	}

	if source.Sinks != nil {
		clone.Sinks = make(map[string][]SinkDefinition, len(source.Sinks))
		for language, sinks := range source.Sinks {
			copied := make([]SinkDefinition, len(sinks))
			copy(copied, sinks)
			clone.Sinks[language] = copied
		}
	}

	if source.OdinRules != nil {
		clone.OdinRules = make([]OdinRule, len(source.OdinRules))
		for i, rule := range source.OdinRules {
			clone.OdinRules[i] = rule
			clone.OdinRules[i].Languages = cloneStrings(rule.Languages)
		}
	}

	if source.Taint != nil {
		clone.Taint = make(map[string][]TaintRegistry, len(source.Taint))
		for language, registries := range source.Taint {
			copied := make([]TaintRegistry, len(registries))
			for i, registry := range registries {
				copied[i] = registry
				if registry.Frameworks != nil {
					copied[i].Frameworks = append(json.RawMessage(nil), registry.Frameworks...)
				}
			}
			clone.Taint[language] = copied
		}
	}

	return clone
}

// LoadRegistry decodes the embedded audit registry once and returns a deep
// copy of the cached result on subsequent calls. Errors are not cached.
func LoadRegistry() (Registry, error) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if registryCache != nil {
		return cloneRegistry(*registryCache), nil
	}
	registry, err := decodeRegistry(registryJSON)
	if err != nil {
		return Registry{}, fmt.Errorf("load embedded audit registry: %w", err)
	}
	registryCache = &registry
	return cloneRegistry(registry), nil
}

// SinksFor returns a copy of the sink, source, and sanitizer definitions for
// language. The result is non-nil even for unknown languages.
func (r Registry) SinksFor(language string) []SinkDefinition {
	sinks := r.Sinks[NormalizeLanguage(language)]
	out := make([]SinkDefinition, len(sinks))
	copy(out, sinks)
	return out
}

// HasSinks reports whether the registry has sink definitions for language.
func (r Registry) HasSinks(language string) bool {
	return len(r.Sinks[NormalizeLanguage(language)]) > 0
}

// CWEsFor returns copies of the CWE definitions applicable to language. The
// result is non-nil even for unknown languages.
func (r Registry) CWEsFor(language string) []CWEDefinition {
	canonical := NormalizeLanguage(language)
	out := make([]CWEDefinition, 0, len(r.CWE))
	if canonical == "" {
		return out
	}
	for _, definition := range r.CWE {
		if !languageMatches(definition.ApplicableLanguages, canonical) {
			continue
		}
		clone := definition
		clone.ApplicableLanguages = cloneStrings(definition.ApplicableLanguages)
		out = append(out, clone)
	}
	return out
}

// OdinRulesFor returns copies of the Odin rules applicable to language.
// Omni-Audit treats all rule languages that normalize to JavaScript
// ("nodejs", "js", "node", etc.) as applying to both JavaScript and
// TypeScript. The result is non-nil even for unknown languages.
func (r Registry) OdinRulesFor(language string) []OdinRule {
	canonical := NormalizeLanguage(language)
	out := make([]OdinRule, 0)
	if canonical == "" {
		return out
	}
	for _, rule := range r.OdinRules {
		if !odinLanguageMatches(rule.Languages, canonical) {
			continue
		}
		clone := rule
		clone.Languages = cloneStrings(rule.Languages)
		out = append(out, clone)
	}
	return out
}

// TaintsFor returns copies of the framework taint registries for language.
// The result is non-nil even for unknown languages.
func (r Registry) TaintsFor(language string) []TaintRegistry {
	registries := r.Taint[NormalizeLanguage(language)]
	out := make([]TaintRegistry, len(registries))
	for i, registry := range registries {
		out[i] = registry
		if registry.Frameworks != nil {
			out[i].Frameworks = append(json.RawMessage(nil), registry.Frameworks...)
		}
	}
	return out
}
