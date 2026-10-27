package audit

import "encoding/json"

// SinkDefinition describes a taint source, sink, or sanitizer symbol.
type SinkDefinition struct {
	CWEID       string `json:"cweId"`
	Symbol      string `json:"symbol"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// CWEDefinition describes a CWE and the languages it applies to.
type CWEDefinition struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Priority            string   `json:"priority"`
	Channel             string   `json:"channel"`
	Description         string   `json:"description"`
	ApplicableLanguages []string `json:"applicableLanguages"`
}

// OdinRule is a detection rule imported from the Odin rule set.
type OdinRule struct {
	CWE       string   `json:"cwe"`
	Name      string   `json:"name"`
	Severity  string   `json:"severity"`
	Keywords  string   `json:"keywords"`
	TraceHint string   `json:"traceHint"`
	Languages []string `json:"languages"`
	Category  string   `json:"category"`
}

// TaintRegistry is a framework taint registry for one language. Frameworks is
// retained as raw JSON because ARTEX currently only needs to pass it through
// to audit agents.
type TaintRegistry struct {
	RegistryName string          `json:"registry_name"`
	Language     string          `json:"language"`
	Frameworks   json.RawMessage `json:"frameworks"`
}

// Registry is the embedded audit registry generated from Omni-Audit.
type Registry struct {
	Source    string                      `json:"source"`
	CWE       []CWEDefinition             `json:"cwe"`
	Sinks     map[string][]SinkDefinition `json:"sinks"`
	OdinRules []OdinRule                  `json:"odin_rules"`
	Taint     map[string][]TaintRegistry  `json:"taint"`
}
