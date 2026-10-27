package audit

import "strings"

// Canonical language identifiers used by the audit registry.
const (
	Java       = "java"
	Python     = "python"
	JavaScript = "javascript"
	TypeScript = "typescript"
	Go         = "go"
	Rust       = "rust"
	C          = "c"
	CPP        = "cpp"
)

var canonicalLanguages = []string{Java, Python, JavaScript, TypeScript, Go, Rust, C, CPP}

// LanguageForPath returns the display language detected from a file extension,
// or an empty string when the extension is unknown. Paths may use either slash
// style; only the extension is inspected.
func LanguageForPath(path string) string {
	return languageForFile(path)
}

// NormalizeLanguage maps a language name or alias to its canonical identifier.
// It returns an empty string when the language is not recognized.
func NormalizeLanguage(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case Java:
		return Java
	case Python, "py":
		return Python
	case JavaScript, "js", "node", "nodejs", "node.js":
		return JavaScript
	case TypeScript, "ts", "tsx":
		return TypeScript
	case Go, "golang":
		return Go
	case Rust, "rs":
		return Rust
	case C:
		return C
	case CPP, "c++", "cxx", "cc":
		return CPP
	default:
		return ""
	}
}

// Languages returns the canonical languages supported by the audit registry.
// The returned slice is a copy and may be modified by the caller.
func Languages() []string {
	out := make([]string, len(canonicalLanguages))
	copy(out, canonicalLanguages)
	return out
}

// languageMatches reports whether any entry in languages normalizes to
// canonical. canonical must be non-empty.
func languageMatches(languages []string, canonical string) bool {
	if canonical == "" {
		return false
	}
	for _, language := range languages {
		if NormalizeLanguage(language) == canonical {
			return true
		}
	}
	return false
}

// odinLanguageMatches reports whether an Odin rule with ruleLanguages applies
// to canonical. Rule languages that normalize to JavaScript ("nodejs", "js",
// "node", etc.) intentionally apply to both JavaScript and TypeScript. This
// expansion is Odin-specific so the canonical mapping used by sinks and CWEs
// is not changed.
func odinLanguageMatches(ruleLanguages []string, canonical string) bool {
	if languageMatches(ruleLanguages, canonical) {
		return true
	}
	return canonical == TypeScript && languageMatches(ruleLanguages, JavaScript)
}

// cloneStrings returns a non-nil copy of in.
func cloneStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}
