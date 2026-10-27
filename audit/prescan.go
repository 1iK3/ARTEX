package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// PrescanLimits bounds deterministic source scanning. Zero MaxFiles and
// MaxFileBytes mean "no additional limit"; MaxSitesPerCWE defaults to 2000.
type PrescanLimits struct {
	MaxFiles       int
	MaxFileBytes   int64
	MaxSitesPerCWE int
	IncludeTests   bool
	IncludeVendor  bool
}

// SinkSite is one deterministic registry sink match in the snapshot.
type SinkSite struct {
	Language string `json:"language"`
	CWE      string `json:"cwe"`
	Path     string `json:"path"`
	Symbol   string `json:"symbol"`
	SinkKey  string `json:"sink_key"`
	Line     int    `json:"line"`
}

// SinkKeyFor returns the stable identity of a sink site. Prescan and engine
// findings both use it so the same physical site deduplicates regardless of
// which adapter discovered it.
func SinkKeyFor(language, cwe, path string, line int, symbol string) string {
	sum := sha256.Sum256([]byte(language + "|" + cwe + "|" + path + "|" + strconv.Itoa(line) + "|" + symbol))
	return hex.EncodeToString(sum[:])
}

// PrescanStats records deterministic inventory omissions that coverage and
// reporting should disclose. SkippedSymbols counts unique raw registry
// symbols rejected by the short-symbol filter. TruncatedCWEs and SiteCapCWEs
// use "<language>|<CWE>" keys when symbol or site caps were hit.
type PrescanStats struct {
	SkippedSymbols          int      `json:"skipped_symbols"`
	TruncatedCWEs           []string `json:"truncated_cwes,omitempty"`
	FileLimitReached        bool     `json:"file_limit_reached"`
	SkippedLargeFiles       int      `json:"skipped_large_files"`
	SkippedLongLines        int      `json:"skipped_long_lines"`
	SkippedBinaryOrMinified int      `json:"skipped_binary_or_minified"`
	SiteCapCWEs             []string `json:"site_cap_cwes,omitempty"`
}

// PrescanResult contains sink sites and scan statistics.
type PrescanResult struct {
	Sites []SinkSite   `json:"sites"`
	Stats PrescanStats `json:"stats"`
}

const (
	prescanDefaultMaxSitesPerCWE = 2000
	prescanMaxSymbolsPerCWE      = 200
	prescanMinSymbolLength       = 4
	prescanMaxLineBytes          = 1 << 20
	prescanBinaryProbeBytes      = 8 << 10
)

var (
	sinkIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	genericSinkNames      = map[string]struct{}{
		"get":     {},
		"set":     {},
		"read":    {},
		"write":   {},
		"open":    {},
		"close":   {},
		"run":     {},
		"find":    {},
		"command": {},
	}
)

type prescanMatcher struct {
	language string
	cwe      string
	regex    *regexp.Regexp
}

// Prescan inventories registry sink matches for planned language/CWE pairs.
// It is best-effort by design: binaries, minified files, oversized files, and
// overlong lines are skipped rather than aborting the whole inventory.
func Prescan(root string, profile Profile, plan Plan, reg Registry, limits PrescanLimits) (PrescanResult, error) {
	result := PrescanResult{
		Sites: []SinkSite{},
		Stats: PrescanStats{
			TruncatedCWEs: []string{},
			SiteCapCWEs:   []string{},
		},
	}

	info, err := os.Stat(root)
	if err != nil {
		return PrescanResult{}, fmt.Errorf("stat source root: %w", err)
	}
	if !info.IsDir() {
		return PrescanResult{}, fmt.Errorf("source root must be a directory: %s", root)
	}

	// profile is intentionally not used to narrow the search: an explicit
	// cfg.Languages may add a registry language that heuristic profiling missed.
	_ = profile

	maxSites := limits.MaxSitesPerCWE
	if maxSites <= 0 {
		maxSites = prescanDefaultMaxSitesPerCWE
	}

	matchers, truncated, skipped, err := buildPrescanMatchers(plan, reg)
	if err != nil {
		return PrescanResult{}, err
	}
	result.Stats.TruncatedCWEs = truncated
	result.Stats.SkippedSymbols = skipped
	if len(matchers) == 0 {
		return result, nil
	}

	byLanguage := make(map[string][]prescanMatcher)
	for _, matcher := range matchers {
		byLanguage[matcher.language] = append(byLanguage[matcher.language], matcher)
	}

	seenSites := make(map[string]struct{})
	siteCounts := make(map[string]int)
	siteCapSeen := make(map[string]struct{})
	scannedFiles := 0

	err = walkSourceTree(root, limits.IncludeTests, limits.IncludeVendor, func(path, relSlash string) error {
		language := languageForFile(relSlash)
		languageMatchers := byLanguage[language]
		if len(languageMatchers) == 0 {
			return nil
		}
		if isMinifiedPath(relSlash) {
			result.Stats.SkippedBinaryOrMinified++
			return nil
		}
		if limits.MaxFiles > 0 && scannedFiles >= limits.MaxFiles {
			result.Stats.FileLimitReached = true
			return filepath.SkipAll
		}
		scannedFiles++

		fileInfo, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat source file %s: %w", relSlash, err)
		}
		if limits.MaxFileBytes > 0 && fileInfo.Size() > limits.MaxFileBytes {
			result.Stats.SkippedLargeFiles++
			return nil
		}
		return scanSourceFile(path, relSlash, languageMatchers, maxSites, seenSites, siteCounts, siteCapSeen, &result.Sites, &result.Stats)
	})
	if err != nil {
		return PrescanResult{}, err
	}

	sort.Slice(result.Sites, func(i, j int) bool {
		left, right := result.Sites[i], result.Sites[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.CWE != right.CWE {
			return left.CWE < right.CWE
		}
		if left.Symbol != right.Symbol {
			return left.Symbol < right.Symbol
		}
		return left.Language < right.Language
	})
	sort.Strings(result.Stats.TruncatedCWEs)
	for key := range siteCapSeen {
		result.Stats.SiteCapCWEs = append(result.Stats.SiteCapCWEs, key)
	}
	sort.Strings(result.Stats.SiteCapCWEs)
	return result, nil
}

// PrescanSites is a convenience wrapper for callers that do not need stats.
func PrescanSites(root string, profile Profile, plan Plan, reg Registry, limits PrescanLimits) ([]SinkSite, error) {
	result, err := Prescan(root, profile, plan, reg, limits)
	return result.Sites, err
}

func buildPrescanMatchers(plan Plan, reg Registry) ([]prescanMatcher, []string, int, error) {
	planned := make(map[string]map[string]struct{})
	for rawLanguage, cwes := range plan.PlannedCWEs {
		language := NormalizeLanguage(rawLanguage)
		if language == "" {
			language = strings.ToLower(strings.TrimSpace(rawLanguage))
		}
		if language == "" {
			continue
		}
		if planned[language] == nil {
			planned[language] = make(map[string]struct{})
		}
		for _, rawCWE := range cwes {
			cwe := strings.ToUpper(strings.TrimSpace(rawCWE))
			if cweIDPattern.MatchString(cwe) {
				planned[language][cwe] = struct{}{}
			}
		}
	}

	languages := make([]string, 0, len(planned))
	for language := range planned {
		languages = append(languages, language)
	}
	sort.Strings(languages)

	truncated := make([]string, 0)
	skippedSymbols := make(map[string]struct{})
	var matchers []prescanMatcher

	for _, language := range languages {
		byCWE := make(map[string][]SinkDefinition)
		for _, definition := range reg.SinksFor(language) {
			if !strings.EqualFold(strings.TrimSpace(definition.Kind), "sink") {
				continue
			}
			cwe := strings.ToUpper(strings.TrimSpace(definition.CWEID))
			if cwe == "" || cwe == "*" {
				continue
			}
			byCWE[cwe] = append(byCWE[cwe], definition)
		}

		cwes := make([]string, 0, len(planned[language]))
		for cwe := range planned[language] {
			cwes = append(cwes, cwe)
		}
		sortCWEIDs(cwes)

		for _, cwe := range cwes {
			seenSymbols := make(map[string]struct{})
			symbols := make([]string, 0)
			for _, definition := range byCWE[cwe] {
				symbol, ok := shortSinkSymbol(definition.Symbol)
				if !ok {
					skippedSymbols[definition.Symbol] = struct{}{}
					continue
				}
				if _, exists := seenSymbols[symbol]; exists {
					continue
				}
				seenSymbols[symbol] = struct{}{}
				symbols = append(symbols, symbol)
			}
			if len(symbols) == 0 {
				continue
			}
			if len(symbols) > prescanMaxSymbolsPerCWE {
				symbols = symbols[:prescanMaxSymbolsPerCWE]
				truncated = append(truncated, language+"|"+cwe)
			}

			quoted := make([]string, 0, len(symbols))
			for _, symbol := range symbols {
				quoted = append(quoted, regexp.QuoteMeta(symbol))
			}
			expression := `\b(` + strings.Join(quoted, "|") + `)\b`
			compiled, err := regexp.Compile(expression)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("compile sink matcher for %s %s: %w", language, cwe, err)
			}
			matchers = append(matchers, prescanMatcher{language: language, cwe: cwe, regex: compiled})
		}
	}
	return matchers, truncated, len(skippedSymbols), nil
}

func shortSinkSymbol(raw string) (string, bool) {
	candidate := strings.TrimSpace(raw)
	if idx := strings.LastIndexByte(candidate, '.'); idx >= 0 {
		candidate = candidate[idx+1:]
	}
	if idx := strings.IndexByte(candidate, '('); idx >= 0 {
		candidate = candidate[:idx]
	}
	if idx := strings.LastIndex(candidate, "::"); idx >= 0 {
		candidate = candidate[idx+2:]
	}
	candidate = strings.TrimSpace(candidate)
	if !sinkIdentifierPattern.MatchString(candidate) {
		return "", false
	}
	if len(candidate) < prescanMinSymbolLength {
		return "", false
	}
	if _, generic := genericSinkNames[strings.ToLower(candidate)]; generic {
		return "", false
	}
	return candidate, true
}

func isMinifiedPath(relSlash string) bool {
	base := strings.ToLower(filepath.Base(relSlash))
	return strings.Contains(base, ".min.") ||
		strings.HasSuffix(base, "-min.js") ||
		strings.HasSuffix(base, ".bundle.js") ||
		strings.HasSuffix(base, ".bundle.ts")
}

func scanSourceFile(path, relSlash string, matchers []prescanMatcher, maxSites int, seenSites map[string]struct{}, siteCounts map[string]int, siteCapSeen map[string]struct{}, sites *[]SinkSite, stats *PrescanStats) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open source file %s: %w", relSlash, err)
	}
	defer file.Close()

	reader := bufio.NewReaderSize(file, prescanMaxLineBytes)
	head, err := reader.Peek(prescanBinaryProbeBytes)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return fmt.Errorf("read source file %s: %w", relSlash, err)
	}
	if bytes.IndexByte(head, 0) >= 0 {
		stats.SkippedBinaryOrMinified++
		return nil
	}

	lineNumber := 0
	for {
		fragment, readErr := reader.ReadSlice('\n')
		if len(fragment) == 0 && errors.Is(readErr, io.EOF) {
			break
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			// Consume the remainder of the overlong line without buffering it.
			stats.SkippedLongLines++
			lineNumber++
			for errors.Is(readErr, bufio.ErrBufferFull) {
				_, readErr = reader.ReadSlice('\n')
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return fmt.Errorf("scan source file %s: %w", relSlash, readErr)
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("scan source file %s: %w", relSlash, readErr)
		}

		lineNumber++
		line := fragment
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		scanPrescanLine(string(line), lineNumber, relSlash, matchers, maxSites, seenSites, siteCounts, siteCapSeen, sites)
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	return nil
}

func scanPrescanLine(line string, lineNumber int, relSlash string, matchers []prescanMatcher, maxSites int, seenSites map[string]struct{}, siteCounts map[string]int, siteCapSeen map[string]struct{}, sites *[]SinkSite) {
	for _, matcher := range matchers {
		countKey := matcher.language + "|" + matcher.cwe
		if siteCounts[countKey] >= maxSites {
			siteCapSeen[countKey] = struct{}{}
			continue
		}
		matches := matcher.regex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			symbol := match[1]
			dedupeKey := matcher.cwe + "\x00" + relSlash + "\x00" + strconv.Itoa(lineNumber) + "\x00" + symbol
			if _, exists := seenSites[dedupeKey]; exists {
				continue
			}
			seenSites[dedupeKey] = struct{}{}
			site := SinkSite{
				Language: matcher.language,
				CWE:      matcher.cwe,
				Path:     relSlash,
				Symbol:   symbol,
				Line:     lineNumber,
				SinkKey:  SinkKeyFor(matcher.language, matcher.cwe, relSlash, lineNumber, symbol),
			}
			*sites = append(*sites, site)
			siteCounts[countKey]++
			if siteCounts[countKey] >= maxSites {
				siteCapSeen[countKey] = struct{}{}
				break
			}
		}
	}
}
