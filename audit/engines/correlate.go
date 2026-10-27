package engines

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/audit"
)

var correlationCallSignature = regexp.MustCompile(`\([^()]*\)`)

// Normalize deduplicates engine findings and merges corroborating engines. The
// correlation identity is CWE + normalized sink path + a ±2 line window +
// short sink symbol. Merged findings expose per-engine evidence under
// Payload["engines"] and raise confidence by 0.1 per extra distinct engine,
// capped at 0.99. Input findings are not mutated.
func Normalize(findings []EngineFinding) []EngineFinding {
	if len(findings) == 0 {
		return []EngineFinding{}
	}

	groups := make([]*correlationGroup, 0, len(findings))
	byBaseKey := make(map[string][]*correlationGroup, len(findings))
	for _, finding := range findings {
		baseKey, line := correlationBaseKey(finding)
		var matched *correlationGroup
		for _, group := range byBaseKey[baseKey] {
			if linesCorrelate(line, group.line) {
				matched = group
				break
			}
		}
		if matched == nil {
			matched = newCorrelationGroup(finding, line)
			byBaseKey[baseKey] = append(byBaseKey[baseKey], matched)
			groups = append(groups, matched)
			continue
		}
		matched.merge(finding)
	}

	out := make([]EngineFinding, 0, len(groups))
	for _, group := range groups {
		out = append(out, group.finding())
	}
	return out
}

type correlationGroup struct {
	result   EngineFinding
	line     int
	payload  map[string]any
	engines  map[string]*correlationEngine
	engineID []string
}

type correlationEngine struct {
	name       string
	queryID    string
	rawRef     string
	confidence float64
}

func newCorrelationGroup(finding EngineFinding, line int) *correlationGroup {
	group := &correlationGroup{
		result:  cloneFinding(finding),
		line:    line,
		payload: clonePayload(finding.Payload),
		engines: make(map[string]*correlationEngine),
	}
	group.addEngine(finding)
	return group
}

func (g *correlationGroup) merge(finding EngineFinding) {
	if !locationHasData(g.result.Location) && locationHasData(finding.Location) {
		g.result.Location = finding.Location
	}
	if g.result.Source == nil && finding.Source != nil {
		g.result.Source = cloneLocationPtr(finding.Source)
	}
	if g.result.Sink == nil && finding.Sink != nil {
		g.result.Sink = cloneLocationPtr(finding.Sink)
	}
	if len(finding.Trace) > len(g.result.Trace) {
		g.result.Trace = append([]audit.TraceStep(nil), finding.Trace...)
	}
	if strings.TrimSpace(g.result.Message) == "" {
		g.result.Message = finding.Message
	}
	if strings.TrimSpace(g.result.Severity) == "" {
		g.result.Severity = finding.Severity
	}
	if strings.TrimSpace(g.result.CWE) == "" {
		g.result.CWE = finding.CWE
	}
	if strings.TrimSpace(g.result.Language) == "" {
		g.result.Language = finding.Language
	}
	if strings.TrimSpace(g.result.QueryID) == "" {
		g.result.QueryID = finding.QueryID
	}
	if strings.TrimSpace(g.result.RawRef) == "" {
		g.result.RawRef = finding.RawRef
	}
	for key, value := range finding.Payload {
		if key == "engines" {
			continue
		}
		if _, exists := g.payload[key]; !exists {
			g.payload[key] = value
		}
	}
	if g.line <= 0 && findingSinkLine(finding) > 0 {
		g.line = findingSinkLine(finding)
	}
	g.addEngine(finding)
}

func (g *correlationGroup) addEngine(finding EngineFinding) {
	name := correlationEngineName(finding.Engine)
	entry, exists := g.engines[name]
	if !exists {
		entry = &correlationEngine{name: name}
		g.engines[name] = entry
		g.engineID = append(g.engineID, name)
	}
	if strings.TrimSpace(entry.queryID) == "" {
		entry.queryID = strings.TrimSpace(finding.QueryID)
	}
	if strings.TrimSpace(entry.rawRef) == "" {
		entry.rawRef = strings.TrimSpace(finding.RawRef)
	}
	confidence := normalizedConfidence(finding.Confidence)
	if confidence > entry.confidence {
		entry.confidence = confidence
	}
}

func (g *correlationGroup) finding() EngineFinding {
	result := g.result
	result.Trace = append([]audit.TraceStep(nil), g.result.Trace...)
	result.Source = cloneLocationPtr(g.result.Source)
	result.Sink = cloneLocationPtr(g.result.Sink)
	result.Payload = clonePayload(g.payload)

	names := append([]string(nil), g.engineID...)
	sort.Strings(names)
	enginePayloads := make([]map[string]any, 0, len(names))
	maxConfidence := 0.0
	for _, name := range names {
		entry := g.engines[name]
		if entry.confidence > maxConfidence {
			maxConfidence = entry.confidence
		}
		item := map[string]any{
			"name":       entry.name,
			"confidence": entry.confidence,
		}
		if entry.queryID != "" {
			item["query_id"] = entry.queryID
		}
		if entry.rawRef != "" {
			item["raw_ref"] = entry.rawRef
		}
		enginePayloads = append(enginePayloads, item)
	}
	if result.Payload == nil {
		result.Payload = make(map[string]any)
	}
	result.Payload["engines"] = enginePayloads

	engineCount := len(names)
	switch {
	case engineCount <= 1:
		result.Confidence = clampConfidence(maxConfidence, 1)
	default:
		result.Confidence = clampConfidence(maxConfidence+0.1*float64(engineCount-1), 0.99)
	}
	if result.Engine == "" && engineCount > 0 {
		result.Engine = names[0]
	}
	return result
}

func correlationBaseKey(finding EngineFinding) (string, int) {
	path := ""
	if finding.Sink != nil && strings.TrimSpace(finding.Sink.Path) != "" {
		path = finding.Sink.Path
	} else {
		path = finding.Location.Path
	}
	path = audit.NormalizeCodePath(path)
	cwe := normalizeCWEID(finding.CWE)
	if cwe == "" {
		cwe = "*"
	}
	symbol := correlationSinkSymbol(finding)
	return cwe + "|" + path + "|" + symbol, findingSinkLine(finding)
}

func correlationSinkSymbol(finding EngineFinding) string {
	symbol := ""
	if finding.Sink != nil {
		symbol = firstNonEmpty(finding.Sink.Symbol, finding.Sink.API)
	}
	if symbol == "" {
		symbol = firstNonEmpty(finding.Location.Symbol, finding.Location.API)
	}
	short := shortCorrelationSymbol(symbol)
	if short == "" {
		return "$"
	}
	return short
}

func findingSinkLine(finding EngineFinding) int {
	if finding.Sink != nil && finding.Sink.Line > 0 {
		return finding.Sink.Line
	}
	if finding.Location.Line > 0 {
		return finding.Location.Line
	}
	return 0
}

func shortCorrelationSymbol(raw string) string {
	symbol := strings.TrimSpace(raw)
	symbol = correlationCallSignature.ReplaceAllString(symbol, "")
	symbol = strings.NewReplacer("(", "", ")", "").Replace(symbol)
	if index := strings.LastIndexByte(symbol, '.'); index >= 0 {
		symbol = symbol[index+1:]
	}
	if index := strings.LastIndex(symbol, "::"); index >= 0 {
		symbol = symbol[index+2:]
	}
	symbol = strings.Join(strings.Fields(symbol), "")
	return strings.ToLower(symbol)
}

func linesCorrelate(left, right int) bool {
	if left <= 0 || right <= 0 {
		return true
	}
	delta := left - right
	if delta < 0 {
		delta = -delta
	}
	return delta <= 2
}

func correlationEngineName(engine string) string {
	if normalized := normalizeEngineName(engine); normalized != "" {
		return normalized
	}
	if trimmed := strings.ToLower(strings.TrimSpace(engine)); trimmed != "" {
		return trimmed
	}
	return "unknown"
}

func normalizedConfidence(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func clampConfidence(value, maximum float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0
	}
	if value > maximum {
		return maximum
	}
	return value
}

func locationHasData(location audit.CodeLocation) bool {
	return location.Path != "" || location.Line > 0 || location.Symbol != ""
}

func cloneLocationPtr(location *audit.CodeLocation) *audit.CodeLocation {
	if location == nil {
		return nil
	}
	clone := *location
	return &clone
}

func clonePayload(payload map[string]any) map[string]any {
	if payload == nil {
		return make(map[string]any)
	}
	clone := make(map[string]any, len(payload))
	for key, value := range payload {
		clone[key] = value
	}
	return clone
}

func cloneFinding(finding EngineFinding) EngineFinding {
	clone := finding
	clone.Source = cloneLocationPtr(finding.Source)
	clone.Sink = cloneLocationPtr(finding.Sink)
	clone.Trace = append([]audit.TraceStep(nil), finding.Trace...)
	clone.Payload = clonePayload(finding.Payload)
	return clone
}

// CorrelationKey returns the stable display key used by Normalize. It is
// exported for query logs and tests; line proximity is applied separately.
func CorrelationKey(finding EngineFinding) string {
	key, line := correlationBaseKey(finding)
	return key + "|" + strconv.Itoa(line)
}
