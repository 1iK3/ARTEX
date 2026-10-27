package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// CodeEvidence is the structured evidence persisted for a code-audit finding.
// It is the Go mirror of appendix B of the code-audit design. The human-readable
// summary stays in findings.evidence; this schema carries the machine-checkable
// taint/verification/reachability chain.
type CodeEvidence struct {
	Version       int                `json:"version"`
	CWEID         string             `json:"cwe_id"`
	Title         string             `json:"title"`
	Severity      string             `json:"severity"`
	Confidence    float64            `json:"confidence"`
	Verification  Verification       `json:"verification"`
	Location      CodeLocation       `json:"location"`
	Source        *CodeLocation      `json:"source,omitempty"`
	Sink          *CodeLocation      `json:"sink,omitempty"`
	Trace         []TraceStep        `json:"trace,omitempty"`
	Sanitizers    []SanitizerVerdict `json:"sanitizers,omitempty"`
	SemanticChain []SemanticStep     `json:"semantic_chain,omitempty"`
	Reachability  *Reachability      `json:"reachability,omitempty"`
	Preconditions []string           `json:"preconditions,omitempty"`
	Impact        string             `json:"impact,omitempty"`
	POC           *POCEvidence       `json:"poc,omitempty"`
	Engines       []EngineEvidence   `json:"engines,omitempty"`
	Analysis      Analysis           `json:"analysis"`
	DedupeKey     string             `json:"dedupe_key,omitempty"`
}

// Verification is the result of the confirmation pipeline for one finding.
type Verification struct {
	Status           string `json:"status"` // unverified|candidate|confirmed|refuted|design_intent
	Method           string `json:"method,omitempty"`
	Reason           string `json:"reason,omitempty"`
	AlternativePath  string `json:"alternative_path,omitempty"`
	VerifiedByIntent int64  `json:"verified_by_intent,omitempty"`
	DesignValidation string `json:"design_validation,omitempty"`
}

// CodeLocation identifies one code site. Line is 1-based; EndLine is optional.
type CodeLocation struct {
	Path    string `json:"path,omitempty"`
	Line    int    `json:"line,omitempty"`
	EndLine int    `json:"end_line,omitempty"`
	Symbol  string `json:"symbol,omitempty"`
	Snippet string `json:"snippet,omitempty"`
	API     string `json:"api,omitempty"`
}

// TraceStep is one hop in a source-to-sink trace.
type TraceStep struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Symbol string `json:"symbol"`
	Note   string `json:"note,omitempty"`
}

// SanitizerVerdict records whether a sanitizer applies at a path (verdict
// present|missing|insufficient). "unknown" is deliberately not accepted.
type SanitizerVerdict struct {
	Symbol  string `json:"symbol"`
	Verdict string `json:"verdict"`
	Note    string `json:"note,omitempty"`
}

// SemanticStep captures a transformation whose semantics change between
// producer and consumer (decode, concat, case, path, protocol, serialize, type).
type SemanticStep struct {
	Stage              string `json:"stage"`
	Operation          string `json:"operation"`
	Input              string `json:"input,omitempty"`
	Output             string `json:"output,omitempty"`
	SemanticsFrom      string `json:"semantics_from,omitempty"`
	SemanticsTo        string `json:"semantics_to,omitempty"`
	ConsumerAssumption string `json:"consumer_assumption,omitempty"`
}

// Reachability describes whether an attacker-controlled entry can reach the
// finding and what authentication the entry needs. AuthStateRecorded must be set
// explicitly: AuthRequired=false otherwise cannot be distinguished from an
// omitted auth decision, which high/critical confirmed findings may not leave
// ambiguous.
type Reachability struct {
	Reachable         bool   `json:"reachable"`
	EntryPoint        string `json:"entry_point,omitempty"`
	AuthRequired      bool   `json:"auth_required"`
	AuthStateRecorded bool   `json:"auth_state_recorded,omitempty"`
	Path              string `json:"path,omitempty"`
}

// POCEvidence points at a PoC artifact. ArtifactPath, when set, is repo-relative.
type POCEvidence struct {
	Kind         string `json:"kind"` // http|script|none
	ArtifactPath string `json:"artifact_path,omitempty"`
	Description  string `json:"description,omitempty"`
	Executed     bool   `json:"executed"`
}

// EngineEvidence records a finding produced by an external analysis engine.
type EngineEvidence struct {
	Name       string  `json:"name"`
	QueryID    string  `json:"query_id,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	RawRef     string  `json:"raw_ref,omitempty"`
}

// Analysis records which audit phase/round produced the evidence.
type Analysis struct {
	Phase    string `json:"phase,omitempty"`
	Round    int    `json:"round,omitempty"`
	IntentID int64  `json:"intent_id,omitempty"`
	Backend  string `json:"backend,omitempty"`
	Fallback bool   `json:"fallback,omitempty"`
}

// Code evidence schema limits.
const (
	CodeEvidenceVersion  = 1
	MaxCodeEvidenceBytes = 256 * 1024
)

// ErrCodeEvidenceTooLarge is returned by MarshalCodeEvidence when the encoded
// payload exceeds MaxCodeEvidenceBytes.
var ErrCodeEvidenceTooLarge = errors.New("code evidence exceeds maximum size")

// Verification statuses.
const (
	VerificationUnverified   = "unverified"
	VerificationCandidate    = "candidate"
	VerificationConfirmed    = "confirmed"
	VerificationRefuted      = "refuted"
	VerificationDesignIntent = "design_intent"
)

// Verification methods.
const (
	MethodTaintTrace       = "taint_trace"
	MethodAlternativePath  = "alternative_path"
	MethodCrossEngine      = "cross_engine"
	MethodDesignValidation = "design_validation"
	MethodManual           = "manual"
)

// Sanitizer verdicts.
const (
	SanitizerPresent      = "present"
	SanitizerMissing      = "missing"
	SanitizerInsufficient = "insufficient"
)

// Design validation verdict. High/critical confirmed findings must be judged a
// real vulnerability against the project's documented design.
const DesignValidationRealVuln = "real_vuln"

// Code finding severities (mirrors the findings.severity contract).
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// ValidSeverity reports whether s is a known finding severity.
func ValidSeverity(s string) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	}
	return false
}

// ValidVerificationStatus reports whether s is a known verification status.
func ValidVerificationStatus(s string) bool {
	switch s {
	case VerificationUnverified, VerificationCandidate, VerificationConfirmed,
		VerificationRefuted, VerificationDesignIntent:
		return true
	}
	return false
}

// ValidVerificationMethod reports whether s is a known verification method.
func ValidVerificationMethod(s string) bool {
	switch s {
	case MethodTaintTrace, MethodAlternativePath, MethodCrossEngine,
		MethodDesignValidation, MethodManual:
		return true
	}
	return false
}

// ValidSanitizerVerdict reports whether s is a final sanitizer verdict.
func ValidSanitizerVerdict(s string) bool {
	switch s {
	case SanitizerPresent, SanitizerMissing, SanitizerInsufficient:
		return true
	}
	return false
}

var (
	windowsDrivePath = regexp.MustCompile(`^[A-Za-z]:`)
	callSignature    = regexp.MustCompile(`\([^()]*\)`)
)

// ValidateCodeEvidence validates ev against the verification status carried in
// ev.Verification.Status. An optional status argument overrides the embedded
// status, which is convenient when a caller defaults an omitted status first.
func ValidateCodeEvidence(ev CodeEvidence, statusOverride ...string) error {
	if len(statusOverride) > 0 {
		return ValidateCodeEvidenceFor(ev, statusOverride[0])
	}
	return ValidateCodeEvidenceFor(ev, ev.Verification.Status)
}

// ValidateCodeEvidenceFor validates ev as if it had the supplied verification
// status. status overrides ev.Verification.Status (a caller may default an
// omitted status to "candidate" before validating).
func ValidateCodeEvidenceFor(ev CodeEvidence, status string) error {
	status = strings.TrimSpace(status)
	if status == "" {
		status = strings.TrimSpace(ev.Verification.Status)
	}
	if status == "" {
		return errors.New("code evidence: verification.status is required")
	}
	if !ValidVerificationStatus(status) {
		return fmt.Errorf("code evidence: unknown verification status %q", status)
	}
	if !cweIDPattern.MatchString(strings.TrimSpace(ev.CWEID)) {
		return fmt.Errorf("code evidence: cwe_id %q must match CWE-<number>", ev.CWEID)
	}
	if !ValidSeverity(strings.TrimSpace(ev.Severity)) {
		return fmt.Errorf("code evidence: unknown severity %q", ev.Severity)
	}
	if math.IsNaN(ev.Confidence) || math.IsInf(ev.Confidence, 0) || ev.Confidence < 0 || ev.Confidence > 1 {
		return fmt.Errorf("code evidence: confidence %v must be within [0,1]", ev.Confidence)
	}
	if strings.TrimSpace(ev.Title) == "" {
		return errors.New("code evidence: title is required")
	}
	if err := validateRequiredLocation("location", ev.Location); err != nil {
		return err
	}
	if err := validateOptionalLocation("source", ev.Source); err != nil {
		return err
	}
	if err := validateOptionalLocation("sink", ev.Sink); err != nil {
		return err
	}
	for i, step := range ev.Trace {
		if _, err := normalizeCodePath(step.Path); err != nil {
			return fmt.Errorf("code evidence: trace[%d].path: %w", i, err)
		}
		if step.Line <= 0 {
			return fmt.Errorf("code evidence: trace[%d].line must be positive", i)
		}
		if strings.TrimSpace(step.Symbol) == "" {
			return fmt.Errorf("code evidence: trace[%d].symbol is required", i)
		}
	}
	for i, sanitizer := range ev.Sanitizers {
		if strings.TrimSpace(sanitizer.Symbol) == "" {
			return fmt.Errorf("code evidence: sanitizers[%d].symbol is required", i)
		}
		if !ValidSanitizerVerdict(strings.TrimSpace(sanitizer.Verdict)) {
			return fmt.Errorf("code evidence: sanitizers[%d].verdict %q must be present, missing or insufficient",
				i, sanitizer.Verdict)
		}
	}
	for i, engine := range ev.Engines {
		if strings.TrimSpace(engine.Name) == "" {
			return fmt.Errorf("code evidence: engines[%d].name is required", i)
		}
		// A hit without a raw reference cannot be corroborated: every engine
		// entry must point back at its native result (SARIF/CPG/query output).
		if strings.TrimSpace(engine.RawRef) == "" {
			return fmt.Errorf("code evidence: engines[%d].raw_ref is required", i)
		}
		if math.IsNaN(engine.Confidence) || math.IsInf(engine.Confidence, 0) ||
			engine.Confidence < 0 || engine.Confidence > 1 {
			return fmt.Errorf("code evidence: engines[%d].confidence %v must be within [0,1]", i, engine.Confidence)
		}
	}
	if ev.POC != nil && strings.TrimSpace(ev.POC.ArtifactPath) != "" {
		if _, err := normalizeCodePath(ev.POC.ArtifactPath); err != nil {
			return fmt.Errorf("code evidence: poc.artifact_path: %w", err)
		}
	}

	method := strings.TrimSpace(ev.Verification.Method)
	if method != "" && !ValidVerificationMethod(method) {
		return fmt.Errorf("code evidence: unknown verification method %q", ev.Verification.Method)
	}
	if method == "" && status != VerificationUnverified && status != VerificationCandidate {
		return fmt.Errorf("code evidence: verification.method is required for status %q", status)
	}

	if status != VerificationConfirmed {
		return nil
	}

	if ev.Source == nil {
		return errors.New("code evidence: confirmed finding requires source")
	}
	if ev.Sink == nil {
		return errors.New("code evidence: confirmed finding requires sink")
	}
	if len(ev.Trace) == 0 {
		return errors.New("code evidence: confirmed finding requires at least one trace step")
	}
	if len(ev.Sanitizers) == 0 {
		return errors.New("code evidence: confirmed finding requires sanitizer verdicts")
	}
	if ev.Confidence < 0.5 {
		return fmt.Errorf("code evidence: confirmed finding requires confidence >= 0.5, got %v", ev.Confidence)
	}
	if err := validateConfirmedHighRisk(ev); err != nil {
		return err
	}
	return nil
}

// validateConfirmedHighRisk enforces the extra bar for high/critical confirmed
// findings: proven reachability with an explicit entry point and recorded auth
// state, an independent cross-check (alternative path, or engine evidence with a
// raw reference), and an explicit real-vulnerability design judgement.
func validateConfirmedHighRisk(ev CodeEvidence) error {
	severity := strings.TrimSpace(ev.Severity)
	if severity != SeverityHigh && severity != SeverityCritical {
		return nil
	}
	if ev.Reachability == nil || !ev.Reachability.Reachable {
		return fmt.Errorf("code evidence: %s confirmed finding requires a reachable path", severity)
	}
	if strings.TrimSpace(ev.Reachability.EntryPoint) == "" {
		return fmt.Errorf("code evidence: %s confirmed finding requires reachability.entry_point", severity)
	}
	if !ev.Reachability.AuthStateRecorded {
		return fmt.Errorf("code evidence: %s confirmed finding requires a recorded reachability.auth_state_recorded", severity)
	}
	hasAlternative := strings.TrimSpace(ev.Verification.AlternativePath) != ""
	hasEngine := false
	for _, engine := range ev.Engines {
		if strings.TrimSpace(engine.Name) != "" && strings.TrimSpace(engine.RawRef) != "" {
			hasEngine = true
			break
		}
	}
	if !hasAlternative && !hasEngine {
		return fmt.Errorf("code evidence: %s confirmed finding requires an alternative path or engine evidence", severity)
	}
	if strings.TrimSpace(ev.Verification.DesignValidation) != DesignValidationRealVuln {
		return fmt.Errorf("code evidence: %s confirmed finding requires design_validation %q",
			severity, DesignValidationRealVuln)
	}
	return nil
}

func validateRequiredLocation(name string, loc CodeLocation) error {
	if _, err := normalizeCodePath(loc.Path); err != nil {
		return fmt.Errorf("code evidence: %s.path: %w", name, err)
	}
	if loc.Line <= 0 {
		return fmt.Errorf("code evidence: %s.line must be positive", name)
	}
	if strings.TrimSpace(loc.Symbol) == "" {
		return fmt.Errorf("code evidence: %s.symbol is required", name)
	}
	return nil
}

func validateOptionalLocation(name string, loc *CodeLocation) error {
	if loc == nil {
		return nil
	}
	if strings.TrimSpace(loc.Symbol) == "" {
		return fmt.Errorf("code evidence: %s.symbol is required", name)
	}
	if strings.TrimSpace(loc.Path) != "" {
		if _, err := normalizeCodePath(loc.Path); err != nil {
			return fmt.Errorf("code evidence: %s.path: %w", name, err)
		}
	}
	if loc.Line < 0 {
		return fmt.Errorf("code evidence: %s.line must not be negative", name)
	}
	return nil
}

// normalizeCodePath validates that p is a repository-relative path. It accepts
// both slash styles and non-clean forms, but rejects absolute paths, Windows
// drive paths and anything that climbs out of the repository root.
func normalizeCodePath(p string) (string, error) {
	raw := strings.TrimSpace(p)
	if raw == "" {
		return "", errors.New("path is required")
	}
	slash := strings.ReplaceAll(raw, "\\", "/")
	if path.IsAbs(slash) || windowsDrivePath.MatchString(slash) {
		return "", fmt.Errorf("path %q must be relative", p)
	}
	cleaned := path.Clean(slash)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path %q escapes the repository root", p)
	}
	return cleaned, nil
}

// NormalizeCodePath canonicalizes a code path for keys and display: backslashes
// become slashes, a leading root or Windows drive prefix is stripped, "." and
// ".." segments are resolved, and any remaining leading "../" escapes are
// dropped so the result stays repository-relative. It is best-effort and cannot
// fail; normalizeCodePath is the strict validator used before persisting.
func NormalizeCodePath(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	p = strings.TrimLeft(p, "/")
	p = windowsDrivePath.ReplaceAllString(p, "")
	p = strings.TrimLeft(p, "/")
	p = path.Clean(p)
	for p == ".." || strings.HasPrefix(p, "../") {
		if p == ".." {
			return ""
		}
		p = strings.TrimPrefix(p, "../")
	}
	if p == "" || p == "." {
		return ""
	}
	return p
}

// ShortSymbol reduces a callable/API name to its last two dotted segments for
// compact display. Arguments, parentheses and whitespace are stripped, e.g.
// "java.sql.Statement.executeQuery(String)" -> "Statement.executeQuery" and
// "UserDao.find" -> "UserDao.find".
func ShortSymbol(s string) string {
	s = strings.TrimSpace(s)
	for {
		stripped := callSignature.ReplaceAllString(s, "")
		if stripped == s {
			break
		}
		s = stripped
	}
	s = strings.NewReplacer("(", "", ")", "").Replace(s)
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return ""
	}
	parts := make([]string, 0, 3)
	for _, part := range strings.Split(s, ".") {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, ".")
}

// DedupeKey builds the server-side finding identity
// "CWE|normalized_path|line|sink_symbol". Paths are canonicalized and the sink
// symbol is reduced to its terminal segment so a model reporting
// "java.sql.Statement.executeQuery" and one reporting "executeQuery" produce the
// same key. Case is preserved; surrounding whitespace is trimmed.
func DedupeKey(cwe, codePath string, line int, sinkSymbol string) string {
	return strings.Join([]string{
		strings.TrimSpace(cwe),
		NormalizeCodePath(codePath),
		strconv.Itoa(line),
		dedupeSymbol(sinkSymbol),
	}, "|")
}

func dedupeSymbol(s string) string {
	short := ShortSymbol(s)
	if i := strings.LastIndexByte(short, '.'); i >= 0 {
		return short[i+1:]
	}
	return short
}

// MarshalCodeEvidence serializes ev for the findings.code_evidence column. It
// fills Version=1, always overwrites DedupeKey with the server-canonical
// identity (a caller-supplied key is never trusted), and rejects payloads
// larger than MaxCodeEvidenceBytes.
func MarshalCodeEvidence(ev CodeEvidence) (json.RawMessage, error) {
	if ev.Version == 0 {
		ev.Version = CodeEvidenceVersion
	}
	sinkSymbol := ""
	if ev.Sink != nil {
		sinkSymbol = ev.Sink.Symbol
	}
	if strings.TrimSpace(sinkSymbol) == "" {
		sinkSymbol = ev.Location.Symbol
	}
	ev.DedupeKey = DedupeKey(ev.CWEID, ev.Location.Path, ev.Location.Line, sinkSymbol)
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("marshal code evidence: %w", err)
	}
	if len(raw) > MaxCodeEvidenceBytes {
		return nil, fmt.Errorf("%w: %d bytes > %d", ErrCodeEvidenceTooLarge, len(raw), MaxCodeEvidenceBytes)
	}
	return json.RawMessage(raw), nil
}
