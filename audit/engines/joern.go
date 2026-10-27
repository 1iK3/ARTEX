package engines

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/audit"
)

// JoernJSONMarker prefixes the single JSON document emitted by the fixed
// wrapper. Anything before the marker is treated as Joern log output.
const JoernJSONMarker = "@@ARTEX_JSON@@"

const (
	maxJoernFindings = 5000
	maxJoernQuery    = 1 << 20
)

// JoernRunner is a Joern adapter. It parses source with joern-parse and executes
// only registered CPGQL templates inside a fixed wrapper. Free-form queries are
// rejected unless SandboxCmd is configured.
type JoernRunner struct {
	Bin        string
	ParseBin   string
	WorkDir    string
	CPGPath    string
	Timeout    time.Duration
	SandboxCmd string
	execFn     ExecFunc

	mu   sync.Mutex
	cpgs map[string]string
}

// NewJoernRunner creates a runner. Empty binary names default to joern and
// joern-parse.
func NewJoernRunner(bin, parseBin, workDir string) *JoernRunner {
	return &JoernRunner{
		Bin:      strings.TrimSpace(bin),
		ParseBin: strings.TrimSpace(parseBin),
		WorkDir:  strings.TrimSpace(workDir),
	}
}

func (r *JoernRunner) Name() string { return EngineJoern }

func (r *JoernRunner) Close() error { return nil }

func (r *JoernRunner) binName() string {
	if r != nil {
		if bin := strings.TrimSpace(r.Bin); bin != "" {
			return bin
		}
	}
	return "joern"
}

func (r *JoernRunner) parseBinName() string {
	if r != nil {
		if bin := strings.TrimSpace(r.ParseBin); bin != "" {
			return bin
		}
	}
	return "joern-parse"
}

type joernCommand struct {
	Name   string
	Prefix []string
	Path   string
}

// toolCommand resolves the Joern launcher. The distributed .bat files are used
// on Windows because the POSIX shell launchers build an MSYS-style classpath
// that the Windows JVM cannot load. Fake executors keep the literal command name
// so unit tests can remain platform-independent.
func (r *JoernRunner) toolCommand(raw string) joernCommand {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "joern"
	}
	resolved := raw
	if r.execFn == nil {
		if path, err := exec.LookPath(raw); err == nil {
			resolved = path
		}
	}
	if runtime.GOOS == "windows" {
		lower := strings.ToLower(resolved)
		if !strings.HasSuffix(lower, ".bat") && !strings.HasSuffix(lower, ".cmd") {
			if info, err := os.Stat(resolved); err == nil && !info.IsDir() {
				if _, err := os.Stat(resolved + ".bat"); err == nil {
					resolved += ".bat"
				}
			}
		}
		lower = strings.ToLower(resolved)
		if strings.HasSuffix(lower, ".bat") || strings.HasSuffix(lower, ".cmd") {
			return joernCommand{Name: "cmd.exe", Prefix: []string{"/d", "/s", "/c", resolved}, Path: resolved}
		}
	}
	return joernCommand{Name: resolved, Path: resolved}
}

func joernInstallVersion(path string) string {
	dirs := []string{filepath.Join(filepath.Dir(path), "lib")}
	dirs = append(dirs, filepath.Join(filepath.Dir(filepath.Dir(path)), "lib"))
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, "io.joern.joern-cli-*.jar"))
		if err != nil {
			continue
		}
		for _, match := range matches {
			base := filepath.Base(match)
			base = strings.TrimPrefix(base, "io.joern.joern-cli-")
			return strings.TrimSuffix(base, ".jar")
		}
	}
	return ""
}

func (r *JoernRunner) commandArgs(command joernCommand, args ...string) []string {
	out := make([]string, 0, len(command.Prefix)+len(args))
	out = append(out, command.Prefix...)
	out = append(out, args...)
	return out
}

func joernCapabilityLanguages() []string {
	return []string{
		audit.Java, audit.Python, audit.JavaScript, audit.TypeScript,
		audit.Go, audit.C, audit.CPP,
	}
}

// Probe verifies both joern and joern-parse launchers. Joern parses source
// rather than requiring a build, so BuildModeNone is true.
func (r *JoernRunner) Probe(ctx context.Context) (Capability, error) {
	bin := r.toolCommand(r.binName())
	parse := r.toolCommand(r.parseBinName())
	path := bin.Path

	helpOut, _, helpErr := executeCommand(ctx, r.execFn, bin.Name, r.commandArgs(bin, "--help"), "", r.Timeout)
	if helpErr != nil {
		if probeContextErr(ctx) != nil {
			return Capability{Reason: "canceled", Path: path}, probeContextErr(ctx)
		}
		return Capability{Available: false, Reason: probeFailureReason(helpErr), Path: path}, nil
	}
	parseHelpOut, _, parseErr := executeCommand(ctx, r.execFn, parse.Name, r.commandArgs(parse, "--help"), "", r.Timeout)
	if parseErr != nil {
		if probeContextErr(ctx) != nil {
			return Capability{Reason: "canceled", Path: path}, probeContextErr(ctx)
		}
		reason := probeFailureReason(parseErr)
		if reason == "version_failed" || reason == "binary_missing" {
			reason = "parse_binary_missing"
		}
		return Capability{Available: false, Reason: reason, Path: path}, nil
	}
	version := joernInstallVersion(bin.Path)
	if version == "" {
		version = firstNonEmpty(parseEngineVersion(helpOut), parseEngineVersion(parseHelpOut))
	}
	return Capability{
		Available:     true,
		Version:       version,
		Path:          path,
		Languages:     joernCapabilityLanguages(),
		BuildModeNone: true,
	}, nil
}

// Prepare parses the snapshot into one CPG shared by all requested languages.
// Per-language unsupported reasons are recorded without discarding a CPG that
// was successfully produced.
func (r *JoernRunner) Prepare(ctx context.Context, src SourceRef, langs []string, opts PrepareOptions) (Prepared, error) {
	started := time.Now()
	prepared := Prepared{
		Engine:      EngineJoern,
		Paths:       make(map[string]string),
		BuildModes:  make(map[string]string),
		Unsupported: make(map[string]string),
		Languages:   []string{},
	}
	languages := normalizeLanguageList(langs)
	if len(languages) == 0 {
		languages = normalizeLanguageList(src.Languages)
	}
	if len(languages) == 0 {
		return prepared, fmt.Errorf("%w: no languages supplied for Joern preparation", ErrInvalidSource)
	}

	supported := make([]string, 0, len(languages))
	for _, language := range languages {
		if languageSupported(joernCapabilityLanguages(), language) {
			supported = append(supported, language)
		} else {
			prepared.Unsupported[language] = "language_not_supported"
		}
	}
	if len(supported) == 0 {
		prepared.Duration = time.Since(started)
		return prepared, fmt.Errorf("%w: Joern does not support any requested language", ErrUnsupported)
	}

	cpgPath := firstNonEmpty(r.CPGPath, opts.PrebuiltPath, src.PrebuiltPath)
	prebuilt := cpgPath != ""
	if prebuilt {
		if err := validateJoernCPG(cpgPath); err != nil {
			for _, language := range supported {
				prepared.Unsupported[language] = "prebuilt_cpg_invalid: " + err.Error()
			}
			prepared.Duration = time.Since(started)
			return prepared, fmt.Errorf("joern prebuilt CPG: %w", err)
		}
	} else {
		workDir := engineWorkDir(r.WorkDir, opts.WorkDir)
		if workDir == "" {
			return prepared, errors.New("joern: work directory is required to create a CPG")
		}
		sourceRoot := strings.TrimSpace(src.Root)
		if sourceRoot == "" {
			return prepared, fmt.Errorf("%w: source root is required to parse a Joern CPG", ErrInvalidSource)
		}
		var err error
		cpgPath, err = safeJoin(workDir, "engines", "joern", "cpg.bin")
		if err != nil {
			return prepared, err
		}
		if err := ensureDir(filepath.Dir(cpgPath)); err != nil {
			return prepared, err
		}
		_ = os.Remove(cpgPath)
		timeout := r.Timeout
		if timeout <= 0 {
			timeout = opts.Timeout
		}
		parse := r.toolCommand(r.parseBinName())
		_, stderr, parseErr := executeCommand(
			ctx, r.execFn, parse.Name,
			r.commandArgs(parse, sourceRoot, "--output", cpgPath), workDir, timeout)
		if parseErr != nil {
			classified := classifyExecError(ctx, parseErr, stderr)
			reason := "joern_parse_failed: " + classified.Error()
			for _, language := range supported {
				prepared.Unsupported[language] = reason
			}
			prepared.Duration = time.Since(started)
			return prepared, fmt.Errorf("joern parse: %w", classified)
		}
		if err := validateJoernCPG(cpgPath); err != nil {
			reason := "joern_parse_failed: " + err.Error()
			for _, language := range supported {
				prepared.Unsupported[language] = reason
			}
			prepared.Duration = time.Since(started)
			return prepared, fmt.Errorf("joern parse: %w", err)
		}
	}

	buildMode := "parse"
	if prebuilt {
		buildMode = "prebuilt"
	}
	for _, language := range supported {
		prepared.Paths[language] = cpgPath
		prepared.BuildModes[language] = buildMode
		prepared.Languages = append(prepared.Languages, language)
		r.rememberCPG(language, cpgPath)
	}
	if prebuilt {
		prepared.Warnings = append(prepared.Warnings, "using operator-supplied Joern CPG; language coverage depends on the CPG")
	}
	prepared.Duration = time.Since(started)
	return prepared, nil
}

func validateJoernCPG(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat CPG: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("CPG path is a directory: %s", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("CPG file is empty: %s", path)
	}
	return nil
}

func (r *JoernRunner) rememberCPG(language, path string) {
	language = normalizeIntentLanguage(language)
	if language == "" || strings.TrimSpace(path) == "" {
		return
	}
	r.mu.Lock()
	if r.cpgs == nil {
		r.cpgs = make(map[string]string)
	}
	r.cpgs[language] = path
	r.mu.Unlock()
}

func (r *JoernRunner) cachedCPG(language string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cpgs[normalizeIntentLanguage(language)]
}

// Validate enforces the template-only CPGQL policy. Without a sandbox command,
// the query must use a registered template ID, must be marked as template
// generated, and must not reference process/file/import facilities outside
// string literals. Character checks always apply.
func (r *JoernRunner) Validate(ctx context.Context, q QuerySpec) error {
	if normalizeEngineName(q.Engine) != "" && normalizeEngineName(q.Engine) != EngineJoern {
		return fmt.Errorf("%w: Joern runner received an engine %q query", ErrInvalidQuery, q.Engine)
	}
	if len(q.QueryText) > maxJoernQuery {
		return fmt.Errorf("%w: Joern query exceeds %d bytes", ErrInvalidQuery, maxJoernQuery)
	}
	if err := validateJoernCharacters(q.QueryText); err != nil {
		return err
	}
	if strings.TrimSpace(r.SandboxCmd) == "" {
		if !isKnownTemplate(EngineJoern, q.Template) {
			return fmt.Errorf("%w: free-form CPGQL is disabled; use a registered Joern template or configure a sandbox", ErrForbiddenQuery)
		}
		generatedBy := strings.ToLower(strings.TrimSpace(q.GeneratedBy))
		if generatedBy != "" && generatedBy != "template" {
			return fmt.Errorf("%w: Joern query generation mode %q is not allowed without a sandbox", ErrForbiddenQuery, generatedBy)
		}
		if err := validateJoernQueryText(q.QueryText); err != nil {
			return err
		}
	}
	return nil
}

func validateJoernCharacters(query string) error {
	if strings.TrimSpace(query) == "" {
		return fmt.Errorf("%w: Joern query text is empty", ErrInvalidQuery)
	}
	for _, r := range query {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: Joern query contains a control character", ErrForbiddenQuery)
		}
	}
	return nil
}

var joernForbiddenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bimport\b`),
	regexp.MustCompile(`(?i)\bsys\s*\.\s*process\b`),
	regexp.MustCompile(`(?i)\bjava\s*\.\s*io\b`),
	regexp.MustCompile(`(?i)\bjava\s*\.\s*net\b`),
	regexp.MustCompile(`(?i)\bProcessBuilder\b`),
	regexp.MustCompile(`(?i)\bRuntime\b`),
	regexp.MustCompile(`(?i)\bFiles\s*\.\s*write\b`),
	regexp.MustCompile(`(?i)\bscala\s*\.\s*sys\b`),
}

// validateJoernQueryText scans code outside ordinary Scala string literals.
// The generated templates embed method names and regexes inside strings; those
// are data, not facilities, so they must not trigger the forbidden-token check.
func validateJoernQueryText(query string) error {
	if strings.Contains(query, `"""`) {
		return fmt.Errorf("%w: triple-quoted CPGQL strings are not allowed", ErrForbiddenQuery)
	}
	code, err := stripScalaStrings(query)
	if err != nil {
		return err
	}
	for _, pattern := range joernForbiddenPatterns {
		if pattern.MatchString(code) {
			return fmt.Errorf("%w: CPGQL contains forbidden token %q", ErrForbiddenQuery, pattern.String())
		}
	}
	return nil
}

func stripScalaStrings(query string) (string, error) {
	var out strings.Builder
	inString := false
	escaped := false
	word := ""
	for _, r := range query {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch r {
			case '\\':
				escaped = true
			case '"':
				inString = false
				word = ""
			}
			continue
		}
		if r == '"' {
			if word == "s" || word == "f" || word == "raw" {
				return "", fmt.Errorf("%w: string interpolation is not allowed in CPGQL", ErrForbiddenQuery)
			}
			inString = true
			word = ""
			out.WriteString(`""`)
			continue
		}
		if isScalaIdentifierRune(r) {
			word += string(r)
		} else {
			word = ""
		}
		out.WriteRune(r)
	}
	if inString {
		return "", fmt.Errorf("%w: unterminated CPGQL string literal", ErrInvalidQuery)
	}
	return out.String(), nil
}

func isScalaIdentifierRune(r rune) bool {
	return r == '_' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// Run executes the fixed wrapper containing the query and parses the marked
// JSON document. Joern logs before the marker are ignored.
func (r *JoernRunner) Run(ctx context.Context, q QuerySpec) ([]EngineFinding, error) {
	if normalizeEngineName(q.Engine) != "" && normalizeEngineName(q.Engine) != EngineJoern {
		return nil, fmt.Errorf("%w: Joern runner received an engine %q query", ErrInvalidQuery, q.Engine)
	}
	if err := r.Validate(ctx, q); err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.WorkDir) == "" {
		return nil, fmt.Errorf("%w: Joern work directory is required", ErrInvalidQuery)
	}
	cpgPath := firstNonEmpty(q.ArtifactPath, r.cachedCPG(q.Language), r.CPGPath)
	if cpgPath == "" {
		return nil, fmt.Errorf("%w: no Joern CPG for language %q", ErrMissingArtifact, q.Language)
	}
	if err := validateJoernCPG(cpgPath); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingArtifact, err)
	}

	queryID := safeEngineID(firstNonEmpty(q.ID, q.IntentID, q.Template, "query"))
	queryDir, err := safeJoin(r.WorkDir, "queries", "joern", queryID)
	if err != nil {
		return nil, err
	}
	if err := ensureDir(queryDir); err != nil {
		return nil, err
	}
	wrapperPath := filepath.Join(queryDir, "query.sc")
	wrapper := joernWrapperPrefix + scalaString(cpgPath) + joernWrapperMiddle +
		strings.TrimSpace(q.QueryText) + "\n\n" + joernWrapperSuffix
	if err := os.WriteFile(wrapperPath, []byte(wrapper), 0o600); err != nil {
		return nil, fmt.Errorf("write Joern wrapper: %w", err)
	}

	command := r.toolCommand(r.binName())
	name := command.Name
	args := r.commandArgs(command, "--script", wrapperPath)
	if sandbox := strings.TrimSpace(r.SandboxCmd); sandbox != "" {
		fields := strings.Fields(sandbox)
		if len(fields) == 0 {
			return nil, fmt.Errorf("%w: empty Joern sandbox command", ErrInvalidQuery)
		}
		name = fields[0]
		args = append([]string{}, fields[1:]...)
		args = append(args, command.Name)
		args = append(args, command.Prefix...)
		args = append(args, "--script", wrapperPath)
	}
	stdout, stderr, runErr := executeCommand(ctx, r.execFn, name, args, r.WorkDir, r.Timeout)
	if runErr != nil {
		return nil, fmt.Errorf("joern query: %w", classifyExecError(ctx, runErr, stderr))
	}
	rows, err := parseJoernOutput(stdout, stderr)
	if err != nil {
		return nil, err
	}
	if len(rows) > maxJoernFindings {
		rows = rows[:maxJoernFindings]
	}
	findings := make([]EngineFinding, 0, len(rows))
	for index, row := range rows {
		finding, ok := joernFinding(row, q, index)
		if ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

const joernWrapperPrefix = `// ARTEX generated Joern wrapper -- do not edit.
import io.shiftleft.codepropertygraph.cpgloading.CpgLoader
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

implicit val cpg = CpgLoader.load(`

const joernWrapperMiddle = `)

`

const joernWrapperSuffix = "println(\"" + JoernJSONMarker + "\" + ujson.write(artexRows))\n"

type joernRow struct {
	File       string            `json:"file"`
	Line       int               `json:"line"`
	Column     int               `json:"column"`
	Symbol     string            `json:"symbol"`
	CWE        string            `json:"cwe"`
	Message    string            `json:"message"`
	Severity   string            `json:"severity"`
	Confidence float64           `json:"confidence"`
	Trace      []joernTracePoint `json:"trace"`
}

type joernTracePoint struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Symbol string `json:"symbol"`
}

func parseJoernOutput(stdout, stderr string) ([]joernRow, error) {
	payload := ""
	found := false
	if index := strings.Index(stdout, JoernJSONMarker); index >= 0 {
		payload = stdout[index+len(JoernJSONMarker):]
		found = true
	} else if index := strings.Index(stderr, JoernJSONMarker); index >= 0 {
		payload = stderr[index+len(JoernJSONMarker):]
		found = true
	}
	if !found {
		if strings.TrimSpace(stdout) == "" && strings.TrimSpace(stderr) == "" {
			return []joernRow{}, nil
		}
		return nil, fmt.Errorf("joern output contains no %s marker", JoernJSONMarker)
	}
	return decodeJoernRows(payload)
}

func decodeJoernRows(payload string) ([]joernRow, error) {
	decoder := json.NewDecoder(strings.NewReader(payload))
	var first json.RawMessage
	if err := decoder.Decode(&first); err != nil {
		if strings.TrimSpace(payload) == "" {
			return []joernRow{}, nil
		}
		return nil, fmt.Errorf("parse joern JSON: %w", err)
	}
	trimmed := bytes.TrimSpace(first)
	if len(trimmed) == 0 {
		return []joernRow{}, nil
	}
	switch trimmed[0] {
	case '[':
		var rows []joernRow
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return nil, fmt.Errorf("parse joern JSON array: %w", err)
		}
		return rows, nil
	case '{':
		var row joernRow
		if err := json.Unmarshal(trimmed, &row); err != nil {
			return nil, fmt.Errorf("parse joern JSON object: %w", err)
		}
		rows := []joernRow{row}
		for {
			var next json.RawMessage
			if err := decoder.Decode(&next); err != nil {
				break
			}
			next = bytes.TrimSpace(next)
			if len(next) == 0 || next[0] != '{' {
				break
			}
			var extra joernRow
			if err := json.Unmarshal(next, &extra); err != nil {
				break
			}
			rows = append(rows, extra)
		}
		return rows, nil
	default:
		return nil, fmt.Errorf("joern JSON must be an array or object")
	}
}

func joernFinding(row joernRow, q QuerySpec, index int) (EngineFinding, bool) {
	if strings.TrimSpace(row.File) == "" &&
		strings.TrimSpace(row.Symbol) == "" &&
		strings.TrimSpace(row.Message) == "" &&
		len(row.Trace) == 0 {
		return EngineFinding{}, false
	}

	location := joernCodeLocation(row.File, row.Line, row.Symbol)
	trace := make([]audit.TraceStep, 0, len(row.Trace))
	locations := make([]audit.CodeLocation, 0, len(row.Trace))
	for _, point := range row.Trace {
		stepLocation := joernCodeLocation(point.File, point.Line, point.Symbol)
		if stepLocation.Path == "" && stepLocation.Line == 0 && stepLocation.Symbol == "" {
			continue
		}
		trace = append(trace, audit.TraceStep{
			Path:   stepLocation.Path,
			Line:   stepLocation.Line,
			Symbol: stepLocation.Symbol,
		})
		locations = append(locations, stepLocation)
	}
	if len(location.Path) == 0 && location.Line == 0 && location.Symbol == "" && len(locations) > 0 {
		location = locations[len(locations)-1]
	}

	var source *audit.CodeLocation
	var sink *audit.CodeLocation
	if q.QueryKind == QueryKindTaint && len(locations) > 0 {
		sourceCopy := locations[0]
		sinkCopy := locations[len(locations)-1]
		if rowSymbol := strings.TrimSpace(row.Symbol); rowSymbol != "" {
			sinkCopy.Symbol = rowSymbol
		}
		source = &sourceCopy
		sink = &sinkCopy
	} else if location.Path != "" || location.Line > 0 || location.Symbol != "" {
		sinkCopy := location
		sink = &sinkCopy
	}

	confidence := row.Confidence
	if math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence <= 0 {
		confidence = 0.5
		if q.QueryKind == QueryKindTaint || len(trace) > 0 {
			confidence = 0.65
		}
	}
	if confidence > 1 {
		confidence = 1
	}
	cwe := normalizeCWEID(row.CWE)
	if cwe == "" {
		cwe = normalizeCWEID(paramString(q.Params, "cwe"))
	}
	severity := strings.ToLower(strings.TrimSpace(row.Severity))
	if severity == "" {
		severity = audit.SeverityMedium
	}
	message := strings.TrimSpace(row.Message)
	if message == "" {
		message = "Joern " + q.QueryKind + " result"
	}

	return EngineFinding{
		Engine:     EngineJoern,
		QueryID:    q.ID,
		CWE:        cwe,
		Language:   q.Language,
		Message:    message,
		Severity:   severity,
		Location:   location,
		Source:     source,
		Sink:       sink,
		Trace:      trace,
		Confidence: confidence,
		RawRef:     fmt.Sprintf("joern:%s:%d", q.ID, index),
		Payload: map[string]any{
			"result": jsonMap(row),
		},
	}, true
}

func joernCodeLocation(file string, line int, symbol string) audit.CodeLocation {
	return audit.CodeLocation{
		Path:   audit.NormalizeCodePath(file),
		Line:   line,
		Symbol: strings.TrimSpace(symbol),
	}
}
