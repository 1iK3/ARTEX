package engines

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/Autumn-27/artex/audit"
)

// Templates in this file are code assets generated from registry symbols. The
// CodeQL Java and Joern Java template families are exercised by real-engine
// integration tests against CodeQL 2.25.5 and Joern 4.0.535. Other language
// templates use the same engine APIs but have not been exercised against a
// pinned frontend/pack; unsupported engine/language/kind combinations are
// reported as capability gaps rather than guessed at. The Joern v2 templates
// model sources and sinks only; sanitizers and path scope are carried in
// QuerySpec.Params but not yet applied in CPGQL.

// Template identifiers. Each identifier encodes engine, template language, and
// query kind so a QuerySpec is self-describing.
const (
	TemplateCodeQLJavaTaint  = "codeql/java/taint-v2"
	TemplateCodeQLJavaSink   = "codeql/java/sink-v2"
	TemplateCodeGraphExplore = "codegraph/explore-v1"
)

// CodeQL Python, JavaScript, and TypeScript templates are intentionally not
// registered. The local CodeQL installation has only the Java library pack, and
// pack downloads are incompatible with CLI 2.25.5's manifest parser; generating
// unverified QL for those languages would violate the template policy. Render
// reports ErrUnsupported so the manager records an explicit capability gap.

const (
	maxTemplateSymbols      = 64
	maxCodeGraphPatterns    = 24
	maxCodeGraphPatternSize = 96
)

type templateInput struct {
	Intent   DetectionIntent
	Params   map[string]any
	SpecID   string
	Template string
}

type templateSpec struct {
	ID       string
	Engine   string
	Language string
	Kind     string
	Format   string
	render   func(templateInput) (string, error)
}

var (
	templatesByKey = make(map[string]templateSpec)
	templatesByID  = make(map[string]templateSpec)
)

func init() {
	addTemplate(templateSpec{
		ID: TemplateCodeQLJavaTaint, Engine: EngineCodeQL, Language: "java",
		Kind: QueryKindTaint, Format: FormatSARIF, render: renderCodeQLJavaTaint,
	})
	addTemplate(templateSpec{
		ID: TemplateCodeQLJavaSink, Engine: EngineCodeQL, Language: "java",
		Kind: QueryKindSink, Format: FormatSARIF, render: renderCodeQLJavaSink,
	})
	for _, language := range []string{"java", "python", "javascript", "go", "c", "cpp"} {
		for _, kind := range []string{QueryKindTaint, QueryKindSink} {
			kindName := "sink"
			render := renderJoernSink
			if kind == QueryKindTaint {
				kindName = "taint-reachable"
				render = renderJoernTaint
			}
			addTemplate(templateSpec{
				ID:       fmt.Sprintf("joern/%s/%s-v2", language, kindName),
				Engine:   EngineJoern,
				Language: language,
				Kind:     kind,
				Format:   FormatJoernJSON,
				render:   render,
			})
		}
	}
	addTemplate(templateSpec{
		ID: TemplateCodeGraphExplore, Engine: EngineCodeGraph, Language: "*",
		Kind: "*", Format: FormatCodeGraphText, render: renderCodeGraphQuery,
	})
}

func addTemplate(spec templateSpec) {
	key := templateKey(spec.Engine, spec.Language, spec.Kind)
	templatesByKey[key] = spec
	templatesByID[spec.Engine+"\x00"+spec.ID] = spec
}

func templateKey(engine, language, kind string) string {
	return engine + "\x00" + language + "\x00" + kind
}

// TemplateFor returns the registered template ID for an engine/language/query
// kind combination. It is useful to callers that need to decide whether a
// query can be generated without constructing a full intent.
func TemplateFor(engine, language, kind string) (string, bool) {
	if !validQueryKind(kind) {
		return "", false
	}
	spec, err := lookupTemplate(engine, language, kind)
	if err != nil {
		return "", false
	}
	return spec.ID, true
}

func lookupTemplate(engine, language, kind string) (templateSpec, error) {
	normalizedEngine := normalizeEngineName(engine)
	if normalizedEngine == "" {
		return templateSpec{}, fmt.Errorf("%w: unknown engine %q", ErrUnsupported, engine)
	}
	if normalizedEngine == EngineCodeGraph {
		return templatesByKey[templateKey(EngineCodeGraph, "*", "*")], nil
	}
	languageKey := templateLanguageKey(normalizedEngine, language)
	spec, ok := templatesByKey[templateKey(normalizedEngine, languageKey, kind)]
	if !ok {
		return templateSpec{}, fmt.Errorf(
			"%w: no %s template for language %q and query kind %q",
			ErrUnsupported, normalizedEngine, language, kind)
	}
	return spec, nil
}

func templateLanguageKey(engine, language string) string {
	canonical := audit.NormalizeLanguage(language)
	if canonical == "" {
		canonical = strings.ToLower(strings.TrimSpace(language))
	}
	switch engine {
	case EngineCodeQL, EngineJoern:
		if canonical == audit.TypeScript {
			return audit.JavaScript
		}
	}
	return canonical
}

func isKnownTemplate(engine, templateID string) bool {
	normalizedEngine := normalizeEngineName(engine)
	if normalizedEngine == "" || strings.TrimSpace(templateID) == "" {
		return false
	}
	_, ok := templatesByID[normalizedEngine+"\x00"+templateID]
	return ok
}

// ---------------------------------------------------------------------------
// CodeQL templates (Java verified with CodeQL 2.25.5)
// ---------------------------------------------------------------------------

const codeQLJavaTaintSource = `/**
 * @name Artex generated Java taint query
 * @kind path-problem
 * @problem.severity warning
 * @id artex/generated/taint/{{.SpecID}}
 */
import java
import semmle.code.java.dataflow.TaintTracking

module ArtexConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(MethodCall call |
      call.getMethod().getName() in {{.SourceList}} and
      src.asExpr() = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().getName() in {{.SinkList}} and
      sink.asExpr() = call.getAnArgument()
    )
  }
{{.BarrierPredicate}}
}

module ArtexFlow = TaintTracking::Global<ArtexConfig>;
import ArtexFlow::PathGraph

from ArtexFlow::PathNode source, ArtexFlow::PathNode sink
where ArtexFlow::flowPath(source, sink)
select sink.getNode(), source, sink, {{.Message}}
`

const codeQLJavaSinkSource = `/**
 * @name Artex generated Java sink query
 * @kind problem
 * @problem.severity warning
 * @id artex/generated/sink/{{.SpecID}}
 */
import java

from MethodCall call
where call.getMethod().getName() in {{.SinkList}}
select call, {{.Message}}
`

var (
	codeQLJavaTaintTmpl = template.Must(template.New("codeql-java-taint").Parse(codeQLJavaTaintSource))
	codeQLJavaSinkTmpl  = template.Must(template.New("codeql-java-sink").Parse(codeQLJavaSinkSource))
)

type codeQLTemplateData struct {
	SpecID           string
	SourceList       string
	SinkList         string
	BarrierPredicate string
	Message          string
}

func renderCodeQLJavaTaint(in templateInput) (string, error) {
	sources := methodSymbols(in.Intent.Sources)
	sinks := methodSymbols(in.Intent.Sinks)
	if len(sinks) == 0 {
		return "", fmt.Errorf("%w: CodeQL Java taint template needs at least one method-call sink", ErrInvalidQuery)
	}
	if len(sources) == 0 {
		return "", fmt.Errorf("%w: CodeQL Java taint template needs at least one method-call source", ErrInvalidQuery)
	}
	data := codeQLTemplateData{
		SpecID:           in.SpecID,
		SourceList:       qlStringList(sources),
		SinkList:         qlStringList(sinks),
		BarrierPredicate: codeQLBarrierPredicate(methodSymbols(in.Intent.Sanitizers)),
		Message:          qlString(templateMessage(in.Intent)),
	}
	return executeTextTemplate(codeQLJavaTaintTmpl, data)
}

func renderCodeQLJavaSink(in templateInput) (string, error) {
	sinks := methodSymbols(in.Intent.Sinks)
	if len(sinks) == 0 {
		return "", fmt.Errorf("%w: CodeQL Java sink template needs at least one method-call sink", ErrInvalidQuery)
	}
	data := codeQLTemplateData{
		SpecID:   in.SpecID,
		SinkList: qlStringList(sinks),
		Message:  qlString(templateMessage(in.Intent)),
	}
	return executeTextTemplate(codeQLJavaSinkTmpl, data)
}

func executeTextTemplate(tmpl *template.Template, data any) (string, error) {
	var out strings.Builder
	if err := tmpl.Execute(&out, data); err != nil {
		return "", fmt.Errorf("render query template: %w", err)
	}
	return out.String(), nil
}

func codeQLBarrierPredicate(sanitizers []string) string {
	if len(sanitizers) == 0 {
		return ""
	}
	return "\n  predicate isBarrier(DataFlow::Node node) {\n" +
		"    exists(MethodCall call |\n" +
		"      call.getMethod().getName() in " + qlStringList(sanitizers) + " and\n" +
		"      (node.asExpr() = call.getAnArgument() or node.asExpr() = call)\n" +
		"    )\n" +
		"  }\n"
}

func templateMessage(intent DetectionIntent) string {
	listed := summarizeSymbols(methodSymbols(intent.Sinks), 8)
	message := fmt.Sprintf("Artex %s sink matches", intent.CWE)
	if intent.QueryKind == QueryKindTaint {
		message = fmt.Sprintf("Artex %s taint reaches sink", intent.CWE)
	}
	if listed != "" {
		message += " (" + listed + ")"
	}
	return message
}

func summarizeSymbols(symbols []string, limit int) string {
	if len(symbols) == 0 {
		return ""
	}
	if limit > 0 && len(symbols) > limit {
		symbols = symbols[:limit]
	}
	return strings.Join(symbols, ", ")
}

// ---------------------------------------------------------------------------
// Joern templates (Java verified with Joern 4.0.535)
// ---------------------------------------------------------------------------

const joernTaintSource = `// Artex generated CPGQL taint query ({{.Template}}, template v2, verified on Java with Joern 4.0.535).
// The fixed wrapper loads the CPG and serializes artexRows as marker-prefixed JSON.
val artexSources = cpg.call.filter(c => c.name.matches({{.SourceRegex}})).l
val artexSinks = cpg.call.filter(c => c.name.matches({{.SinkRegex}})).l
val artexRows: List[ujson.Value] = artexSinks.flatMap { sinkCall =>
  Iterator.single(sinkCall).reachableByFlows(artexSources).map { path =>
    val steps = path.elements
    val artexTrace = steps.map { step =>
      ujson.Obj(
        "file" -> ujson.Str(step.file.name.headOption.getOrElse("")),
        "line" -> ujson.Num(step.lineNumber.headOption.getOrElse(0).toDouble),
        "symbol" -> ujson.Str(step.code)
      )
    }
    ujson.Obj(
      "file" -> ujson.Str(sinkCall.file.name.headOption.getOrElse("")),
      "line" -> ujson.Num(sinkCall.lineNumber.headOption.getOrElse(0).toDouble),
      "column" -> ujson.Num(sinkCall.columnNumber.headOption.getOrElse(0).toDouble),
      "symbol" -> ujson.Str(sinkCall.name),
      "cwe" -> ujson.Str({{.CWE}}),
      "message" -> ujson.Str({{.Message}}),
      "confidence" -> ujson.Num(0.65),
      "trace" -> ujson.Arr.from(artexTrace)
    )
  }
}.toList
`

const joernSinkSource = `// Artex generated CPGQL sink query ({{.Template}}, template v2, verified on Java with Joern 4.0.535).
// The fixed wrapper loads the CPG and serializes artexRows as marker-prefixed JSON.
val artexSinks = cpg.call.filter(c => c.name.matches({{.SinkRegex}})).l
val artexRows: List[ujson.Value] = artexSinks.map { call =>
  ujson.Obj(
    "file" -> ujson.Str(call.file.name.headOption.getOrElse("")),
    "line" -> ujson.Num(call.lineNumber.headOption.getOrElse(0).toDouble),
    "column" -> ujson.Num(call.columnNumber.headOption.getOrElse(0).toDouble),
    "symbol" -> ujson.Str(call.name),
    "cwe" -> ujson.Str({{.CWE}}),
    "message" -> ujson.Str({{.Message}}),
    "confidence" -> ujson.Num(0.5),
    "trace" -> ujson.Arr.from(List.empty[ujson.Value])
  )
}
`

var (
	joernTaintTmpl = template.Must(template.New("joern-taint").Parse(joernTaintSource))
	joernSinkTmpl  = template.Must(template.New("joern-sink").Parse(joernSinkSource))
)

type joernTemplateData struct {
	Template    string
	SourceRegex string
	SinkRegex   string
	CWE         string
	Message     string
}

func renderJoernTaint(in templateInput) (string, error) {
	sourceRegex, err := joernNameRegex(in.Intent.Sources)
	if err != nil {
		return "", fmt.Errorf("%w: Joern taint template has no usable source pattern", ErrInvalidQuery)
	}
	sinkRegex, err := joernNameRegex(in.Intent.Sinks)
	if err != nil {
		return "", fmt.Errorf("%w: Joern taint template has no usable sink pattern", ErrInvalidQuery)
	}
	data := joernTemplateData{
		Template:    in.Template,
		SourceRegex: scalaString(sourceRegex),
		SinkRegex:   scalaString(sinkRegex),
		CWE:         scalaString(in.Intent.CWE),
		Message:     scalaString(templateMessage(in.Intent)),
	}
	return executeTextTemplate(joernTaintTmpl, data)
}

func renderJoernSink(in templateInput) (string, error) {
	sinkRegex, err := joernNameRegex(in.Intent.Sinks)
	if err != nil {
		return "", fmt.Errorf("%w: Joern sink template has no usable sink pattern", ErrInvalidQuery)
	}
	data := joernTemplateData{
		Template:  in.Template,
		SinkRegex: scalaString(sinkRegex),
		CWE:       scalaString(in.Intent.CWE),
		Message:   scalaString(templateMessage(in.Intent)),
	}
	return executeTextTemplate(joernSinkTmpl, data)
}

func joernNameRegex(patterns []Pattern) (string, error) {
	alternatives := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		var alternative string
		switch normalizeMatch(pattern.Match) {
		case MatchMethodCall:
			symbol, ok := shortPatternSymbol(pattern.Pattern)
			if !ok {
				continue
			}
			alternative = regexp.QuoteMeta(symbol)
		case MatchRegex:
			raw := strings.TrimSpace(pattern.Pattern)
			if !safeJoernRegex(raw) {
				continue
			}
			alternative = "(?:" + raw + ")"
		default:
			continue
		}
		if _, exists := seen[alternative]; exists {
			continue
		}
		seen[alternative] = struct{}{}
		alternatives = append(alternatives, alternative)
		if len(alternatives) >= maxTemplateSymbols {
			break
		}
	}
	if len(alternatives) == 0 {
		return "", ErrInvalidQuery
	}
	sort.Strings(alternatives)
	return "(?i).*(?:" + strings.Join(alternatives, "|") + ").*", nil
}

var safeJoernRegexPattern = regexp.MustCompile(`^[A-Za-z0-9_ \\.\^$\|?*+()\[\]{}@:,-]+$`)

func safeJoernRegex(raw string) bool {
	if raw == "" || len(raw) > maxFrameworkPatternLen {
		return false
	}
	if strings.ContainsAny(raw, "\"`\n\r\t") {
		return false
	}
	return safeJoernRegexPattern.MatchString(raw)
}

// ---------------------------------------------------------------------------
// CodeGraph template
// ---------------------------------------------------------------------------

func renderCodeGraphQuery(in templateInput) (string, error) {
	intent := in.Intent
	var out strings.Builder
	title := strings.TrimSpace(intent.Title)
	if title == "" {
		title = intent.CWE
	}
	fmt.Fprintf(&out, "Trace source to sink for %s in %s: %s.\n",
		intent.CWE, intent.Language, oneLineText(title))
	sinks := codeGraphPatterns(intent.Sinks)
	sources := codeGraphPatterns(intent.Sources)
	sanitizers := codeGraphPatterns(intent.Sanitizers)
	if len(sinks) > 0 {
		fmt.Fprintf(&out, "Sinks: %s.\n", strings.Join(sinks, ", "))
	}
	if len(sources) > 0 {
		fmt.Fprintf(&out, "Sources: %s.\n", strings.Join(sources, ", "))
	}
	if len(sanitizers) > 0 {
		fmt.Fprintf(&out, "Sanitizers to check: %s.\n", strings.Join(sanitizers, ", "))
	}
	if len(intent.Scope.Paths) > 0 {
		fmt.Fprintf(&out, "Scope paths: %s.\n", oneLineText(strings.Join(intent.Scope.Paths, ", ")))
	}
	if len(intent.Scope.Modules) > 0 {
		fmt.Fprintf(&out, "Modules: %s.\n", oneLineText(strings.Join(intent.Scope.Modules, ", ")))
	}
	fmt.Fprintf(&out, "Use codegraph_explore to trace source to sink and return exact file, line, and sink API evidence for %s.\n", intent.CWE)
	return out.String(), nil
}

func codeGraphPatterns(patterns []Pattern) []string {
	out := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		text := ""
		if symbol, ok := shortPatternSymbol(pattern.Pattern); ok {
			text = symbol
		} else {
			text = oneLineText(pattern.Pattern)
		}
		if text == "" {
			continue
		}
		if len(text) > maxCodeGraphPatternSize {
			text = text[:maxCodeGraphPatternSize]
		}
		if _, exists := seen[text]; exists {
			continue
		}
		seen[text] = struct{}{}
		out = append(out, text)
		if len(out) >= maxCodeGraphPatterns {
			break
		}
	}
	return out
}

func oneLineText(value string) string {
	value = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		default:
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}
	}, value)
	return strings.Join(strings.Fields(value), " ")
}

// ---------------------------------------------------------------------------
// Escaping and symbol helpers
// ---------------------------------------------------------------------------

func methodSymbols(patterns []Pattern) []string {
	out := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		if normalizeMatch(pattern.Match) != MatchMethodCall {
			continue
		}
		symbol, ok := shortPatternSymbol(pattern.Pattern)
		if !ok {
			continue
		}
		if _, exists := seen[symbol]; exists {
			continue
		}
		seen[symbol] = struct{}{}
		out = append(out, symbol)
	}
	sort.Strings(out)
	if len(out) > maxTemplateSymbols {
		out = out[:maxTemplateSymbols]
	}
	return out
}

func qlStringList(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = qlString(value)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// qlString escapes a value for a QL string literal. Symbols are already
// restricted to identifiers, but messages and future pattern kinds may contain
// arbitrary text, so escaping is centralized here.
func qlString(value string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			out.WriteString(`\\`)
		case '"':
			out.WriteString(`\"`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			switch {
			case r >= 0x20 && r <= 0x7e:
				out.WriteRune(r)
			case r > 0xffff:
				// Java/QL escape non-BMP runes as a UTF-16 surrogate pair.
				value := r - 0x10000
				high := 0xd800 + (value >> 10)
				low := 0xdc00 + (value & 0x3ff)
				fmt.Fprintf(&out, `\u%04x\u%04x`, high, low)
			default:
				fmt.Fprintf(&out, `\u%04x`, r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

// scalaString escapes a value for a regular Scala string literal (no
// interpolation prefix is used, so ${...} remains data).
func scalaString(value string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			out.WriteString(`\\`)
		case '"':
			out.WriteString(`\"`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}
