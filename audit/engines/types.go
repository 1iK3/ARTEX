// Package engines implements the multi-engine detection layer described in
// section 7 of the code-audit fusion design. It turns registry data and an
// audit plan into engine-independent detection intents, renders those intents
// into CodeQL, Joern, or CodeGraph queries, and normalizes per-engine findings
// into correlated candidates.
//
// The package is deliberately side-effect free until an adapter is asked to
// Prepare or Run. It does not execute repository build commands: CodeQL uses
// build-mode=none or an operator-supplied prebuilt database, and Joern only
// parses source into a CPG.
package engines

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Autumn-27/artex/audit"
)

// Engine names understood by this package. They alias the audit package
// constants so callers can use either import.
const (
	EngineCodeGraph = audit.EngineCodeGraph
	EngineCodeQL    = audit.EngineCodeQL
	EngineJoern     = audit.EngineJoern
)

// DetectionIntent origins.
const (
	OriginSinkRule         = "sink_rule"
	OriginUserGoal         = "user_goal"
	OriginPhaseRequirement = "phase_requirement"
	OriginEngineProbe      = "engine_probe"
	OriginLLM              = "llm"
)

// Query kinds carried by DetectionIntent and QuerySpec.
const (
	QueryKindSink            = "sink"
	QueryKindTaint           = "taint"
	QueryKindControlFlow     = "control_flow"
	QueryKindCallGraph       = "callgraph"
	QueryKindDataflow        = "dataflow"
	QueryKindLogic           = "logic"
	QueryKindErrorContract   = "error_contract"
	QueryKindStateTransition = "state_transition"
	QueryKindInvariant       = "invariant"
)

// Pattern match modes.
const (
	MatchMethodCall = "method_call"
	MatchType       = "type"
	MatchRegex      = "regex"
)

// Expected engine result formats.
const (
	FormatSARIF         = "sarif"
	FormatJoernJSON     = "joern-json"
	FormatCodeGraphText = "codegraph-text"
)

// Job statuses recorded by the manager.
const (
	JobStatusDone    = "done"
	JobStatusFailed  = "failed"
	JobStatusSkipped = "skipped"
)

// TemplateVersion is the version stamped into every generated query. Templates
// are code assets: changing their text in a way that changes results requires a
// new version.
const TemplateVersion = "v2"

// DetectionPriorityBase values. P0 CWEs sort above non-P0 CWEs.
const (
	priorityP0Base    = 1000
	priorityOtherBase = 100
)

// Sentinel errors used for programmatic classification. Adapter errors wrap
// these so callers (and the manager) can distinguish a capability gap from a
// transient execution failure.
var (
	// ErrUnavailable means the engine binary or service is not available.
	ErrUnavailable = errors.New("engine unavailable")
	// ErrUnsupported means no template or adapter supports the requested
	// engine/language/query-kind combination.
	ErrUnsupported = errors.New("unsupported engine combination")
	// ErrUnsupportedBuildRequired means the engine would need to build the
	// target (for example a CodeQL database for C/C++ or Go) and no prebuilt
	// artifact was supplied.
	ErrUnsupportedBuildRequired = errors.New("unsupported_build_required")
	// ErrCapability means a required engine component (query pack, CPG, ...)
	// is missing or cannot be resolved.
	ErrCapability = errors.New("engine capability error")
	// ErrInvalidQuery means a QuerySpec is malformed before it reaches an
	// engine.
	ErrInvalidQuery = errors.New("invalid query")
	// ErrForbiddenQuery means a free-form Joern query was rejected because no
	// sandbox is configured or it contains forbidden tokens.
	ErrForbiddenQuery = errors.New("forbidden query")
	// ErrInvalidSource means the source reference lacks a usable snapshot.
	ErrInvalidSource = errors.New("invalid audit source")
	// ErrMissingArtifact means no database, CPG, or query artifact is
	// available for the requested language.
	ErrMissingArtifact = errors.New("missing engine artifact")
	// ErrTimeout means an engine command exceeded its configured timeout.
	ErrTimeout = errors.New("engine timeout")
)

// DetectionIntent is an engine-independent structured detection job. It is the
// output of deterministic intent recognition and the only input to query
// synthesis.
type DetectionIntent struct {
	ID               string         `json:"id"`
	Origin           string         `json:"origin"`
	Language         string         `json:"language"`
	CWE              string         `json:"cwe"`
	Title            string         `json:"title"`
	QueryKind        string         `json:"query_kind"`
	Sources          []Pattern      `json:"sources,omitempty"`
	Sinks            []Pattern      `json:"sinks,omitempty"`
	Sanitizers       []Pattern      `json:"sanitizers,omitempty"`
	Propagators      []Pattern      `json:"propagators,omitempty"`
	Scope            Scope          `json:"scope"`
	Constraints      Constraints    `json:"constraints"`
	PreferredEngines []string       `json:"preferred_engines,omitempty"`
	Priority         int            `json:"priority"`
	Provenance       map[string]any `json:"provenance,omitempty"`
}

// Pattern is one detection symbol. Match is method_call, type, or regex.
// Patterns sourced from the registry normally use the terminal dotted segment
// of an API symbol (for example executeQuery).
type Pattern struct {
	Name    string `json:"name,omitempty"`
	Pattern string `json:"pattern"`
	Match   string `json:"match"`
}

// Scope narrows an intent. Empty paths mean the whole snapshot.
type Scope struct {
	Paths   []string `json:"paths,omitempty"`
	Modules []string `json:"modules,omitempty"`
	Symbols []string `json:"symbols,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// Constraints are advisory execution constraints for an intent. Nil boolean
// pointers mean "unknown", not false.
type Constraints struct {
	Reachable    *bool  `json:"reachable,omitempty"`
	AuthRequired *bool  `json:"auth_required,omitempty"`
	MaxResults   int    `json:"max_results,omitempty"`
	SeverityMin  string `json:"severity_min,omitempty"`
}

// QuerySpec is the intermediate representation accepted by every engine
// adapter. QueryText is engine-specific but always generated from a registered
// template; adapters never receive arbitrary free-form text from an LLM.
type QuerySpec struct {
	ID              string         `json:"id"`
	IntentID        string         `json:"intent_id"`
	Engine          string         `json:"engine"`
	Language        string         `json:"language"`
	QueryKind       string         `json:"query_kind"`
	Template        string         `json:"template"`
	TemplateVersion string         `json:"template_version,omitempty"`
	EngineVersion   string         `json:"engine_version,omitempty"`
	Commit          string         `json:"commit,omitempty"`
	IRHash          string         `json:"ir_hash,omitempty"`
	QueryText       string         `json:"query_text"`
	QueryPath       string         `json:"query_path,omitempty"`
	ExpectedFormat  string         `json:"expected_format"`
	GeneratedBy     string         `json:"generated_by"`
	Params          map[string]any `json:"params,omitempty"`
	Provenance      map[string]any `json:"provenance,omitempty"`
	// ArtifactPath is a runtime-only pointer to the prepared database or CPG
	// for this query. It is populated by the manager and deliberately excluded
	// from the query cache key.
	ArtifactPath string `json:"artifact_path,omitempty"`
}

// EngineFinding is one structured engine result before cross-engine
// correlation. Location/Source/Sink/Trace reuse the audit evidence schema so
// adapters can feed the existing evidence pipeline without a second migration.
type EngineFinding struct {
	Engine     string              `json:"engine"`
	QueryID    string              `json:"query_id,omitempty"`
	CWE        string              `json:"cwe,omitempty"`
	Language   string              `json:"language,omitempty"`
	Message    string              `json:"message,omitempty"`
	Severity   string              `json:"severity,omitempty"`
	Location   audit.CodeLocation  `json:"location"`
	Source     *audit.CodeLocation `json:"source,omitempty"`
	Sink       *audit.CodeLocation `json:"sink,omitempty"`
	Trace      []audit.TraceStep   `json:"trace,omitempty"`
	Confidence float64             `json:"confidence"`
	RawRef     string              `json:"raw_ref,omitempty"`
	Payload    map[string]any      `json:"payload,omitempty"`
}

// Capability describes what an engine can do in this environment. Languages is
// the set of audit language identifiers the engine can analyze; an empty list
// means "not restricted" for adapters such as CodeGraph.
type Capability struct {
	Available     bool     `json:"available"`
	Version       string   `json:"version,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	Path          string   `json:"path,omitempty"`
	Languages     []string `json:"languages,omitempty"`
	BuildModeNone bool     `json:"build_mode_none,omitempty"`
}

// SourceRef identifies the snapshot an engine should prepare.
type SourceRef struct {
	Root         string   `json:"root"`
	RepoKey      string   `json:"repo_key,omitempty"`
	Commit       string   `json:"commit,omitempty"`
	Languages    []string `json:"languages,omitempty"`
	PrebuiltPath string   `json:"prebuilt_path,omitempty"`
}

// PrepareOptions configures engine preparation. WorkDir must be a task-owned
// directory; adapters refuse to write outside it. PrebuiltPath is an operator
// supplied CodeQL database directory or Joern CPG file.
type PrepareOptions struct {
	WorkDir      string        `json:"work_dir,omitempty"`
	PrebuiltPath string        `json:"prebuilt_path,omitempty"`
	RAMMB        int           `json:"ram_mb,omitempty"`
	Timeout      time.Duration `json:"timeout,omitempty"`
}

// Prepared is the result of engine preparation. Paths maps canonical audit
// languages to a CodeQL database directory or Joern CPG file. Unsupported
// records per-language capability gaps instead of failing the entire prepare.
type Prepared struct {
	Engine      string            `json:"engine"`
	Languages   []string          `json:"languages,omitempty"`
	Paths       map[string]string `json:"paths,omitempty"`
	BuildModes  map[string]string `json:"build_modes,omitempty"`
	Unsupported map[string]string `json:"unsupported,omitempty"`
	Warnings    []string          `json:"warnings,omitempty"`
	Duration    time.Duration     `json:"duration,omitempty"`
}

// Engine is the adapter contract. Adapters only accept QuerySpec values and
// must reject combinations their Probe capability does not advertise.
type Engine interface {
	Name() string
	Probe(ctx context.Context) (Capability, error)
	Prepare(ctx context.Context, src SourceRef, langs []string, opts PrepareOptions) (Prepared, error)
	Validate(ctx context.Context, q QuerySpec) error
	Run(ctx context.Context, q QuerySpec) ([]EngineFinding, error)
	Close() error
}

// ExecFunc is the narrow process-execution seam used by the CodeQL and Joern
// adapters. Tests replace it with a fake; production uses runExec.
type ExecFunc func(ctx context.Context, name string, args []string, dir string) (stdout string, stderr string, err error)

// JobResult records one intent/engine execution or capability gap. Status is
// done, failed, or skipped. QueryHash is the QuerySpec cache key when a query
// was rendered.
type JobResult struct {
	Engine    string        `json:"engine"`
	IntentID  string        `json:"intent_id"`
	QueryHash string        `json:"query_hash,omitempty"`
	Status    string        `json:"status"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration,omitempty"`
}

func normalizeEngineName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case EngineCodeGraph:
		return EngineCodeGraph
	case EngineCodeQL:
		return EngineCodeQL
	case EngineJoern:
		return EngineJoern
	default:
		return ""
	}
}

func validQueryKind(kind string) bool {
	switch kind {
	case QueryKindSink, QueryKindTaint, QueryKindControlFlow, QueryKindCallGraph, QueryKindDataflow, QueryKindLogic,
		QueryKindErrorContract, QueryKindStateTransition, QueryKindInvariant:
		return true
	default:
		return false
	}
}
