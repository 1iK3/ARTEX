package engines

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/audit"
	"gopkg.in/yaml.v3"
)

const maxSARIFBytes = 64 << 20

var (
	codeQLPackLinePattern     = regexp.MustCompile(`(?im)^\s*(codeql/[a-z0-9_.-]+)(?:@([^\s:]+))?\s*:`)
	codeQLPackLocationPattern = regexp.MustCompile(`(?im)^\s*(codeql/[a-z0-9_.-]+)@([^\s:]+):\s*\((?:library|query)\)\s+(.+?)\s*$`)
	codeQLPackNamePattern     = regexp.MustCompile(`^codeql/[a-z0-9_.-]+$`)
	codeQLPackVersionPattern  = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.-]+)?$`)
	cweTagPattern             = regexp.MustCompile(`(?i)cwe[-_/]?0*([0-9]+)`)
)

const CodeQLDefaultThreads = 2

// CodeQLRunner is a CodeQL CLI adapter. It never runs a repository build: only
// build-mode=none database creation is supported, unless the caller supplies a
// prebuilt database for C/C++ or Go.
type CodeQLRunner struct {
	Bin        string
	WorkDir    string
	DBPath     string
	SearchPath string
	RAMMB      int
	Threads    int
	Timeout    time.Duration
	execFn     ExecFunc

	mu        sync.Mutex
	dbs       map[string]string
	packs     map[string]string
	packPaths map[string]string
}

// NewCodeQLRunner creates a runner. Empty bin defaults to "codeql".
func NewCodeQLRunner(bin, workDir string) *CodeQLRunner {
	return &CodeQLRunner{Bin: strings.TrimSpace(bin), WorkDir: strings.TrimSpace(workDir)}
}

func (r *CodeQLRunner) Name() string { return EngineCodeQL }

func (r *CodeQLRunner) Close() error { return nil }

func (r *CodeQLRunner) binName() string {
	if r != nil {
		if bin := strings.TrimSpace(r.Bin); bin != "" {
			return bin
		}
	}
	return "codeql"
}

func (r *CodeQLRunner) executable() (name, path string, err error) {
	name = r.binName()
	if strings.TrimSpace(r.Bin) != "" || r.execFn != nil {
		return name, name, nil
	}
	resolved, lookupErr := exec.LookPath(name)
	if lookupErr != nil {
		return name, "", fmt.Errorf("%w: %v", ErrUnavailable, lookupErr)
	}
	return name, resolved, nil
}

// packRoots returns explicit build roots for CodeQL pack resolution. The
// CodeQL CLI does not list the user pack cache from a plain resolve command;
// it must be passed as an additional-pack root. SearchPath is honored first,
// followed by the standard ~/.codeql/packages cache.
func (r *CodeQLRunner) packRoots() []string {
	roots := make([]string, 0, 4)
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if info, err := os.Stat(raw); err == nil && !info.IsDir() {
			raw = filepath.Dir(raw)
		} else if _, err := os.Stat(filepath.Join(raw, "qlpack.yml")); err == nil {
			raw = filepath.Dir(raw)
		}
		absolute, err := filepath.Abs(raw)
		if err != nil {
			absolute = filepath.Clean(raw)
		}
		for _, existing := range roots {
			if strings.EqualFold(existing, absolute) {
				return
			}
		}
		roots = append(roots, absolute)
	}
	if searchPath := strings.TrimSpace(r.SearchPath); searchPath != "" {
		for _, part := range strings.Split(searchPath, string(os.PathListSeparator)) {
			add(part)
		}
		// An explicit search path is authoritative. Mixing it with the default
		// cache can expose two versions of the same dependency pack and make
		// CodeQL's resolver reject the query as ambiguous.
		return roots
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		add(filepath.Join(home, ".codeql", "packages"))
	}
	return roots
}

func (r *CodeQLRunner) discoveryPacksArg() string {
	return additionalPacksArg(r.packRoots())
}

func additionalPacksArg(roots []string) string {
	if len(roots) == 0 {
		return ""
	}
	return "--additional-packs=" + strings.Join(roots, string(os.PathListSeparator))
}

func (r *CodeQLRunner) discoverPacks(ctx context.Context) (map[string]string, error) {
	name, _, err := r.executable()
	if err != nil {
		return nil, err
	}
	args := []string{"resolve", "packs"}
	if additional := r.discoveryPacksArg(); additional != "" {
		args = append(args, additional)
	}
	if searchPath := strings.TrimSpace(r.SearchPath); searchPath != "" {
		args = append(args, "--search-path="+searchPath)
	}
	stdout, stderr, runErr := executeCommand(ctx, r.execFn, name, args, "", r.Timeout)
	if runErr != nil {
		classified := classifyExecError(ctx, runErr, stderr)
		if errors.Is(classified, ErrUnavailable) || errors.Is(classified, ErrTimeout) {
			return nil, classified
		}
		return nil, fmt.Errorf("%w: %v", ErrCapability, classified)
	}
	packs := parseCodeQLPackVersions(stdout)
	if len(packs) == 0 {
		packs = parseCodeQLPackVersions(stderr)
	}
	if len(packs) == 0 {
		return nil, fmt.Errorf("%w: no CodeQL packs resolved", ErrCapability)
	}
	locations := parseCodeQLPackLocations(stdout)
	if len(locations) == 0 {
		locations = parseCodeQLPackLocations(stderr)
	}
	r.mu.Lock()
	r.packs = packs
	r.packPaths = locations
	r.mu.Unlock()
	return packs, nil
}

func (r *CodeQLRunner) packVersion(packName string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.packs[packName]
}

func (r *CodeQLRunner) packPath(packName string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.packPaths[packName]
}

func (r *CodeQLRunner) ensureLanguagePack(ctx context.Context, language string) (packName, version string, err error) {
	databaseLanguage, ok := codeQLDatabaseLanguage(language)
	if !ok {
		return "", "", fmt.Errorf("%w: CodeQL does not support language %q", ErrUnsupported, language)
	}
	packName = "codeql/" + databaseLanguage + "-all"
	version = r.packVersion(packName)
	if version != "" {
		return packName, version, nil
	}
	if _, discoverErr := r.discoverPacks(ctx); discoverErr != nil {
		return "", "", discoverErr
	}
	version = r.packVersion(packName)
	if version == "" {
		return "", "", fmt.Errorf("%w: CodeQL pack %s is not installed", ErrCapability, packName)
	}
	return packName, version, nil
}

// Probe checks the CLI version, available extractors, and installed query
// packs. Missing pieces are encoded in Capability rather than returned as an
// error so the manager can record an engine gap and continue.
func (r *CodeQLRunner) Probe(ctx context.Context) (Capability, error) {
	name, path, err := r.executable()
	if err != nil {
		return Capability{Available: false, Reason: "binary_missing"}, nil
	}

	versionOut, versionErrOut, versionErr := executeCommand(ctx, r.execFn, name, []string{"version"}, "", r.Timeout)
	if versionErr != nil {
		if probeContextErr(ctx) != nil {
			return Capability{Reason: "canceled", Path: path}, probeContextErr(ctx)
		}
		return Capability{Available: false, Reason: probeFailureReason(versionErr), Path: path}, nil
	}
	version := firstNonEmpty(parseEngineVersion(versionOut), parseEngineVersion(versionErrOut))

	languagesOut, languagesErrOut, languagesErr := executeCommand(ctx, r.execFn, name, []string{"resolve", "languages"}, "", r.Timeout)
	if languagesErr != nil {
		if probeContextErr(ctx) != nil {
			return Capability{Reason: "canceled", Path: path, Version: version}, probeContextErr(ctx)
		}
		return Capability{
			Available: false, Reason: "language_resolve_failed", Path: path, Version: version,
		}, nil
	}
	resolved := parseCodeQLLanguages(languagesOut)
	if len(resolved) == 0 {
		resolved = parseCodeQLLanguages(languagesErrOut)
	}
	if len(resolved) == 0 {
		return Capability{
			Available: false, Reason: "language_resolve_failed", Path: path, Version: version,
		}, nil
	}

	packs, packsErr := r.discoverPacks(ctx)
	if packsErr != nil {
		if probeContextErr(ctx) != nil {
			return Capability{Reason: "canceled", Path: path, Version: version}, probeContextErr(ctx)
		}
		reason := "query_pack_missing"
		if !errors.Is(packsErr, ErrCapability) {
			reason = "pack_resolve_failed"
		}
		return Capability{
			Available: false, Reason: reason, Path: path, Version: version,
			Languages: resolved,
		}, nil
	}
	available := make([]string, 0, len(resolved))
	seen := make(map[string]struct{}, len(resolved))
	for _, language := range resolved {
		packLanguage := codeQLPackLanguage(language)
		if packLanguage == "" {
			continue
		}
		if _, ok := packs["codeql/"+packLanguage+"-all"]; !ok {
			continue
		}
		if _, exists := seen[language]; exists {
			continue
		}
		seen[language] = struct{}{}
		available = append(available, language)
	}
	if len(available) == 0 {
		return Capability{
			Available: false, Reason: "query_pack_missing", Path: path, Version: version,
			Languages: resolved,
		}, nil
	}
	sort.Strings(available)
	return Capability{
		Available:     true,
		Version:       version,
		Path:          path,
		Languages:     available,
		BuildModeNone: true,
	}, nil
}

func probeContextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func probeFailureReason(err error) string {
	switch {
	case isBinaryMissing(err):
		return "binary_missing"
	case errors.Is(err, ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "version_failed"
	}
}

// Prepare creates one build-mode=none database per language. C/C++ and Go are
// recorded as unsupported_build_required unless a prebuilt database is
// supplied. Failures for one language do not discard databases prepared for
// another language.
func (r *CodeQLRunner) Prepare(ctx context.Context, src SourceRef, langs []string, opts PrepareOptions) (Prepared, error) {
	started := time.Now()
	prepared := Prepared{
		Engine:      EngineCodeQL,
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
		return prepared, fmt.Errorf("%w: no languages supplied for CodeQL preparation", ErrInvalidSource)
	}

	workDir := engineWorkDir(r.WorkDir, opts.WorkDir)
	prebuilt := firstNonEmpty(opts.PrebuiltPath, src.PrebuiltPath, r.DBPath)
	sourceRoot := strings.TrimSpace(src.Root)
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = opts.Timeout
	}

	var failures []error
	buildRequired := false
	created := make(map[string]string)
	unsupportedByLanguage := make(map[string]string)
	processed := make(map[string]struct{})

	for _, language := range languages {
		codeQLLanguage, ok := codeQLDatabaseLanguage(language)
		if !ok {
			prepared.Unsupported[language] = "language_not_supported"
			continue
		}
		if _, exists := processed[codeQLLanguage]; !exists {
			processed[codeQLLanguage] = struct{}{}
			switch {
			case codeQLLanguage == "cpp" || codeQLLanguage == "go":
				if prebuilt == "" {
					buildRequired = true
					unsupportedByLanguage[codeQLLanguage] = "unsupported_build_required"
				} else if statErr := validatePrebuiltCodeQLDatabase(prebuilt); statErr != nil {
					reason := "prebuilt_database_invalid: " + statErr.Error()
					unsupportedByLanguage[codeQLLanguage] = reason
					failures = append(failures, fmt.Errorf("codeql prebuilt database: %w", statErr))
				} else {
					created[codeQLLanguage] = prebuilt
				}
			case codeQLBuildModeNoneLanguages[codeQLLanguage]:
				if sourceRoot == "" {
					unsupportedByLanguage[codeQLLanguage] = "source_root_required"
					failures = append(failures, fmt.Errorf("%w: source root is required to create a CodeQL database", ErrInvalidSource))
					break
				}
				if workDir == "" {
					unsupportedByLanguage[codeQLLanguage] = "work_dir_required"
					failures = append(failures, errors.New("codeql: work directory is required to create a database"))
					break
				}
				databasePath, pathErr := safeJoin(workDir, "engines", "codeql", codeQLLanguage)
				if pathErr != nil {
					unsupportedByLanguage[codeQLLanguage] = "invalid_work_dir"
					failures = append(failures, pathErr)
					break
				}
				if mkErr := ensureDir(filepath.Dir(databasePath)); mkErr != nil {
					unsupportedByLanguage[codeQLLanguage] = "database_directory_failed"
					failures = append(failures, mkErr)
					break
				}
				args := []string{
					"database", "create", databasePath,
					"--language=" + codeQLLanguage,
					"--build-mode=none",
					"--source-root=" + sourceRoot,
					"--overwrite",
				}
				if strings.TrimSpace(r.SearchPath) != "" {
					args = append(args, "--search-path="+strings.TrimSpace(r.SearchPath))
				}
				name, _, execErr := r.executable()
				if execErr != nil {
					unsupportedByLanguage[codeQLLanguage] = "binary_missing"
					failures = append(failures, execErr)
					break
				}
				_, stderr, runErr := executeCommand(ctx, r.execFn, name, args, workDir, timeout)
				if runErr != nil {
					classified := classifyExecError(ctx, runErr, stderr)
					unsupportedByLanguage[codeQLLanguage] = "database_create_failed: " + classified.Error()
					failures = append(failures, classified)
					break
				}
				created[codeQLLanguage] = databasePath
			default:
				unsupportedByLanguage[codeQLLanguage] = "unsupported_build_mode"
			}
		}

		if reason, unsupported := unsupportedByLanguage[codeQLLanguage]; unsupported {
			prepared.Unsupported[language] = reason
			continue
		}
		databasePath := created[codeQLLanguage]
		if databasePath == "" {
			prepared.Unsupported[language] = "database_not_prepared"
			continue
		}
		prepared.Paths[language] = databasePath
		if codeQLLanguage == "cpp" || codeQLLanguage == "go" {
			prepared.BuildModes[language] = "prebuilt"
		} else {
			prepared.BuildModes[language] = "none"
		}
		prepared.Languages = append(prepared.Languages, language)
		r.rememberDB(language, databasePath)
		switch language {
		case audit.JavaScript:
			if aliased, ok := created[codeQLLanguage]; ok {
				r.rememberDB(audit.TypeScript, aliased)
			}
		case audit.TypeScript:
			r.rememberDB(audit.JavaScript, databasePath)
		}
	}

	prepared.Duration = time.Since(started)
	if len(prepared.Paths) == 0 {
		if buildRequired {
			return prepared, fmt.Errorf(
				"%w: %w: C/C++ and Go require an operator-supplied prebuilt CodeQL database",
				ErrUnsupported, ErrUnsupportedBuildRequired)
		}
		if len(failures) > 0 {
			return prepared, errors.Join(failures...)
		}
		return prepared, fmt.Errorf("%w: no CodeQL language could be prepared", ErrUnsupported)
	}
	for _, failure := range failures {
		prepared.Warnings = append(prepared.Warnings, failure.Error())
	}
	return prepared, nil
}

var codeQLBuildModeNoneLanguages = map[string]bool{
	"java": true, "javascript": true, "python": true, "ruby": true, "csharp": true,
}

func codeQLDatabaseLanguage(language string) (string, bool) {
	canonical := normalizeIntentLanguage(language)
	switch canonical {
	case audit.Java:
		return "java", true
	case audit.Python:
		return "python", true
	case audit.JavaScript, audit.TypeScript:
		return "javascript", true
	case audit.Go:
		return "go", true
	case audit.C, audit.CPP:
		return "cpp", true
	case "ruby":
		return "ruby", true
	case "csharp":
		return "csharp", true
	default:
		return "", false
	}
}

func validatePrebuiltCodeQLDatabase(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat database: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("database path is not a directory: %s", path)
	}
	return nil
}

func (r *CodeQLRunner) rememberDB(language, path string) {
	language = normalizeIntentLanguage(language)
	if language == "" || strings.TrimSpace(path) == "" {
		return
	}
	r.mu.Lock()
	if r.dbs == nil {
		r.dbs = make(map[string]string)
	}
	r.dbs[language] = path
	r.mu.Unlock()
}

func (r *CodeQLRunner) cachedDB(language string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dbs[normalizeIntentLanguage(language)]
}

// Validate writes a standalone QL file plus qlpack.yml and compiles the query.
// Missing packs are surfaced as ErrCapability (a deployment gap), not as a
// generated-query syntax error.
func (r *CodeQLRunner) Validate(ctx context.Context, q QuerySpec) error {
	if normalizeEngineName(q.Engine) != "" && normalizeEngineName(q.Engine) != EngineCodeQL {
		return fmt.Errorf("%w: CodeQL runner received an engine %q query", ErrInvalidQuery, q.Engine)
	}
	if strings.TrimSpace(q.QueryText) == "" {
		return fmt.Errorf("%w: CodeQL query text is empty", ErrInvalidQuery)
	}
	if _, ok := codeQLDatabaseLanguage(q.Language); !ok {
		return fmt.Errorf("%w: CodeQL does not support language %q", ErrUnsupported, q.Language)
	}
	if strings.TrimSpace(r.WorkDir) == "" {
		return fmt.Errorf("%w: CodeQL work directory is required", ErrInvalidQuery)
	}
	name, _, err := r.executable()
	if err != nil {
		return err
	}
	packName, packVersion, err := r.ensureLanguagePack(ctx, q.Language)
	if err != nil {
		return err
	}
	packPath := r.packPath(packName)
	if packPath == "" {
		return fmt.Errorf("%w: CodeQL pack %s location is not available", ErrCapability, packName)
	}
	queryFile, packDirs, err := r.writeQueryFiles(q, packName, packVersion, packPath)
	if err != nil {
		return err
	}

	args := []string{"query", "compile"}
	if additional := additionalPacksArg(packDirs); additional != "" {
		args = append(args, additional)
	}
	if searchPath := strings.TrimSpace(r.SearchPath); searchPath != "" {
		args = append(args, "--search-path="+searchPath)
	}
	args = append(args, queryFile)
	stdout, stderr, compileErr := executeCommand(ctx, r.execFn, name, args, r.WorkDir, r.Timeout)
	if compileErr == nil {
		return nil
	}
	classified := classifyExecError(ctx, compileErr, stderr)
	if errors.Is(classified, ErrUnavailable) || errors.Is(classified, ErrTimeout) {
		return classified
	}
	combined := strings.ToLower(stdout + "\n" + stderr + "\n" + classified.Error())
	if strings.Contains(combined, "query pack") ||
		strings.Contains(combined, "pack ") ||
		strings.Contains(combined, "could not resolve") ||
		strings.Contains(combined, "cannot resolve") {
		return fmt.Errorf("%w: %v", ErrCapability, classified)
	}
	return fmt.Errorf("codeql query compile: %w", classified)
}

// Run analyzes the prepared database and parses SARIF into EngineFinding
// values. Output and query artifacts are confined to WorkDir.
func (r *CodeQLRunner) Run(ctx context.Context, q QuerySpec) ([]EngineFinding, error) {
	if normalizeEngineName(q.Engine) != "" && normalizeEngineName(q.Engine) != EngineCodeQL {
		return nil, fmt.Errorf("%w: CodeQL runner received an engine %q query", ErrInvalidQuery, q.Engine)
	}
	if strings.TrimSpace(q.QueryText) == "" {
		return nil, fmt.Errorf("%w: CodeQL query text is empty", ErrInvalidQuery)
	}
	if _, ok := codeQLDatabaseLanguage(q.Language); !ok {
		return nil, fmt.Errorf("%w: CodeQL does not support language %q", ErrUnsupported, q.Language)
	}
	if strings.TrimSpace(r.WorkDir) == "" {
		return nil, fmt.Errorf("%w: CodeQL work directory is required", ErrInvalidQuery)
	}
	databasePath := firstNonEmpty(q.ArtifactPath, r.cachedDB(q.Language), r.DBPath)
	if databasePath == "" {
		return nil, fmt.Errorf("%w: no CodeQL database for language %q", ErrMissingArtifact, q.Language)
	}
	name, _, err := r.executable()
	if err != nil {
		return nil, err
	}
	packName, packVersion, err := r.ensureLanguagePack(ctx, q.Language)
	if err != nil {
		return nil, err
	}
	packPath := r.packPath(packName)
	if packPath == "" {
		return nil, fmt.Errorf("%w: CodeQL pack %s location is not available", ErrCapability, packName)
	}
	queryFile, packDirs, err := r.writeQueryFiles(q, packName, packVersion, packPath)
	if err != nil {
		return nil, err
	}
	queryID := safeEngineID(firstNonEmpty(q.ID, q.IntentID, q.Template, "query"))
	outputPath, err := safeJoin(r.WorkDir, "sarif", queryID+".sarif")
	if err != nil {
		return nil, err
	}
	if err := ensureDir(filepath.Dir(outputPath)); err != nil {
		return nil, err
	}
	_ = os.Remove(outputPath)

	args := []string{
		"database", "analyze",
		"--format=sarif-latest",
		"--output=" + outputPath,
	}
	if r.RAMMB > 0 {
		args = append(args, "--ram="+strconv.Itoa(r.RAMMB))
	}
	threads := r.Threads
	if threads <= 0 {
		threads = CodeQLDefaultThreads
	}
	args = append(args, "--threads="+strconv.Itoa(threads))
	if additional := additionalPacksArg(packDirs); additional != "" {
		args = append(args, additional)
	}
	if searchPath := strings.TrimSpace(r.SearchPath); searchPath != "" {
		args = append(args, "--search-path="+searchPath)
	}
	args = append(args, databasePath, queryFile)
	_, stderr, runErr := executeCommand(ctx, r.execFn, name, args, r.WorkDir, r.Timeout)
	if runErr != nil {
		return nil, fmt.Errorf("codeql database analyze: %w", classifyExecError(ctx, runErr, stderr))
	}

	info, statErr := os.Stat(outputPath)
	if statErr != nil {
		return nil, fmt.Errorf("codeql SARIF output: %w", statErr)
	}
	if info.Size() > maxSARIFBytes {
		return nil, fmt.Errorf("codeql SARIF output exceeds %d bytes", maxSARIFBytes)
	}
	data, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		return nil, fmt.Errorf("read codeql SARIF: %w", readErr)
	}
	meta := FindingMeta{
		Engine:      EngineCodeQL,
		QueryID:     q.ID,
		CWE:         paramString(q.Params, "cwe"),
		Language:    q.Language,
		SinkSymbols: paramStringSlice(q.Params, "sink_symbols"),
	}
	findings, parseErr := ParseSARIF(data, meta)
	if parseErr != nil {
		return nil, parseErr
	}
	return findings, nil
}

func (r *CodeQLRunner) writeQueryFiles(q QuerySpec, packName, packVersion, packPath string) (string, []string, error) {
	queryID := safeEngineID(firstNonEmpty(q.ID, q.IntentID, q.Template, "query"))
	directory, err := safeJoin(r.WorkDir, "queries", "codeql", queryID)
	if err != nil {
		return "", nil, err
	}
	if err := ensureDir(directory); err != nil {
		return "", nil, err
	}
	queryFile := filepath.Join(directory, "query.ql")
	if err := os.WriteFile(queryFile, []byte(q.QueryText), 0o600); err != nil {
		return "", nil, fmt.Errorf("write CodeQL query: %w", err)
	}
	qlpack := fmt.Sprintf("name: artex/generated-%s\nversion: 0.0.1\ndependencies:\n  %s: %q\n",
		queryID, packName, packVersion)
	if err := os.WriteFile(filepath.Join(directory, "qlpack.yml"), []byte(qlpack), 0o600); err != nil {
		return "", nil, fmt.Errorf("write CodeQL qlpack: %w", err)
	}
	packDirs, err := r.writeCodeQLPackLock(directory, packPath)
	if err != nil {
		return "", nil, fmt.Errorf("%w: resolve CodeQL pack dependencies: %v", ErrCapability, err)
	}
	return queryFile, packDirs, nil
}

func (r *CodeQLRunner) writeCodeQLPackLock(directory, packPath string) ([]string, error) {
	closure := newCodeQLPackClosure()
	if err := r.collectCodeQLPackClosure(packPath, closure); err != nil {
		return nil, err
	}
	names := closure.sortedNames()

	var out strings.Builder
	out.WriteString("---\nlockVersion: 1.0.0\ndependencies:\n")
	for _, name := range names {
		out.WriteString("  " + name + ":\n    version: " + closure.versions[name] + "\n")
	}
	out.WriteString("compiled: false\n")
	if err := os.WriteFile(filepath.Join(directory, "codeql-pack.lock.yml"), []byte(out.String()), 0o600); err != nil {
		return nil, err
	}
	return closure.packDirectories(), nil
}

type codeQLPackClosure struct {
	versions map[string]string
	paths    map[string]string
}

func newCodeQLPackClosure() *codeQLPackClosure {
	return &codeQLPackClosure{versions: make(map[string]string), paths: make(map[string]string)}
}

func (c *codeQLPackClosure) sortedNames() []string {
	names := make([]string, 0, len(c.versions))
	for name := range c.versions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *codeQLPackClosure) packDirectories() []string {
	names := c.sortedNames()
	directories := make([]string, 0, len(names))
	for _, name := range names {
		directories = append(directories, filepath.Dir(c.paths[name]))
	}
	return directories
}

func (r *CodeQLRunner) collectCodeQLPackClosure(packPath string, closure *codeQLPackClosure) error {
	manifest, err := readCodeQLPackManifest(packPath)
	if err != nil {
		return err
	}
	if existing, ok := closure.versions[manifest.Name]; ok {
		if existing != manifest.Version {
			return fmt.Errorf("conflicting versions for %s: %s and %s", manifest.Name, existing, manifest.Version)
		}
		return nil
	}
	closure.versions[manifest.Name] = manifest.Version
	closure.paths[manifest.Name] = packPath

	roots := r.codeQLPackLookupRoots(packPath)
	dependencies := make([]string, 0, len(manifest.Dependencies))
	for name := range manifest.Dependencies {
		dependencies = append(dependencies, name)
	}
	sort.Strings(dependencies)
	for _, name := range dependencies {
		version, err := exactCodeQLPackVersion(manifest.Dependencies[name])
		if err != nil {
			return fmt.Errorf("dependency %s: %w", name, err)
		}
		if closure.versions[name] == version {
			continue
		}
		dependencyPath := findCodeQLPack(roots, name, version)
		if dependencyPath == "" {
			return fmt.Errorf("pack %s@%s is not installed", name, version)
		}
		if err := r.collectCodeQLPackClosure(dependencyPath, closure); err != nil {
			return err
		}
	}
	return nil
}

func (r *CodeQLRunner) codeQLPackLookupRoots(packPath string) []string {
	roots := make([]string, 0, 3)
	add := func(raw string) {
		if raw == "" {
			return
		}
		absolute, err := filepath.Abs(raw)
		if err != nil {
			absolute = filepath.Clean(raw)
		}
		for _, existing := range roots {
			if strings.EqualFold(existing, absolute) {
				return
			}
		}
		roots = append(roots, absolute)
	}

	add(codeQLPackCacheRoot(packPath))
	for _, root := range r.packRoots() {
		add(root)
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		add(filepath.Join(home, ".codeql", "packages"))
	}
	return roots
}

type codeQLPackManifest struct {
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
	Dependencies map[string]string `yaml:"dependencies"`
}

func readCodeQLPackManifest(path string) (codeQLPackManifest, error) {
	var manifest codeQLPackManifest
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest, err
	}
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("parse CodeQL pack manifest %s: %w", path, err)
	}
	if manifest.Name == "" || manifest.Version == "" {
		return manifest, fmt.Errorf("CodeQL pack manifest %s has no name or version", path)
	}
	return manifest, nil
}

func codeQLPackCacheRoot(packPath string) string {
	versionDir := filepath.Dir(packPath)
	return filepath.Clean(filepath.Dir(filepath.Dir(filepath.Dir(versionDir))))
}

func findCodeQLPack(roots []string, name, version string) string {
	if !codeQLPackNamePattern.MatchString(name) || !codeQLPackVersionPattern.MatchString(version) {
		return ""
	}
	for _, root := range roots {
		path := filepath.Join(root, filepath.FromSlash(name), version, "qlpack.yml")
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func paramString(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	text, _ := params[key].(string)
	return strings.TrimSpace(text)
}

// ---------------------------------------------------------------------------
// Capability parsing
// ---------------------------------------------------------------------------

func parseCodeQLLanguages(output string) []string {
	trimmed := strings.TrimSpace(output)
	if trimmed != "" && (trimmed[0] == '[' || trimmed[0] == '{') {
		if languages := parseCodeQLLanguagesJSON(trimmed); len(languages) > 0 {
			return sortedCopy(languages)
		}
	}
	out := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		token := strings.Fields(line)[0]
		if idx := strings.IndexByte(token, '@'); idx >= 0 {
			token = token[:idx]
		}
		for _, language := range codeQLAuditLanguagesForName(token) {
			if _, exists := seen[language]; exists {
				continue
			}
			seen[language] = struct{}{}
			out = append(out, language)
		}
	}
	return sortedCopy(out)
}

func parseCodeQLLanguagesJSON(data string) []string {
	var names []string
	if err := json.Unmarshal([]byte(data), &names); err == nil && names != nil {
		return codeQLLanguagesFromNames(names)
	}
	var objects []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(data), &objects); err == nil && objects != nil {
		names = make([]string, 0, len(objects))
		for _, object := range objects {
			names = append(names, object.Name)
		}
		return codeQLLanguagesFromNames(names)
	}
	var wrapper struct {
		Languages []string `json:"languages"`
	}
	if err := json.Unmarshal([]byte(data), &wrapper); err == nil && wrapper.Languages != nil {
		return codeQLLanguagesFromNames(wrapper.Languages)
	}
	return nil
}

func codeQLLanguagesFromNames(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{})
	for _, name := range names {
		for _, language := range codeQLAuditLanguagesForName(name) {
			if _, exists := seen[language]; exists {
				continue
			}
			seen[language] = struct{}{}
			out = append(out, language)
		}
	}
	return out
}

func codeQLAuditLanguagesForName(name string) []string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "javascript", "js", "typescript", "ts":
		return []string{audit.JavaScript, audit.TypeScript}
	case "cpp", "c++", "c":
		return []string{audit.CPP, audit.C}
	case "java":
		return []string{audit.Java}
	case "python", "py":
		return []string{audit.Python}
	case "go", "golang":
		return []string{audit.Go}
	case "ruby":
		return []string{"ruby"}
	case "csharp", "c#":
		return []string{"csharp"}
	case "swift":
		return []string{"swift"}
	case "kotlin":
		return []string{"kotlin"}
	default:
		if language := audit.NormalizeLanguage(name); language != "" {
			return []string{language}
		}
		return nil
	}
}

func parseCodeQLPackVersions(output string) map[string]string {
	out := make(map[string]string)
	for _, match := range codeQLPackLinePattern.FindAllStringSubmatch(output, -1) {
		if len(match) < 2 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(match[1]))
		version := ""
		if len(match) > 2 {
			version = strings.TrimSpace(match[2])
		}
		if existing, ok := out[name]; !ok || (existing == "" && version != "") {
			out[name] = version
		}
	}
	return out
}

func parseCodeQLPackLocations(output string) map[string]string {
	out := make(map[string]string)
	for _, match := range codeQLPackLocationPattern.FindAllStringSubmatch(output, -1) {
		if len(match) < 4 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(match[1]))
		version := strings.TrimSpace(match[2])
		path := strings.TrimSpace(match[3])
		if version == "" || path == "" {
			continue
		}
		if existing, ok := out[name]; !ok || existing == "" {
			out[name] = path
		}
	}
	return out
}

func exactCodeQLPackVersion(version string) (string, error) {
	version = strings.TrimSpace(version)
	if !codeQLPackVersionPattern.MatchString(version) {
		return "", fmt.Errorf("version constraint %q is not an exact installed pack version", version)
	}
	return version, nil
}

func codeQLPackLanguage(language string) string {
	canonical := normalizeIntentLanguage(language)
	switch canonical {
	case audit.JavaScript, audit.TypeScript:
		return "javascript"
	case audit.C, audit.CPP:
		return "cpp"
	case audit.Java, audit.Python, audit.Go:
		return canonical
	case "ruby", "csharp":
		return canonical
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// SARIF parsing
// ---------------------------------------------------------------------------

// FindingMeta supplies query context that SARIF itself does not carry (the
// target CWE and ARTEX query identity).
type FindingMeta struct {
	Engine      string
	QueryID     string
	CWE         string
	Language    string
	SinkSymbols []string
}

type sarifLog struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Properties sarifProperties `json:"properties"`
}

type sarifProperties struct {
	Tags []string `json:"tags"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           *int              `json:"ruleIndex"`
	Message             sarifMessage      `json:"message"`
	Level               string            `json:"level"`
	Locations           []sarifLocation   `json:"locations"`
	CodeFlows           []sarifCodeFlow   `json:"codeFlows"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
	Message          sarifMessage           `json:"message"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location     sarifLocation `json:"location"`
	NestingLevel int           `json:"nestingLevel"`
}

// ParseSARIF normalizes SARIF 2.1.0 runs/results into EngineFinding values.
// Missing optional fields are tolerated; malformed JSON is an error. A code
// flow yields confidence 0.75 and source/sink locations; a sink-only result
// yields confidence 0.45.
func ParseSARIF(data []byte, meta FindingMeta) ([]EngineFinding, error) {
	var log sarifLog
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&log); err != nil {
		return nil, fmt.Errorf("parse SARIF: %w", err)
	}
	if strings.TrimSpace(meta.Engine) == "" {
		meta.Engine = EngineCodeQL
	}

	findings := make([]EngineFinding, 0)
	resultIndex := 0
	for _, run := range log.Runs {
		for _, result := range run.Results {
			rule := sarifRuleForResult(run, result)
			ruleID := strings.TrimSpace(result.RuleID)
			if ruleID == "" {
				ruleID = strings.TrimSpace(rule.ID)
			}
			if ruleID == "" {
				ruleID = "unknown"
			}
			message := firstNonEmpty(result.Message.Text, result.Message.Markdown, "SARIF result "+ruleID)
			severity := sarifSeverity(result.Level)
			cwe := strings.TrimSpace(meta.CWE)
			if cwe == "" {
				cwe = cweFromRuleTags(rule.Properties.Tags)
			}

			primary, hasPrimary := sarifLocationFromSARIF(firstSARIFLocation(result.Locations))
			primaryColumn := 0
			if len(result.Locations) > 0 {
				primaryColumn = result.Locations[0].PhysicalLocation.Region.StartColumn
			}
			trace, flowLocations := sarifTrace(result.CodeFlows)
			inferredSymbol := inferSARIFSymbol(result, ruleID, trace, meta.SinkSymbols)
			for index := range trace {
				if trace[index].Symbol == "" {
					trace[index].Symbol = symbolFromMessage(trace[index].Note)
				}
			}
			if len(trace) > 0 && trace[len(trace)-1].Symbol == "" {
				trace[len(trace)-1].Symbol = inferredSymbol
			}
			if !hasPrimary && len(flowLocations) > 0 {
				primary = flowLocations[len(flowLocations)-1]
				hasPrimary = true
			}
			if hasPrimary && strings.TrimSpace(primary.Symbol) == "" {
				primary.Symbol = inferredSymbol
			}
			location := audit.CodeLocation{}
			if hasPrimary {
				location = primary
			}

			var source *audit.CodeLocation
			var sink *audit.CodeLocation
			if len(flowLocations) > 0 {
				sourceCopy := flowLocations[0]
				sinkCopy := flowLocations[len(flowLocations)-1]
				if sourceCopy.Symbol == "" && len(trace) > 0 {
					sourceCopy.Symbol = trace[0].Symbol
				}
				if sinkCopy.Symbol == "" {
					sinkCopy.Symbol = inferredSymbol
				}
				source = &sourceCopy
				sink = &sinkCopy
			} else if hasPrimary {
				sinkCopy := primary
				sink = &sinkCopy
			}

			confidence := 0.45
			if len(result.CodeFlows) > 0 {
				confidence = 0.75
			}
			payload := map[string]any{
				"rule_id": ruleID,
				"level":   strings.TrimSpace(result.Level),
				"symbol":  inferredSymbol,
				"result":  jsonMap(result),
			}
			if primaryColumn > 0 {
				payload["start_column"] = primaryColumn
			}
			if len(rule.Properties.Tags) > 0 {
				payload["rule_tags"] = append([]string(nil), rule.Properties.Tags...)
			}
			if rule.Name != "" {
				payload["rule_name"] = rule.Name
			}
			if len(result.PartialFingerprints) > 0 {
				payload["partial_fingerprints"] = result.PartialFingerprints
			}

			finding := EngineFinding{
				Engine:     firstNonEmpty(meta.Engine, EngineCodeQL),
				QueryID:    meta.QueryID,
				CWE:        cwe,
				Language:   meta.Language,
				Message:    message,
				Severity:   severity,
				Location:   location,
				Source:     source,
				Sink:       sink,
				Trace:      trace,
				Confidence: confidence,
				RawRef:     fmt.Sprintf("sarif:%s:%d", ruleID, resultIndex),
				Payload:    payload,
			}
			findings = append(findings, finding)
			resultIndex++
		}
	}
	return findings, nil
}

var sarifMessageCallPattern = regexp.MustCompile(`([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(`)

func inferSARIFSymbol(result sarifResult, ruleID string, trace []audit.TraceStep, sinkSymbols []string) string {
	haystack := strings.ToLower(result.Message.Text + " " + result.Message.Markdown)
	for _, step := range trace {
		haystack += " " + strings.ToLower(step.Note+" "+step.Symbol)
	}
	ordered := append([]string(nil), sinkSymbols...)
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, symbol := range ordered {
		symbol = strings.TrimSpace(symbol)
		if symbol != "" && strings.Contains(haystack, strings.ToLower(symbol)) {
			return symbol
		}
	}
	for index := len(trace) - 1; index >= 0; index-- {
		if symbol := symbolFromMessage(trace[index].Note); symbol != "" {
			return symbol
		}
	}
	if symbol := symbolFromMessage(result.Message.Text); symbol != "" {
		return symbol
	}
	ruleID = strings.TrimSpace(ruleID)
	if ruleID != "" {
		if index := strings.LastIndexAny(ruleID, "/\\"); index >= 0 && index+1 < len(ruleID) {
			return ruleID[index+1:]
		}
		return ruleID
	}
	return "engine-sink"
}

func symbolFromMessage(message string) string {
	matches := sarifMessageCallPattern.FindAllStringSubmatch(message, -1)
	for index := len(matches) - 1; index >= 0; index-- {
		if len(matches[index]) > 1 {
			symbol := strings.TrimSpace(matches[index][1])
			if dot := strings.LastIndexByte(symbol, '.'); dot >= 0 {
				symbol = symbol[dot+1:]
			}
			if symbol = strings.TrimSpace(symbol); symbol != "" {
				return symbol
			}
		}
	}
	return ""
}

func sarifRuleForResult(run sarifRun, result sarifResult) sarifRule {
	if result.RuleIndex != nil && *result.RuleIndex >= 0 && *result.RuleIndex < len(run.Tool.Driver.Rules) {
		return run.Tool.Driver.Rules[*result.RuleIndex]
	}
	ruleID := strings.TrimSpace(result.RuleID)
	if ruleID == "" {
		return sarifRule{}
	}
	for _, rule := range run.Tool.Driver.Rules {
		if strings.TrimSpace(rule.ID) == ruleID {
			return rule
		}
	}
	return sarifRule{}
}

func sarifSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return audit.SeverityHigh
	case "note", "none":
		return audit.SeverityLow
	default:
		return audit.SeverityMedium
	}
}

func cweFromRuleTags(tags []string) string {
	for _, tag := range tags {
		match := cweTagPattern.FindStringSubmatch(tag)
		if len(match) == 2 {
			number := strings.TrimLeft(match[1], "0")
			if number == "" {
				number = "0"
			}
			return "CWE-" + number
		}
	}
	return ""
}

func firstSARIFLocation(locations []sarifLocation) sarifLocation {
	if len(locations) == 0 {
		return sarifLocation{}
	}
	return locations[0]
}

func sarifLocationFromSARIF(location sarifLocation) (audit.CodeLocation, bool) {
	physical := location.PhysicalLocation
	path := normalizeSARIFPath(physical.ArtifactLocation.URI)
	line := physical.Region.StartLine
	endLine := physical.Region.EndLine
	symbol := sarifLogicalSymbol(location.LogicalLocations)
	if path == "" && line == 0 && symbol == "" {
		return audit.CodeLocation{}, false
	}
	return audit.CodeLocation{
		Path:    path,
		Line:    line,
		EndLine: endLine,
		Symbol:  symbol,
	}, true
}

func sarifLogicalSymbol(locations []sarifLogicalLocation) string {
	for _, location := range locations {
		if symbol := firstNonEmpty(location.FullyQualifiedName, location.Name); symbol != "" {
			return symbol
		}
	}
	return ""
}

func normalizeSARIFPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "file:") {
		if parsed, err := url.Parse(raw); err == nil && parsed.Path != "" {
			raw = parsed.Path
		}
	}
	if unescaped, err := url.PathUnescape(raw); err == nil {
		raw = unescaped
	}
	return audit.NormalizeCodePath(raw)
}

// sarifTrace returns trace steps and the physical locations backing them (used
// for source/sink). The first code flow is treated as the canonical path.
func sarifTrace(flows []sarifCodeFlow) ([]audit.TraceStep, []audit.CodeLocation) {
	if len(flows) == 0 {
		return nil, nil
	}
	var (
		trace     []audit.TraceStep
		locations []audit.CodeLocation
	)
	for _, flow := range flows {
		for _, threadFlow := range flow.ThreadFlows {
			for _, flowLocation := range threadFlow.Locations {
				location, ok := sarifLocationFromSARIF(flowLocation.Location)
				if !ok {
					continue
				}
				note := strings.TrimSpace(flowLocation.Location.Message.Text)
				trace = append(trace, audit.TraceStep{
					Path:   location.Path,
					Line:   location.Line,
					Symbol: location.Symbol,
					Note:   note,
				})
				locations = append(locations, location)
				if len(trace) >= 200 {
					break
				}
			}
			if len(trace) >= 200 {
				break
			}
		}
		if len(trace) > 0 {
			break
		}
	}
	if len(trace) > 0 {
		if trace[0].Note == "" {
			trace[0].Note = "source"
		}
		if len(trace) > 1 && trace[len(trace)-1].Note == "" {
			trace[len(trace)-1].Note = "sink"
		}
	}
	return trace, locations
}

func jsonMap(value any) map[string]any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil
	}
	return out
}
