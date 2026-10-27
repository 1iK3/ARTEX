# ARTEX Code Audit Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first end-to-end static code-audit vertical slice inside ARTEX: create a `code_audit` task from Git/local/zip, ingest and snapshot source, index with CodeGraph, seed audit intents, run audit workers with structured evidence, compute coverage/gates, and produce an audit report and UI.

**Architecture:** A deterministic `audit` package owns source ingest, profiling, sink prescan, coverage/gates, and reports. A server-side `AuditDirector` manages per-task lifecycle and exposes candidates; the existing planner/worker engine executes audit intents via new `code_planner`/`code_worker` agents with a restricted tool surface. CodeQL/Joern/query synthesis are deliberately deferred to the follow-up plan `2026-10-26-artex-code-audit-engines.md`, but the engine interfaces and data model are introduced here.

**Tech Stack:** Go 1.26, PostgreSQL (pgx), existing norma agent SDK, CodeGraph CLI/MCP, Next.js/React/TypeScript, Vitest not used for Go; Go tests + existing web build.

**Constraint:** Do not commit unless the user explicitly asks. Each task ends with a test checkpoint instead of a commit.

---

## File Structure

```text
audit/
  types.go                 # enums, configs, source/evidence/query types
  registry.go              # embed/load audit-registry.json
  source.go                # git/local/zip acquire + snapshot
  zip.go                   # safe zip extraction
  profile.go               # language/framework/build detection
  plan.go                  # phases, CWE plan, candidate generation
  prescan.go               # deterministic sink-site scan
  coverage.go              # coverage counts + gate formulas
  evidence.go              # evidence validation/dedupe/report helpers
  report.go                # Markdown/JSON report
  registry_test.go
  source_test.go
  profile_test.go
  prescan_test.go
  coverage_test.go
  evidence_test.go
  report_test.go
  data/
    audit-registry.json    # generated from Omni-Audit
    README.md
db/
  audit.go                 # persistence structs + CRUD
  audit_test.go            # DB tests skip when no PG
  schema.sql               # additive idempotent DDL
  tasks.go                 # TaskMode/AuditConfig
  db.go                    # builtin code agents
agent/
  codeaudit_tools.go       # audit tool set
  codeaudit_tools_test.go
  promptcatalog.go         # code_planner/code_worker prompts
  planner.go               # prompt key + mode-aware toolset
  worker.go                # prompt key + mode-aware toolset
server/
  audit_director.go        # per-task director lifecycle
  audit_director_test.go
  audit.go                 # API + startCodeAudit
  audit_api_test.go
  task_llm.go              # per-mode agent keys
  goals.go                 # code_audit bootstrap branch
  dto.go                   # task/finding DTO fields
  server.go                # create task mode/audit fields
  assembly.go              # seed new tools/prompts
  finding_traffic.go       # extend RecordFindingInput
web/src/
  lib/types.ts
  lib/api.ts
  lib/mock/data.ts
  lib/mock/handler.ts
  app/(main)/function/tasks/page.tsx
  app/(main)/function/tasks/detail/page.tsx
  app/(main)/function/tasks/detail/_tabs/code-audit-tab.tsx
  app/(main)/function/findings/detail/page.tsx
docs/
  superpowers/specs/2026-10-26-artex-code-audit-fusion-design.md
  superpowers/plans/2026-10-26-artex-code-audit-core.md
```

---

### Task 1: Export Omni-Audit registries into ARTEX

**Files:**
- Create: `D:/Codex/Projects/Artex/Omni-Audit/scripts/export-artex-audit-data.mts`
- Create: `audit/data/audit-registry.json` (generated)
- Create: `audit/data/README.md`
- Create: `audit/types.go`
- Create: `audit/language.go`
- Create: `audit/registry.go`
- Create: `audit/registry_test.go`
- Modify: `.gitattributes`

- [x] **Step 1: Write the deterministic exporter**

`Omni-Audit/scripts/export-artex-audit-data.mts` must be reproducible:

- Import `CWE_P0`, the five sink registries, `ODIN_RULES`,
  `TAINT_REGISTRIES`, and the per-language taint registries from
  `../packages/shared/src/index.ts`.
- Emit no timestamps. Serialize with two-space indentation and a trailing
  newline.
- Derive `source` from `git -C <Omni-Audit> rev-parse HEAD` (short SHA).
  Append `-dirty` when `git status --porcelain -- packages/shared` is
  non-empty. Refuse to write a dirty shared tree unless `--allow-dirty` is
  passed.
- Deduplicate CWE IDs, keeping the highest priority
  (`P0` > `P1` > `P2` > `P3`, e.g. CWE-918 stays P0).
- Emit every `taint` entry as an array: `Object.values(TAINT_REGISTRIES)` for
  Java and one-element arrays for the other languages.
- Accept an optional output directory argument (default
  `../../ARTEX/audit/data`, resolved from the script directory).
- Support `--check`: write the generated result to a temporary file and exit
  1 if it differs from the checked-in JSON.
- Handle file errors concisely: `--check` must report a clear message if the
  checked-in file cannot be read. Normal exports write to a temporary file in
  the output directory and rename it into place (atomic where practical).

Key payload shape:

```ts
const out = {
  source: `Omni-Audit@${commit}${sharedDirty ? "-dirty" : ""}`,
  cwe: dedupeCWEs(CWE_P0),
  sinks: { java: JAVA_SINKS, python: PYTHON_SINKS, /* ... */ },
  odin_rules: ODIN_RULES,
  taint: {
    java: Object.values(TAINT_REGISTRIES),
    python: [PYTHON_TAINT_REGISTRY],
    go: [GO_TAINT_REGISTRY],
    /* ... every language is an array ... */
  },
};
const content = `${JSON.stringify(out, null, 2)}\n`;
```

Do not add a `generated_at` field; `--check` depends on byte-for-byte
reproducibility.

- [x] **Step 2: Generate and verify**

```bash
cd "D:/Codex/Projects/Artex/Omni-Audit"
packages/engine/node_modules/.bin/tsx scripts/export-artex-audit-data.mts
packages/engine/node_modules/.bin/tsx scripts/export-artex-audit-data.mts --check
```

Expected: `wrote .../ARTEX/audit/data/audit-registry.json
(Omni-Audit@f439e2d)`, then `audit-registry.json is up to date`. The generated
file must be > 500 KB, end with a newline, and contain no CRLF bytes.

Add LF rules to `.gitattributes` so fresh Windows checkouts stay
byte-identical:

```gitattributes
*.go text eol=lf
audit/data/audit-registry.json text eol=lf
```

Do not run `git add --renormalize`; existing tracked files are intentionally
not renormalized. Verify:

```bash
cd "D:/Codex/Projects/Artex/ARTEX"
git check-attr text eol -- audit/data/audit-registry.json
python -c "d=open('audit/data/audit-registry.json','rb').read(); assert b'\r' not in d; print('LF OK')"
```

Expected attributes: `text: set` and `eol: lf`.

- [x] **Step 3: Add types and language normalization**

`audit/types.go`: define `SinkDefinition`, `CWEDefinition`, `OdinRule`
(including `TraceHint` and `Category`), `TaintRegistry` (`registry_name`,
`language`, `frameworks json.RawMessage`), and `Registry` with
`Taint map[string][]TaintRegistry`.

`audit/language.go`: define canonical constants (`Java`, `Python`,
`JavaScript`, `TypeScript`, `Go`, `Rust`, `C`, `CPP`),
`NormalizeLanguage` (`js`/`node`/`nodejs` -> javascript, `ts` -> typescript,
`c++`/`cxx`/`cc` -> cpp, etc.), and `Languages()` returning a copy.

- [x] **Step 4: Add the cached loader and accessors**

`audit/registry.go`:

```go
//go:embed data/audit-registry.json
var registryJSON []byte

func decodeRegistry(data []byte) (Registry, error)
func LoadRegistry() (Registry, error)
func (r Registry) SinksFor(language string) []SinkDefinition
func (r Registry) HasSinks(language string) bool
func (r Registry) CWEsFor(language string) []CWEDefinition
func (r Registry) OdinRulesFor(language string) []OdinRule
func (r Registry) TaintsFor(language string) []TaintRegistry
```

Requirements:

- Cache only a successful decode; return `Registry{}` plus a context-wrapped
  error on failure, never expose partially populated data, and do not populate
  the cache after a failed load.
- `LoadRegistry` returns a deep copy of the cached registry (including nested
  maps, slices, and taint raw JSON). Accessors also clone returned mutable
  slices/bytes so callers cannot mutate the cache.
- Normalize every language argument. `CWEsFor` matching treats Node.js as
  JavaScript. `OdinRulesFor` treats every rule language that normalizes to
  JavaScript (`nodejs`, `js`, `node`, etc.) as applying to both JavaScript and
  TypeScript. Use a dedicated Odin matching helper so the canonical mapping
  used by sinks/CWEs is unchanged.
- Return non-nil empty slices for unknown languages.
- Go intentionally has no sink table: `SinksFor("go")` is empty while
  `CWEsFor("go")` and `TaintsFor("go")` return data.

- [x] **Step 5: Write contract tests**

`audit/registry_test.go` must cover more than the original smoke test:

- provenance (`Omni-Audit@f439e2d`), unique CWE IDs, and CWE-918 kept as P0;
- table-driven `SinksFor`/`CWEsFor` cases for canonical names, aliases,
  case/whitespace, unknown languages, and duplicate language entries;
- representative entries (CWE-89, a Java JDBC sink, the servlet source, and an
  Odin rule with `traceHint`/`category`);
- `OdinRulesFor` parity for `nodejs`, `javascript`, `typescript`, `ts`, and
  `js`, including a known nodejs-tagged rule; every JavaScript-normalized rule
  language must apply to TypeScript;
- every language/section non-empty as appropriate (Go sinks empty; Odin rules
  non-empty for every canonical language). Assert explicitly that
  `CWEsFor("rust")` is empty because the source CWE table has no `rust`
  entries, while Rust sinks and taint data exist;
- taint contract (`registry_name`, `language`, non-empty `frameworks` with
  sources/sinks/pairs);
- malformed JSON and wrong taint shapes via `decodeRegistry`, asserting a zero
  registry and wrapped error;
- `LoadRegistry` deep-copy regression: mutate a loaded registry's nested
  maps/slices/raw JSON, then verify a later load equals an independent decode;
- failed-load regression: temporarily replace `registryJSON` with malformed
  data, reset the cache under cleanup, call `LoadRegistry` twice, assert both
  fail with wrapped errors and the cache stays empty, then restore valid data
  and verify success;
- accessor copy semantics for every accessor.

Run:

```bash
cd "D:/Codex/Projects/Artex/ARTEX"
go test ./audit -v
go vet ./audit
```

- [x] **Step 6: Document the generated file**

`audit/data/README.md` must document prerequisites (Git CLI, sibling
ARTEX/Omni-Audit checkouts, Node >= 22, pnpm, engine `tsx`), the exact
generation command, `--check`, checksum verification, LF normalization via
`.gitattributes`, source provenance policy, generated contents, coverage
caveats, and `go test ./audit`. Include a regeneration checklist covering the
source commit, checksum, `wantRegistrySource` in `audit/registry_test.go`, the
Git/sibling prerequisites, and LF checks without renormalizing existing tracked
files. Do not hand-edit `audit-registry.json`.

---

### Task 2: Audit schema and DB persistence

**Files:**
- Modify: `db/schema.sql` (append new section at the end)
- Create: `db/audit.go`
- Create: `db/audit_test.go`
- Create: `db/jsonb.go` (shared JSONB clone helper)
- Modify: `db/tasks.go`
- Modify: `db/finding_traffic_archive.go` (backfill new findings columns on restore)
- Modify: `db/task_archives.go` and `db/task_archives_restore.go` (temporary archive guard, repository identity)

- [x] **Step 1: Add additive schema**

Append to `db/schema.sql`:

```sql
-- ===================== Code Audit =====================
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS task_mode TEXT NOT NULL DEFAULT 'pentest';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS audit_config JSONB NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_tasks_task_mode
  ON tasks(task_mode, created_at DESC) WHERE deleted_at IS NULL;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe_id TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS code_path TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS code_line INT NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS code_symbol TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence REAL NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verification TEXT NOT NULL DEFAULT 'unverified';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dedupe_key TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS code_evidence JSONB NOT NULL DEFAULT '{}';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS audit_round INT NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS audit_phase TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_task_dedupe
  ON findings(task_id, dedupe_key) WHERE dedupe_key <> '';
CREATE INDEX IF NOT EXISTS idx_findings_cwe
  ON findings(task_id, cwe_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_verification
  ON findings(task_id, verification);

CREATE TABLE IF NOT EXISTS audit_sessions (
  id BIGSERIAL PRIMARY KEY,
  task_id BIGINT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'ingest',
  source_type TEXT NOT NULL,
  source_ref TEXT NOT NULL DEFAULT '',
  snapshot_path TEXT NOT NULL DEFAULT '',
  commit_sha TEXT NOT NULL DEFAULT '',
  repo_asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,
  depth TEXT NOT NULL DEFAULT 'deep',
  backend TEXT NOT NULL DEFAULT 'codegraph',
  languages TEXT[] NOT NULL DEFAULT '{}',
  engines JSONB NOT NULL DEFAULT '{}',
  plan JSONB NOT NULL DEFAULT '{}',
  round INT NOT NULL DEFAULT 1,
  max_rounds INT NOT NULL DEFAULT 5,
  gate_results JSONB NOT NULL DEFAULT '{}',
  stats JSONB NOT NULL DEFAULT '{}',
  report_md TEXT NOT NULL DEFAULT '',
  report_json JSONB NOT NULL DEFAULT '{}',
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_sessions_status
  ON audit_sessions(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS audit_phases (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
  round INT NOT NULL,
  phase TEXT NOT NULL,
  required BOOLEAN NOT NULL DEFAULT true,
  status TEXT NOT NULL DEFAULT 'pending',
  gate JSONB NOT NULL DEFAULT '{}',
  stats JSONB NOT NULL DEFAULT '{}',
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  UNIQUE(session_id, round, phase)
);

CREATE TABLE IF NOT EXISTS audit_coverage (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
  round INT NOT NULL,
  kind TEXT NOT NULL,
  language TEXT NOT NULL DEFAULT '',
  cwe TEXT NOT NULL DEFAULT '',
  module TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  line INT NOT NULL DEFAULT 0,
  symbol TEXT NOT NULL DEFAULT '',
  sink_key TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'planned',
  intent_id BIGINT,
  engine TEXT NOT NULL DEFAULT '',
  evidence JSONB NOT NULL DEFAULT '{}',
  reason TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(session_id, round, kind, sink_key)
);
CREATE INDEX IF NOT EXISTS idx_audit_cov_session_status
  ON audit_coverage(session_id, round, status);
CREATE INDEX IF NOT EXISTS idx_audit_cov_cwe
  ON audit_coverage(session_id, round, cwe, status);

CREATE TABLE IF NOT EXISTS audit_detection_intents (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
  round INT NOT NULL,
  intent_key TEXT NOT NULL,
  origin TEXT NOT NULL,
  language TEXT NOT NULL DEFAULT '',
  cwe TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT '',
  query_kind TEXT NOT NULL DEFAULT 'sink',
  sources JSONB NOT NULL DEFAULT '[]',
  sinks JSONB NOT NULL DEFAULT '[]',
  sanitizers JSONB NOT NULL DEFAULT '[]',
  propagators JSONB NOT NULL DEFAULT '[]',
  scope JSONB NOT NULL DEFAULT '{}',
  constraints JSONB NOT NULL DEFAULT '{}',
  preferred_engines JSONB NOT NULL DEFAULT '[]',
  priority INT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'planned',
  error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(session_id, round, intent_key)
);

CREATE TABLE IF NOT EXISTS audit_hypotheses (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
  round INT NOT NULL,
  hypothesis_key TEXT NOT NULL,
  statement TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'untested',
  attempts JSONB NOT NULL DEFAULT '[]',
  evidence TEXT NOT NULL DEFAULT '',
  priority INT NOT NULL DEFAULT 5,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(session_id, hypothesis_key)
);

CREATE TABLE IF NOT EXISTS audit_rounds (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
  round INT NOT NULL,
  new_findings INT NOT NULL DEFAULT 0,
  new_confirmed INT NOT NULL DEFAULT 0,
  new_candidate INT NOT NULL DEFAULT 0,
  total_findings INT NOT NULL DEFAULT 0,
  gate_c TEXT NOT NULL DEFAULT '',
  gate_cwe TEXT NOT NULL DEFAULT '',
  gate_h TEXT NOT NULL DEFAULT '',
  gate_e TEXT NOT NULL DEFAULT '',
  gate_coverage TEXT NOT NULL DEFAULT '',
  gate_engine TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL DEFAULT '',
  focus JSONB NOT NULL DEFAULT '{}',
  token_usage JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(session_id, round)
);

CREATE TABLE IF NOT EXISTS audit_engine_jobs (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
  intent_id BIGINT REFERENCES audit_detection_intents(id) ON DELETE CASCADE,
  engine TEXT NOT NULL,
  job_kind TEXT NOT NULL,
  query_hash TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  query_text TEXT NOT NULL DEFAULT '',
  query_path TEXT NOT NULL DEFAULT '',
  artifact_path TEXT NOT NULL DEFAULT '',
  result_count INT NOT NULL DEFAULT 0,
  duration_ms BIGINT NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  sarif JSONB NOT NULL DEFAULT '{}',
  provenance JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- NULLS NOT DISTINCT makes nil-intent jobs conflict on their natural key
-- (PostgreSQL 15+; Compose targets PG16). The guard migrates an earlier
-- NULLS DISTINCT constraint on databases initialized mid-task.
DO $$
DECLARE c record;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'audit_engine_jobs'::regclass
      AND conname = 'uq_audit_engine_jobs_key'
  ) THEN
    FOR c IN
      SELECT conname FROM pg_constraint
      WHERE conrelid = 'audit_engine_jobs'::regclass AND contype = 'u'
    LOOP
      EXECUTE format('ALTER TABLE audit_engine_jobs DROP CONSTRAINT IF EXISTS %I', c.conname);
    END LOOP;
    EXECUTE 'ALTER TABLE audit_engine_jobs ADD CONSTRAINT uq_audit_engine_jobs_key UNIQUE NULLS NOT DISTINCT (session_id, intent_id, engine, job_kind, query_hash)';
  END IF;
END $$;

-- repository asset type: self-skipping migration. Drop the original asset-type
-- CHECK precisely, then add a named one. Do NOT match every constraint containing
-- the word "type" — that would also drop service_type's CHECK. Once the named
-- check admits repository, repeated startup does no work.
DO $$
DECLARE c record;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'assets'::regclass
      AND conname = 'assets_type_check'
      AND pg_get_constraintdef(oid) LIKE '%repository%'
  ) THEN
    RETURN;
  END IF;
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'assets'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%''root_domain''%'
      AND pg_get_constraintdef(oid) LIKE '%''subdomain''%'
      AND pg_get_constraintdef(oid) LIKE '%''endpoint''%'
  LOOP
    EXECUTE format('ALTER TABLE assets DROP CONSTRAINT IF EXISTS %I', c.conname);
  END LOOP;
  EXECUTE 'ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_type_check';
  EXECUTE 'ALTER TABLE assets ADD CONSTRAINT assets_type_check CHECK (type IN (''root_domain'',''ip'',''subdomain'',''app'',''service'',''endpoint'',''repository''))';
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_repository
  ON assets(url) WHERE type = 'repository';
```

- [x] **Step 2: Extend task types**

`db/tasks.go`:

```go
const (
	TaskModePentest  = "pentest"
	TaskModeCodeAudit = "code_audit"
)

func ValidTaskMode(mode string) bool {
	return mode == TaskModePentest || mode == TaskModeCodeAudit
}

type Task struct {
	// existing fields...
	Mode       string          `json:"task_mode"`
	AuditConfig json.RawMessage `json:"audit_config,omitempty"`
}
```

Add `Mode`/`AuditConfig` to `TaskCreateOptions`, the INSERT, `taskCols`, and `scanTask`. Use `COALESCE(task_mode,'pentest')`, `COALESCE(audit_config,'{}'::jsonb)`.

- [x] **Step 3: Write `db/audit.go`**

Define persistence structs and methods:

```go
package db

type AuditSession struct {
	ID           int64           `json:"id"`
	TaskID       int64           `json:"task_id"`
	Status       string          `json:"status"`
	SourceType   string          `json:"source_type"`
	SourceRef    string          `json:"source_ref"`
	SnapshotPath string          `json:"snapshot_path"`
	CommitSHA    string          `json:"commit_sha"`
	RepoAssetID  *int64          `json:"repo_asset_id,omitempty"`
	Depth        string          `json:"depth"`
	Backend      string          `json:"backend"`
	Languages    []string        `json:"languages"`
	Engines      json.RawMessage `json:"engines"`
	Plan         json.RawMessage `json:"plan"`
	Round        int             `json:"round"`
	MaxRounds    int             `json:"max_rounds"`
	GateResults  json.RawMessage `json:"gate_results"`
	Stats        json.RawMessage `json:"stats"`
	ReportMD     string          `json:"report_md"`
	ReportJSON   json.RawMessage `json:"report_json"`
	StartedAt    *time.Time      `json:"started_at,omitempty"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// CreateAuditSession is idempotent by task_id: ON CONFLICT DO NOTHING +
// GetAuditSession returns the existing row on retries.
func (d *DB) CreateAuditSession(s AuditSession) (*AuditSession, error)
func (d *DB) GetAuditSession(taskID int64) (*AuditSession, error)
func (d *DB) UpdateAuditSession(taskID int64, upd AuditSessionUpdate) (*AuditSession, error)
func (d *DB) InsertAuditPhases(sessionID int64, round int, phases []AuditPhase) error
func (d *DB) ListAuditPhases(sessionID int64, round int) ([]AuditPhase, error)
func (d *DB) UpdateAuditPhase(sessionID int64, round int, phase string, upd AuditPhaseUpdate) error
func (d *DB) UpsertAuditCoverage(rows []AuditCoverage) error
func (d *DB) ListAuditCoverage(sessionID int64, round int) ([]AuditCoverage, error)
// MarkAuditCoverage is round-scoped so a re-plan cannot mark another round.
func (d *DB) MarkAuditCoverage(sessionID int64, round int, sinkKeys []string, status, reason string, intentID int64) error
// InsertAuditDetectionIntent is an upsert by (session, round, intent_key).
func (d *DB) InsertAuditDetectionIntent(i AuditDetectionIntent) (*AuditDetectionIntent, error)
func (d *DB) ListAuditDetectionIntents(sessionID int64, round int) ([]AuditDetectionIntent, error)
func (d *DB) UpdateAuditDetectionIntentStatus(sessionID int64, round int, intentKey, status, errMsg string) error
func (d *DB) UpsertAuditHypothesis(h AuditHypothesis) error
func (d *DB) ListAuditHypotheses(sessionID int64) ([]AuditHypothesis, error)
func (d *DB) InsertAuditRound(r AuditRound) error
func (d *DB) ListAuditRounds(sessionID int64) ([]AuditRound, error)
func (d *DB) UpsertAuditEngineJob(j AuditEngineJob) error
func (d *DB) ListAuditEngineJobs(sessionID int64) ([]AuditEngineJob, error)
```

Use `pgx`/`database/sql` conventions matching `db/findings.go` and `db/tasks.go`. For list methods, return `sql.ErrNoRows` as `(nil,nil)` where existing code does. `AuditPhase.Required` defaults to true on insert and `AuditHypothesis.Priority` defaults to 5 (bool/int zero values would otherwise bypass the SQL defaults).

- [x] **Step 4: Add DB test**

`db/audit_test.go`: use `testDSN(t)` (existing helper) and skip if PG unavailable. Create a task, insert session/phases/coverage/intent/hypothesis/round, read back, delete task, verify cascade.

```go
func TestAuditSessionRoundTrip(t *testing.T) {
	d := testDB(t) // use existing helper pattern from db tests
	task := mustCreateTask(t, d)
	s, err := d.CreateAuditSession(AuditSession{TaskID: task.ID, SourceType: "local", Depth: "deep", MaxRounds: 5})
	if err != nil { t.Fatal(err) }
	if s.Status != "ingest" { t.Fatalf("status=%s", s.Status) }
	...
}
```

Follow the exact helper names used in existing tests; if no `testDB` helper, copy the pattern from `db/finding_assets_test.go`.

**Archive compatibility:**
- `normalizeArchivedFindingVersions` backfills the ten new NOT NULL findings columns (`cwe_id`, `code_path`, `code_line`, `code_symbol`, `confidence`, `verification`, `dedupe_key`, `code_evidence`, `audit_round`, `audit_phase`) so pre-audit archives restore.
- Until M5 archives audit tables, archive creation/snapshot/finalization rejects `task_mode='code_audit'` with exported `ErrTaskArchiveUnsupported`.
- `findArchiveAssetNaturalID` restores `repository` assets by unique URL.

- [x] **Step 5: Run tests**

```bash
cd "D:/Codex/Projects/Artex/ARTEX"
go test ./db -run 'TestAudit|TestOpenSeed' -v
```

Expected: PASS when PG available; SKIP when unavailable. Compile must pass.

---

### Task 3: Task mode plumbing (DB/manager/server/DTO)

**Files:**
- Modify: `server/manager.go` (Task struct mirror + taskFromPG)
- Modify: `server/dto.go`
- Modify: `server/server.go` (`createTaskReq` + validation + launch)
- Modify: `server/orchestration.go` (spawn_task mode)
- Modify: `server/task_templates.go`, `db/task_templates.go` (template mode/config)
- Test: `server/audit_api_test.go` (compile + handler tests; DB skip)

- [ ] **Step 1: Mirror fields in manager Task**

Add `Mode string` and `AuditConfig json.RawMessage` to `server.Task`; copy from `pgdb.Task` in `taskFromPG`; update lifecycle snapshot only if needed (mode is immutable, so it can be a plain field).

- [ ] **Step 2: Extend createTaskReq**

```go
type auditConfigReq struct {
	SourceType string   `json:"source_type"`
	RepoURL    string   `json:"repo_url,omitempty"`
	Ref        string   `json:"ref,omitempty"`
	LocalPath  string   `json:"local_path,omitempty"`
	UploadID   string   `json:"upload_id,omitempty"`
	Depth      string   `json:"depth"`
	CWEScope   string   `json:"cwe_scope"`
	CWEIDs     []string `json:"cwe_ids,omitempty"`
	Languages  []string `json:"languages,omitempty"`
	MaxRounds  int      `json:"max_rounds"`
	Engines    map[string]string `json:"engines,omitempty"`
	Budgets    map[string]any    `json:"budgets,omitempty"`
	IncludeTests bool `json:"include_tests,omitempty"`
	IncludeVendor bool `json:"include_vendor,omitempty"`
}

type createTaskReq struct {
	// existing...
	TaskMode string          `json:"task_mode,omitempty"`
	Audit    *auditConfigReq `json:"audit,omitempty"`
}
```

Validation:

```go
if req.TaskMode == "" { req.TaskMode = db.TaskModePentest }
if !db.ValidTaskMode(req.TaskMode) { writeErr(w, 400, "无效的任务模式"); return }
if req.TaskMode == db.TaskModeCodeAudit {
	if req.Audit == nil { writeErr(w, 400, "代码审计任务缺少 audit 配置"); return }
	if err := validateAuditConfig(*req.Audit); err != nil { writeErr(w, 400, err.Error()); return }
	raw, _ := json.Marshal(req.Audit)
	opts.Mode, opts.AuditConfig = req.TaskMode, raw
} else if req.Audit != nil {
	writeErr(w, 400, "渗透测试任务不支持 audit 配置"); return
}
```

`validateAuditConfig` lives in `server/audit.go` (Task 12) but for this task implement a temporary pure function in `audit/config.go` with tests, and call it. Prefer `audit.ValidateConfig`.

- [ ] **Step 3: Extend TaskDTO**

```go
TaskMode    string          `json:"task_mode"`
AuditConfig json.RawMessage `json:"audit_config,omitempty"`
```

`taskDTO` copies from the Task. Ensure older tasks report `pentest`.

- [ ] **Step 4: Update spawn_task**

Add `task_mode`/`audit` to the spawn tool schema and pass through to `CreateTaskWithOptions`. Reject `code_audit` if the parent isn't code_audit unless explicitly configured (keep simple: allow, but require audit config).

- [ ] **Step 5: Update task templates**

- `task_templates` add `task_mode TEXT NOT NULL DEFAULT 'pentest'`, `audit_config JSONB NOT NULL DEFAULT '{}'`.
- Structs/inputs/patch/scan/INSERT/UPDATE.
- API request fields.
- Web types later.

- [ ] **Step 6: Tests**

`audit/config_test.go`:

```go
func TestValidateConfig(t *testing.T) {
	cases := []struct{ name string; cfg Config; want string }{
		{"git ok", Config{SourceType: "git", RepoURL: "https://example.com/a.git", Depth: "deep", MaxRounds: 5}, ""},
		{"git bad scheme", Config{SourceType: "git", RepoURL: "file:///etc/passwd", Depth: "deep"}, "git 仓库只允许 https 或 ssh"},
		{"local bad root", Config{SourceType: "local", LocalPath: "/tmp/x", Depth: "deep"}, "本地目录不在允许范围"},
	}
	for _, tc := range cases {
		err := ValidateConfig(tc.cfg, "/srv/code")
		got := ""
		if err != nil { got = err.Error() }
		if (tc.want == "") != (got == "") || (tc.want != "" && !strings.Contains(got, tc.want)) {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
```

Run `go test ./audit -run TestValidateConfig -v`.

- [ ] **Step 7: Checkpoint**

```bash
go test ./audit ./db ./server -run 'TestValidateConfig|TestAudit|TestOpenSeed' -v
go build ./cmd/artex
```

Expected: compile pass; DB tests skip/pass.

---

### Task 4: Source acquisition and snapshot

**Files:**
- Create: `audit/source.go`
- Create: `audit/zip.go`
- Test: `audit/source_test.go`
- Create: `audit/config.go`
- Test: `audit/config_test.go`

- [ ] **Step 1: Write failing tests**

`audit/source_test.go`:

```go
func TestPrepareLocalSnapshot(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "project")
	os.MkdirAll(filepath.Join(src, "src"), 0o755)
	os.WriteFile(filepath.Join(src, "src", "main.go"), []byte("package main\n"), 0o644)
	os.WriteFile(filepath.Join(src, "node_modules", "x.js"), []byte("x"), 0o644)
	out := filepath.Join(t.TempDir(), "snapshot")
	meta, err := PrepareSource(context.Background(), SourceConfig{
		Type: "local", LocalPath: src, AllowedRoots: []string{root},
	}, out)
	if err != nil { t.Fatal(err) }
	if meta.Language == "" { t.Fatal("expected language") }
	if _, err := os.Stat(filepath.Join(out, "src", "main.go")); err != nil { t.Fatal(err) }
	if _, err := os.Stat(filepath.Join(out, "node_modules")); !os.IsNotExist(err) { t.Fatal("node_modules should be excluded") }
}

func TestPrepareLocalRejectsEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	_, err := PrepareSource(context.Background(), SourceConfig{Type: "local", LocalPath: outside, AllowedRoots: []string{root}}, t.TempDir())
	if err == nil { t.Fatal("expected escape error") }
}

func TestSafeZipRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "x.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("../evil.txt")
	w.Write([]byte("x"))
	zw.Close(); f.Close()
	err := ExtractZip(zipPath, filepath.Join(dir, "out"), ZipLimits{MaxFiles: 10, MaxBytes: 1 << 20, MaxFileBytes: 1 << 20})
	if err == nil { t.Fatal("expected traversal error") }
}
```

- [ ] **Step 2: Implement config validation**

`audit/config.go`:

```go
type Config struct {
	SourceType string `json:"source_type"`
	RepoURL string `json:"repo_url,omitempty"`
	Ref string `json:"ref,omitempty"`
	LocalPath string `json:"local_path,omitempty"`
	UploadID string `json:"upload_id,omitempty"`
	Depth string `json:"depth"`
	CWEScope string `json:"cwe_scope"`
	CWEIDs []string `json:"cwe_ids,omitempty"`
	Languages []string `json:"languages,omitempty"`
	MaxRounds int `json:"max_rounds"`
	Engines map[string]string `json:"engines,omitempty"`
	Budgets map[string]any `json:"budgets,omitempty"`
	IncludeTests bool `json:"include_tests,omitempty"`
	IncludeVendor bool `json:"include_vendor,omitempty"`
}

func ValidateConfig(c Config, allowedRoots []string) error
```

Rules: source type, git URL scheme, local root containment (lexical; `EvalSymlinks` at runtime), zip upload id, depth enum, cwe_scope enum, max rounds clamp/validation, deep+codegraph off reject.

- [ ] **Step 3: Implement snapshot**

`audit/source.go`:

```go
type SourceConfig struct {
	Type string
	RepoURL, Ref, LocalPath, UploadPath string
	AllowedRoots []string
	IncludeVendor, IncludeTests bool
	MaxBytes int64
	MaxFiles int
}

type SourceMeta struct {
	Type string `json:"type"`
	Ref string `json:"ref,omitempty"`
	Commit string `json:"commit_sha,omitempty"`
	SourceRef string `json:"source_ref"`
	Language string `json:"language,omitempty"` // primary language
	Languages []string `json:"languages,omitempty"`
	Bytes int64 `json:"bytes"`
	Files int `json:"files"`
	SnapshotPath string `json:"snapshot_path"`
	Warnings []string `json:"warnings,omitempty"`
}

func PrepareSource(ctx context.Context, cfg SourceConfig, dst string) (SourceMeta, error)
```

- Git: `git clone --depth=1 --no-recurse-submodules --single-branch --branch <ref>` (fallback clone then checkout for commit); env as spec; `git rev-parse HEAD`; `.git` never enters the snapshot. Snapshot copy excludes `.git`, `node_modules`, `vendor`, build output, and tests/`testdata` unless configured.
- Git/URL credentials: reject literal and percent-encoded userinfo containing `:`, `@`, or control characters (`ssh://user%3Apass@host`, `ssh://user%40host@host`); redaction drops or strips credential-shaped userinfo before persisting `SourceRef`.
- Local: resolve lexical paths and real symlink/junction targets; validate root containment, walk and copy regular files only, skip excluded dirs, reject symlinks pointing outside, and never follow links inside the snapshot.
- Zip: call `ExtractZip`, prune excluded paths, then treat as snapshot root. `MaxFiles` bounds total archive entries (files and directories), not just regular files.
- Snapshot permissions: directories 0755 and source files read-only 0444. Directory writability intentionally allows CodeGraph (and other engines) to create their own metadata such as `.codegraph` under the snapshot root without modifying source files.

- [ ] **Step 4: Implement safe zip**

Reject:
- entries with absolute path, `..`, drive letter, backslash traversal, Windows reserved device names;
- symlinks/hardlinks (mode bits), device files;
- duplicate files, duplicate directories, and file/directory collisions;
- uncompressed total > MaxBytes, total entries (directories included) > MaxFiles, single > MaxFileBytes, compression ratio > 100x.
Use `io.CopyN` and check.

- [ ] **Step 5: Run tests**

```bash
go test ./audit -run 'TestPrepare|TestSafeZip|TestValidateConfig' -v
```

Expected: PASS.

---

### Task 5: Language/profile detection and audit plan

**Files:**
- Create: `audit/profile.go`
- Test: `audit/profile_test.go`
- Create: `audit/plan.go`
- Test: `audit/plan_test.go`

- [ ] **Step 1: Tests**

`profile_test.go` builds a temp tree with `pom.xml`, `src/main/java/A.java`, `package.json`, `src/app.ts`; expects languages `java` and `typescript`, framework/build info, and module roots. Also test that an empty/no-identifiable-language source returns an empty profile without error, and `BuildPlan` then fails with `无法确定审计语言`.

`plan_test.go`: given registry + languages + depth, expects phases required matrix, CWE scope counts (core 26; full > 100), and candidate intents for S1/S2.

- [ ] **Step 2: Implement profile**

```go
type Profile struct {
	Languages []string
	Primary string
	BuildSystems []string
	Frameworks []string
	Modules []string
	ProductType string // web-application|microservice|sdk-library|desktop-client|mobile-app|middleware-plugin|cli-tool|embedded-firmware
	FileCount int
	Bytes int64
	Warnings []string
	Truncated bool
}

func ProfileSource(root string, limits PrescanLimits) (Profile, error)
```

- Extension counts + build file signals.
- Ignore `.git`, `node_modules`, `vendor`, `dist`, `build`, test dirs unless included.
- Enforce `limits.MaxFiles` by stopping with `Truncated=true` and a warning; skip files over `limits.MaxFileBytes` with warnings/counts. Empty/no-identifiable-language sources return an empty profile without error; `BuildPlan` then rejects with `无法确定审计语言`.
- Modules: top-level directory names containing source files (max 50, sorted).
- ProductType values follow the design enum above.

- [ ] **Step 3: Implement plan**

```go
type PhasePlan struct {
	Phase string `json:"phase"`
	Required bool `json:"required"`
}

type Plan struct {
	Phases []PhasePlan `json:"phases"`
	PlannedCWEs map[string][]string `json:"planned_cwes"` // language -> CWE
	Modules []string `json:"modules"`
	EntryPoints []string `json:"entry_points"`
	MaxRounds int `json:"max_rounds"`
	Depth string `json:"depth"`
}

func BuildPlan(profile Profile, cfg Config, reg Registry) (Plan, error)
```

Core CWE list constant (26). Full scope: registry CWE applicable to language + Odin rule CWEs + taint CWEs, deduped, sorted. Phase depths per spec Appendix E.

- [ ] **Step 4: Run tests**

```bash
go test ./audit -run 'TestProfile|TestBuildPlan' -v
```

---

### Task 6: Sink prescan and coverage plan

**Files:**
- Create: `audit/prescan.go`
- Test: `audit/prescan_test.go`
- Create: `audit/coverage.go`
- Test: `audit/coverage_test.go`

- [ ] **Step 1: Tests**

`prescan_test.go`: temp tree with Java file containing `stmt.executeQuery(...)` and `safe()`; scan CWE-89; expect one site with path/line/symbol and a stable sink key; scanning a second time yields identical keys; cap respected.

`coverage_test.go`: build coverage rows and assert formulas/statuses and gate thresholds.

- [ ] **Step 2: Implement prescan**

```go
type SinkSite struct {
	Language string
	CWE string
	Path string
	Line int
	Symbol string
	SinkKey string
}

type PrescanLimits struct {
	MaxFiles int
	MaxFileBytes int64
	MaxSitesPerCWE int
	IncludeTests bool
	IncludeVendor bool
}

type PrescanStats struct {
	SkippedSymbols int
	TruncatedCWEs []string
	FileLimitReached bool
	SkippedLargeFiles int
	SkippedLongLines int
	SkippedBinaryOrMinified int
	SiteCapCWEs []string
}

type PrescanResult struct { Sites []SinkSite; Stats PrescanStats }

func Prescan(root string, profile Profile, plan Plan, reg Registry, limits PrescanLimits) (PrescanResult, error)
// PrescanSites remains a convenience wrapper returning []SinkSite.
```

- Walk source files; language by extension.
- For each CWE in plan for that language, collect `kind=sink` definitions; take last symbol segment; filter length <4 or generic names; build regex `\b(sym1|sym2)\b`; run per line.
- Dedup; cap per CWE and record `SiteCapCWEs`; sort by path/line.
- Exclude `.git`, binaries, huge files, minified files, vendor/test by config.
- Record omissions in `PrescanStats`: `FileLimitReached`, `SkippedLargeFiles`, `SkippedLongLines`, `SkippedBinaryOrMinified`, symbol/site caps.
- `SinkKey = sha256(language|cwe|path|line|symbol)` hex.

- [ ] **Step 3: Implement coverage**

```go
type CoverageCounts struct {
	CWE, SinkSites, Modules, EntryPoints float64
	PlannedCWE, CoveredCWE int
	PlannedSites, CoveredSites int
	PlannedModules, CoveredModules int
	PlannedEntries, CoveredEntries int
	InvalidExemptions int
}

func ComputeCoverage(plan Plan, rows []CoverageRow) CoverageCounts
func Thresholds(depth string) CoverageThresholds
func GateCoverage(plan Plan, rows []CoverageRow, depth string) GateResult
```

Status covered = `scanned|candidate|benign|exempt`; `planned|missed` not covered. Exempt only counts when `Reason` is `category` or `category: detail`, case-insensitive, where category is one of `language_not_applicable|no_sinks|index_unavailable|budget_exhausted|generated_code|test_code|unsupported_engine`; invalid exemptions increment `InvalidExemptions` and are reported/failed by Gate-Coverage. Gate-Phase requires a non-empty reason for skipped/exempt required phases and fails required phases with more than 2 attempts.

- [ ] **Step 4: Run tests**

```bash
go test ./audit -run 'TestPrescan|TestCoverage' -v
```

---

### Task 7: Evidence schema, dedupe, and finding recording

**Files:**
- Create: `audit/evidence.go`
- Test: `audit/evidence_test.go`
- Modify: `db/findings.go` (add code finding insert with dedupe)
- Modify: `db/finding_traffic.go` (`RecordFindingInput` extension)
- Modify: `server/dto.go` (finding DTO fields)
- Test: `db/audit_findings_test.go` (DB skip)

- [ ] **Step 1: Tests**

`evidence_test.go`:

```go
func TestValidateCodeEvidence(t *testing.T) {
	ev := CodeEvidence{
		CWEID: "CWE-89", Severity: "high", Confidence: 0.9,
		Location: CodeLocation{Path: "src/A.java", Line: 42, Symbol: "A.find"},
		Source: CodeLocation{Symbol: "getParameter"},
		Sink: CodeLocation{Path: "src/A.java", Line: 42, Symbol: "executeQuery"},
		Trace: []TraceStep{{Path: "src/A.java", Line: 42, Symbol: "A.find"}},
		Sanitizers: []SanitizerVerdict{{Symbol: "setString", Verdict: "missing"}},
		Verification: Verification{Status: "confirmed", Method: "taint_trace"},
	}
	if err := ValidateCodeEvidence(ev, "confirmed"); err != nil { t.Fatal(err) }
	ev.Sanitizers[0].Verdict = "unknown"
	if err := ValidateCodeEvidence(ev, "confirmed"); err == nil { t.Fatal("expected sanitizer error") }
}

func TestDedupeKey(t *testing.T) {
	k1 := DedupeKey("CWE-89", "/a/../src/A.java", 42, "java.sql.Statement.executeQuery")
	k2 := DedupeKey("CWE-89", "src/A.java", 42, "executeQuery")
	if k1 != k2 { t.Fatalf("%s != %s", k1, k2) }
}
```

- [ ] **Step 2: Implement types/validation**

Define `CodeEvidence`, `CodeLocation`, `TraceStep`, `SanitizerVerdict`, `Verification`, `EngineEvidence`, `POCEvidence`. Implement path canonicalization (backslashes → slash, `path.Clean`, strip root/Windows drive prefixes; strict validation rejects absolute, drive and `..`-escaping paths), short symbol (last two segments), dedupe key, size cap, required fields per verification status, confidence range, CWE regex. `MarshalCodeEvidence` always overwrites `DedupeKey` with the canonical `CWE|path|line|sink_symbol` value — a supplied key is never trusted. High/critical confirmed findings additionally require `reachability.entry_point`, `reachability.auth_state_recorded`, and each engine hit must carry both `name` and `raw_ref`.

- [ ] **Step 3: Add DB method**

```go
type CodeFindingInput struct {
	TaskID int64
	NodeID int64
	CWEID, Title, Severity, Summary, Evidence, Worker string
	CodePath string
	CodeLine int
	CodeSymbol string
	Confidence float64
	Verification string
	DedupeKey string
	CodeEvidence json.RawMessage
	AuditRound int
	AuditPhase string
	AssetIDs []int64
}

func (d *DB) AddCodeFinding(in CodeFindingInput) (id int64, existing bool, err error)
```

Use `INSERT ... ON CONFLICT (task_id, dedupe_key) WHERE dedupe_key <> '' DO NOTHING RETURNING id`, then select existing. Must handle `task_id IS NULL` (dedupe index allows multiple null task ids; code findings always have task). Both `RecordFindingTx` and `AddCodeFinding` recompute the key from `CWEID/CodePath/CodeLine/CodeSymbol` via `audit.DedupeKey`; a supplied mismatched or empty key is ignored whenever code identity is present. Findings without code identity keep the legacy supplied key so pentest behavior is unchanged. Persistence rejects `code_evidence` larger than 256 KiB (`audit.MaxCodeEvidenceBytes`) with `audit.ErrCodeEvidenceTooLarge`. Update `RecordFindingInput` with the new fields and pass through `RecordFindingTx` so the graph node payload includes code evidence.

- [ ] **Step 4: Update DTO**

Add to `FindingDTO`: `cwe_id`, `code_path`, `code_line`, `code_symbol`, `confidence`, `verification`, top-level `engines` (`FindingEngineDTO`), and `code_evidence` (detail only). List/page/per-task/inherited/export/status-patch responses keep the compact fields and engine hits but omit `code_evidence`; `GET /api/exploration/findings/{id}` includes it. Update `findingPayload`/`findingFromDB` and the per-task `findingDTO` conversion accordingly. Keep `evidence` text compatibility.

- [ ] **Step 5: Run tests**

```bash
go test ./audit -run 'TestCodeEvidence|TestDedupe' -v
go test ./db -run TestCodeFinding -v
go build ./...
```

---

### Task 8: CodeGraph client wrapper

**Files:**
- Create: `audit/codegraph.go` (or `audit/engines/codegraph.go`)
- Test: `audit/codegraph_test.go`
- Modify: `agent/codeaudit_tools.go` (tools consume the wrapper)

- [ ] **Step 1: Tests**

Use a fake `MCPCaller` interface:

```go
type MCPCaller interface {
	Call(ctx context.Context, tool string, args map[string]any) (string, error)
}
```

Test:
- projectPath injected when omitted;
- cache hit avoids second call;
- third identical hit prefixes warning;
- per-result 15K truncation and cumulative 60K budget;
- errors not cached.

- [ ] **Step 2: Implement**

```go
type CodeGraphClient struct {
	projectPath string
	caller MCPCaller
	mu sync.Mutex
	cache map[string]string
	counts map[string]int
	cumulative int
}

func (c *CodeGraphClient) Explore(ctx context.Context, query string, maxFiles int) (string, error)
```

- Normalize Windows path with `filepath.Abs`/`filepath.ToSlash` as needed by CodeGraph (use absolute native path for MCP).
- Cache key `explore|query|maxFiles`; max 512 FIFO.
- Truncate per result; cumulative budget resets per agent loop (create a per-run wrapper).
- If MCP unavailable, return typed error so tools can fall back.

- [ ] **Step 3: Add stdio connection**

Server-side factory:

```go
func StartCodeGraphMCP(ctx context.Context, bin, projectPath string) (*mcp.Client, error)
```

- `exec.LookPath(bin)`; on Windows use `.cmd` automatically via exec.
- `mcp.NewStdioClient(ctx, "codegraph", bin, nil, "serve", "--mcp", "-p", projectPath)`.
- Cache per task; close on task stop.
- If `bin` empty, use `codegraph`; return actionable error.

- [ ] **Step 4: Run tests**

```bash
go test ./audit -run TestCodeGraph -v
```

---

### Task 9: Audit tools and restricted worker surface

**Files:**
- Create: `agent/codeaudit_tools.go`
- Test: `agent/codeaudit_tools_test.go`
- Modify: `agent/tools.go` (ToolSet fields/constructor)
- Modify: `agent/worker.go` (mode branch)
- Modify: `agent/planner.go` (mode branch)
- Modify: `agent/toolcatalog.go` (seed audit tools)
- Modify: `server/assembly.go` (tool bindings)

- [ ] **Step 1: Add audit ToolSet**

```go
type AuditDeps interface {
	ValidateFinding(ctx context.Context, in db.CodeFindingInput) (id int64, existing bool, err error)
	UpdateVerification(ctx context.Context, taskID, findingID int64, verification, method, evidence, altPath string, confidence *float64) error
	RecordHypothesis(ctx context.Context, taskID int64, in audit.HypothesisInput) error
	CompleteIntent(ctx context.Context, taskID, intentID int64, coverage []audit.CoverageReceipt, stats map[string]any) error
	AssignedCoverage(ctx context.Context, taskID, intentID int64) ([]audit.CoverageRow, error)
	ClaimAuditCoverage(ctx context.Context, taskID, intentID int64, sinkKeys []string) error
	WriteArtifact(ctx context.Context, taskID int64, relPath string, content []byte) (string, error)
	AuditProgress(ctx context.Context, taskID int64) (audit.Progress, error)
}

func (t *ToolSet) SetAuditDeps(d AuditDeps)
func (t *ToolSet) AuditWorkerTools() []actool.CoreTool
func (t *ToolSet) AuditPlannerTools() []actool.CoreTool
```

Tool names/schemas per spec. Use `readExpTool`/`writeExpTool` helpers. All writes update `t.writes` counters and notify planner.

- [ ] **Step 2: CodeGraph tools**

Implement `codegraph_explore`, `codegraph_node`, `codegraph_files`, `codegraph_callers`, `codegraph_callees`, `codegraph_impact`, `code_search`, `code_read`. For M1, `codegraph_explore` uses the wrapper; CLI commands use `exec.CommandContext` with a fixed binary and args, output capped. `code_search`/`code_read` use the snapshot root passed via tool context (add `auditSourceRoot` to ToolSet).

- [ ] **Step 3: Restrict worker tools**

In `Worker.execute`:

```go
if w.auditMode {
    base = tsx.AuditWorkerTools()
} else {
    base = append(tsx.WorkerTools(), w.extraTools...)
    base = append(base, defaultToolsExcept("MultiEdit", "Glob", "Grep")...)
}
```

Audit mode must call neither `AugmentTools` nor `ToolAugment`/`ToolResolve`: use the curated base directly with zero `DeferredInfo` and a no-op cleanup (only `guardPanic` wrapping is allowed). This prevents agent_visibility MCP/skills, interactive_shell, host tools, and DB tool bindings from injecting shell/network tools. Do not append default tools; no WebFetch/WebSearch; no proxy env. Keep `ModeBypass` only because the curated list is the security boundary, and document that. Force the audit identity defaults (`code_worker`/`code_planner`). Add `Worker.SetAuditMode(bool)`, `Worker.SetAuditDeps(AuditDeps)`, `Worker.SetAgentKey(string)`.

In `Planner.Plan`:

```go
if p.auditMode {
    base = tsx.AuditPlannerTools()
} else {
    base = append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
}
```

Add `Planner.SetAuditMode`, `SetAgentKey`.

- [ ] **Step 4: Seed tools and bindings**

Add to `builtinToolsByAgent`:

```go
"code_worker": ts.AuditWorkerTools(),
"code_planner": ts.AuditPlannerTools(),
```

Add `defaultUnbound` entries for audit-only tools that should not leak to pentest agents. Seed via existing `wireTools`.

Tool rows are insert-only: existing DBs may not have `code_worker`/`code_planner` in the shared tools' bindings. This does NOT affect audit runtime because audit mode bypasses `ToolResolve`; new DBs still seed the catalog/UI bindings. No binding migration is required for audit correctness (document this in the spec). If the curated-list bypass is ever removed, add an idempotent migration that appends the audit keys to the relevant shared rows.

- [ ] **Step 5: Tests**

Unit tests for schema validation, dedupe, audit_intent_complete ownership check, artifact path escape/size cap, code_read escape, CodeGraph cache. Use fake AuditDeps. No DB required. Add regression tests that fake `ToolAugment`/`ToolResolve` cannot inject Bash/Read/shell/MCP tools into audit assembly, that audit agent-key defaults are forced, and that a marker-containing user prompt cannot suppress the code-owned safety blocks.

```bash
go test ./agent -run 'TestAudit|TestCodeGraph|TestArtifact' -v
```

#### Audit boundary implementation notes (Tasks 12-13)

- Audit mode never calls `AugmentTools`/`ToolAugment`/`ToolResolve`. The curated `AuditWorkerTools`/`AuditPlannerTools` list is used directly (zero `DeferredInfo`, no-op cleanup, optional `guardPanic` wrapping). Agent visibility, interactive shell, MCP/skills, host tools, and the DB tools table cannot add tools.
- Audit sessions set `DisableBackgroundTasks: true`. Without it, `agentcore.NewSession` auto-adds `TaskOutput/TaskStop/TaskList/Monitor`; `Monitor` can spawn arbitrary shell commands and `ModeBypass` would allow them. `DisallowedTools` additionally blocks Monitor, the background-task tools, Bash/Read/Write/Edit/MultiEdit/WebFetch/WebSearch, and the shell_* tools as defense in depth.
- Forced identities: audit Worker defaults to `code_worker`, audit Planner defaults to `code_planner` even when no agent key is set; pentest defaults stay `worker`/`planner`.
- The code-owned audit discipline/protocol block is ALWAYS appended. Marker-based suppression is forbidden; duplicate text is acceptable and a DB prompt edit cannot remove the safety instructions.
- `add_intent` accepts an optional `audit` object; when `audit.sink_keys` is non-empty the tool calls `ClaimAuditCoverage` after creating the node. S4 with empty `sink_keys` is rejected (nothing to scan); S1/S2/S3/S5+ may omit keys.
- `ClaimAuditCoverage` requires `audit.round == audit_sessions.round`, every key present in the round and `intent_id IS NULL`, rejects partial/unknown/already-owned sets atomically, assigns all keys, and canonicalizes the intent payload.
- `audit_assigned_coverage` gives a worker the exact coverage rows assigned to its intent; receipts may cover only a batch of them.
- `audit_intent_complete` rejects receipts outside the intent's assigned set and validates `candidate` `finding_id` existence/ownership through AuditDeps/server. When the intent reaches any terminal state (including done), the director releases still-planned/missed rows back to the candidate pool and emits an activity; completed verdicts stay attached.
- `audit_artifact_write` rejects content larger than 10 MiB. Paths additionally reject Windows ADS (`:`), reserved device names (CON/PRN/AUX/NUL/COM1..COM9/LPT1..LPT9/CLOCK$ etc., including extension forms), path segments ending in dot/space, and control characters.
- Every audit worker run calls `AuditCodeGraph.ResetLoopBudget()` before its first query, so a shared task-scoped CodeGraph client gets a fresh per-intent context budget.
- `WriteCounts` tracks verifications, hypotheses, coverage receipts and artifacts; `Total()` includes them so an audit intent with writes is not treated as no-output. Verification/hypothesis/intent-complete writes call the generic planner wake when the engine wires `Worker.SetNotify`; artifact writes are counted but intentionally quiet.

---

### Task 10: Agent roles, prompts, and per-task agent selection

**Files:**
- Modify: `db/db.go` (`builtinAgents`)
- Modify: `agent/promptcatalog.go`
- Modify: `agent/prompt.go` (PlannerVars/WorkerVars or new audit vars)
- Modify: `server/task_llm.go` (`agentsForTask` mode selection)
- Modify: `server/goals.go` (`startTaskEngine` branch)
- Test: `agent/prompt_test.go`, `db/db_test.go`

- [ ] **Step 1: Add built-in agents**

```go
{"code_planner", "代码审计规划", "planner", "读取审计进度与门禁，派发下一步代码审计意图；不读代码、不执行审计。", nil, false, nil},
{"code_worker", "代码审计执行", "worker", "领取一条代码审计意图，用 CodeGraph 做符号/调用链/源码分析并写回结构化证据。", nil, false, nil},
```

Add prompt seeds `code_planner`, `code_worker` to `BuiltinPromptSeeds`.

- [ ] **Step 2: Write prompts**

`codePlannerDefaultTmpl` must include:
- Role: audit dispatcher, not executor.
- Read `audit_progress`; candidates and gates.
- Dispatch 0–4 intents; hard bottom line; use todolist.
- Cannot prove while `ready_to_complete=false`.
- No code tools.

`codeWorkerDefaultTmpl` must include:
- Code is data; no execution/network/build.
- CodeGraph-only (or fallback tools).
- Evidence requirements; engine results are candidates.
- Complete intent with coverage receipt.
- Artifact path limits.

- [ ] **Step 3: Per-task selection**

In `agentsForTask`:

```go
plannerKey, workerKey := "planner", "worker"
if t.Mode == db.TaskModeCodeAudit {
    plannerKey, workerKey = "code_planner", "code_worker"
}
plannerRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: plannerKey}
workerRuntime := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: workerKey}
wk := agent.NewWorker(workerRuntime, "task-router", ...)
wk.SetAgentKey(workerKey)
wk.SetAuditMode(t.Mode == db.TaskModeCodeAudit)
...
pl := agent.NewPlanner(plannerRuntime, ...)
pl.SetAgentKey(plannerKey)
pl.SetAuditMode(t.Mode == db.TaskModeCodeAudit)
```

Update `taskRuntimeAvailable(t, plannerKey, workerKey)` callers (search for `"planner","worker"`).

- [ ] **Step 4: Bootstrap branch**

`startTaskEngine`:

```go
if t.Mode == db.TaskModeCodeAudit {
    s.startCodeAudit(t)
    return
}
```

`startCodeAudit` is implemented in Task 11; for now stub returning an error/activity.

- [ ] **Step 5: Tests**

- `db` seed test expects new agent count and prompt rows.
- `agent` prompt render tests for the new keys.
- Server test that a code task uses `code_planner`/`code_worker` (can inspect `agentsForTask` with a fake task and no DB? It needs server; use existing test fixture).

Run:

```bash
go test ./agent ./db -run 'TestPrompt|TestOpenSeed' -v
go build ./...
```

---

### Task 11: Audit director core

**Files:**
- Create: `server/audit_director.go`
- Create: `audit/director.go` (pure state helpers)
- Test: `server/audit_director_test.go`
- Test: `audit/director_test.go`
- Modify: `server/server.go` (wire director, stop on delete)
- Modify: `server/goals.go` (`startCodeAudit`)

- [ ] **Step 1: Define director API**

```go
type AuditDirector struct {
	s *Server
	mu sync.Mutex
	runs map[string]*auditRun
}

type auditRun struct {
	cancel context.CancelFunc
	done chan struct{}
}

func (s *Server) startCodeAudit(t *Task) error
func (d *AuditDirector) Start(ctx context.Context, t *Task) error
func (d *AuditDirector) OnIntentDone(t *Task, intent *db.Node)
func (d *AuditDirector) Stop(taskID string)
func (d *AuditDirector) Progress(ctx context.Context, taskID int64) (audit.Progress, error)
```

- [ ] **Step 2: Ingest + plan**

`Start`:
1. `CreateAuditSession` (idempotent).
2. `PrepareSource` into `<workdir>/tasks/<taskID>/audit/source` (git/local/zip; zip upload path from staging).
3. `ProfileSource`.
4. Start CodeGraph MCP + run `codegraph init`/`index` (via `audit/codegraph` runner), record engine state.
5. `BuildPlan` + `Prescan`; bulk insert coverage (CWEs, sites, modules initially from profile).
6. Upsert session (status `running`, languages, plan, engines, round=1).
7. Insert phases for round 1.
8. Create one goal (`"完成对 <source> 的静态代码审计"` via `t.Store.AddNode(db.KindGoal, ...)`).
9. Seed S1/S2 intents using `t.Store.AddIntent` with payload:
```json
{"summary":"...","audit":{"phase":"S1","round":1,"cwe":"","language":"java","scope":{"modules":["..."]},"deliverables":["..."],"sink_keys":[]}}
```
10. `s.engine.Run(s.ctx, t)`.

- [ ] **Step 3: Intent observer**

Add `Engine.SetIntentObserver` hook in `server/engine.go`; call after final intent state write in `runIntent`/`runWorkerStep` for done/blocked/exhausted/stopped. Wire to director in `Server.New`.

- [ ] **Step 4: Coverage updates**

On any terminal intent state:
- Parse intent payload audit fields; phase completion counts only intents whose payload round equals the session round.
- Release still-planned/missed coverage rows with `db.ReleaseAuditCoverage(session, round, intentID)` for done/blocked/exhausted/stopped/deleted, emit an activity with the released count, and leave scanned/candidate/benign/exempt verdicts attached.
- If worker completed via `audit_intent_complete` (audit receipts stored), update the receipted coverage rows; partial batches are allowed and unreceipted rows are reclaimed at terminal cleanup.
- Update phase stats/status only when every current-round phase intent is terminal; all-done closes `done`, any non-done terminal closes `failed`.
- Recompute gates; write `audit_phases`, `audit_rounds`.
- Notify planner.

For M1, implement simple phase completion by counting intents for the phase (done vs active). Full gates in Task 13.

- [ ] **Step 5: Stop/delete**

`Stop(taskID)` cancels director context, closes CodeGraph client; hook into `Manager`/`engine.StopTask` or delete path. On server shutdown, stop all runs.

- [ ] **Step 6: Tests**

Pure tests in `audit/director_test.go` for phase planning/seeding payload; server tests for `Start` with a fake source runner or local temp dir and no PG skip. Do not require CodeGraph for the basic test; inject a `CodeGraphPreparer` interface fake.

Run:

```bash
go test ./audit ./server -run 'TestDirector|TestStartCodeAudit' -v
```

---

### Task 12: API endpoints and audit_progress

**Files:**
- Create: `server/audit.go` (handlers)
- Modify: `server/server.go` (routes)
- Create: `audit/progress.go`
- Test: `server/audit_api_test.go`, `audit/progress_test.go`

- [ ] **Step 1: Progress computation**

`audit.Progress` struct per spec. `BuildProgress(session, phases, coverage, intents, findings, hypotheses, engines, budget)` pure function. Tests for counts/gates/ready flag.

- [ ] **Step 2: Routes**

```go
mux.HandleFunc("GET /api/tasks/{id}/audit/progress", s.auditProgress)
mux.HandleFunc("GET /api/tasks/{id}/audit/report", s.auditReport)
mux.HandleFunc("GET /api/tasks/{id}/audit/source/file", s.auditSourceFile)
mux.HandleFunc("GET /api/tasks/{id}/audit/engines", s.auditEngines)
mux.HandleFunc("GET /api/audit/capabilities", s.auditCapabilities)
```

- `auditProgress`: resolve task, require code_audit, build and return.
- `auditReport`: return MD/JSON; 409 if not ready.
- `auditSourceFile`: path confined to `<workdir>/tasks/<id>/audit/source`; line range; binary/size checks.
- `auditEngines`: return session engines + jobs (empty in M1).
- `auditCapabilities`: probe binaries via `exec.LookPath`, versions; read settings; no secrets.

- [ ] **Step 3: Settings**

Add settings keys with defaults: `audit.codegraph_bin`, `audit.codeql_bin`, `audit.joern_bin`, `audit.local_roots`, `audit.max_source_bytes`, etc. A helper `s.auditSettings()` reads DB with env fallback. Tests for parsing roots.

- [ ] **Step 4: Tests**

Handler tests with `httptest` and JWT per existing fixture; skip DB when unavailable. Pure tests for progress/source file path.

---

### Task 13: Gates and multi-round loop (M2 core)

**Files:**
- Modify: `audit/coverage.go` (gates)
- Create: `audit/gates.go`
- Test: `audit/gates_test.go`
- Modify: `server/audit_director.go`
- Test: `server/audit_director_test.go`

- [ ] **Step 1: Implement gates**

Functions:
```go
func GatePhase(phases []AuditPhase) GateResult
func GateCWE(plan Plan, cov []AuditCoverageRow) GateResult
func GateC(gateCWE, gateCoverage GateResult, newFindings int, zeroStreak, round, maxRounds int, activeIntents, unverifiedHigh int) GateResult
func GateH(hs []AuditHypothesis, findings int) GateResult
func GateEvidence(ev CodeEvidence) GateResult
```

Match spec thresholds/formulas. Return `{Name, Passed, Reason, Details}`.

- [ ] **Step 2: Round review**

On no active intents and required phases done:
- Compute gates, insert `audit_rounds`.
- If converged → status `reporting`, generate report.
- Else increment round, insert phases, generate focused candidate coverage/intents (missing CWE/sites; unverified high), notify planner.
- Max rounds → forced converge with gaps.

- [ ] **Step 3: prove_goal guard**

In `ToolSet.proveGoal`, if task mode code_audit:
```go
progress, err := t.auditDeps.AuditProgress(ctx, t.taskID)
if err != nil { return error }
if !progress.ReadyToComplete { return error with missing gates }
```
The guard needs access to task mode; add `AuditDeps.IsCodeAudit(ctx, taskID) (bool,error)` or `AuditProgress` returns `Mode`. Use progress.

- [ ] **Step 4: Completion fallback**

Director monitors: report ready + no active intents for 2 heartbeats → mark goal met via `t.Store`/`ProveGoal` equivalent, activity `origin=system`. Implement in director goroutine.

- [ ] **Step 5: Tests**

Pure gate tests with table-driven cases: thresholds, exemptions, zero streak, max rounds, unverified high, engine gaps. Director round review tests with fakes.

---

### Task 14: Report generation

**Files:**
- Create: `audit/report.go`
- Test: `audit/report_test.go`
- Modify: `server/audit.go`

- [ ] **Step 1: Tests**

Build a session with confirmed/candidate/refuted findings, coverage, gates, rounds, hypotheses, queries; assert Markdown contains required sections and JSON round-trips; assert no secret leaks.

- [ ] **Step 2: Implement**

`BuildReport(input ReportInput) (md string, js json.RawMessage, err error)`. Use Go templates or strings.Builder. Include severity/CWE tables, per-finding evidence, code snippet (read ±6 lines from snapshot, capped), coverage/gaps, rounds, gates, hypotheses, engine queries. Escape Markdown code fences.

- [ ] **Step 3: Persist**

Director calls `BuildReport`, writes `audit/report.md`/`report.json`, updates session. `auditReport` handler serves it.

---

### Task 15: Web types/API and create-task UI

**Files:**
- Modify: `web/src/lib/types.ts`
- Modify: `web/src/lib/api.ts`
- Modify: `web/src/app/(main)/function/tasks/page.tsx`
- Modify: `web/src/components/task-template-controls.tsx` (if template mode)
- Test: `web` build (no unit test framework for these pages)

- [ ] **Step 1: Types**

Add `TaskMode`, `Task.task_mode`, `Task.audit_config`, `AuditConfig`, `AuditProgress`, `CoverageCounts`, `AuditPhase`, `AuditRound`, `AuditEngineState`, `CodeEvidence`, `Finding` code fields.

- [ ] **Step 2: API client**

Extend createTask input mapping; add `getAuditProgress`, `getAuditReport`, `getAuditCapabilities`, `readAuditSource`.

- [ ] **Step 3: Create-task sheet**

- Add mode toggle (ToggleGroup or Select).
- Conditional code-audit fields: source type tabs, Git URL/ref, local path, zip upload; depth, CWE scope, max rounds, engines, budgets.
- Fetch `/audit/capabilities` on open; show readiness badges.
- Validation and reset.
- Task row shows mode badge.

- [ ] **Step 4: Build**

```bash
cd web
npm ci
npm run build:static
```

Expected: build passes. If dependencies already installed, `npm run build:static` is enough.

---

### Task 16: Audit tab, findings evidence UI, mock data

**Files:**
- Create: `web/src/app/(main)/function/tasks/detail/_tabs/code-audit-tab.tsx`
- Modify: `web/src/app/(main)/function/tasks/detail/page.tsx`
- Modify: `web/src/app/(main)/function/tasks/detail/_tabs/report-tab.tsx`
- Modify: `web/src/app/(main)/function/findings/detail/page.tsx`
- Modify: `web/src/app/(main)/function/findings/_components/findings-table.tsx`
- Modify: `web/src/lib/mock/data.ts`
- Modify: `web/src/lib/mock/handler.ts`

- [ ] **Step 1: Audit tab**

- Props `{taskId}`; fetch progress every 5s.
- Cards: source, engines, phase pipeline, gates, coverage, rounds, hypotheses, report download.
- Handle empty/loading/error; no layout shift.

- [ ] **Step 2: Detail page**

- Include tab only for `task?.mode === "code_audit"`.
- Header mode badge.
- Report tab title conditional.

- [ ] **Step 3: Finding evidence**

- Parse `code_evidence` (already an object from API) and render:
  - CWE/severity/confidence/verification badges;
  - location with copy button and optional source link;
  - source→sink trace timeline;
  - sanitizer table;
  - semantic chain;
  - engine badges;
  - PoC artifact download link (if any).
- Fallback to existing `<pre>` evidence for pentest findings.

- [ ] **Step 4: Mock**

- Add a code_audit task, audit progress, phases, coverage, code evidence finding.
- Extend `POST /tasks` and task detail responses.
- Add handlers for audit endpoints.

- [ ] **Step 5: Build**

```bash
cd web
npm run build:static
```

---

### Task 17: Integration test and documentation

**Files:**
- Create: `audit/integration_test.go` (build-tag or skip)
- Modify: `README.md` (section: code audit installation/usage)
- Create: `docs/code-audit-usage.md` (if docs cleanup keeps it)
- Modify: `docs/superpowers/plans/...` status checkboxes

- [ ] **Step 1: Integration test**

Test with a temp local directory and fake CodeGraph:
- PrepareSource → Profile → BuildPlan → Prescan.
- Create session/phases/coverage/intents (DB or fake store).
- Simulate intent completion receipts.
- Compute gates, build report.
- Assert coverage and report sections.

If a fake CodeGraph MCP is available, test `Explore` end-to-end via `io.Pipe`.

- [ ] **Step 2: Full test run**

```bash
cd "D:/Codex/Projects/Artex/ARTEX"
go test ./audit/... -v
go test ./... 2>&1 | tail -50
cd web && npm run build:static
```

Expected: pure tests pass; DB/engine tests skip when unavailable; build passes.

- [ ] **Step 3: README**

Add:
- Task mode usage.
- Input types and limits.
- CodeGraph installation (`npm i -g @colbymchenry/codegraph`), CodeQL/Joern future plan.
- Security boundaries (static only, no target execution).
- Depth/gates explanation.
- How to read the audit tab/report.

- [ ] **Step 4: Docs cleanup check**

- `docs/code-audit-integration.md` is deleted (superseded).
- `docs/漏洞流量证据.md` remains (still valid).
- New spec and plan remain.

---

## Self-Review

**Spec coverage**

| Spec section | Plan task |
|---|---|
| Task mode / audit config | 2, 3, 10 |
| Source ingest / snapshot / zip safety | 4 |
| Profile / plan | 5 |
| Sink prescan / coverage | 6 |
| Evidence / dedupe / findings | 7 |
| CodeGraph | 8 |
| Audit tools / restricted surface | 9 |
| Agent roles / prompts / per-task selection | 10 |
| Director / lifecycle / intent seeding | 11 |
| API / progress | 12 |
| Gates / rounds | 13 |
| Report | 14 |
| Create UI / audit tab / evidence UI | 15, 16 |
| Integration / docs | 17 |
| CodeQL/Joern/query synthesis | Deferred to `2026-10-26-artex-code-audit-engines.md` (follow-up plan) |
| Dynamic validation | Explicitly out of scope |

**Placeholder scan:** No TBD/TODO. Follow-up plan is named; it must be written before implementing engines.

**Type consistency:** `audit.Config`, `audit.Registry`, `audit.Plan`, `audit.SinkSite`, `audit.CodeEvidence`, `db.AuditSession`, `db.AuditCoverage`, `agent.AuditDeps` are used consistently across tasks. Server uses `db.TaskModeCodeAudit`; DB uses the same constant names.

**Scope check:** This plan produces a working static audit with CodeGraph. The multi-engine layer is a separate plan because it changes engine execution, query synthesis, and result normalization independently.

---

## Execution Handoff

Plan complete. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks.
2. **Inline Execution** — execute tasks in this session with checkpoints.

Choose one. The follow-up multi-engine plan will be written after the core vertical slice is running.
