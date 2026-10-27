# Generated audit registries

`audit-registry.json` is generated from Omni-Audit and embedded into the
`audit` Go package by `audit/registry.go`. Do not hand-edit this file;
regenerate it with the exporter.

- Source commit: `f439e2d` (`Omni-Audit@f439e2d`)
- Contents: deduplicated CWE definitions, per-language sink/source/sanitizer
  definitions, Odin rules, and per-language framework taint registries. CWE
  IDs are deduplicated by priority (`P0` highest).
- Format: deterministic, pretty-printed JSON with a trailing newline. The
  output has no timestamp field.
- Line endings: `ARTEX/.gitattributes` forces `*.go` and
  `audit/data/audit-registry.json` to LF (`text eol=lf`) on checkout, so a
  Windows checkout must not introduce CRLF or change the checksum.

## Prerequisites

- Git CLI on PATH
- Node.js >= 22
- pnpm >= 9 with the Omni-Audit workspace dependencies installed
  (`pnpm install`)
- `tsx` from the engine package (`packages/engine/node_modules/.bin/tsx`)
- ARTEX and Omni-Audit checked out as sibling repositories (the default output
  path is resolved from the exporter script)

## Regenerate

From the Omni-Audit repository:

```bash
cd "D:/Codex/Projects/Artex/Omni-Audit"
packages/engine/node_modules/.bin/tsx scripts/export-artex-audit-data.mts
```

The output directory defaults to `../../ARTEX/audit/data` relative to the
exporter script. Pass a directory argument to override it; relative arguments
are resolved from the script directory. The exporter writes atomically through
a temporary file and rename. Pass `--allow-dirty` only for local investigation
when `packages/shared` has uncommitted changes.

## Verify

Check that the checked-in file matches the exporter output. The exporter writes
the generated output to a temporary file and exits 1 on any difference:

```bash
cd "D:/Codex/Projects/Artex/Omni-Audit"
packages/engine/node_modules/.bin/tsx scripts/export-artex-audit-data.mts --check
```

Checksum:

```bash
cd "D:/Codex/Projects/Artex/ARTEX"
sha256sum audit/data/audit-registry.json
```

Reference SHA-256 for the current file:
`8e6935ec3f9427064b88578ba6108dfbd33752a1818961e031551f2d6d9f05de`.

LF verification:

```bash
cd "D:/Codex/Projects/Artex/ARTEX"
git check-attr text eol -- audit/data/audit-registry.json
python -c "d=open('audit/data/audit-registry.json','rb').read(); assert b'\r' not in d, 'CRLF found'; print('LF OK')"
```

Expected attributes: `text: set` and `eol: lf`.

Go contract tests:

```bash
cd "D:/Codex/Projects/Artex/ARTEX"
go test ./audit
```

## Source provenance policy

`source` is derived with `git -C <Omni-Audit> rev-parse HEAD` (short SHA) at
export time. A `-dirty` suffix is appended when `packages/shared` has
uncommitted changes. The exporter refuses to write a dirty shared tree unless
`--allow-dirty` is passed; do not check in data generated with `--allow-dirty`.
Re-run the exporter and update this README whenever the source commit changes.

## Regeneration checklist

1. Confirm the prerequisites above, including the Git CLI and sibling
   ARTEX/Omni-Audit checkouts.
2. Commit or discard changes under `Omni-Audit/packages/shared`; the exporter
   refuses a dirty shared tree unless `--allow-dirty` is used for local work.
3. Run the exporter command above.
4. If Omni-Audit HEAD changed, update the source commit line above and
   `wantRegistrySource` in `audit/registry_test.go`.
5. If the bytes changed, recompute and update the reference SHA-256 above.
6. Verify LF: `git check-attr text eol -- audit/data/audit-registry.json` must
   report `text: set` and `eol: lf`, and the JSON must contain no CRLF bytes.
   Do not run `git add --renormalize`; existing tracked files are intentionally
   not renormalized.
7. Run the exporter `--check`, `go test ./audit`, `go vet ./audit`, and
   `gofmt -l audit`.

## Coverage notes

- Go has no deterministic sink table in Omni-Audit, so `SinksFor("go")` is
  empty while `CWEsFor("go")` and `TaintsFor("go")` return data.
- Rust has sink and taint data, but Omni-Audit's CWE table has no entries tagged
  `rust`; the contract test asserts this so the caveat cannot go stale.
- C and C++ share the C++ sink and taint registries; JavaScript and TypeScript
  share the JavaScript sink registry and the Node taint registry.
- Odin rule languages that normalize to JavaScript (`nodejs`, `js`, `node`,
  etc.) intentionally apply to both JavaScript and TypeScript; `OdinRulesFor`
  expands them to TypeScript. The current source tags them `nodejs`.
