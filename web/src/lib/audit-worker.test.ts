import {
  applyAuditWorkerBackend,
  auditWorkerDraftFromConfig,
  buildAuditWorkerConfig,
  changeAuditWorkerMode,
  defaultAuditWorkerDraft,
  parseAuditWorkerArgs,
} from "./audit-worker.ts";
import type { AuditWorkerBackendOption } from "./types.ts";
import assert from "node:assert/strict";
import test from "node:test";

const backendOptions: AuditWorkerBackendOption[] = [
  {
    backend: "builtin",
    label: "ARTEX 内置 Worker",
    external: false,
    requires_command: false,
    modes: ["static", "privileged"],
    suggested_mode: "static",
    available: true,
  },
  {
    backend: "codex",
    label: "Codex CLI",
    external: true,
    requires_command: true,
    modes: ["static", "privileged"],
    suggested_mode: "static",
    suggested_command: "codex",
    suggested_args: ["exec", "--sandbox", "read-only", "{{prompt}}"],
    suggested_privileged_args: ["exec", "--dangerously-bypass-approvals-and-sandbox", "{{prompt}}"],
    available: true,
  },
  {
    backend: "custom",
    label: "自定义 CLI",
    external: true,
    requires_command: true,
    modes: ["static", "privileged"],
    suggested_mode: "static",
    suggested_args: ["{{input_file}}"],
    available: false,
  },
];

test("audit worker draft defaults to builtin static mode", () => {
  assert.deepEqual(defaultAuditWorkerDraft(), {
    backend: "builtin",
    mode: "static",
    command: "",
    args: "",
    timeoutSeconds: "",
    privilegedConfirmed: false,
  });
});

test("audit worker backend selection applies a command template", () => {
  const draft = applyAuditWorkerBackend("codex", backendOptions);

  assert.equal(draft.backend, "codex");
  assert.equal(draft.mode, "static");
  assert.equal(draft.command, "codex");
  assert.equal(draft.args, "exec\n--sandbox\nread-only\n{{prompt}}");
  assert.equal(draft.privilegedConfirmed, false);
});

test("audit worker mode switch swaps unedited command templates", () => {
  const draft = applyAuditWorkerBackend("codex", backendOptions);
  const privileged = changeAuditWorkerMode(draft, "privileged", backendOptions);
  const staticAgain = changeAuditWorkerMode(privileged, "static", backendOptions);

  assert.equal(privileged.mode, "privileged");
  assert.equal(privileged.args, "exec\n--dangerously-bypass-approvals-and-sandbox\n{{prompt}}");
  assert.equal(privileged.privilegedConfirmed, false);
  assert.equal(staticAgain.mode, "static");
  assert.equal(staticAgain.args, "exec\n--sandbox\nread-only\n{{prompt}}");
});

test("audit worker config round-trips from a stored task config", () => {
  const draft = auditWorkerDraftFromConfig({
    worker: {
      backend: "codex",
      mode: "privileged",
      command: "codex",
      args: ["exec", "{{input_file}}"],
      cwd: "{{workspace}}",
      timeout_seconds: 120,
    },
  });

  assert.equal(draft.backend, "codex");
  assert.equal(draft.mode, "privileged");
  assert.equal(draft.command, "codex");
  assert.equal(draft.args, "exec\n{{input_file}}");
  assert.equal(draft.timeoutSeconds, "120");
});

test("builtin audit worker is omitted from the task payload", () => {
  assert.equal(buildAuditWorkerConfig(defaultAuditWorkerDraft()), undefined);
});

test("external audit worker payload uses argv and explicit confirmation", () => {
  const config = buildAuditWorkerConfig({
    backend: "codex",
    mode: "privileged",
    command: " codex ",
    args: " exec \n {{input_file}} ",
    timeoutSeconds: "120",
    privilegedConfirmed: true,
  });

  assert.deepEqual(config, {
    backend: "codex",
    mode: "privileged",
    command: "codex",
    args: ["exec", "{{input_file}}"],
    cwd: "{{workspace}}",
    timeout_seconds: 120,
  });
});

test("audit worker payload validation rejects unsafe or incomplete input", () => {
  const draft = {
    ...defaultAuditWorkerDraft(),
    backend: "codex" as const,
    command: "codex",
    args: "exec\n{{input_file}}",
  };

  assert.throws(() => buildAuditWorkerConfig({ ...draft, command: "" }), /command/);
  assert.throws(() => buildAuditWorkerConfig({ ...draft, args: "" }), /args/);
  assert.throws(() => buildAuditWorkerConfig({ ...draft, mode: "privileged" }), /确认/);
  assert.throws(() => buildAuditWorkerConfig({ ...draft, timeoutSeconds: "-1" }), /timeout/);
});

test("audit worker args are line-delimited and shell-free", () => {
  assert.deepEqual(parseAuditWorkerArgs(" exec \n\n --json \n {{input_file}} "), ["exec", "--json", "{{input_file}}"]);
});
