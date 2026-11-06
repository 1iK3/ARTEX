import { mockHandle } from "./handler.ts";
import assert from "node:assert/strict";
import test from "node:test";

test("mock audit verification batch returns the updated count", async () => {
  const result = await mockHandle<{ updated: number; verification: string }>(
    "POST",
    "/tasks/t-audit-orders/audit/findings/verification-batch",
    JSON.stringify({
      finding_ids: [18, 19],
      verification: "confirmed",
      evidence: "manual review proof",
    }),
  );

  assert.deepEqual(result, { updated: 2, verification: "confirmed" });
});

test("mock worker backend catalog returns selectable backends", async () => {
  const result = await mockHandle<{
    default_backend?: string;
    backends: Array<{ backend: string; modes: string[]; suggested_mode: string }>;
  }>("GET", "/worker-backends");

  assert.equal(result.default_backend, "builtin");
  assert.deepEqual(
    result.backends.map((backend) => backend.backend),
    ["builtin", "codex", "opencode", "claudecode", "cursor", "pi", "custom"],
  );
  assert.ok(result.backends.every((backend) => backend.modes.includes("static")));
  assert.ok(result.backends.every((backend) => backend.suggested_mode === "static"));
});

test("mock audit verification batch rejects invalid verdicts and blank evidence", async () => {
  await assert.rejects(
    mockHandle(
      "POST",
      "/tasks/t-audit-orders/audit/findings/verification-batch",
      JSON.stringify({ finding_ids: [18], verification: "candidate", evidence: "proof" }),
    ),
    /verification/,
  );
  await assert.rejects(
    mockHandle(
      "POST",
      "/tasks/t-audit-orders/audit/findings/verification-batch",
      JSON.stringify({ finding_ids: [18], verification: "confirmed", evidence: " " }),
    ),
    /evidence/,
  );
});

test("mock task template update switches mode and clears audit config", async () => {
  const created = await mockHandle<{
    id: number;
    task_mode?: string;
    audit_config?: { source_type: string; depth: string; cwe_scope: string };
  }>(
    "POST",
    "/task-templates",
    JSON.stringify({
      name: "Mock 代码审计模板",
      description: "mock code audit template",
      goal: "audit goal",
      task_mode: "code_audit",
      audit_config: { source_type: "zip", depth: "deep", cwe_scope: "core" },
    }),
  );

  assert.equal(created.task_mode, "code_audit");
  assert.equal(created.audit_config?.source_type, "zip");

  const updated = await mockHandle<{ task_mode?: string; audit_config?: unknown }>(
    "PATCH",
    `/task-templates/${created.id}`,
    JSON.stringify({ task_mode: "pentest" }),
  );

  assert.equal(updated.task_mode, "pentest");
  assert.equal(updated.audit_config, undefined);
});
