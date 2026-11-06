import type { AuditConfig, AuditWorkerBackend, AuditWorkerBackendOption, AuditWorkerConfig, AuditWorkerMode } from "./types.ts";

export interface AuditWorkerDraft {
  backend: AuditWorkerBackend;
  mode: AuditConfig["worker"] extends undefined ? never : NonNullable<AuditConfig["worker"]>["mode"];
  command: string;
  args: string;
  timeoutSeconds: string;
  privilegedConfirmed: boolean;
}

export function defaultAuditWorkerDraft(): AuditWorkerDraft {
  return {
    backend: "builtin",
    mode: "static",
    command: "",
    args: "",
    timeoutSeconds: "",
    privilegedConfirmed: false,
  };
}

export function applyAuditWorkerBackend(
  backend: AuditWorkerBackend,
  options: AuditWorkerBackendOption[],
): AuditWorkerDraft {
  const option = options.find((item) => item.backend === backend);
  if (option && !option.external) {
    return { ...defaultAuditWorkerDraft() };
  }
  return {
    ...defaultAuditWorkerDraft(),
    backend,
    command: option?.suggested_command ?? "",
    args: (option?.suggested_args ?? []).join("\n"),
  };
}

export function changeAuditWorkerMode(
  draft: AuditWorkerDraft,
  mode: AuditWorkerMode,
  options: AuditWorkerBackendOption[],
): AuditWorkerDraft {
  const option = options.find((item) => item.backend === draft.backend);
  const currentArgs = parseAuditWorkerArgs(draft.args);
  const staticArgs = option?.suggested_args ?? [];
  const privilegedArgs = option?.suggested_privileged_args ?? staticArgs;
  let args = draft.args;
  if (mode === "privileged" && areArgsEqual(currentArgs, staticArgs) && privilegedArgs.length > 0) {
    args = privilegedArgs.join("\n");
  } else if (mode === "static" && areArgsEqual(currentArgs, privilegedArgs) && staticArgs.length > 0) {
    args = staticArgs.join("\n");
  }
  return { ...draft, mode, args, privilegedConfirmed: false };
}

function areArgsEqual(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((arg, index) => arg === right[index]);
}

export function auditWorkerDraftFromConfig(config: Pick<AuditConfig, "worker">): AuditWorkerDraft {
  const worker = config.worker;
  if (!worker) return defaultAuditWorkerDraft();
  return {
    backend: worker.backend,
    mode: worker.mode,
    command: worker.command ?? "",
    args: (worker.args ?? []).join("\n"),
    timeoutSeconds: worker.timeout_seconds ? String(worker.timeout_seconds) : "",
    privilegedConfirmed: false,
  };
}

export function parseAuditWorkerArgs(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((arg) => arg.trim())
    .filter((arg) => arg !== "");
}

export function buildAuditWorkerConfig(draft: AuditWorkerDraft): AuditWorkerConfig | undefined {
  if (draft.backend === "builtin") return undefined;
  const command = draft.command.trim();
  if (command === "") throw new Error("外部 worker command 不能为空");
  const args = parseAuditWorkerArgs(draft.args);
  if (args.length === 0) throw new Error("外部 worker args 不能为空");
  if (draft.mode === "privileged" && !draft.privilegedConfirmed) {
    throw new Error("高权限 worker 需要先确认风险");
  }
  const timeoutSeconds = draft.timeoutSeconds.trim() === "" ? 3600 : Number(draft.timeoutSeconds);
  if (!Number.isSafeInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 86_400) {
    throw new Error("worker timeout_seconds 必须在 1-86400 之间");
  }
  return {
    backend: draft.backend,
    mode: draft.mode,
    command,
    args,
    cwd: "{{workspace}}",
    timeout_seconds: timeoutSeconds,
  };
}
