"use client";

import * as React from "react";

import { AlertTriangleIcon, ArrowRightIcon, CheckIcon, SearchIcon, ShieldAlertIcon, XIcon } from "lucide-react";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type {
  AuditSourceFile,
  CodeEvidence,
  CodeLocation,
  CodeTraceStep,
  Finding,
  SanitizerVerdict,
  SemanticStep,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const VERIFICATION_LABELS: Record<string, string> = {
  unverified: "未验证",
  candidate: "候选",
  confirmed: "已确认",
  refuted: "已反驳",
  design_intent: "设计意图",
};

const SANITIZER_LABELS: Record<string, string> = {
  present: "有效",
  missing: "缺失",
  insufficient: "不足",
};

function parseEvidence(finding: Finding): CodeEvidence | null {
  return finding.code_evidence ?? null;
}

function verificationLabel(value?: string): string {
  if (!value) return "未验证";
  return VERIFICATION_LABELS[value.toLowerCase()] ?? value;
}

function verificationTone(value?: string): "default" | "secondary" | "destructive" | "outline" {
  switch (value?.toLowerCase()) {
    case "confirmed":
      return "destructive";
    case "candidate":
      return "secondary";
    case "refuted":
      return "outline";
    default:
      return "outline";
  }
}

function confidenceText(value?: number): string {
  if (typeof value !== "number" || Number.isNaN(value)) return "—";
  return `${Math.round(value * 100)}%`;
}

function locationText(location?: CodeLocation | null): string {
  if (!location?.path) return "";
  return `${location.path}${location.line ? `:${location.line}` : ""}${location.symbol ? ` · ${location.symbol}` : ""}`;
}

function sourceTarget(location?: CodeLocation | null): { path: string; line?: number } | null {
  if (!location?.path) return null;
  return { path: location.path, line: location.line };
}

function SourceLink({
  location,
  onOpen,
  label,
}: {
  location?: CodeLocation | null;
  onOpen: (path: string, line?: number) => void;
  label?: string;
}) {
  if (!location?.path) return <span className="text-muted-foreground">—</span>;
  return (
    <button
      type="button"
      className="min-w-0 truncate text-left font-mono text-xs text-primary hover:underline"
      title={`查看源码 ${location.path}${location.line ? `:${location.line}` : ""}`}
      onClick={() => onOpen(location.path as string, location.line)}
    >
      {label ? `${label}：` : ""}
      {locationText(location)}
    </button>
  );
}

function TraceList({ trace }: { trace: CodeTraceStep[] }) {
  return (
    <ol className="flex flex-col gap-1.5">
      {trace.map((step, index) => (
        <li key={`${step.path}-${step.line}-${index}`} className="flex gap-2 text-xs">
          <span className="mt-0.5 inline-flex size-4 shrink-0 items-center justify-center rounded-full bg-muted font-mono text-[10px] text-muted-foreground">
            {index + 1}
          </span>
          <div className="min-w-0">
            <div className="break-all font-mono">
              {step.path}:{step.line}
              {step.symbol ? <span className="text-muted-foreground"> · {step.symbol}</span> : null}
            </div>
            {step.note && <p className="mt-0.5 whitespace-pre-wrap break-words text-muted-foreground">{step.note}</p>}
          </div>
        </li>
      ))}
    </ol>
  );
}

function sanitizerTone(verdict: string): string {
  switch (verdict) {
    case "present":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
    case "missing":
      return "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300";
    case "insufficient":
      return "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300";
    default:
      return "border-border bg-muted/40 text-muted-foreground";
  }
}

function SourceDialog({
  taskId,
  target,
  onClose,
}: {
  taskId: string;
  target: { path: string; line?: number } | null;
  onClose: () => void;
}) {
  const [file, setFile] = React.useState<AuditSourceFile | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    if (!target) {
      setFile(null);
      setError("");
      return;
    }
    let active = true;
    setLoading(true);
    setFile(null);
    setError("");
    api
      .auditSourceFile(taskId, target.path, target.line)
      .then((next) => {
        if (active) setFile(next);
      })
      .catch((err: Error) => {
        if (active) setError(err.message || "源码读取失败");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [target, taskId]);

  const lines = file?.content.split("\n") ?? [];
  const targetLine = target?.line ?? 0;

  return (
    <Dialog open={target != null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-5xl">
        <DialogHeader>
          <DialogTitle className="break-all pr-6 font-mono text-xs">
            {target ? `${target.path}${target.line ? `:${target.line}` : ""}` : "源码"}
          </DialogTitle>
          <DialogDescription>
            {file
              ? `${file.language || "text"} · 第 ${file.start_line}-${file.end_line} 行 / 共 ${file.total_lines} 行（只读快照）`
              : "正在读取任务源码快照…"}
          </DialogDescription>
        </DialogHeader>
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
            <Spinner /> 加载源码…
          </div>
        ) : error ? (
          <div className="flex flex-col items-center gap-2 py-12 text-center text-sm">
            <AlertTriangleIcon className="size-7 text-amber-500" />
            <p className="text-muted-foreground">{error}</p>
          </div>
        ) : file ? (
          <div className="max-h-[65vh] overflow-auto rounded-md border bg-muted/20">
            <div className="min-w-max py-2 font-mono text-xs">
              {lines.map((line, index) => {
                const lineNo = file.start_line + index;
                const highlighted = targetLine > 0 && lineNo === targetLine;
                return (
                  <div
                    key={lineNo}
                    className={cn("flex min-h-5 px-2", highlighted && "bg-amber-500/20 dark:bg-amber-400/15")}
                  >
                    <span className="sticky left-0 w-12 shrink-0 select-none bg-inherit pr-3 text-right text-muted-foreground">
                      {lineNo}
                    </span>
                    <span className="whitespace-pre pr-6">{line || " "}</span>
                  </div>
                );
              })}
            </div>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <div className="text-xs font-medium text-muted-foreground">{children}</div>;
}

export function CodeEvidenceSection({ finding, contextTaskId }: { finding: Finding; contextTaskId?: string }) {
  const evidence = React.useMemo(() => parseEvidence(finding), [finding]);
  const [target, setTarget] = React.useState<{ path: string; line?: number } | null>(null);
  const taskId = finding.task_id ?? contextTaskId ?? "";
  const openSource = React.useCallback(
    (path: string, line?: number) => {
      if (!taskId) return;
      setTarget({ path, line });
    },
    [taskId],
  );

  const cweID = evidence?.cwe_id || finding.cwe_id || "";
  const codePath = evidence?.location?.path || finding.code_path || "";
  const evidenceHasData = Boolean(evidence && Object.keys(evidence).length > 0);
  const hasStructured =
    evidenceHasData ||
    Boolean(cweID) ||
    Boolean(codePath) ||
    Boolean(finding.code_symbol) ||
    typeof finding.code_line === "number";

  if (!hasStructured) return null;

  const verification = evidence?.verification?.status || finding.verification;
  const confidence = evidence?.confidence ?? finding.confidence;
  const location: CodeLocation = evidence?.location ?? {
    path: finding.code_path,
    line: finding.code_line,
    symbol: finding.code_symbol,
  };
  const engines = evidence?.engines?.length ? evidence.engines : (finding.engines ?? []);
  const sanitizers: SanitizerVerdict[] = evidence?.sanitizers ?? [];
  const semanticChain: SemanticStep[] = evidence?.semantic_chain ?? [];
  const trace = evidence?.trace ?? [];
  const reachability = evidence?.reachability;
  const poco = evidence?.poc;
  const analysis = evidence?.analysis;
  const targetLocation = sourceTarget(location);

  return (
    <div className="flex flex-col gap-4">
      <CardShell>
        <div className="flex flex-wrap items-center gap-2 border-b pb-3">
          <span className="flex items-center gap-1.5 text-sm font-semibold">
            <ShieldAlertIcon className="size-4 text-rose-500" /> 代码证据
          </span>
          {cweID && <Badge variant="outline">{cweID}</Badge>}
          <StatusBadge domain="severity" value={evidence?.severity || finding.severity} dot />
          <Badge variant={verificationTone(verification)}>验证：{verificationLabel(verification)}</Badge>
          <Badge variant="secondary">置信度 {confidenceText(confidence)}</Badge>
          {engines.map((engine, index) => (
            <Badge key={`${engine.name}-${engine.query_id ?? ""}-${index}`} variant="outline">
              引擎：{engine.name}
            </Badge>
          ))}
          {analysis?.phase && (
            <Badge variant="outline">
              {analysis.phase}
              {analysis.round ? ` · R${analysis.round}` : ""}
            </Badge>
          )}
        </div>

        <div className="grid gap-4 pt-3 lg:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <SectionTitle>位置</SectionTitle>
            <div className="flex flex-wrap items-center gap-2">
              {targetLocation ? (
                <SourceLink location={location} onOpen={openSource} />
              ) : (
                <span className="text-xs text-muted-foreground">—</span>
              )}
              {taskId && targetLocation && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-6 px-2 text-xs"
                  onClick={() => openSource(targetLocation.path, targetLocation.line)}
                >
                  <SearchIcon className="size-3" /> 查看源码
                </Button>
              )}
            </div>
            {evidence?.title && <p className="text-sm font-medium">{evidence.title}</p>}
            {evidence?.impact && (
              <div>
                <SectionTitle>影响</SectionTitle>
                <p className="whitespace-pre-wrap break-words text-xs">{evidence.impact}</p>
              </div>
            )}
            {evidence?.preconditions && evidence.preconditions.length > 0 && (
              <div>
                <SectionTitle>前置条件</SectionTitle>
                <ul className="list-disc pl-4 text-xs">
                  {evidence.preconditions.map((item, index) => (
                    <li key={`${item}-${index}`}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <SectionTitle>验证结论</SectionTitle>
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge variant={verificationTone(verification)}>{verificationLabel(verification)}</Badge>
              {evidence?.verification?.method && <Badge variant="outline">方法：{evidence.verification.method}</Badge>}
              {evidence?.verification?.design_validation && (
                <Badge variant="outline">设计校验：{evidence.verification.design_validation}</Badge>
              )}
            </div>
            {evidence?.verification?.reason && (
              <p className="whitespace-pre-wrap break-words text-xs text-muted-foreground">
                {evidence.verification.reason}
              </p>
            )}
            {evidence?.verification?.alternative_path && (
              <p className="break-all font-mono text-[11px] text-muted-foreground">
                替代路径：{evidence.verification.alternative_path}
              </p>
            )}
            {analysis && (
              <p className="text-xs text-muted-foreground">
                阶段：{analysis.phase || "—"} · 轮次：{analysis.round ?? "—"} · 后端：{analysis.backend || "—"}
                {analysis.fallback ? "（降级路径）" : ""}
              </p>
            )}
            {evidence?.dedupe_key && (
              <p className="break-all font-mono text-[10px] text-muted-foreground">去重键：{evidence.dedupe_key}</p>
            )}
          </div>
        </div>
      </CardShell>

      {(evidence?.source || evidence?.sink || trace.length > 0) && (
        <CardShell>
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between gap-2">
              <SectionTitle>Source → Sink 链路</SectionTitle>
              {trace.length > 0 && <Badge variant="outline">{trace.length} 跳</Badge>}
            </div>
            <div className="grid gap-2">
              {evidence?.source && <SourceLink location={evidence.source} onOpen={openSource} label="Source" />}
              {trace.length > 0 && (
                <div className="flex gap-2">
                  <ArrowRightIcon className="mt-0.5 size-3 shrink-0 text-muted-foreground" />
                  <TraceList trace={trace} />
                </div>
              )}
              {evidence?.sink && <SourceLink location={evidence.sink} onOpen={openSource} label="Sink" />}
              {!evidence?.source && !evidence?.sink && trace.length === 0 && (
                <p className="text-xs text-muted-foreground">暂无 source/sink 链路，旧漏洞或仅保存了位置字段。</p>
              )}
            </div>
          </div>
        </CardShell>
      )}

      {sanitizers.length > 0 && (
        <CardShell>
          <SectionTitle>Sanitizer 判定</SectionTitle>
          <div className="mt-2 overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>符号</TableHead>
                  <TableHead>结论</TableHead>
                  <TableHead>说明</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sanitizers.map((sanitizer, index) => (
                  <TableRow key={`${sanitizer.symbol}-${index}`}>
                    <TableCell className="font-mono text-xs">{sanitizer.symbol}</TableCell>
                    <TableCell>
                      <span
                        className={cn(
                          "inline-flex rounded-md border px-1.5 py-0.5 text-xs",
                          sanitizerTone(sanitizer.verdict),
                        )}
                      >
                        {SANITIZER_LABELS[sanitizer.verdict] ?? sanitizer.verdict}
                      </span>
                    </TableCell>
                    <TableCell className="whitespace-normal text-xs text-muted-foreground">
                      {sanitizer.note || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardShell>
      )}

      {semanticChain.length > 0 && (
        <CardShell>
          <SectionTitle>语义链</SectionTitle>
          <div className="mt-2 overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>阶段</TableHead>
                  <TableHead>操作</TableHead>
                  <TableHead>输入 → 输出</TableHead>
                  <TableHead>语义变化</TableHead>
                  <TableHead>消费方假设</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {semanticChain.map((step, index) => (
                  <TableRow key={`${step.stage}-${step.operation}-${index}`}>
                    <TableCell className="text-xs">{step.stage}</TableCell>
                    <TableCell className="whitespace-normal text-xs">{step.operation}</TableCell>
                    <TableCell className="max-w-48 whitespace-normal break-words font-mono text-[11px]">
                      {step.input || "—"} → {step.output || "—"}
                    </TableCell>
                    <TableCell className="whitespace-normal text-xs text-muted-foreground">
                      {step.semantics_from || "—"} → {step.semantics_to || "—"}
                    </TableCell>
                    <TableCell className="whitespace-normal text-xs text-muted-foreground">
                      {step.consumer_assumption || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardShell>
      )}

      {(reachability || poco) && (
        <div className="grid gap-3 sm:grid-cols-2">
          {reachability && (
            <CardShell>
              <SectionTitle>可达性</SectionTitle>
              <div className="mt-2 flex flex-col gap-1.5 text-xs">
                <div className="flex items-center gap-2">
                  <Badge variant={reachability.reachable ? "destructive" : "outline"}>
                    {reachability.reachable ? <CheckIcon className="size-3" /> : <XIcon className="size-3" />}
                    {reachability.reachable ? "可达" : "不可达"}
                  </Badge>
                  <span className="text-muted-foreground">
                    认证：{reachability.auth_required ? "需要" : "不需要"}
                    {reachability.auth_state_recorded === false ? "（未记录）" : ""}
                  </span>
                </div>
                {reachability.entry_point && <p className="break-all">入口：{reachability.entry_point}</p>}
                {reachability.path && <p className="break-all text-muted-foreground">路径：{reachability.path}</p>}
              </div>
            </CardShell>
          )}
          {poco && (
            <CardShell>
              <SectionTitle>PoC 工件</SectionTitle>
              <div className="mt-2 flex flex-col gap-1.5 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline">{poco.kind || "none"}</Badge>
                  <Badge variant={poco.executed ? "secondary" : "outline"}>
                    {poco.executed ? "已执行（演示）" : "未执行"}
                  </Badge>
                </div>
                {poco.artifact_path && <p className="break-all font-mono text-[11px]">{poco.artifact_path}</p>}
                {poco.description && (
                  <p className="whitespace-pre-wrap break-words text-muted-foreground">{poco.description}</p>
                )}
              </div>
            </CardShell>
          )}
        </div>
      )}

      {engines.length > 0 && (
        <CardShell>
          <SectionTitle>引擎命中</SectionTitle>
          <div className="mt-2 overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>引擎</TableHead>
                  <TableHead>Query</TableHead>
                  <TableHead>置信度</TableHead>
                  <TableHead>原始引用</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {engines.map((engine, index) => (
                  <TableRow key={`${engine.name}-${index}`}>
                    <TableCell className="text-xs font-medium">{engine.name}</TableCell>
                    <TableCell className="font-mono text-xs">{engine.query_id || "—"}</TableCell>
                    <TableCell className="text-xs tabular-nums">{confidenceText(engine.confidence)}</TableCell>
                    <TableCell className="max-w-64 whitespace-normal break-words font-mono text-[11px] text-muted-foreground">
                      {engine.raw_ref || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardShell>
      )}

      {taskId && <SourceDialog taskId={taskId} target={target} onClose={() => setTarget(null)} />}
    </div>
  );
}

function CardShell({ children }: { children: React.ReactNode }) {
  return <div className="rounded-xl border bg-card px-4 py-3 text-sm text-card-foreground">{children}</div>;
}
