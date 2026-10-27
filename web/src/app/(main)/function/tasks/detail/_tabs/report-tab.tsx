"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, DownloadIcon, FileTextIcon } from "lucide-react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import type { TaskMode } from "@/lib/types";
import { copyText } from "@/lib/utils";

export function ReportTab({ taskId, taskMode = "pentest" }: { taskId: string; taskMode?: TaskMode }) {
  const [report, setReport] = React.useState<string>("");
  const [loading, setLoading] = React.useState(true);
  const [copied, setCopied] = React.useState(false);
  const [error, setError] = React.useState("");
  const [downloading, setDownloading] = React.useState(false);
  const codeAudit = taskMode === "code_audit";

  React.useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    const request = codeAudit ? api.auditReport(taskId, "md") : api.report(taskId);
    request
      .then((text) => {
        if (active) setReport(text);
      })
      .catch((err: Error) => {
        if (active) {
          setReport("");
          setError(err.message || "报告加载失败");
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [codeAudit, taskId]);

  async function download() {
    setDownloading(true);
    try {
      await api.downloadAuditReport(taskId, "md");
      toast.success("审计报告已下载");
    } catch (err) {
      toast.error("下载失败：" + (err as Error).message);
    } finally {
      setDownloading(false);
    }
  }

  async function copy() {
    if (!report) return;
    const ok = await copyText(report);
    if (ok) {
      setCopied(true);
      toast.success("已复制 Markdown");
      setTimeout(() => setCopied(false), 1500);
    } else {
      toast.error("复制失败，请手动选择文本复制");
    }
  }

  let content: React.ReactNode;
  if (loading) {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        加载中…
      </div>
    );
  } else if (report) {
    content = (
      <div className="max-h-[60vh] overflow-auto rounded-md border bg-muted/20 p-4">
        <Markdown text={report} />
      </div>
    );
  } else {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed px-4 py-16 text-center text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        <span>{codeAudit ? "审计报告尚未生成" : "暂无报告"}</span>
        {codeAudit && (
          <span className="max-w-xl text-xs">
            {error || "代码审计收敛并生成报告后，可在此预览和下载；运行中请查看“代码审计”页签的门禁与覆盖度。"}
          </span>
        )}
      </div>
    );
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-sm">
          <FileTextIcon className="size-4" /> {codeAudit ? "代码审计报告（Markdown）" : "渗透测试报告（Markdown）"}
        </CardTitle>
        <div className="flex gap-2">
          {report && (
            <>
              <Button size="sm" variant="outline" onClick={copy}>
                {copied ? <CheckIcon /> : <CopyIcon />} 复制
              </Button>
              {codeAudit && (
                <Button size="sm" variant="outline" disabled={downloading} onClick={() => void download()}>
                  {downloading ? <Spinner /> : <DownloadIcon />} 下载
                </Button>
              )}
            </>
          )}
        </div>
      </CardHeader>
      <CardContent>{content}</CardContent>
    </Card>
  );
}
