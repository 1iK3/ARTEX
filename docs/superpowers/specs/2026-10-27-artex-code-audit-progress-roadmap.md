# ARTEX 代码审计进度与下一步规划

- 日期：2026-10-27
- 分支：`feat/code-audit`
- 本地提交：`a137d14 feat(code-audit): integrate static code audit with CodeGraph, CodeQL and Joern`
- 远程：`origin` = `https://github.com/1iK3/ARTEX.git`（推送因当前网络无法连接 GitHub 尚未完成）
- 设计基线：`docs/superpowers/specs/2026-10-26-artex-code-audit-fusion-design.md`
- 实施计划：`docs/superpowers/plans/2026-10-26-artex-code-audit-core.md`
- 使用说明：`docs/code-audit-usage.md`

---

## 1. 当前结论

第一版**静态代码审计闭环**已经打通：

```text
创建 code_audit 任务
  → Git/本地/zip 源码摄取与快照
  → 语言/框架画像 + CWE 计划 + sink 预扫描
  → CodeGraph 索引 + CodeQL/Joern 检测
  → S1/S2/S4 审计意图 + 受限 code_worker
  → 覆盖回执/结构化证据/验证
  → 覆盖度与门禁
  → 确定性 Markdown/JSON 报告
  → prove_goal 仅在报告就绪后允许
```

已真实验证：

- CodeQL 2.27.3：Java/Python/JavaScript/TypeScript build-mode=none 建库、QL 编译、analyze，各自 taint 与 sink 均命中 1 条；本地 pack 闭包会生成 lockfile，避免多版本依赖解析歧义（Java 曾在 2.25.5 验证）。
- Joern 4.0.535：Java、Python、JavaScript、TypeScript、Go、C、C++ 均完成 CPG 解析与 taint/sink 查询，各语言 taint/sink 均命中 1 条；Python/C/Go 模板按 Joern 前端差异使用 sink call argument。
- CodeGraph：真实 MCP/CLI 适配测试通过。
- Web：`tsc --noEmit` 与 `build:static` 通过，31 个路由静态生成。
- Go：audit/engines/agent/db/server 目标测试与 `go build ./...` 通过。
- 归档/恢复：`code_audit` format v4 归档后可恢复审计七表与报告，任务保持暂停且不启动 pentest 逻辑。
- LLM 辅助意图：自由目标可转换为受限 `DetectionIntent` IR；严格拒绝原生查询文本，失败回退确定性意图并记录 provenance/query gap。

---

## 2. Spec 章节进度

| Spec 章节 | 状态 | 说明 |
|---|---|---|
| 1. 目标与非目标 | ✅ 完成 | 静态闭环已落地；动态验证仍为非目标 |
| 2. 现状与约束 | ✅ 完成 | 约束已写入实现/文档 |
| 3. 设计原则 | ✅ 完成 | 导演/planner/worker/引擎边界已实现 |
| 4. 总体架构 | 🟡 大部分 | 组件、数据流、职责已实现；引擎结果只作为候选 |
| 5.1 任务模式 | ✅ 完成 | `task_mode` 全链路 |
| 5.2 审计配置 | ✅ 完成 | 校验/默认值/引擎白名单 |
| 5.3 生命周期 | ✅ 完成 | ingest/running/done/done_with_gaps；门禁失败自动 round+1 聚焦补扫（S0 仅第 1 轮） |
| 5.4 恢复 | 🟡 大部分 | 快照/索引检查、幂等 session/intent/coverage；完成态恢复已保护 |
| 5.5 删除 | 🟡 大部分 | 导演停止、CodeGraph 关闭；审计表随任务级联删除 |
| 6. 源码获取与快照 | ✅ 完成 | git/local/zip、路径/压缩炸弹/符号链接防护、超时 |
| 7.1 引擎能力矩阵 | ✅ 完成 | CodeGraph/CodeQL/Joern/fallback |
| 7.2 DetectionIntent | ✅ 完成 | sink 规则确定性生成 + 框架污点合并 |
| 7.3 QuerySpec IR | ✅ 完成 | 模板/哈希/缓存/规范化 |
| 7.4 意图识别 | ✅ 完成 | sink 规则确定性识别 + 自由目标 LLM 严格 JSON/白名单校验 + 失败回退 |
| 7.5 查询合成 | ✅ 完成 | LLM 只产出 DetectionIntent IR；模板渲染主路径 + 版本化缓存 key |
| 7.6 CodeQL 适配器 | ✅ 完成 | Java/Python/JS/TS taint/sink 模板真实验证；Go/C/C++ 仅支持预构建 DB |
| 7.7 Joern 适配器 | ✅ 完成 | Java/Python/JS/TS/Go/C/C++ taint/sink 真实验证；sanitizer/path scope 已接入 |
| 7.8 CodeGraph 适配器 | ✅ 完成 | MCP explore + CLI 工具 |
| 7.9 原生兜底 | ✅ 完成 | 只读 search/read，路径限制 |
| 7.10 引擎调度 | ✅ 完成 | preflight 内 probe/prepare/run，失败记 gap |
| 7.11 结果归一化 | ✅ 完成 | 跨引擎归并、置信度、sink site 转换 |
| 8. 审计阶段流水线 | ✅ 大部分 | S0–S10 均有调度候选/协议/回执路径；S10 PoC 绑定不执行；真实 LLM 深链质量待专项验证 |
| 9. 覆盖度与门禁 | ✅ 大部分 | Gate-Phase/Coverage/CWE/Evidence/C 基础完成；Gate-Engine 0.80 成功率阈值与 Gate-H 评分/pivot/attempt 纪律已接入 |
| 10. 轮次与收敛 | ✅ 完成 | round 递增+覆盖/阶段台账按轮隔离前滚；Gate-C 连续 2 轮零新增收敛；max rounds 强制部分报告；audit_rounds 逐轮决策可追溯 |
| 11. 数据模型 | ✅ 完成 | 表/列/索引/repository 资产/审计表 format v4 归档快照 |
| 12. Agent 与工具 | ✅ 完成 | code_planner/code_worker、受限工具面、证据/覆盖/假设工具 |
| 13. API | ✅ 完成 | progress/report/source/capabilities |
| 14. UI | ✅ 完成 | 创建/审计页签/证据/报告/Mock |
| 15. 报告格式 | ✅ 完成 | 确定性 Markdown/JSON + 缺口/引擎/限制 |
| 16. 安全与资源 | 🟡 大部分 | 工具白名单/静态不执行/路径/预算；动态沙箱未接 |
| 17. 失败处理与恢复 | 🟡 大部分 | 常见失败/重启/完成态保护；轮次/watchdog 细节待加固 |
| 18. 测试与评估 | 🟡 大部分 | 单元/真实引擎/UI 构建/PG 端到端/真实 LLM 三源 E2E/三语言基准/归档恢复；动态验证仍未做 |
| 19. 里程碑 | 🟡 M1/M2 部分、M4 部分 | 见下节 |
| 20. 风险与限制 | ✅ 完成 | 使用说明/报告均有披露 |
| 附录 A–G | 🟡 部分 | CWE/证据/QuerySpec/门禁已用；引擎模板矩阵需扩充 |

**整体估算：**

- 静态审计主链：约 85%
- 三引擎检测：约 75%（CodeQL 四语言与 Joern 七语言真实验证；Go/C/C++ CodeQL 仍需预构建 DB）
- 轮次/聚焦补扫：约 15%
- UI/报告/证据：约 85%
- 动态验证：0%（明确非本轮目标）
- 生产级测试/基准：约 35%

---

## 3. 已完成里程碑

### M1 基础设施 ✅

- `task_mode`、审计配置、audit_sessions/phases/coverage/intents/hypotheses/rounds/engine_jobs。
- findings 扩展、dedupe、结构化 code_evidence、repository 资产。
- 源码摄取（git/local/zip）、快照、安全校验。
- CodeGraph MCP/CLI 适配。
- code_planner/code_worker、受限工具面、审计工具。
- 审计导演 preflight、S1/S2/S4 种子意图、engine 启动。
- 进度/报告/源码/能力 API + 全栈 UI。
- 真实 CodeQL/Joern Java 验证。

### M2 审计闭环 🟡

- sink 预扫描、CWE/模块/站点覆盖台账、S4 批次意图。
- 覆盖回执、候选/确认/反驳、去重、报告。
- Gate-Phase/Coverage/CWE/Evidence 基础；完成态/部分报告。
- ✅ 多轮聚焦补扫：覆盖/阶段台账按轮隔离前滚（终态行保留、planned/missed 重置为可认领）、S0 仅第 1 轮、audit_rounds 逐轮决策记录。
- ✅ Gate-C 收敛：连续 2 轮零新增（排除 refuted/design_intent）→ done_with_gaps；max rounds 强制部分报告。
- ✅ S3/S5–S10 深链：入口点候选、finding_ids、阶段协议、S10 非执行 PoC 与报告可见。
- **未完成**：真实 LLM 深链质量抽样（Gate-H 评分/pivot 细则已于 2026-10-28 完成）。

### M3 深度与门禁 🟡

- ✅ S3/S5–S10 服务端全链路、S10 PoC artifact 绑定与 Gate-Engine 成功率阈值。
- 已完成：Gate-H findings→hypotheses 硬规则、30/30/20/20 评分、低于 70 警告、连续反驳 pivot 缺口与轮次台账。未完成：真实 LLM 深链质量基准。

### M4 三引擎 🟡

- CodeQL/Joern/CodeGraph 适配、意图/查询合成、SARIF/JSON 解析、跨引擎归并。
- 已真实验证 CodeQL Java/Python/JS/TS 与 Joern Java/Python/JS/TS/Go/C/C++ taint/sink。
- 未接入 LLM 辅助自由目标意图识别/查询体生成。

### M5 兜底/加固 🟡

- CodeGraph fallback、路径/压缩炸弹/超时/工具白名单/报告脱敏。
- ✅ 审计归档/恢复：format v4 快照/恢复审计七表；服务端验证报告保留且 pentest 逻辑保持 idle。
- 未完成：性能/成本评估、动态沙箱。

---

> 详细待完成清单（任务/文件/验收/禁止事项）已补充到设计 spec §22–§24，Codex 实施以该清单为准；本路线图保留优先级概览。

## 4. 下一步计划（按优先级）

### P0：可交付性验证（建议下一迭代）

1. **PostgreSQL 端到端**
   - 准备测试 PG，执行 `ARTEX_PG_DSN=... go test ./db ./server -run 'TestAudit|TestCodeFinding|TestTaskTemplate' -v`。
   - ✅（2026-10-27 部分完成）用便携 PostgreSQL 16.15（Maven Central zonky 二进制）在 55432 端口起测试库，`ARTEX_PG_DSN` 指向它后：`./db ./server -run TestAudit` 70 项审计测试全部实际执行并通过（0 skip）。修复 1 个真实缺陷：`findings.confidence` 由 `REAL` 迁移为 `DOUBLE PRECISION`（0.9 存取精度损失导致 `TestAuditUpdateFindingVerification` 失败）。
   - ✅（2026-10-27 完成）真实 LLM 配置已跑通 Git/本地/zip 三种输入端到端，报告与 token/耗时记录见 `docs/audit-benchmarks/2026-10-27-llm-e2e-and-benchmarks.md`。
   - 验收：任务从 created → running → done/done_with_gaps，报告可下载，无 SQL 错误/死锁。

2. **真实任务基准回归**
   - 建 3 个夹具：Java Spring（SQLi/命令注入）、Python Flask（路径/SSRF）、Node Express（命令/原型污染）。
   - ✅（2026-10-27 完成）Java/Python/Node 三夹具已各命中至少 1 个真实漏洞；召回、误报、耗时、token、引擎缺口记录见 `docs/audit-benchmarks/2026-10-27-llm-e2e-and-benchmarks.md`。

3. **归档/恢复**

   - 把 audit_sessions/phases/coverage/intents/hypotheses/rounds/engine_jobs 纳入 task archive 格式（版本升级+兼容测试），解除 code_audit 归档守卫。
   - ✅（2026-10-27 完成）`TaskArchiveFormatVersion=4`，数据层 round-trip 覆盖审计七表；服务层隔离 PG 验证归档→恢复→报告下载、任务暂停、无 pentest deadline/goals。
   - 验收：归档→恢复→报告/证据仍在，恢复后不会自动跑渗透逻辑。

### P1：深度与多轮（核心能力）

4. **多轮聚焦补扫与收敛 ✅（2026-10-27）**
   - round 递增；为下一轮复制覆盖/阶段台账（终态保留、planned/missed 重置为 unowned planned）；S0 仅第 1 轮；audit_rounds 记录每轮新增/门禁/决策。
   - Gate-C 连续 2 轮零新增收敛；最大轮次强制部分报告；轮次隔离保证不重复派同一意图（claim 校验 intent round == session round）。
   - 验证：`TestAuditDirectorAdvancesRoundOnGateFailure`、`TestAuditDirectorConvergesAfterTwoZeroRounds`、`TestAuditRoundFindingCounts` 通过；70→73 个审计测试全绿。

5. **完整质量门禁 ✅（2026-10-28）**
   - Gate-C/CWE/H/Engine 接入轮次决策；Gate-H 假设纪律（3 次失败 pivot/超过尝试上限）。
   - Gate-Engine：required 引擎缺失/查询失败率超阈值时阻断或降级。
   - ✅（2026-10-27 完成）Gate-Engine 按 attempted/succeeded 计算成功率，标准阈值 0.80；required 缺失仍阻断。
   - ✅（2026-10-28 完成）Gate-H：有 findings 但零假设即失败；非终态假设达到/超过 3 次尝试失败；连续 3 个 refuted 且无新方向失败；30/30/20/20 评分低于 70 记 warning 不单独阻断；planner 收到 Gate-H 失败/警告时要求记录新假设并改变验证角度。
   - 验证：`TestAuditGatesScoreHypothesisQualityAndPivot`、`TestAuditDeepChainCompletesWithNonExecutingPoC`、`TestBuiltinCodeAuditPromptSeeds`。
   - 验收：门禁结果与轮次决策一致，报告中可追溯。

6. **S3/S5–S10 全链路 ✅（2026-10-27）**
   - S3 数据流、S5 验证（source→sink/sanitizer/替代路径）、S6 逻辑/合规、S7 Odin 深析、S8 设计验证、S9 深度放大、S10 PoC artifact。
   - 验收：每个 high/critical 候选有验证结论；高危确认有设计验证/替代路径；PoC artifact 不执行。
   - 已完成：S3 入口点 coverage 候选；S5/S8/S10 assigned findings；S6/S7/S9 阶段候选；planner/worker 强制阶段协议；S10 artifact 写入并绑定 `code_evidence.poc`，`executed=false`。
   - 验证：`TestAuditDeepChainCompletesWithNonExecutingPoC` 覆盖候选→派发→覆盖回执→PoC→报告。

### P1：多引擎扩展

7. **CodeQL 非 Java 模板 ✅（2026-10-28）**
   - 已修复 query pack 获取/安装说明；Python/JS/TS taint 与 sink 模板均用 CodeQL 2.27.3 真实建库、编译、analyze 并命中；本地 pack 依赖闭包生成 `codeql-pack.lock.yml` 并向 CodeQL 传递精确版本目录，避免多版本解析歧义；Go/C/C++ 保持预构建 DB 路径。
   - 验收：Python/JS/TS 真实夹具均命中，Java 历史验证保留。

8. **Joern 非 Java 验证 ✅（2026-10-28）**
   - Python/JS/TS/Go/C/C++ 均有 live taint/sink 测试；修正 CPGQL 重复主体、sanitizer path element 匹配与 Python/C/Go sink argument 数据流终点；补 sanitizer/path-scope 过滤。
   - 验收：每个声明支持的语言均真实验证；Java 基线复跑通过；Windows `.bat` 启动器与 JDK 17 已验证。

9. **LLM 辅助意图识别/查询合成 ✅（2026-10-28）**
   - 自由目标 → DetectionIntent JSON（严格 schema、CWE/语言/scope/engine/pattern 校验）；LLM 只能扩展结构化 IR，不能输出任意 CPGQL/CodeQL。初始输出最多 2 次修复，失败回退确定性 sink intents。
   - 报告/`audit_sessions.engines` 记录模型、prompt v1、raw hash、识别来源、修复次数和 query gap；`audit_detection_intents.provenance` 持久化每条意图来源。
   - 查询缓存 key 包含 engine version、language、commit、IR hash、template version。
   - 验收：用户输入“重点看文件上传和 SSRF”可生成 `CWE-434` 与 `CWE-918` 对应 intent；失败回退测试通过。

### P2：体验与加固

10. **UI 完善**
    - ✅ 引擎查询日志/缺口详情（2026-10-28）：任务详情展示最近作业、query hash、耗时、错误、意图识别 provenance 与缺口，不暴露查询文本/绝对路径。
    - ✅ 覆盖度缺口钻取（2026-10-28）：任务详情展示 planned/missed/exempt 行、位置、原因与未覆盖 CWE，不暴露绝对路径。
    - ✅ 候选/验证批量操作（2026-10-29）：任务详情支持候选批次多选与批量写入 confirmed/refuted/design_intent；后端校验任务归属、candidate/unverified 状态、必填证据和 200 条上限。
    - ✅ 报告渲染/下载与源码行高亮（2026-10-29）：报告页支持 Markdown 预览、复制和 fetch→blob 下载并携带 Bearer；源码查看器支持起止行区间高亮、窗口裁剪与醒目的行号/边框标识。
    - ✅ 模板管理 mode/audit_config 编辑（2026-10-29）：模板抽屉可选择渗透/代码审计模式，代码审计模板编辑 audit_config JSON；保存走后端校验/归一化，切换渗透模式清空配置，Mock 同步。
11. **安全加固**
    - ✅ 安全加固（2026-10-29）：引擎 stderr/错误在分类源头截断并统一脱敏绝对路径、userinfo、Bearer、secret assignment、云 key 与私钥；报告 DLP 沿用同一模式；artifact 符号链接/ADS 防护已复核；CodeQL 限定 no-build/RAM/线程/超时，Joern 限定模板/可选沙箱/超时/输出。
12. **性能/成本**
    - ✅ 引擎查询作业并发（2026-10-29）：`RunIntents` 使用有界 worker 池；预算 `engine_concurrency` 默认 1、上限 4；JobResult 顺序稳定且单作业失败不中断其他作业。
    - 待办：大仓库索引/DB/CPG 缓存、准备阶段并发、token 预算、max sink site 采样策略；基准回归纳入 CI（可选）。
13. **动态验证（后续独立项目）**
    - 一次性容器部署、构建、PoC 执行、MITM 流量取证、finding 绑定。当前明确不在静态轮次内。

---

## 5. 建议的下一迭代范围（两周粒度）

**迭代 A（可交付性）**

- PG 端到端 + 3 夹具基准 + 归档/恢复 + 修复所有 skipped 审计测试。
- 验收：真实任务可创建、运行、完成、报告下载；归档恢复通过。

**迭代 B（深度）**

- 多轮聚焦补扫/收敛 + Gate-C/H/Engine + S5/S8 验证链。
- 验收：覆盖不足自动补扫；高危候选有验证/设计校验；报告轮次历史可追溯。

**迭代 C（引擎扩展）**

- CodeQL Python/JS 模板 + Joern 非 Java 验证 + LLM 意图识别原型。
- 验收：至少 Python/JS 引擎命中；自由目标能生成结构化 DetectionIntent。

---

## 6. 风险与阻塞

| 风险/阻塞 | 影响 | 下一步 |
|---|---|---|
| GitHub 网络不可达 | 提交已本地完成但未推送 | 配置代理/SSH key 后 `git push -u origin feat/code-audit` |
| CodeQL packs 版本/清单 | 已解决（2.27.3 + 版本化 packs + lockfile） | CI 可缓存 CodeQL 2.27.3 与 java-all@9.2.0/python-all@7.2.8/javascript-all@2.10.4 |

---

## 7. 提交/推送状态

- 本地提交：`a137d14`（121 files，+72184/−288）。
- 分支：`feat/code-audit`。
- 远程：`origin` = `https://github.com/1iK3/ARTEX.git`。
- 推送失败原因：`Failed to connect to github.com port 443`（当前网络不可达）。未配置代理/SSH key 授权。
- 待网络恢复后执行：

```bash
cd ARTEX
git push -u origin feat/code-audit
```

- 如需走代理：

```bash
git config --global http.proxy http://127.0.0.1:7890
git config --global https.proxy http://127.0.0.1:7890
git push -u origin feat/code-audit
```

- 若使用 SSH：将 `~/.ssh/id_ed25519.pub` 加到 GitHub 账号，改用 `git@github.com:1iK3/ARTEX.git`。
