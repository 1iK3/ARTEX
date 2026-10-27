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

- CodeQL 2.25.5：Java build-mode=none 建库、QL 编译、analyze，taint 与 sink 各命中 1 条。
- Joern 4.0.535：Java CPG 解析、CPGQL taint/sink 执行，各命中 1 条。
- CodeGraph：真实 MCP/CLI 适配测试通过。
- Web：`tsc --noEmit` 与 `build:static` 通过，31 个路由静态生成。
- Go：audit/engines/agent/db/server 目标测试与 `go build ./...` 通过。

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
| 5.3 生命周期 | 🟡 大部分 | ingest/running/done/done_with_gaps；多轮 round_review 未接 |
| 5.4 恢复 | 🟡 大部分 | 快照/索引检查、幂等 session/intent/coverage；完成态恢复已保护 |
| 5.5 删除 | 🟡 大部分 | 导演停止、CodeGraph 关闭；审计表随任务级联删除 |
| 6. 源码获取与快照 | ✅ 完成 | git/local/zip、路径/压缩炸弹/符号链接防护、超时 |
| 7.1 引擎能力矩阵 | ✅ 完成 | CodeGraph/CodeQL/Joern/fallback |
| 7.2 DetectionIntent | ✅ 完成 | sink 规则确定性生成 + 框架污点合并 |
| 7.3 QuerySpec IR | ✅ 完成 | 模板/哈希/缓存/规范化 |
| 7.4 意图识别 | 🟡 部分 | sink 规则/计划确定性识别完成；自由目标 LLM 解析未接 |
| 7.5 查询合成 | 🟡 部分 | 模板主路径完成；LLM 辅助 IR/查询体未接 |
| 7.6 CodeQL 适配器 | 🟡 部分 | Java 真实验证；Python/JS/TS 模板受 packs 限制未注册 |
| 7.7 Joern 适配器 | 🟡 部分 | Java 真实验证；其他语言模板已注册未逐一验证 |
| 7.8 CodeGraph 适配器 | ✅ 完成 | MCP explore + CLI 工具 |
| 7.9 原生兜底 | ✅ 完成 | 只读 search/read，路径限制 |
| 7.10 引擎调度 | ✅ 完成 | preflight 内 probe/prepare/run，失败记 gap |
| 7.11 结果归一化 | ✅ 完成 | 跨引擎归并、置信度、sink site 转换 |
| 8. 审计阶段流水线 | 🟡 部分 | S0/S1/S2/S4/S5 主链；S3/S6/S7/S8/S9/S10 仍多为跳过/预留 |
| 9. 覆盖度与门禁 | 🟡 部分 | Gate-Phase/Coverage/CWE/Evidence 基础；Gate-C/H/Engine 未完整驱动轮次 |
| 10. 轮次与收敛 | ❌ 未完成 | M1 固定轮次；聚焦补扫/连续零发现收敛未实现 |
| 11. 数据模型 | ✅ 完成 | 表/列/索引/repository 资产/归档守卫 |
| 12. Agent 与工具 | ✅ 完成 | code_planner/code_worker、受限工具面、证据/覆盖/假设工具 |
| 13. API | ✅ 完成 | progress/report/source/capabilities |
| 14. UI | ✅ 完成 | 创建/审计页签/证据/报告/Mock |
| 15. 报告格式 | ✅ 完成 | 确定性 Markdown/JSON + 缺口/引擎/限制 |
| 16. 安全与资源 | 🟡 大部分 | 工具白名单/静态不执行/路径/预算；动态沙箱未接 |
| 17. 失败处理与恢复 | 🟡 大部分 | 常见失败/重启/完成态保护；轮次/watchdog 细节待加固 |
| 18. 测试与评估 | 🟡 部分 | 单元/真实引擎/UI 构建；无 PG 端到端、无基准回归 |
| 19. 里程碑 | 🟡 M1/M2 部分、M4 部分 | 见下节 |
| 20. 风险与限制 | ✅ 完成 | 使用说明/报告均有披露 |
| 附录 A–G | 🟡 部分 | CWE/证据/QuerySpec/门禁已用；引擎模板矩阵需扩充 |

**整体估算：**

- 静态审计主链：约 75%
- 三引擎检测：约 55%（Java 验证；其他语言/查询类型待扩展）
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
- **未完成**：Gate-C/H/Engine 完整驱动、S3/S5/S6/S7/S8/S9/S10 全链路、多轮聚焦补扫。

### M3 深度与门禁 ❌/🟡

- 已预留 S3/S5–S10 阶段与候选；S5 有 finding_ids 候选/assigned findings 工具。
- 未实现：设计验证、深度放大、PoC artifact 完整流程、多轮收敛。

### M4 三引擎 🟡

- CodeQL/Joern/CodeGraph 适配、意图/查询合成、SARIF/JSON 解析、跨引擎归并。
- 已真实验证 Java taint/sink；Python/JS/TS CodeQL 与 Joern 非 Java 待验证/补齐。
- 未接入 LLM 辅助自由目标意图识别/查询体生成。

### M5 兜底/加固 🟡

- CodeGraph fallback、路径/压缩炸弹/超时/工具白名单/报告脱敏。
- 未完成：审计归档/恢复、PG 端到端、基准回归、性能/成本评估、动态沙箱。

---

## 4. 下一步计划（按优先级）

### P0：可交付性验证（建议下一迭代）

1. **PostgreSQL 端到端**
   - 准备测试 PG，执行 `ARTEX_PG_DSN=... go test ./db ./server -run 'TestAudit|TestCodeFinding|TestTaskTemplate' -v`。
   - 修复所有 skipped 的审计 DB 测试（preflight、claim/release、completion、report、verification）。
   - 用一个真实 LLM 配置创建 code_audit 任务，跑通 Git/本地/zip 三种输入，产出报告。
   - 验收：任务从 created → running → done/done_with_gaps，报告可下载，无 SQL 错误/死锁。

2. **真实任务基准回归**
   - 建 3 个夹具：Java Spring（SQLi/命令注入）、Python Flask（路径/SSRF）、Node Express（命令/原型污染）。
   - 记录：召回、误报、耗时、token、引擎缺口。
   - 验收：至少各命中 ground truth 的 1 个真实漏洞；报告标明未覆盖项。

3. **归档/恢复**
   - 把 audit_sessions/phases/coverage/intents/hypotheses/rounds/engine_jobs 纳入 task archive 格式（版本升级+兼容测试），解除 code_audit 归档守卫。
   - 验收：归档→恢复→报告/证据仍在，恢复后不会自动跑渗透逻辑。

### P1：深度与多轮（核心能力）

4. **多轮聚焦补扫与收敛**
   - round 递增；为下一轮复制/生成 planned CWE/module/sink 覆盖行；候选生成按缺口/未验证发现/引擎失败。
   - Gate-C 连续 2 轮零新增收敛；最大轮次强制部分报告。
   - 验收：覆盖不达标任务能自动补扫，不是直接 done_with_gaps；重复轮次不重复派同一意图。

5. **完整质量门禁**
   - Gate-C/CWE/H/Engine 接入轮次决策；Gate-H 假设纪律（3 次失败 pivot/超过尝试上限）。
   - Gate-Engine：required 引擎缺失/查询失败率超阈值时阻断或降级。
   - 验收：门禁结果与轮次决策一致，报告中可追溯。

6. **S3/S5–S10 全链路**
   - S3 数据流、S5 验证（source→sink/sanitizer/替代路径）、S6 逻辑/合规、S7 Odin 深析、S8 设计验证、S9 深度放大、S10 PoC artifact。
   - 验收：每个 high/critical 候选有验证结论；高危确认有设计验证/替代路径；PoC artifact 不执行。

### P1：多引擎扩展

7. **CodeQL 非 Java 模板**
   - 修复 query pack 获取/安装说明；补齐 Python/JS/TS taint 或 sink 模板并用真实引擎验证；Go/C/C++ 预构建 DB 路径。
   - 验收：至少 Python/JS 各一个真实夹具命中。

8. **Joern 非 Java 验证**
   - 对 Python/JS/TS/Go/C/C++ 逐一跑 parse+taint/sink；修正 CPGQL；补 sanitizer/path-scope 过滤。
   - 验收：每个声明支持的语言有 live 测试或明确 unsupported。

9. **LLM 辅助意图识别/查询合成**
   - 自由目标 → DetectionIntent JSON（schema 校验、CWE/语言/scope 校验）；模板不足时 LLM 扩展 IR（不是任意 CPGQL）。
   - 验收：用户输入“重点看文件上传和 SSRF”能生成对应 intent/查询；失败回退确定性意图。

### P2：体验与加固

10. **UI 完善**
    - 引擎查询日志/缺口详情；覆盖度缺口钻取；候选/验证批量操作；报告 Markdown 渲染/下载鉴权；源码查看器行高亮改进。
    - 模板管理支持编辑 task_mode/audit_config。
11. **安全加固**
    - 引擎 stderr/路径脱敏全量覆盖；报告 DLP（私钥/云 key）；artifact 符号链接/ADS 复核；CodeQL/Joern 资源/沙箱策略。
12. **性能/成本**
    - 大仓库索引/DB/CPG 缓存、引擎并发/超时、token 预算、max sink site 采样策略；基准回归纳入 CI（可选）。
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
| 本机无 PostgreSQL | 审计 DB 测试全部 skip，端到端未执行 | 提供 `ARTEX_PG_DSN` 或测试 PG |
| GitHub 网络不可达 | 提交已本地完成但未推送 | 配置代理/SSH key 后 `git push -u origin feat/code-audit` |
| CodeQL packs 版本/清单 | Python/JS/TS 模板不可用 | 固定 packs 版本/重新下载；在 CI 缓存 |
| Joern 非 Java 未验证 | 其他语言模板可能失效 | 逐语言 live 测试/修正 CPGQL |
| 无真实 LLM 运行记录 | 任务级端到端未证明 | 配置 LLM profile 跑夹具 |
| 多轮缺失 | 覆盖不足时只能部分报告 | 优先迭代 B |
| 归档守卫 | code_audit 任务不能归档 | 迭代 A 纳入审计表 |

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
