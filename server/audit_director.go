package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
)

// errAuditRunStopped is the cancellation cause used when a task is deleted or
// the server shuts down. Preflight treats it as a control-flow stop, not a
// task failure.
var errAuditRunStopped = errors.New("audit run stopped")

type auditRun struct {
	ctx          context.Context
	cancel       context.CancelCauseFunc
	started      bool
	watchdogOnce sync.Once
}

// AuditDirector owns the code-audit preflight and the lifetime of one run per
// task. The existing Engine still executes planner/worker loops; the director
// just prepares the session/source/graph and hands the engine a task-scoped
// context that Stop can cancel.
type AuditDirector struct {
	s    *Server
	mu   sync.Mutex
	runs map[string]*auditRun

	// completeMu serializes completion decisions. Multiple terminal intents can
	// be observed in quick succession; only the first one may generate a report.
	completeMu sync.Mutex
}

func newAuditDirector(s *Server) *AuditDirector {
	return &AuditDirector{s: s, runs: map[string]*auditRun{}}
}

// Start prepares (first run) or reuses (resume) an audit session and starts the
// engine. Concurrency is guarded per task: a second Start while preflight is
// still running is a no-op, and a second Start after it completes just nudges the
// already-running engine.
func (d *AuditDirector) Start(ctx context.Context, t *Task) error {
	if t == nil {
		return nil
	}
	if t.Mode != db.TaskModeCodeAudit {
		return fmt.Errorf("任务 %s 不是代码审计任务", t.ID)
	}
	if d == nil || d.s == nil || d.s.m == nil || d.s.m.pg == nil {
		return errors.New("审计导演未初始化")
	}
	if d.s.engine.IsDeleting(t.ID) {
		return errors.New("任务正在删除，无法启动代码审计")
	}

	d.mu.Lock()
	if run := d.runs[t.ID]; run != nil {
		started := run.started
		d.mu.Unlock()
		if !started {
			return nil // preflight is still in flight
		}
		d.s.invalidateTaskAgentsFor(t.ID)
		if auditTaskWaitingForAdmission(t) {
			return nil
		}
		d.s.engine.Run(run.ctx, t)
		d.startCompletionWatchdog(run, t)
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	run := &auditRun{ctx: runCtx, cancel: cancel}
	d.runs[t.ID] = run
	d.mu.Unlock()

	if err := d.prepareAndRun(runCtx, t, run); err != nil {
		canceled := runCtx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, errAuditRunStopped)
		d.finishRun(t.ID, run)
		if canceled {
			return err
		}
		d.emit(t, db.Activity{
			Worker: "system", Kind: "text", IsError: true,
			Summary: "代码审计启动失败: " + err.Error(), Detail: err.Error(),
		})
		d.markSessionFailed(t.ID)
		if _, statusErr := d.s.m.SetTaskStatusGuarded(t.ID, "failed"); statusErr != nil {
			log.Printf("[audit] task %s 标记失败: %v", t.ID, statusErr)
		}
		return err
	}
	return nil
}

func (d *AuditDirector) prepareAndRun(ctx context.Context, t *Task, run *auditRun) error {
	taskID, err := parseTaskID(t.ID)
	if err != nil {
		return err
	}
	session, err := d.s.m.pg.GetAuditSession(taskID)
	if err != nil {
		return err
	}
	if session != nil && db.AuditStatusTerminal(session.Status) {
		d.handleFinishedAuditSession(t, session, run)
		return nil
	}

	cfg, err := decodeAuditTaskConfig(t)
	if err != nil {
		return err
	}
	if err := audit.ValidateConfig(cfg, d.s.auditLocalRoots()); err != nil {
		return fmt.Errorf("审计配置无效: %w", err)
	}
	cfg = audit.NormalizeConfig(cfg)

	if session == nil {
		engines, _ := json.Marshal(cfg.Engines)
		session, err = d.s.m.pg.CreateAuditSession(db.AuditSession{
			TaskID: taskID, Status: db.AuditStatusIngest, SourceType: cfg.SourceType,
			Depth: cfg.Depth, Backend: audit.EngineCodeGraph, MaxRounds: cfg.MaxRounds,
			Engines: engines,
		})
		if err != nil {
			return err
		}
	}

	switch session.Status {
	case db.AuditStatusIngest:
		if err := d.preflight(ctx, t, taskID, cfg, session); err != nil {
			return err
		}
	case db.AuditStatusDone, db.AuditStatusDoneWithGaps:
		d.handleFinishedAuditSession(t, session, run)
		return nil
	case db.AuditStatusRunning, db.AuditStatusRoundReview:
		if !auditSnapshotExists(session.SnapshotPath) {
			d.emit(t, db.Activity{Worker: "system", Kind: "text",
				Summary: "代码审计：源码快照缺失，重置为 ingest 并重新预检"})
			ingest := db.AuditStatusIngest
			if _, err := d.s.m.pg.UpdateAuditSession(taskID, db.AuditSessionUpdate{Status: &ingest}); err != nil {
				return fmt.Errorf("重置审计会话为 ingest 失败: %w", err)
			}
			if err := d.preflight(ctx, t, taskID, cfg, session); err != nil {
				return err
			}
		} else if auditResumeNeedsReindex(session.Backend, session.SnapshotPath) {
			d.emit(t, db.Activity{Worker: "system", Kind: "text",
				Summary: "代码审计：CodeGraph 索引缺失，重新建立索引"})
			backend, err := d.indexCodeGraph(ctx, t, cfg, session.SnapshotPath)
			if err != nil {
				return err
			}
			if !strings.EqualFold(backend, session.Backend) {
				if _, err := d.s.m.pg.UpdateAuditSession(taskID, db.AuditSessionUpdate{Backend: &backend}); err != nil {
					return fmt.Errorf("更新审计 backend 失败: %w", err)
				}
			}
		}
	default:
		return fmt.Errorf("审计会话状态为 %s，不能启动（需要 ingest/running/round_review）", session.Status)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Rebuild the task's agents after preflight so they pick up the session
	// snapshot/backend and the now-available audit deps. A graph adapter created
	// during admission may point at the pre-ingest path; close it first.
	d.s.closeAuditGraph(t.ID)
	d.s.invalidateTaskAgentsFor(t.ID)
	d.markStarted(t.ID, run)
	if auditTaskWaitingForAdmission(t) {
		d.emit(t, db.Activity{Worker: "system", Kind: "text",
			Summary: "代码审计：预检完成，等待并发准入"})
		return nil
	}
	d.s.engine.Run(run.ctx, t)
	d.startCompletionWatchdog(run, t)
	return nil
}

const auditCompletionWatchdogInterval = 30 * time.Second

// startCompletionWatchdog is the M1 safety net for cancelled/stopped workers
// and transient completion errors: the engine callback is not guaranteed to be
// the last event after a run is stopped, so poll the authoritative DB state.
func (d *AuditDirector) startCompletionWatchdog(run *auditRun, t *Task) {
	if d == nil || run == nil || t == nil {
		return
	}
	run.watchdogOnce.Do(func() {
		go watchAuditCompletion(run.ctx, auditCompletionWatchdogInterval,
			func() bool { return isTerminalStatus(t.lifecycleSnapshot().Status) },
			func() { d.maybeCompleteAudit(t, nil) })
	})
}

func watchAuditCompletion(ctx context.Context, interval time.Duration, isTerminal func() bool, check func()) {
	if interval <= 0 {
		interval = auditCompletionWatchdogInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if isTerminal != nil && isTerminal() {
				return
			}
			if check != nil {
				check()
			}
		}
	}
}

// auditTaskWaitingForAdmission reports whether the persisted task lifecycle is
// still queued or explicitly paused. The director must not start (or clear the
// pause barrier for) such a task; admission owns that transition under concMu.
func auditTaskWaitingForAdmission(t *Task) bool {
	if t == nil {
		return true
	}
	state := t.lifecycleSnapshot()
	return state.Queued || state.Paused
}

// handleFinishedAuditSession keeps a terminal audit session terminal. It is
// called before config validation so an old/incomplete task config can never
// turn an already-generated report into a failed session on restart.
func (d *AuditDirector) handleFinishedAuditSession(t *Task, session *db.AuditSession, run *auditRun) {
	d.emit(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("代码审计：会话已收尾（status=%s），保留现有报告", session.Status)})
	if !isTerminalStatus(t.lifecycleSnapshot().Status) {
		if _, statusErr := d.s.m.SetTaskStatusGuarded(t.ID, "done"); statusErr != nil {
			log.Printf("[audit] task %s 已收尾会话标记任务完成失败: %v", t.ID, statusErr)
		} else {
			t.Notify()
		}
	}
	if run != nil {
		d.finishRun(t.ID, run)
	}
}

func (d *AuditDirector) preflight(ctx context.Context, t *Task, taskID int64, cfg audit.Config, session *db.AuditSession) error {
	if d.s.m.dir == "" {
		return errors.New("服务器工作目录未配置")
	}
	d.emit(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("代码审计：开始源码摄取（%s，depth=%s）", cfg.SourceType, cfg.Depth)})

	var uploadPath string
	var err error
	if cfg.SourceType == audit.SourceZip {
		uploadPath, err = d.resolveUpload(cfg.UploadID)
		if err != nil {
			return err
		}
	}
	snapshot := filepath.Join(d.s.m.dir, "tasks", t.ID, "audit", "source")
	if err := ctx.Err(); err != nil {
		return err
	}
	// A previous, partially completed ingest may have left a snapshot behind.
	// The snapshot is derived data; dropping it lets an ingest-status retry run
	// from a clean destination without touching the session row.
	if err := os.RemoveAll(snapshot); err != nil {
		return fmt.Errorf("清理旧源码快照失败: %w", err)
	}
	sourceCfg := audit.SourceConfig{
		Type: cfg.SourceType, RepoURL: cfg.RepoURL, Ref: cfg.Ref,
		LocalPath: cfg.LocalPath, UploadPath: uploadPath,
		AllowedRoots: d.s.auditLocalRoots(),
		IncludeTests: cfg.IncludeTests, IncludeVendor: cfg.IncludeVendor,
		MaxBytes:     auditBudgetInt64(cfg, "max_bytes"),
		MaxFiles:     auditBudgetInt(cfg, "max_files"),
		MaxFileBytes: auditBudgetInt64(cfg, "max_file_bytes"),
	}
	sourceTimeout := auditSourceTimeout(cfg)
	sourceCtx, cancelSource := context.WithTimeout(ctx, sourceTimeout)
	meta, err := audit.PrepareSource(sourceCtx, sourceCfg, snapshot)
	timedOut := errors.Is(sourceCtx.Err(), context.DeadlineExceeded)
	cancelSource()
	if err != nil {
		if timedOut {
			return fmt.Errorf("源码摄取超时（max_source_seconds=%s）: %w", sourceTimeout, err)
		}
		return fmt.Errorf("源码摄取失败: %w", err)
	}
	d.emit(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("代码审计：源码快照完成（%d 文件，%s）", meta.Files, languageSummary(meta.Languages))})
	if err := ctx.Err(); err != nil {
		return err
	}

	limits := auditPrescanLimits(cfg)
	profile, err := audit.ProfileSource(snapshot, limits)
	if err != nil {
		return fmt.Errorf("仓库画像失败: %w", err)
	}
	registry, err := audit.LoadRegistry()
	if err != nil {
		return fmt.Errorf("加载审计注册表失败: %w", err)
	}
	plan, err := audit.BuildPlan(profile, cfg, registry)
	if err != nil {
		return fmt.Errorf("生成审计计划失败: %w", err)
	}
	prescan, err := audit.Prescan(snapshot, profile, plan, registry, limits)
	if err != nil {
		return fmt.Errorf("sink 预扫描失败: %w", err)
	}
	d.emit(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("代码审计：计划完成（%d 阶段，%d 个 sink 站点，语言 %s）",
			len(plan.Phases), len(prescan.Sites), languageSummary(plan.Languages))})
	if err := ctx.Err(); err != nil {
		return err
	}

	// Optional engine detection runs inside preflight so S4 coverage includes
	// engine-only sites. Engine failures are gaps, never a reason to discard the
	// deterministic prescan inventory.
	engineSession := *session
	if strings.TrimSpace(engineSession.CommitSHA) == "" {
		engineSession.CommitSHA = meta.Commit
	}
	engineTimeout := auditEngineTimeout(cfg)
	engineCtx, cancelEngine := context.WithTimeout(ctx, engineTimeout)
	engRun, engErr := d.runAuditEngines(engineCtx, t, cfg, &engineSession, snapshot, plan, registry)
	engineTimedOut := errors.Is(engineCtx.Err(), context.DeadlineExceeded)
	cancelEngine()
	if engErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		redactions := auditEngineRedactPaths(snapshot, filepath.Join(d.s.m.dir, "tasks", t.ID, "audit", "engines"))
		redactions = auditEngineAddRedaction(redactions, d.s.m.dir)
		message := sanitizeAuditText(engErr.Error(), redactions)
		engRun.Warnings = append(engRun.Warnings, "引擎检测失败，已保留 prescan 结果: "+message)
		d.emit(t, db.Activity{Worker: "system", Kind: "text", IsError: true,
			Summary: "代码审计：引擎检测失败，继续使用 prescan 结果", Detail: message})
	}
	if engineTimedOut {
		engRun.Warnings = append(engRun.Warnings,
			fmt.Sprintf("引擎检测超时（max_engine_seconds=%s），已保留已完成的引擎结果", engineTimeout))
	}
	if engErr != nil || engineTimedOut {
		engRun.EnginesJSON = auditEngineJSONWithWarnings(engRun.EnginesJSON, cfg.Engines, engRun.Warnings)
	}
	d.emitAuditEngineActivity(t, engRun)
	if err := ctx.Err(); err != nil {
		return err
	}

	mergedSites := mergeAuditSinkSites(prescan.Sites, engRun.Sites, engRun.EngineEvidence)

	repoURL := strings.TrimSpace(meta.SourceRef)
	if repoURL == "" {
		repoURL = auditSourceLabel(cfg)
	}
	repoAssetID, err := d.s.m.pg.UpsertRepositoryAsset(repoURL, map[string]any{
		"source_type": meta.Type,
		"source_ref":  meta.SourceRef,
		"commit":      meta.Commit,
		"languages":   meta.Languages,
		"files":       meta.Files,
		"bytes":       meta.Bytes,
		"depth":       cfg.Depth,
	}, taskID)
	if err != nil {
		return fmt.Errorf("登记仓库资产失败: %w", err)
	}

	backend, err := d.indexCodeGraph(ctx, t, cfg, snapshot)
	if err != nil {
		return err
	}

	coverageRows := auditPlanCoverageRows(session.ID, plan, mergedSites.Sites, backend)
	coverageRows = applyAuditEngineCoverageEvidence(coverageRows, mergedSites)
	coverageRows = applyAuditNoSinkCoverageExemptions(coverageRows, mergedSites.Sites)
	if err := d.s.m.pg.UpsertAuditCoverage(coverageRows); err != nil {
		return fmt.Errorf("写入覆盖计划失败: %w", err)
	}
	if err := d.insertAuditPhases(session.ID, plan); err != nil {
		return fmt.Errorf("写入审计阶段失败: %w", err)
	}
	if len(mergedSites.Sites) == 0 {
		// No deterministic sink sites means S4 has no work. The phase remains
		// required in the plan, but it is explicitly satisfied by no_sinks so the
		// phase gate can pass without inventing an empty detection intent.
		phaseNow := time.Now()
		gateRaw, _ := json.Marshal(map[string]any{"reason": "no_sinks", "skipped_by": "audit_director"})
		if err := d.s.m.pg.UpdateAuditPhase(session.ID, 1, audit.PhaseDetect, db.AuditPhaseUpdate{
			Status: "skipped", SetStatus: true,
			Gate: gateRaw, SetGate: true,
			CompletedAt: &phaseNow, SetCompletedAt: true,
		}); err != nil {
			return fmt.Errorf("标记无 sink 的 S4 跳过失败: %w", err)
		}
	}

	seeds := append(buildAuditSeedIntents(plan, profile), buildAuditDetectionSeedIntents(mergedSites.Sites, 25)...)
	for _, seed := range seeds {
		intentID, exists, err := auditSeedIntentExists(t, seed)
		if err != nil {
			return err
		}
		if !exists {
			intentID, err = t.Store.AddIntent(auditSeedPayload(seed, 1), seed.Priority, nil, "audit_director")
			if err != nil {
				return fmt.Errorf("派发 %s 意图失败: %w", seed.Phase, err)
			}
		}
		if len(seed.SinkKeys) > 0 {
			assigned, err := d.s.m.pg.AssignAuditCoverage(session.ID, 1, seed.SinkKeys, intentID)
			if err != nil {
				return fmt.Errorf("分配 %s 覆盖行失败: %w", seed.Phase, err)
			}
			if !exists && assigned != int64(len(seed.SinkKeys)) {
				return fmt.Errorf("分配 %s 覆盖行不完整: %d/%d（%s）", seed.Phase, assigned, len(seed.SinkKeys), seed.Key)
			}
		}
	}
	if err := ensureAuditGoal(t); err != nil {
		return fmt.Errorf("创建审计目标失败: %w", err)
	}
	s0DoneAt := time.Now()
	if err := d.s.m.pg.UpdateAuditPhase(session.ID, 1, audit.PhaseIngest, db.AuditPhaseUpdate{
		Status: "done", SetStatus: true, CompletedAt: &s0DoneAt, SetCompletedAt: true,
	}); err != nil {
		return fmt.Errorf("标记 S0 完成失败: %w", err)
	}

	now := time.Now()
	one := 1
	maxRounds := cfg.MaxRounds
	if maxRounds < 1 {
		maxRounds = 1
	}
	planRaw, err := json.Marshal(plan)
	if err != nil {
		return fmt.Errorf("序列化审计计划失败: %w", err)
	}
	enginesRaw := engRun.EnginesJSON
	if len(enginesRaw) == 0 {
		enginesRaw, err = json.Marshal(cfg.Engines)
		if err != nil {
			return fmt.Errorf("序列化审计引擎配置失败: %w", err)
		}
	}
	status := db.AuditStatusRunning
	sourceRef := meta.SourceRef
	sourceType := meta.Type
	depth := cfg.Depth
	upd := db.AuditSessionUpdate{
		Status: &status, SourceType: &sourceType, SourceRef: &sourceRef,
		SnapshotPath: &snapshot, CommitSHA: &meta.Commit,
		Depth: &depth, Backend: &backend,
		Languages: plan.Languages, SetLanguages: true,
		Engines: enginesRaw, SetEngines: true,
		Plan: planRaw, SetPlan: true,
		Round: &one, MaxRounds: &maxRounds,
		RepoAssetID: &repoAssetID, SetRepoAsset: true,
	}
	if session.StartedAt == nil {
		upd.StartedAt = &now
		upd.SetStartedAt = true
	}
	if _, err := d.s.m.pg.UpdateAuditSession(taskID, upd); err != nil {
		return fmt.Errorf("更新审计会话失败: %w", err)
	}
	d.emit(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("代码审计：会话已启动（backend=%s，第 1/%d 轮，M1 不自动推进轮次），已派发 S1/S2 种子意图", backend, maxRounds)})
	return nil
}

func decodeAuditTaskConfig(t *Task) (audit.Config, error) {
	if t == nil || len(t.AuditConfig) == 0 || strings.TrimSpace(string(t.AuditConfig)) == "null" {
		return audit.Config{}, errors.New("代码审计任务缺少 audit 配置")
	}
	var cfg audit.Config
	if err := json.Unmarshal(t.AuditConfig, &cfg); err != nil {
		return audit.Config{}, fmt.Errorf("解析 audit 配置失败: %w", err)
	}
	return cfg, nil
}

func (d *AuditDirector) resolveUpload(uploadID string) (string, error) {
	uploadID = strings.TrimSpace(uploadID)
	if !safeChatID.MatchString(uploadID) {
		return "", errors.New("zip 审计 upload_id 非法")
	}
	dir := filepath.Join(d.s.m.dir, "drafts", uploadID, "uploads")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("读取上传目录失败: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	switch len(files) {
	case 0:
		return "", fmt.Errorf("上传目录 %s 中没有 zip 文件", dir)
	case 1:
		return files[0], nil
	default:
		names := make([]string, 0, len(files))
		for _, file := range files {
			names = append(names, filepath.Base(file))
		}
		sort.Strings(names)
		return "", fmt.Errorf("上传目录中有多个文件（%s），zip 审计只接受一个上传文件", strings.Join(names, ", "))
	}
}

func (d *AuditDirector) insertAuditPhases(sessionID int64, plan audit.Plan) error {
	phases := make([]db.AuditPhase, 0, len(plan.Phases))
	for _, phase := range plan.Phases {
		phases = append(phases, db.AuditPhase{Phase: phase.Phase, Required: phase.Required, Status: "pending"})
	}
	if err := d.s.m.pg.InsertAuditPhases(sessionID, 1, phases); err != nil {
		return err
	}
	// InsertAuditPhases treats the bool zero value as "required" (the schema
	// default). Apply the plan's exact required flag afterwards.
	for _, phase := range plan.Phases {
		if err := d.s.m.pg.UpdateAuditPhase(sessionID, 1, phase.Phase, db.AuditPhaseUpdate{
			Required: phase.Required, SetRequired: true,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (d *AuditDirector) indexCodeGraph(ctx context.Context, t *Task, cfg audit.Config, snapshot string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Engines[audit.EngineCodeGraph]))
	if mode == "" {
		mode = "required"
	}
	if mode == "off" {
		d.emit(t, db.Activity{Worker: "system", Kind: "text",
			Summary: "代码审计：CodeGraph 已关闭，使用只读源码兜底工具"})
		return "fallback", nil
	}
	bin := d.s.auditCodeGraphBin()
	if err := runCodeGraphIndex(ctx, bin, snapshot); err != nil {
		if cfg.Depth == audit.DepthDeep && mode == "required" {
			return "", fmt.Errorf("CodeGraph 索引失败（depth=deep 要求 codegraph）：%w", err)
		}
		d.emit(t, db.Activity{Worker: "system", Kind: "text", IsError: true,
			Summary: "代码审计：CodeGraph 索引失败，降级为源码兜底", Detail: err.Error()})
		return "fallback", nil
	}
	d.emit(t, db.Activity{Worker: "system", Kind: "text",
		Summary: "代码审计：CodeGraph 索引完成"})
	return audit.EngineCodeGraph, nil
}

func (d *AuditDirector) emit(t *Task, activity db.Activity) {
	if d == nil || d.s == nil || d.s.engine == nil || t == nil {
		return
	}
	d.s.engine.emitActivity(t, activity)
}

// markSessionFailed persists an unrecoverable preflight failure on the audit
// session while leaving its diagnostics in place.
func (d *AuditDirector) markSessionFailed(taskID string) {
	if d == nil || d.s == nil || d.s.m == nil || d.s.m.pg == nil {
		return
	}
	id, err := parseTaskID(taskID)
	if err != nil {
		return
	}
	session, err := d.s.m.pg.GetAuditSession(id)
	if err != nil || session == nil {
		return
	}
	failed := db.AuditStatusFailed
	if _, err := d.s.m.pg.UpdateAuditSession(id, db.AuditSessionUpdate{Status: &failed}); err != nil {
		log.Printf("[audit] task %s 标记审计会话失败: %v", taskID, err)
	}
}

func auditSnapshotExists(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func auditCodeGraphIndexExists(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(path, ".codegraph"))
	return err == nil && info.IsDir()
}

func auditResumeNeedsReindex(backend, snapshot string) bool {
	return strings.EqualFold(strings.TrimSpace(backend), audit.EngineCodeGraph) &&
		!auditCodeGraphIndexExists(snapshot)
}

func auditSourceTimeout(cfg audit.Config) time.Duration {
	const defaultSourceSeconds = 1800
	seconds := auditBudgetInt(cfg, "max_source_seconds")
	if seconds <= 0 {
		seconds = defaultSourceSeconds
	}
	if seconds > 24*60*60 {
		seconds = 24 * 60 * 60
	}
	return time.Duration(seconds) * time.Second
}

func (d *AuditDirector) markStarted(taskID string, run *auditRun) {
	d.mu.Lock()
	if d.runs[taskID] == run {
		run.started = true
	}
	d.mu.Unlock()
}

func (d *AuditDirector) finishRun(taskID string, run *auditRun) {
	d.mu.Lock()
	if d.runs[taskID] == run {
		delete(d.runs, taskID)
	}
	d.mu.Unlock()
	run.cancel(errAuditRunStopped)
}

// Stop cancels one task's audit run and closes its CodeGraph adapter. It is
// idempotent and safe to call from the task-delete barrier.
func (d *AuditDirector) Stop(taskID string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	run := d.runs[taskID]
	delete(d.runs, taskID)
	d.mu.Unlock()
	// Stop is also reached from run cancellation/deletion paths where the engine
	// observer may never fire. Best-effort completion here prevents a terminal
	// round from waiting forever for one last worker callback.
	if d.s != nil && d.s.m != nil && d.s.m.pg != nil {
		if t, ok := d.s.m.Task(taskID); ok && t.Mode == db.TaskModeCodeAudit &&
			!isTerminalStatus(t.lifecycleSnapshot().Status) {
			d.maybeCompleteAudit(t, nil)
		}
	}
	if run != nil {
		run.cancel(errAuditRunStopped)
	}
	if d.s != nil {
		d.s.closeAuditGraph(taskID)
	}
}

// StopAll cancels every run on server shutdown.
func (d *AuditDirector) StopAll() {
	if d == nil {
		return
	}
	d.mu.Lock()
	runs := d.runs
	d.runs = map[string]*auditRun{}
	d.mu.Unlock()
	for _, run := range runs {
		run.cancel(errAuditRunStopped)
	}
	if d.s != nil {
		d.s.closeAllAuditGraphs()
	}
}

// OnIntentDone gives the director basic per-phase bookkeeping: when every intent
// belonging to one audit phase reaches a terminal state, the phase is closed and
// the planner is nudged. Full gate/round decisions remain in the next task.
func (d *AuditDirector) OnIntentDone(t *Task, intentID int64, state string) {
	if d == nil || d.s == nil || d.s.m == nil || d.s.m.pg == nil || t == nil {
		return
	}
	if t.Mode != db.TaskModeCodeAudit || t.Store == nil || intentID <= 0 {
		return
	}
	taskID, err := parseTaskID(t.ID)
	if err != nil {
		return
	}
	session, err := d.s.m.pg.GetAuditSession(taskID)
	if err != nil || session == nil {
		return
	}
	if auditStateReleasesCoverage(state) {
		released, releaseErr := d.s.m.pg.ReleaseAuditCoverage(session.ID, session.Round, intentID)
		if releaseErr != nil {
			log.Printf("[audit] task %s intent #%d 覆盖行释放失败: %v", t.ID, intentID, releaseErr)
		} else if released > 0 {
			nodeID := intentID
			d.emit(t, db.Activity{
				Worker: "system", Kind: "text", NodeID: &nodeID,
				Summary: fmt.Sprintf("代码审计：意图 #%d 结束（%s），释放 %d 个未完成覆盖行回候选池", intentID, state, released),
			})
		}
	}
	if isTerminalStatus(t.lifecycleSnapshot().Status) {
		d.Stop(t.ID)
		return
	}
	// Completion is evaluated even when this intent has no audit phase metadata:
	// an unrelated terminal node can still be the last thing keeping the task
	// alive, and the check itself only counts active audit intents.
	defer d.maybeCompleteAudit(t, session)
	node, err := t.Store.GetNode(intentID)
	if err != nil || node == nil {
		return
	}
	phase := auditIntentPhase(node.Payload)
	if phase == "" {
		return
	}
	phases, err := d.s.m.pg.ListAuditPhases(session.ID, session.Round)
	if err != nil {
		return
	}
	var current *db.AuditPhase
	for i := range phases {
		if phases[i].Phase == phase {
			current = &phases[i]
			break
		}
	}
	if current == nil {
		return
	}
	intents, err := t.Store.ListByKind(db.KindIntent, 10000)
	if err != nil {
		return
	}
	status, complete := summarizeAuditPhaseIntents(intents, phase, session.Round)
	if !complete || current.Status == status {
		return
	}
	now := time.Now()
	if err := d.s.m.pg.UpdateAuditPhase(session.ID, session.Round, phase, db.AuditPhaseUpdate{
		Status: status, SetStatus: true, CompletedAt: &now, SetCompletedAt: true,
	}); err != nil {
		log.Printf("[audit] task %s phase %s 状态更新失败: %v", t.ID, phase, err)
		return
	}
	t.Notify()
}

// auditCompletionDecision is the pure action chosen after a round has no active
// intents and no unverified findings.
type auditCompletionDecision string

const (
	auditDecisionWait                auditCompletionDecision = "wait"
	auditDecisionRequestVerification auditCompletionDecision = "request_verification"
	auditDecisionRetryCoverage       auditCompletionDecision = "retry_coverage"
	auditDecisionComplete            auditCompletionDecision = "complete"
	auditDecisionCompleteWithGaps    auditCompletionDecision = "complete_with_gaps"
)

// decideAuditCompletion encodes the M1 convergence rules:
//   - active work or unverified findings always block completion;
//   - passing gates, or exhausting the round budget, produce a report;
//   - failed gates with remaining sink candidates stay in the loop;
//   - failed gates without any actionable candidate produce a partial report so
//     the task cannot hang forever.
func decideAuditCompletion(activeIntents, unverifiedFindings int, gatesPassed, atMaxRounds, hasSinkCandidates bool) auditCompletionDecision {
	switch {
	case activeIntents > 0:
		return auditDecisionWait
	case unverifiedFindings > 0:
		return auditDecisionRequestVerification
	case gatesPassed:
		return auditDecisionComplete
	case atMaxRounds:
		return auditDecisionCompleteWithGaps
	case hasSinkCandidates:
		return auditDecisionRetryCoverage
	default:
		return auditDecisionCompleteWithGaps
	}
}

// maybeCompleteAudit is the completion loop invoked after each terminal audit
// intent. It is deliberately conservative: it refuses to close the audit while
// any current-round audit intent is active or any finding still needs S5 review.
func (d *AuditDirector) maybeCompleteAudit(t *Task, session *db.AuditSession) {
	if d == nil || d.s == nil || d.s.m == nil || d.s.m.pg == nil || t == nil || t.Store == nil {
		return
	}
	d.completeMu.Lock()
	defer d.completeMu.Unlock()

	taskID, err := parseTaskID(t.ID)
	if err != nil {
		return
	}
	session, err = d.s.m.pg.GetAuditSession(taskID)
	if err != nil || session == nil {
		return
	}
	if session.Status != db.AuditStatusRunning && session.Status != db.AuditStatusRoundReview {
		return
	}
	intents, err := t.Store.ListByKind(db.KindIntent, 10000)
	if err != nil {
		return
	}
	active, phaseIntentCounts := summarizeAuditIntents(intents, session.Round)
	if active > 0 {
		return
	}
	ctx := d.s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	phases, err := d.s.m.pg.ListAuditPhases(session.ID, session.Round)
	if err != nil {
		return
	}
	now := time.Now()
	// Concurrent workers can finish at the same time; reconcile every phase from
	// the authoritative intent snapshot so a callback that has not run yet cannot
	// leave a phase pending in the report.
	phases, err = d.reconcileAuditPhases(session, phases, intents, now)
	if err != nil {
		log.Printf("[audit] task %s 阶段状态收口失败: %v", t.ID, err)
		return
	}
	unverified, err := countAuditUnverifiedFindings(ctx, d.s.m.pg, taskID)
	if err != nil {
		log.Printf("[audit] task %s 统计未验证 finding 失败: %v", t.ID, err)
		return
	}
	if unverified > 0 {
		d.emit(t, db.Activity{
			Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("代码审计：本轮意图已清空，但仍有 %d 个候选/未验证 finding，等待 S5 验证", unverified),
		})
		t.Notify()
		return
	}
	plan := auditPlanFromSession(session)
	rows, err := d.s.m.pg.ListAuditCoverage(session.ID, session.Round)
	if err != nil {
		return
	}
	phases, skipped, err := d.skipEmptyAuditPhases(session, phases, phaseIntentCounts, plan, rows, now)
	if err != nil {
		log.Printf("[audit] task %s 跳过无可执行阶段失败: %v", t.ID, err)
		d.emit(t, db.Activity{Worker: "system", Kind: "text", IsError: true,
			Summary: "代码审计：写入阶段跳过状态失败", Detail: err.Error()})
		return
	}
	if len(skipped) > 0 {
		d.emit(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("代码审计：跳过无目标阶段 %s", strings.Join(skipped, ", "))})
	}

	coverageRows := auditCoverageRows(rows)
	gates := auditGates(plan, auditCompletionPhaseStatuses(phases), coverageRows)
	gatesPassed := auditGatesPassed(gates)
	// M1 deliberately keeps round=1 and does not advance rounds. A session with a
	// missing/legacy MaxRounds still gets the forced-partial path by treating the
	// budget as one round; multi-round focused re-scan is not implemented yet.
	effectiveMaxRounds := session.MaxRounds
	if effectiveMaxRounds < 1 {
		effectiveMaxRounds = 1
	}
	atMaxRounds := session.Round >= effectiveMaxRounds

	if !gatesPassed && !atMaxRounds {
		released, releaseErr := d.releaseResidualCoverage(session, rows)
		if releaseErr != nil {
			log.Printf("[audit] task %s 释放未完成覆盖行失败: %v", t.ID, releaseErr)
			d.emit(t, db.Activity{Worker: "system", Kind: "text", IsError: true,
				Summary: "代码审计：释放未完成覆盖行失败", Detail: releaseErr.Error()})
			t.Notify()
			return
		}
		if released > 0 {
			rows, err = d.s.m.pg.ListAuditCoverage(session.ID, session.Round)
			if err != nil {
				return
			}
			d.emit(t, db.Activity{Worker: "system", Kind: "text",
				Summary: fmt.Sprintf("代码审计：释放 %d 个未完成覆盖行回候选池，等待补覆盖", released)})
		}
	}

	sinkCandidates := buildAuditCoverageCandidates(rows, 8, 25)
	decision := decideAuditCompletion(0, 0, gatesPassed, atMaxRounds, len(sinkCandidates) > 0)
	switch decision {
	case auditDecisionWait, auditDecisionRequestVerification:
		return
	case auditDecisionRetryCoverage:
		d.emit(t, db.Activity{
			Worker: "system", Kind: "text",
			Summary: "代码审计：门禁未通过，已释放未完成覆盖并通知规划者补扫（M1 不自动增加轮次）: " + auditGateGapSummary(gates),
		})
		t.Notify()
		return
	case auditDecisionComplete, auditDecisionCompleteWithGaps:
		status := db.AuditStatusDone
		forced := decision == auditDecisionCompleteWithGaps || !gatesPassed
		if forced {
			status = db.AuditStatusDoneWithGaps
		}
		if err := d.persistAuditCompletion(ctx, t, session, phases, rows, gates, status, forced, now); err != nil {
			log.Printf("[audit] task %s 生成审计报告失败: %v", t.ID, err)
			d.emit(t, db.Activity{Worker: "system", Kind: "text", IsError: true,
				Summary: "代码审计：报告生成失败，审计保持运行", Detail: err.Error()})
			t.Notify()
			return
		}
		d.emit(t, db.Activity{
			Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("代码审计完成：报告已生成（status=%s，round=%d/%d，门禁通过=%v）",
				status, session.Round, session.MaxRounds, gatesPassed),
		})
		t.Notify()
	}
}

// summarizeAuditIntents counts active current-round audit intents and the
// intents belonging to each phase. Unknown/future states are treated as active
// so a new engine state can never accidentally close a phase early.
func summarizeAuditIntents(intents []*db.Node, round int) (int, map[string]int) {
	byPhase := map[string]int{}
	active := 0
	for _, intent := range intents {
		if intent == nil || intent.Kind != db.KindIntent {
			continue
		}
		phase := auditIntentPhase(intent.Payload)
		if phase == "" || auditIntentRound(intent.Payload) != round {
			continue
		}
		if intent.State == "deleted" {
			continue
		}
		byPhase[phase]++
		switch intent.State {
		case "done", "blocked", "exhausted", "stopped":
		default:
			active++
		}
	}
	return active, byPhase
}

// reconcileAuditPhases closes any current-round phase whose intents are all
// terminal. It is the idempotent backstop for concurrent completion callbacks.
func (d *AuditDirector) reconcileAuditPhases(session *db.AuditSession, phases []db.AuditPhase, intents []*db.Node, now time.Time) ([]db.AuditPhase, error) {
	for i := range phases {
		status, complete := summarizeAuditPhaseIntents(intents, phases[i].Phase, session.Round)
		if !complete || strings.EqualFold(strings.TrimSpace(phases[i].Status), status) {
			continue
		}
		if err := d.s.m.pg.UpdateAuditPhase(session.ID, session.Round, phases[i].Phase, db.AuditPhaseUpdate{
			Status: status, SetStatus: true,
			CompletedAt: &now, SetCompletedAt: true,
		}); err != nil {
			return phases, err
		}
		phases[i].Status = status
		phases[i].CompletedAt = &now
	}
	return phases, nil
}

// auditSkipReason returns the persisted reason a required pending phase may be
// skipped without inventing work. S0 and S11 are never skipped here; S11 is
// host-generated, and S0 is the director's own immutable ingest record.
func auditSkipReason(phase string, phaseIntents int, plan audit.Plan, rows []db.AuditCoverage) (string, bool) {
	if phaseIntents > 0 {
		return "", false
	}
	switch phase {
	case audit.PhaseProfile, audit.PhaseSurface:
		if !auditHasAnyTarget(plan, rows) {
			return "no_targets", true
		}
		return "", false
	case audit.PhaseDataFlow:
		if auditHasPendingCoverageKind(rows, audit.CoverageKindEntryPoint) {
			return "", false
		}
		return "no_targets", true
	case audit.PhaseVerify, audit.PhaseLogic, audit.PhaseOdinDeep,
		audit.PhaseDesign, audit.PhaseDepth, audit.PhasePoC:
		return "no_targets", true
	case audit.PhaseDetect:
		if !auditHasCoverageKind(rows, audit.CoverageKindSinkSite) {
			return "no_sinks", true
		}
		return "", false
	default:
		return "", false
	}
}

func auditHasAnyTarget(plan audit.Plan, rows []db.AuditCoverage) bool {
	if len(plan.Languages) > 0 || len(plan.Modules) > 0 || len(plan.EntryPoints) > 0 {
		return true
	}
	for _, cwes := range plan.PlannedCWEs {
		for _, cwe := range cwes {
			if strings.TrimSpace(cwe) != "" {
				return true
			}
		}
	}
	for _, row := range rows {
		switch strings.ToLower(strings.TrimSpace(row.Kind)) {
		case audit.CoverageKindSinkSite, audit.CoverageKindEntryPoint:
			return true
		}
	}
	return false
}

func auditHasCoverageKind(rows []db.AuditCoverage, kind string) bool {
	for _, row := range rows {
		if strings.EqualFold(strings.TrimSpace(row.Kind), kind) {
			return true
		}
	}
	return false
}

func auditHasPendingCoverageKind(rows []db.AuditCoverage, kind string) bool {
	for _, row := range rows {
		if !strings.EqualFold(strings.TrimSpace(row.Kind), kind) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(row.Status)) {
		case audit.CoverageStatusPlanned, audit.CoverageStatusMissed:
			return true
		}
	}
	return false
}

// skipEmptyAuditPhases marks yet-pending required phases that genuinely have no
// work. S1/S2 are skipped only when the plan itself has no targets; S4 is skipped
// only when no sink-site rows exist. Phases with real targets remain pending.
func (d *AuditDirector) skipEmptyAuditPhases(session *db.AuditSession, phases []db.AuditPhase, phaseIntents map[string]int, plan audit.Plan, rows []db.AuditCoverage, now time.Time) ([]db.AuditPhase, []string, error) {
	skipped := make([]string, 0)
	for i := range phases {
		phase := &phases[i]
		if !phase.Required {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(phase.Status))
		if status != "" && status != "pending" {
			continue
		}
		reason, canSkip := auditSkipReason(phase.Phase, phaseIntents[phase.Phase], plan, rows)
		if !canSkip {
			continue
		}
		gateRaw, err := json.Marshal(map[string]any{"reason": reason, "skipped_by": "audit_director"})
		if err != nil {
			return phases, skipped, err
		}
		if err := d.s.m.pg.UpdateAuditPhase(session.ID, session.Round, phase.Phase, db.AuditPhaseUpdate{
			Status: "skipped", SetStatus: true,
			Gate: gateRaw, SetGate: true,
			CompletedAt: &now, SetCompletedAt: true,
		}); err != nil {
			return phases, skipped, err
		}
		phase.Status = "skipped"
		phase.Gate = gateRaw
		phase.CompletedAt = &now
		skipped = append(skipped, phase.Phase+"="+reason)
	}
	return phases, skipped, nil
}

// releaseResidualCoverage returns planned/missed rows still attached to an
// intent to the unowned candidate pool. Incomplete ownership must not mask
// actionable coverage from the planner.
func (d *AuditDirector) releaseResidualCoverage(session *db.AuditSession, rows []db.AuditCoverage) (int64, error) {
	ownerSet := map[int64]struct{}{}
	for _, row := range rows {
		status := strings.ToLower(strings.TrimSpace(row.Status))
		if row.IntentID == nil || (status != audit.CoverageStatusPlanned && status != audit.CoverageStatusMissed) {
			continue
		}
		ownerSet[*row.IntentID] = struct{}{}
	}
	owners := make([]int64, 0, len(ownerSet))
	for id := range ownerSet {
		owners = append(owners, id)
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i] < owners[j] })
	var released int64
	for _, id := range owners {
		n, err := d.s.m.pg.ReleaseAuditCoverage(session.ID, session.Round, id)
		if err != nil {
			return released, err
		}
		released += n
	}
	return released, nil
}

// auditCompletionPhaseStatuses treats the report phase as satisfied for the
// pre-report gate decision: S11 is pending precisely because this completion
// path is about to produce the report. The persisted phase row is only marked
// done after the report write succeeds.
func auditCompletionPhaseStatuses(phases []db.AuditPhase) []audit.PhaseStatus {
	statuses := auditPhaseStatuses(phases)
	for i := range statuses {
		if statuses[i].Phase != audit.PhaseReport {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(statuses[i].Status))
		if status == "" || status == "pending" {
			statuses[i].Status = "done"
		}
	}
	return statuses
}

func auditGateGapSummary(gates map[string]audit.GateResult) string {
	order := []string{"phase", "coverage", "cwe"}
	parts := make([]string, 0, len(order))
	for _, key := range order {
		gate, ok := gates[key]
		if !ok || gate.Passed {
			continue
		}
		parts = append(parts, gate.Name+": "+gate.Reason)
	}
	if len(parts) == 0 {
		return "无门禁缺口"
	}
	return strings.Join(parts, "; ")
}

// persistAuditCompletion builds and writes the deterministic report, closes S11,
// and only then flips the session to done/done_with_gaps.
func (d *AuditDirector) persistAuditCompletion(ctx context.Context, t *Task, session *db.AuditSession, phases []db.AuditPhase, rows []db.AuditCoverage, gates map[string]audit.GateResult, status string, forced bool, now time.Time) error {
	redact := make([]string, 0, 2)
	redact = addAuditRedactPath(redact, session.SnapshotPath)
	redact = addAuditRedactPath(redact, d.s.m.dir)
	safeGates := sanitizeAuditGates(gates, redact)
	gateResults := map[string]any{
		"round":      session.Round,
		"max_rounds": session.MaxRounds,
		"status":     status,
		"forced":     forced,
		"gates":      safeGates,
		"coverage":   audit.ComputeCoverage(auditPlanFromSession(session), auditCoverageRows(rows)),
	}
	gateRaw, err := json.Marshal(gateResults)
	if err != nil {
		return fmt.Errorf("序列化门禁结果失败: %w", err)
	}
	generatedAt := now.UTC()
	reportPhases := append([]db.AuditPhase(nil), phases...)
	for i := range reportPhases {
		if reportPhases[i].Phase == audit.PhaseReport &&
			(strings.TrimSpace(reportPhases[i].Status) == "" ||
				strings.EqualFold(strings.TrimSpace(reportPhases[i].Status), "pending")) {
			reportPhases[i].Status = "done"
			reportPhases[i].CompletedAt = &now
		}
	}
	md, js, err := d.s.buildAuditReport(ctx, t, session, reportPhases, rows, safeGates, status, generatedAt)
	if err != nil {
		return fmt.Errorf("生成报告失败: %w", err)
	}
	if err := d.writeAuditReportFiles(t, md, js); err != nil {
		return err
	}
	if err := d.markAuditPhaseStatus(session, audit.PhaseReport, "done", gateRaw, &now); err != nil {
		return fmt.Errorf("标记 S11 完成失败: %w", err)
	}
	completed := db.AuditSessionUpdate{
		Status:      &status,
		GateResults: gateRaw, SetGateResults: true,
		ReportJSON: js, SetReportJSON: true,
		ReportMD:    &md,
		CompletedAt: &now, SetCompletedAt: true,
	}
	if _, err := d.s.m.pg.UpdateAuditSession(session.TaskID, completed); err != nil {
		return fmt.Errorf("更新审计会话报告失败: %w", err)
	}
	return nil
}

func (d *AuditDirector) writeAuditReportFiles(t *Task, md string, reportJSON json.RawMessage) error {
	if d == nil || d.s == nil || d.s.m == nil || strings.TrimSpace(d.s.m.dir) == "" {
		return errors.New("服务器工作目录未配置，无法写入审计报告")
	}
	dir := filepath.Join(d.s.m.dir, "tasks", t.ID, "audit")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建审计报告目录失败: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(md), 0o644); err != nil {
		return fmt.Errorf("写入 report.md 失败: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), reportJSON, 0o644); err != nil {
		return fmt.Errorf("写入 report.json 失败: %w", err)
	}
	return nil
}

// markAuditPhaseStatus creates the phase row if an older plan omitted it (S11),
// then writes the terminal status and gate snapshot.
func (d *AuditDirector) markAuditPhaseStatus(session *db.AuditSession, phase, status string, gate json.RawMessage, completedAt *time.Time) error {
	phases, err := d.s.m.pg.ListAuditPhases(session.ID, session.Round)
	if err != nil {
		return err
	}
	found := false
	for _, p := range phases {
		if p.Phase == phase {
			found = true
			break
		}
	}
	if !found {
		if err := d.s.m.pg.InsertAuditPhases(session.ID, session.Round, []db.AuditPhase{{
			Phase: phase, Required: true, Status: status, Gate: gate, CompletedAt: completedAt,
		}}); err != nil {
			return err
		}
	}
	return d.s.m.pg.UpdateAuditPhase(session.ID, session.Round, phase, db.AuditPhaseUpdate{
		Status: status, SetStatus: true,
		Gate: gate, SetGate: true,
		CompletedAt: completedAt, SetCompletedAt: true,
	})
}

// auditStateReleasesCoverage reports whether a finished intent should return
// its still-planned/missed coverage rows to the candidate pool. Non-done
// terminal states release everything incomplete; done still releases planned
// rows the worker never receipted. Running/open/paused intents keep ownership.
func auditStateReleasesCoverage(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "done", "blocked", "exhausted", "stopped", "deleted":
		return true
	}
	return false
}

// summarizeAuditPhaseIntents counts only intents whose payload phase and round
// match. A phase closes as "done" only when every matching intent is terminal
// done; any blocked/exhausted/stopped sibling makes it "failed". Open/running/
// paused intents mean the phase is still in progress.
func summarizeAuditPhaseIntents(intents []*db.Node, phase string, round int) (string, bool) {
	total := 0
	allDone := true
	for _, intent := range intents {
		if intent == nil || auditIntentPhase(intent.Payload) != phase {
			continue
		}
		if auditIntentRound(intent.Payload) != round {
			continue
		}
		if intent.State == "deleted" {
			continue // retracted/soft-deleted intents do not poison a phase
		}
		total++
		switch intent.State {
		case "open", "running", "paused":
			return "", false
		case "done":
		default:
			allDone = false
		}
	}
	if total == 0 {
		return "", false
	}
	if allDone {
		return "done", true
	}
	return "failed", true
}

func languageSummary(languages []string) string {
	if len(languages) == 0 {
		return "未知"
	}
	return strings.Join(languages, ", ")
}

// --- pure helpers (unit-tested) ---

type auditSeedIntent struct {
	Key          string
	Phase        string
	Summary      string
	CWE          string
	Language     string
	Modules      []string
	SinkKeys     []string
	Deliverables []string
	Priority     int
}

func buildAuditSeedIntents(plan audit.Plan, profile audit.Profile) []auditSeedIntent {
	language := ""
	for _, candidate := range plan.Languages {
		if language == "" {
			language = candidate
		}
		if profile.Primary != "" && candidate == profile.Primary {
			language = candidate
			break
		}
	}
	modules := append([]string(nil), plan.Modules...)
	return []auditSeedIntent{
		{
			Key:   audit.PhaseProfile,
			Phase: audit.PhaseProfile,
			Summary: "S1 仓库画像核对：确认语言/框架/模块/入口与构建方式，" +
				"标记不适用语言与模块，补齐 profile 与入口清单。",
			Language: language,
			Modules:  modules,
			SinkKeys: []string{},
			Deliverables: []string{
				"语言/框架/模块核对结论",
				"入口点与信任边界清单",
				"计划覆盖 CWE 的适用性确认",
			},
			Priority: 8,
		},
		{
			Key:   audit.PhaseSurface,
			Phase: audit.PhaseSurface,
			Summary: "S2 攻击面与 sink 普查：核对预扫描 sink 站点，" +
				"标注测试/生成代码豁免，补充缺失入口与 sink，输出 S3/S4 候选。",
			Language: language,
			Modules:  modules,
			SinkKeys: []string{},
			Deliverables: []string{
				"sink 站点复核与豁免理由",
				"入口→sink 候选清单",
				"下一轮检测意图建议",
			},
			Priority: 8,
		},
	}
}

// buildAuditDetectionSeedIntents batches prescan sink sites into deterministic S4
// intents (grouped by language+CWE, batchSize sites per intent). Each seed's
// sink keys are assigned to the created intent by the director.
func buildAuditDetectionSeedIntents(sites []audit.SinkSite, batchSize int) []auditSeedIntent {
	if batchSize <= 0 {
		batchSize = 25
	}
	type bucket struct {
		language string
		cwe      string
		sites    []audit.SinkSite
	}
	buckets := map[string]*bucket{}
	order := make([]string, 0)
	for _, site := range sites {
		key := site.Language + "\x00" + site.CWE
		b := buckets[key]
		if b == nil {
			b = &bucket{language: site.Language, cwe: site.CWE}
			buckets[key] = b
			order = append(order, key)
		}
		b.sites = append(b.sites, site)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := buckets[order[i]], buckets[order[j]]
		if a.language != b.language {
			return a.language < b.language
		}
		return a.cwe < b.cwe
	})
	seeds := make([]auditSeedIntent, 0)
	for _, key := range order {
		b := buckets[key]
		sort.Slice(b.sites, func(i, j int) bool { return b.sites[i].SinkKey < b.sites[j].SinkKey })
		totalBatches := (len(b.sites) + batchSize - 1) / batchSize
		for batch := 0; batch < totalBatches; batch++ {
			start := batch * batchSize
			end := start + batchSize
			if end > len(b.sites) {
				end = len(b.sites)
			}
			chunk := b.sites[start:end]
			sinkKeys := make([]string, 0, len(chunk))
			moduleSet := map[string]struct{}{}
			for _, site := range chunk {
				sinkKeys = append(sinkKeys, site.SinkKey)
				moduleSet[auditModuleForPath(site.Path)] = struct{}{}
			}
			modules := make([]string, 0, len(moduleSet))
			for module := range moduleSet {
				modules = append(modules, module)
			}
			sort.Strings(modules)
			seeds = append(seeds, auditSeedIntent{
				Key:   fmt.Sprintf("S4:%s:%s:%d", b.language, b.cwe, batch),
				Phase: audit.PhaseDetect,
				Summary: fmt.Sprintf("S4 检测：%s %s sink 站点第 %d/%d 批（%d 个），逐点复核 source→sink→sanitizer 并提交覆盖回执。",
					b.language, b.cwe, batch+1, totalBatches, len(chunk)),
				CWE:      b.cwe,
				Language: b.language,
				Modules:  modules,
				SinkKeys: sinkKeys,
				Deliverables: []string{
					"逐 sink 的 source→sink 证据结论",
					"candidate/benign/exempt/missed 覆盖回执",
					"可疑点、假设与下一轮建议",
				},
				Priority: 8,
			})
		}
	}
	return seeds
}

func auditSeedPayload(seed auditSeedIntent, round int) map[string]any {
	modules := append([]string(nil), seed.Modules...)
	sinkKeys := append([]string(nil), seed.SinkKeys...)
	deliverables := append([]string(nil), seed.Deliverables...)
	if modules == nil {
		modules = []string{}
	}
	if sinkKeys == nil {
		sinkKeys = []string{}
	}
	if deliverables == nil {
		deliverables = []string{}
	}
	auditPayload := map[string]any{
		"phase":        seed.Phase,
		"round":        round,
		"language":     seed.Language,
		"scope":        map[string]any{"modules": modules},
		"sink_keys":    sinkKeys,
		"deliverables": deliverables,
		"seed_key":     seed.Key,
	}
	if seed.CWE != "" {
		auditPayload["cwe"] = seed.CWE
	}
	return map[string]any{"summary": seed.Summary, "audit": auditPayload}
}

// auditSeedIntentExists also returns the existing intent id so a retried
// preflight can repair coverage assignment without duplicating the intent.
func auditSeedIntentExists(t *Task, seed auditSeedIntent) (int64, bool, error) {
	if t == nil || t.Store == nil {
		return 0, false, errors.New("任务图存储不可用")
	}
	intents, err := t.Store.ListByKind(db.KindIntent, 10000)
	if err != nil {
		return 0, false, err
	}
	for _, intent := range intents {
		if intent.Origin != "audit_director" || auditIntentPhase(intent.Payload) != seed.Phase {
			continue
		}
		storedKey := auditIntentSeedKey(intent.Payload)
		if storedKey == seed.Key {
			return intent.ID, true, nil
		}
		// Intents created before seed_key existed: only S1/S2 can be matched
		// unambiguously (there is exactly one of each).
		if storedKey == "" && (seed.Phase == audit.PhaseProfile || seed.Phase == audit.PhaseSurface) {
			return intent.ID, true, nil
		}
	}
	return 0, false, nil
}

func auditIntentSeedKey(payload json.RawMessage) string {
	var p struct {
		Audit struct {
			SeedKey string `json:"seed_key"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return ""
	}
	return strings.TrimSpace(p.Audit.SeedKey)
}

func ensureAuditGoal(t *Task) error {
	if t == nil || t.Store == nil {
		return errors.New("任务图存储不可用")
	}
	goals, err := t.Store.ListByKind(db.KindGoal, 1)
	if err != nil {
		return err
	}
	if len(goals) > 0 {
		return nil
	}
	goal := strings.TrimSpace(t.Goal)
	if goal == "" {
		goal = "完成代码审计"
	}
	id, err := t.Store.AddGoal(map[string]any{"text": goal}, "audit_director")
	if err != nil {
		return err
	}
	if origin, originErr := t.Store.OriginFactID(); originErr == nil && origin > 0 && id > 0 {
		_ = t.Store.Link(origin, db.RelSpawns, id)
	}
	return nil
}

const (
	auditNoSinkCWEExemptionReason    = "no_sinks: no deterministic registry sink matches"
	auditNoSinkModuleExemptionReason = "no_sinks: module has no deterministic sink sites"
)

// applyAuditNoSinkCoverageExemptions makes planned CWE/module rows honestly
// covered when deterministic prescan found no sink sites for them. CWEs or
// modules that DO have sink sites stay planned: they become covered only by
// covered sink-site rows, so a missing receipt remains a real coverage gap.
func applyAuditNoSinkCoverageExemptions(rows []db.AuditCoverage, sites []audit.SinkSite) []db.AuditCoverage {
	siteCWE := map[string]int{}
	siteModule := map[string]int{}
	for _, site := range sites {
		language := audit.NormalizeLanguage(site.Language)
		if language == "" {
			language = strings.ToLower(strings.TrimSpace(site.Language))
		}
		cwe := strings.ToUpper(strings.TrimSpace(site.CWE))
		if language != "" && cwe != "" {
			siteCWE[language+"\x00"+cwe]++
		}
		if module := strings.TrimSpace(filepath.ToSlash(auditModuleForPath(site.Path))); module != "" {
			siteModule[module]++
		}
		// A plan module can be a multi-segment path (for example internal/pay),
		// while auditModuleForPath only returns the first segment. Count every
		// directory prefix so those module rows are not falsely exempted.
		parts := strings.Split(strings.Trim(strings.TrimSpace(filepath.ToSlash(site.Path)), "/"), "/")
		for i := 1; i < len(parts); i++ {
			prefix := strings.Join(parts[:i], "/")
			if prefix != "" {
				siteModule[prefix]++
			}
		}
	}
	out := make([]db.AuditCoverage, len(rows))
	copy(out, rows)
	for i := range out {
		if strings.ToLower(strings.TrimSpace(out[i].Status)) != audit.CoverageStatusPlanned {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(out[i].Kind)) {
		case audit.CoverageKindCWE:
			language := audit.NormalizeLanguage(out[i].Language)
			if language == "" {
				language = strings.ToLower(strings.TrimSpace(out[i].Language))
			}
			cwe := strings.ToUpper(strings.TrimSpace(out[i].CWE))
			if language != "" && cwe != "" && siteCWE[language+"\x00"+cwe] == 0 {
				out[i].Status = audit.CoverageStatusExempt
				out[i].Reason = auditNoSinkCWEExemptionReason
			}
		case audit.CoverageKindModule:
			module := strings.TrimSpace(filepath.ToSlash(out[i].Module))
			if module != "" && siteModule[module] == 0 {
				out[i].Status = audit.CoverageStatusExempt
				out[i].Reason = auditNoSinkModuleExemptionReason
			}
		}
	}
	return out
}

func auditPlanCoverageRows(sessionID int64, plan audit.Plan, sites []audit.SinkSite, backend string) []db.AuditCoverage {
	if strings.TrimSpace(backend) == "" {
		backend = audit.EngineCodeGraph
	}
	rows := make([]db.AuditCoverage, 0, len(sites)+len(plan.Modules)+16)
	languages := append([]string(nil), plan.Languages...)
	sort.Strings(languages)
	for _, language := range languages {
		cwes := append([]string(nil), plan.PlannedCWEs[language]...)
		sort.Strings(cwes)
		for _, cwe := range cwes {
			rows = append(rows, db.AuditCoverage{
				SessionID: sessionID, Round: 1, Kind: audit.CoverageKindCWE,
				Language: language, CWE: cwe, SinkKey: "cwe:" + language + ":" + cwe,
				Status: audit.CoverageStatusPlanned, Engine: backend,
			})
		}
	}
	primary := ""
	if len(plan.Languages) > 0 {
		primary = plan.Languages[0]
	}
	modules := append([]string(nil), plan.Modules...)
	sort.Strings(modules)
	for _, module := range modules {
		module = strings.TrimSpace(filepath.ToSlash(module))
		if module == "" {
			continue
		}
		rows = append(rows, db.AuditCoverage{
			SessionID: sessionID, Round: 1, Kind: audit.CoverageKindModule,
			Language: primary, Module: module, SinkKey: "module:" + module,
			Status: audit.CoverageStatusPlanned, Engine: backend,
		})
	}
	for _, site := range sites {
		rows = append(rows, db.AuditCoverage{
			SessionID: sessionID, Round: 1, Kind: audit.CoverageKindSinkSite,
			Language: site.Language, CWE: site.CWE, Module: auditModuleForPath(site.Path),
			Path: site.Path, Line: site.Line, Symbol: site.Symbol, SinkKey: site.SinkKey,
			Status: audit.CoverageStatusPlanned, Engine: backend,
		})
	}
	return rows
}

func auditModuleForPath(rel string) string {
	rel = strings.TrimSpace(filepath.ToSlash(rel))
	if idx := strings.IndexByte(rel, '/'); idx > 0 {
		return rel[:idx]
	}
	return "."
}

func auditPrescanLimits(cfg audit.Config) audit.PrescanLimits {
	return audit.PrescanLimits{
		MaxFiles:       auditBudgetInt(cfg, "max_files"),
		MaxFileBytes:   auditBudgetInt64(cfg, "max_file_bytes"),
		MaxSitesPerCWE: auditBudgetInt(cfg, "max_sites_per_cwe"),
		IncludeTests:   cfg.IncludeTests,
		IncludeVendor:  cfg.IncludeVendor,
	}
}

func auditBudgetInt(cfg audit.Config, key string) int {
	value := auditBudgetInt64(cfg, key)
	if value <= 0 {
		return 0
	}
	return int(value)
}

func auditBudgetInt64(cfg audit.Config, key string) int64 {
	if cfg.Budgets == nil {
		return 0
	}
	switch value := cfg.Budgets[key].(type) {
	case int:
		return int64(value)
	case int64:
		return value
	case float64:
		if value <= 0 {
			return 0
		}
		return int64(value)
	case json.Number:
		n, err := value.Int64()
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}
