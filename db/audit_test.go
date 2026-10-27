package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestValidTaskMode(t *testing.T) {
	if TaskModePentest != "pentest" || TaskModeCodeAudit != "code_audit" {
		t.Fatalf("task mode constants changed: pentest=%q code_audit=%q", TaskModePentest, TaskModeCodeAudit)
	}
	cases := []struct {
		mode string
		want bool
	}{
		{"pentest", true},
		{"code_audit", true},
		{"", false},
		{"audit", false},
		{"PENTEST", false},
		{" pentest", false},
	}
	for _, tc := range cases {
		if got := ValidTaskMode(tc.mode); got != tc.want {
			t.Errorf("ValidTaskMode(%q)=%v, want %v", tc.mode, got, tc.want)
		}
	}
}

func TestValidTaskModeCreateRejectsInvalid(t *testing.T) {
	// Validation happens before the transaction/connection, so a zero DB is enough.
	_, err := (&DB{}).CreateTaskWithOptions("invalid mode", "goal", TaskCreateOptions{Mode: "audit"})
	if !errors.Is(err, ErrTaskModeInvalid) {
		t.Fatalf("CreateTaskWithOptions invalid mode error=%v, want ErrTaskModeInvalid", err)
	}
}

func assertAuditJSON(t *testing.T, got json.RawMessage, want string) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode got JSON %q: %v", string(got), err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("decode want JSON %q: %v", want, err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("JSON=%s, want %s", got, want)
	}
}

func TestAuditSchemaRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	stamp := time.Now().UnixNano()
	task, err := d.CreateTaskWithOptions(
		fmt.Sprintf("audit schema test %d", stamp),
		"verify audit persistence",
		TaskCreateOptions{
			Mode:        TaskModeCodeAudit,
			AuditConfig: json.RawMessage(fmt.Sprintf(`{"source":{"type":"local","ref":"repo-%d"},"depth":"deep"}`, stamp)),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()

	if task.Mode != TaskModeCodeAudit {
		t.Fatalf("task mode=%q, want %q", task.Mode, TaskModeCodeAudit)
	}
	assertAuditJSON(t, task.AuditConfig, fmt.Sprintf(`{"source":{"type":"local","ref":"repo-%d"},"depth":"deep"}`, stamp))

	// The ordinary CreateTask path must keep the original pentest defaults.
	plain, err := d.CreateTask(fmt.Sprintf("plain task %d", stamp), "pentest", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(plain.ID) }()
	if plain.Mode != TaskModePentest {
		t.Fatalf("default task mode=%q, want %q", plain.Mode, TaskModePentest)
	}
	assertAuditJSON(t, plain.AuditConfig, `{}`)

	gotTask, err := d.GetTask(task.ID)
	if err != nil || gotTask == nil {
		t.Fatalf("get task: %v", err)
	}
	if gotTask.Mode != TaskModeCodeAudit {
		t.Fatalf("persisted task mode=%q", gotTask.Mode)
	}
	assertAuditJSON(t, gotTask.AuditConfig, string(task.AuditConfig))

	session, err := d.CreateAuditSession(AuditSession{
		TaskID:       task.ID,
		SourceType:   "local",
		SourceRef:    fmt.Sprintf("repo-%d", stamp),
		SnapshotPath: "/tmp/audit-snapshot",
		CommitSHA:    "deadbeef",
		Languages:    []string{"go", "java"},
		Engines:      json.RawMessage(`{"codegraph":{"available":true}}`),
		Plan:         json.RawMessage(`{"profiles":["go"]}`),
		GateResults:  json.RawMessage(`{"C":"pass"}`),
		Stats:        json.RawMessage(`{"files":2}`),
		ReportMD:     "initial",
		ReportJSON:   json.RawMessage(`{"sections":[]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.ID == 0 || session.TaskID != task.ID {
		t.Fatalf("bad session identity: %+v", session)
	}
	if session.Status != "ingest" || session.Depth != "deep" || session.Backend != "codegraph" {
		t.Fatalf("session defaults not applied: %+v", session)
	}
	if session.Round != 1 || session.MaxRounds != 5 {
		t.Fatalf("session round defaults=%d/%d, want 1/5", session.Round, session.MaxRounds)
	}
	if !slices.Equal(session.Languages, []string{"go", "java"}) {
		t.Fatalf("languages=%v", session.Languages)
	}
	if session.StartedAt != nil || session.CompletedAt != nil {
		t.Fatalf("new session should have no timestamps: %+v", session)
	}
	assertAuditJSON(t, session.Engines, `{"codegraph":{"available":true}}`)
	assertAuditJSON(t, session.Plan, `{"profiles":["go"]}`)
	assertAuditJSON(t, session.GateResults, `{"C":"pass"}`)
	assertAuditJSON(t, session.Stats, `{"files":2}`)
	assertAuditJSON(t, session.ReportJSON, `{"sections":[]}`)

	loaded, err := d.GetAuditSession(task.ID)
	if err != nil || loaded == nil {
		t.Fatalf("get audit session: %v", err)
	}
	if loaded.SourceRef != session.SourceRef || loaded.SnapshotPath != session.SnapshotPath ||
		loaded.CommitSHA != session.CommitSHA || !slices.Equal(loaded.Languages, session.Languages) {
		t.Fatalf("loaded session=%+v, created=%+v", loaded, session)
	}

	// Restarts/retries may create the session more than once; the existing row
	// must be returned unchanged instead of erroring or overwriting state.
	retried, err := d.CreateAuditSession(AuditSession{
		TaskID: task.ID, SourceType: "git", SourceRef: "must-not-overwrite", Depth: "shallow", MaxRounds: 1,
	})
	if err != nil {
		t.Fatalf("idempotent CreateAuditSession: %v", err)
	}
	if retried.ID != session.ID || retried.SourceType != "local" || retried.SourceRef != session.SourceRef ||
		retried.Depth != "deep" || retried.MaxRounds != 5 {
		t.Fatalf("idempotent create returned %+v, want existing %+v", retried, session)
	}

	phaseStart := time.Now().UTC().Truncate(time.Microsecond)
	if err := d.InsertAuditPhases(session.ID, 1, []AuditPhase{
		{
			Phase: "S1", Required: true, Status: "done",
			Gate: json.RawMessage(`{"ok":true}`), Stats: json.RawMessage(`{"x":1}`),
			StartedAt: &phaseStart,
		},
		{Phase: "S0", Status: "pending"}, // Required zero value must default true.
	}); err != nil {
		t.Fatal(err)
	}
	// A conflicting phase must be left untouched.
	if err := d.InsertAuditPhases(session.ID, 1, []AuditPhase{{Phase: "S0", Required: true, Status: "done"}}); err != nil {
		t.Fatal(err)
	}
	phases, err := d.ListAuditPhases(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(phases) != 2 || phases[0].Phase != "S0" || phases[1].Phase != "S1" {
		t.Fatalf("phases=%+v", phases)
	}
	if phases[0].Status != "pending" {
		t.Fatalf("conflicting phase overwrote status: %+v", phases[0])
	}
	if phases[0].SessionID != session.ID || phases[0].Round != 1 {
		t.Fatalf("phase keys=%+v", phases[0])
	}
	if !phases[0].Required {
		t.Fatalf("phase required default was not true: %+v", phases[0])
	}
	assertAuditJSON(t, phases[1].Gate, `{"ok":true}`)
	assertAuditJSON(t, phases[1].Stats, `{"x":1}`)

	phaseStarted := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	if err := d.UpdateAuditPhase(session.ID, 1, "S0", AuditPhaseUpdate{
		Required:       false,
		SetRequired:    true,
		Status:         "running",
		SetStatus:      true,
		Gate:           json.RawMessage(`{"gate":"updated"}`),
		SetGate:        true,
		Stats:          json.RawMessage(`{"updated":true}`),
		SetStats:       true,
		StartedAt:      &phaseStarted,
		SetStartedAt:   true,
		CompletedAt:    nil,
		SetCompletedAt: true,
	}); err != nil {
		t.Fatal(err)
	}
	phases, err = d.ListAuditPhases(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(phases) != 2 {
		t.Fatalf("phases after update=%+v", phases)
	}
	if phases[0].Phase != "S0" || phases[0].Required || phases[0].Status != "running" ||
		phases[0].StartedAt == nil || !phases[0].StartedAt.Equal(phaseStarted) || phases[0].CompletedAt != nil {
		t.Fatalf("updated phase=%+v", phases[0])
	}
	assertAuditJSON(t, phases[0].Gate, `{"gate":"updated"}`)
	assertAuditJSON(t, phases[0].Stats, `{"updated":true}`)
	if phases[1].Status != "done" || phases[1].StartedAt == nil || !phases[1].StartedAt.Equal(phaseStart) {
		t.Fatalf("unrelated phase changed: %+v", phases[1])
	}

	intent, err := d.InsertAuditDetectionIntent(AuditDetectionIntent{
		SessionID:        session.ID,
		Round:            1,
		IntentKey:        fmt.Sprintf("intent-%d", stamp),
		Origin:           "prescan",
		Language:         "go",
		CWE:              "CWE-89",
		Title:            "SQL injection",
		Sources:          json.RawMessage(`[{"symbol":"request"}]`),
		Sinks:            json.RawMessage(`[{"symbol":"Query"}]`),
		Scope:            json.RawMessage(`{"path":"db"}`),
		PreferredEngines: json.RawMessage(`["codegraph"]`),
		Priority:         9,
	})
	if err != nil {
		t.Fatal(err)
	}
	if intent.ID == 0 || intent.QueryKind != "sink" || intent.Status != "planned" {
		t.Fatalf("intent defaults: %+v", intent)
	}
	assertAuditJSON(t, intent.Sources, `[{"symbol":"request"}]`)
	assertAuditJSON(t, intent.Sinks, `[{"symbol":"Query"}]`)
	assertAuditJSON(t, intent.Sanitizers, `[]`)
	assertAuditJSON(t, intent.Propagators, `[]`)
	assertAuditJSON(t, intent.Scope, `{"path":"db"}`)
	assertAuditJSON(t, intent.Constraints, `{}`)
	assertAuditJSON(t, intent.PreferredEngines, `["codegraph"]`)

	intents, err := d.ListAuditDetectionIntents(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 || intents[0].IntentKey != intent.IntentKey || intents[0].Priority != 9 {
		t.Fatalf("intents=%+v", intents)
	}

	// Re-running the same plan must update the existing intent, not duplicate it.
	intent, err = d.InsertAuditDetectionIntent(AuditDetectionIntent{
		SessionID: session.ID,
		Round:     1,
		IntentKey: intent.IntentKey,
		Origin:    "replan",
		Language:  "go",
		CWE:       "CWE-89",
		Title:     "SQL injection (updated)",
		Sources:   json.RawMessage(`[{"symbol":"request2"}]`),
		Sinks:     json.RawMessage(`[{"symbol":"Query"}]`),
		Scope:     json.RawMessage(`{"path":"db2"}`),
		Priority:  3,
		Status:    "running",
	})
	if err != nil {
		t.Fatal(err)
	}
	if intent.Priority != 3 || intent.Status != "running" || intent.Title != "SQL injection (updated)" {
		t.Fatalf("reinserted intent=%+v", intent)
	}
	intents, err = d.ListAuditDetectionIntents(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 || intents[0].ID != intent.ID || intents[0].Priority != 3 || intents[0].Status != "running" {
		t.Fatalf("intent upsert duplicated or failed to update: %+v", intents)
	}
	assertAuditJSON(t, intents[0].Sources, `[{"symbol":"request2"}]`)
	assertAuditJSON(t, intents[0].Scope, `{"path":"db2"}`)

	if err := d.UpdateAuditDetectionIntentStatus(session.ID, 1, intent.IntentKey, "failed", "engine unavailable"); err != nil {
		t.Fatal(err)
	}
	intents, err = d.ListAuditDetectionIntents(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 || intents[0].Status != "failed" || intents[0].Error != "engine unavailable" {
		t.Fatalf("intent status update=%+v", intents)
	}

	covRows := []AuditCoverage{
		{
			SessionID: session.ID, Round: 1, Kind: "sink_site", Language: "go",
			CWE: "CWE-89", Path: "db/query.go", Line: 42, Symbol: "Query",
			SinkKey: fmt.Sprintf("sink-a-%d", stamp), Status: "planned",
			IntentID: &intent.ID, Engine: "codegraph",
		},
		{
			SessionID: session.ID, Round: 1, Kind: "sink_site", Language: "go",
			CWE: "CWE-79", Path: "web/render.go", Line: 10, Symbol: "Render",
			SinkKey: fmt.Sprintf("sink-b-%d", stamp),
		},
	}
	if err := d.UpsertAuditCoverage(covRows); err != nil {
		t.Fatal(err)
	}
	duplicate := covRows[0]
	duplicate.Status = "scanned"
	duplicate.Reason = "must not overwrite"
	if err := d.UpsertAuditCoverage([]AuditCoverage{duplicate}); err != nil {
		t.Fatal(err)
	}
	coverage, err := d.ListAuditCoverage(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(coverage) != 2 {
		t.Fatalf("coverage rows=%d, want 2", len(coverage))
	}
	if coverage[0].SinkKey != covRows[1].SinkKey || coverage[1].SinkKey != covRows[0].SinkKey {
		t.Fatalf("coverage ordering=%+v", coverage)
	}
	if coverage[1].Status != "planned" || coverage[1].Reason != "" {
		t.Fatalf("upsert conflict reset coverage: %+v", coverage[1])
	}
	if coverage[1].IntentID == nil || *coverage[1].IntentID != intent.ID {
		t.Fatalf("coverage intent id=%v, want %d", coverage[1].IntentID, intent.ID)
	}

	// The same sink key is valid in another round; marking round 1 must not
	// touch the round-2 row.
	roundTwoRow := AuditCoverage{
		SessionID: session.ID, Round: 2, Kind: "sink_site", Language: "go",
		CWE: "CWE-89", Path: "db/query.go", Line: 42, Symbol: "Query",
		SinkKey: covRows[0].SinkKey, Status: "planned",
	}
	if err := d.UpsertAuditCoverage([]AuditCoverage{roundTwoRow}); err != nil {
		t.Fatal(err)
	}
	roundTwoBefore, err := d.ListAuditCoverage(session.ID, 2)
	if err != nil || len(roundTwoBefore) != 1 {
		t.Fatalf("round 2 coverage=%+v err=%v", roundTwoBefore, err)
	}

	if err := d.MarkAuditCoverage(session.ID, 1, []string{covRows[0].SinkKey}, "scanned", "verified", intent.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkAuditCoverage(session.ID, 1, nil, "ignored", "no-op", 0); err != nil {
		t.Fatalf("empty coverage mark should be a no-op: %v", err)
	}
	coverage, err = d.ListAuditCoverage(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	var marked *AuditCoverage
	for i := range coverage {
		if coverage[i].SinkKey == covRows[0].SinkKey {
			marked = &coverage[i]
			break
		}
	}
	if marked == nil || marked.Status != "scanned" || marked.Reason != "verified" || marked.IntentID == nil || *marked.IntentID != intent.ID {
		t.Fatalf("marked coverage=%+v", marked)
	}
	roundTwoAfter, err := d.ListAuditCoverage(session.ID, 2)
	if err != nil || len(roundTwoAfter) != 1 {
		t.Fatalf("round 2 coverage after mark=%+v err=%v", roundTwoAfter, err)
	}
	if roundTwoAfter[0].Status != "planned" || roundTwoAfter[0].Reason != "" ||
		!roundTwoAfter[0].UpdatedAt.Equal(roundTwoBefore[0].UpdatedAt) {
		t.Fatalf("marking round 1 changed round 2: before=%+v after=%+v", roundTwoBefore[0], roundTwoAfter[0])
	}

	hypothesis := AuditHypothesis{
		SessionID: session.ID, Round: 1, HypothesisKey: fmt.Sprintf("hyp-%d", stamp),
		Statement: "unsafe query reaches the sink", Attempts: json.RawMessage(`[]`),
	}
	if err := d.UpsertAuditHypothesis(hypothesis); err != nil {
		t.Fatal(err)
	}
	firstHypotheses, err := d.ListAuditHypotheses(session.ID)
	if err != nil || len(firstHypotheses) != 1 || firstHypotheses[0].Priority != 5 {
		t.Fatalf("hypothesis priority default=%+v err=%v", firstHypotheses, err)
	}
	hypothesis.Status = "confirmed"
	hypothesis.Statement = "confirmed unsafe query"
	hypothesis.Attempts = json.RawMessage(`[{"engine":"codegraph"}]`)
	hypothesis.Evidence = "proof"
	hypothesis.Priority = 8
	if err := d.UpsertAuditHypothesis(hypothesis); err != nil {
		t.Fatal(err)
	}
	hypotheses, err := d.ListAuditHypotheses(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hypotheses) != 1 || hypotheses[0].Status != "confirmed" ||
		hypotheses[0].Evidence != "proof" || hypotheses[0].Priority != 8 {
		t.Fatalf("hypotheses=%+v", hypotheses)
	}
	assertAuditJSON(t, hypotheses[0].Attempts, `[{"engine":"codegraph"}]`)

	auditRound := AuditRound{
		SessionID: session.ID, Round: 1, NewFindings: 2, NewCandidate: 2, TotalFindings: 2,
		GateC: "pass", Decision: "continue",
		Focus: json.RawMessage(`{"cwe":["CWE-89"]}`), TokenUsage: json.RawMessage(`{"input":10}`),
	}
	if err := d.InsertAuditRound(auditRound); err != nil {
		t.Fatal(err)
	}
	auditRound.NewConfirmed = 1
	auditRound.NewCandidate = 1
	auditRound.Decision = "stop"
	auditRound.TokenUsage = json.RawMessage(`{"input":20}`)
	if err := d.InsertAuditRound(auditRound); err != nil {
		t.Fatal(err)
	}
	rounds, err := d.ListAuditRounds(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rounds) != 1 || rounds[0].NewConfirmed != 1 || rounds[0].NewCandidate != 1 ||
		rounds[0].Decision != "stop" || rounds[0].CreatedAt.IsZero() {
		t.Fatalf("rounds=%+v", rounds)
	}
	assertAuditJSON(t, rounds[0].Focus, `{"cwe":["CWE-89"]}`)
	assertAuditJSON(t, rounds[0].TokenUsage, `{"input":20}`)

	job := AuditEngineJob{
		SessionID: session.ID, IntentID: &intent.ID, Engine: "codegraph", JobKind: "run",
		QueryHash: fmt.Sprintf("hash-%d", stamp), QueryText: "MATCH (n) RETURN n",
		QueryPath: "queries/sink.cypher", Provenance: json.RawMessage(`{"tool":"codegraph"}`),
	}
	if err := d.UpsertAuditEngineJob(job); err != nil {
		t.Fatal(err)
	}
	job.Status = "done"
	job.ResultCount = 7
	job.DurationMS = 123
	job.ArtifactPath = "/tmp/out.sarif"
	job.SARIF = json.RawMessage(`{"runs":[]}`)
	if err := d.UpsertAuditEngineJob(job); err != nil {
		t.Fatal(err)
	}
	// NULL-intent jobs must also upsert (NULLS NOT DISTINCT).
	nilIntentJob := AuditEngineJob{
		SessionID: session.ID, Engine: "codegraph", JobKind: "prepare",
		QueryHash: fmt.Sprintf("nil-hash-%d", stamp), QueryText: "first query",
	}
	if err := d.UpsertAuditEngineJob(nilIntentJob); err != nil {
		t.Fatal(err)
	}
	nilIntentJob.Status = "done"
	nilIntentJob.ResultCount = 2
	nilIntentJob.QueryText = "second query"
	if err := d.UpsertAuditEngineJob(nilIntentJob); err != nil {
		t.Fatal(err)
	}
	jobs, err := d.ListAuditEngineJobs(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("jobs=%+v, want bound and nil-intent rows", jobs)
	}
	var boundJob, nilJob *AuditEngineJob
	for i := range jobs {
		switch jobs[i].QueryHash {
		case job.QueryHash:
			boundJob = &jobs[i]
		case nilIntentJob.QueryHash:
			nilJob = &jobs[i]
		}
	}
	if boundJob == nil || boundJob.Status != "done" || boundJob.ResultCount != 7 ||
		boundJob.DurationMS != 123 || boundJob.ArtifactPath != "/tmp/out.sarif" {
		t.Fatalf("bound job=%+v", boundJob)
	}
	if boundJob.IntentID == nil || *boundJob.IntentID != intent.ID {
		t.Fatalf("job intent id=%v", boundJob.IntentID)
	}
	assertAuditJSON(t, boundJob.Provenance, `{"tool":"codegraph"}`)
	assertAuditJSON(t, boundJob.SARIF, `{"runs":[]}`)
	if nilJob == nil || nilJob.IntentID != nil || nilJob.Status != "done" ||
		nilJob.ResultCount != 2 || nilJob.QueryText != "second query" {
		t.Fatalf("nil-intent job was duplicated or not updated: %+v", nilJob)
	}

	status := "running"
	roundNumber := 2
	maxRounds := 6
	languages := []string{"go", "rust"}
	completedAt := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	updated, err := d.UpdateAuditSession(task.ID, AuditSessionUpdate{
		Status:         &status,
		Languages:      languages,
		SetLanguages:   true,
		Plan:           json.RawMessage(`{"profiles":["go","rust"]}`),
		SetPlan:        true,
		Round:          &roundNumber,
		MaxRounds:      &maxRounds,
		CompletedAt:    &completedAt,
		SetCompletedAt: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil || updated.Status != "running" || updated.Round != 2 || updated.MaxRounds != 6 {
		t.Fatalf("updated session=%+v", updated)
	}
	if !slices.Equal(updated.Languages, languages) {
		t.Fatalf("updated languages=%v", updated.Languages)
	}
	if updated.CompletedAt == nil || !updated.CompletedAt.Equal(completedAt) {
		t.Fatalf("updated completed_at=%v, want %v", updated.CompletedAt, completedAt)
	}
	if updated.SourceRef != session.SourceRef || updated.Depth != "deep" || updated.Backend != "codegraph" ||
		updated.ReportMD != "initial" {
		t.Fatalf("partial update lost fields: %+v", updated)
	}
	assertAuditJSON(t, updated.Plan, `{"profiles":["go","rust"]}`)
	assertAuditJSON(t, updated.Stats, `{"files":2}`)

	reloaded, err := d.GetAuditSession(task.ID)
	if err != nil || reloaded == nil {
		t.Fatalf("reload audit session: %v", err)
	}
	if reloaded.Status != "running" || reloaded.Round != 2 || !slices.Equal(reloaded.Languages, languages) {
		t.Fatalf("reloaded session=%+v", reloaded)
	}

	if err := d.DeleteTask(task.ID); err != nil {
		t.Fatal(err)
	}
	var sessions int
	if err := d.QueryRow(`SELECT count(*) FROM audit_sessions WHERE task_id=$1`, task.ID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("audit session should be cascade-deleted, got %d", sessions)
	}
	for _, table := range []string{
		"audit_phases", "audit_coverage", "audit_detection_intents",
		"audit_hypotheses", "audit_rounds", "audit_engine_jobs",
	} {
		var count int
		if err := d.QueryRow(`SELECT count(*) FROM `+table+` WHERE session_id=$1`, session.ID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s should be cascade-deleted, got %d rows", table, count)
		}
	}
	if missing, err := d.GetAuditSession(task.ID); err != nil || missing != nil {
		t.Fatalf("deleted session lookup=%+v err=%v", missing, err)
	}
}

func TestRepositoryAssetType(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	repoURL := fmt.Sprintf("https://audit-repo-%d.example.test/repo.git", time.Now().UnixNano())
	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type, url) VALUES ('repository',$1) RETURNING id`, repoURL).Scan(&assetID); err != nil {
		t.Fatalf("insert repository asset: %v", err)
	}
	defer func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
		_, _ = d.Exec(`DELETE FROM assets WHERE url=$1`, repoURL)
	}()

	var gotType, gotURL string
	if err := d.QueryRow(`SELECT type, COALESCE(url,'') FROM assets WHERE id=$1`, assetID).Scan(&gotType, &gotURL); err != nil {
		t.Fatal(err)
	}
	if gotType != "repository" || gotURL != repoURL {
		t.Fatalf("repository asset=(%q,%q), want (%q,%q)", gotType, gotURL, "repository", repoURL)
	}

	// Repository identity is URL-based for archive restore remapping.
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	foundID, found, findErr := findArchiveAssetNaturalID(tx, map[string]any{"type": "repository", "url": repoURL})
	rollbackErr := tx.Rollback()
	if findErr != nil || rollbackErr != nil || !found || foundID != assetID {
		t.Fatalf("repository natural id=(%d,%v,%v) rollback=%v, want (%d,true,nil)", foundID, found, findErr, rollbackErr, assetID)
	}

	// The partial unique index must protect repository URLs too.
	if _, err := d.Exec(`INSERT INTO assets(type, url) VALUES ('repository',$1)`, repoURL); err == nil {
		t.Fatal("duplicate repository URL should violate uq_assets_repository")
	}

	// The assets.type migration must not have dropped service_type's CHECK.
	serviceURL := fmt.Sprintf("https://audit-service-%d.example.test", time.Now().UnixNano())
	var serviceID int64
	if err := d.QueryRow(`INSERT INTO assets(type, service_type, url) VALUES ('service','http',$1) RETURNING id`, serviceURL).Scan(&serviceID); err != nil {
		t.Fatalf("service_type CHECK must allow http: %v", err)
	}
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, serviceID) }()
	if _, err := d.Exec(`INSERT INTO assets(type, service_type, url) VALUES ('service','bogus',$1)`, serviceURL+"-bogus"); err == nil {
		t.Fatal("bogus service_type should still violate the surviving CHECK")
	}

	if _, err := d.Exec(`DELETE FROM assets WHERE id=$1`, assetID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE id=$1`, assetID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("repository asset not deleted, got %d rows", count)
	}

	if _, err := d.Exec(`INSERT INTO assets(type, url) VALUES ('bogus',$1)`, repoURL+"-bogus"); err == nil {
		t.Fatal("bogus asset type should violate assets_type_check")
	}

	// Applying the whole schema a second time must be a no-op: both asset-type
	// constraints still accept their valid values and reject invalid ones.
	d2, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("second schema application: %v", err)
	}
	defer d2.Close()
	repoURL2 := fmt.Sprintf("https://audit-repo-2-%d.example.test/repo.git", time.Now().UnixNano())
	var assetID2 int64
	if err := d2.QueryRow(`INSERT INTO assets(type, url) VALUES ('repository',$1) RETURNING id`, repoURL2).Scan(&assetID2); err != nil {
		t.Fatalf("repository insert after second schema application: %v", err)
	}
	defer func() {
		_, _ = d2.Exec(`DELETE FROM assets WHERE id=$1`, assetID2)
		_, _ = d2.Exec(`DELETE FROM assets WHERE url=$1`, repoURL2)
	}()
	serviceURL2 := fmt.Sprintf("https://audit-service-2-%d.example.test", time.Now().UnixNano())
	var serviceID2 int64
	if err := d2.QueryRow(`INSERT INTO assets(type, service_type, url) VALUES ('service','http',$1) RETURNING id`, serviceURL2).Scan(&serviceID2); err != nil {
		t.Fatalf("service_type CHECK after second schema application: %v", err)
	}
	defer func() { _, _ = d2.Exec(`DELETE FROM assets WHERE id=$1`, serviceID2) }()
	if _, err := d2.Exec(`INSERT INTO assets(type, service_type, url) VALUES ('service','bogus',$1)`, serviceURL2+"-bogus"); err == nil {
		t.Fatal("bogus service_type should fail after second schema application")
	}
	if _, err := d2.Exec(`INSERT INTO assets(type, url) VALUES ('bogus',$1)`, repoURL2+"-bogus"); err == nil {
		t.Fatal("bogus asset type should fail after second schema application")
	}
}
