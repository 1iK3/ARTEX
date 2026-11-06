package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestAuditFindingVerificationBatch(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	t.Cleanup(func() {
		cancel()
		s.archiveWG.Wait()
		<-s.side.done
		m.Close()
	})

	cfg := json.RawMessage(`{"source_type":"zip","upload_id":"batch-verification-fixture"}`)
	task, err := m.CreateTaskWithOptions("audit batch local", "batch local", db.TaskCreateOptions{
		Mode: db.TaskModeCodeAudit, AuditConfig: cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	foreignTask, err := m.CreateTaskWithOptions("audit batch foreign", "batch foreign", db.TaskCreateOptions{
		Mode: db.TaskModeCodeAudit, AuditConfig: cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustTaskID(t, task.ID)
	foreignTaskID := mustTaskID(t, foreignTask.ID)
	t.Cleanup(func() {
		_ = m.pg.DeleteTask(taskID)
		_ = m.pg.DeleteTask(foreignTaskID)
	})

	recordCandidate := func(owner *Task, summary string) *db.RecordedFinding {
		t.Helper()
		finding, err := s.evidenceStore().Record(ctx, db.RecordFindingInput{
			TaskID:        mustTaskID(t, owner.ID),
			ExplorationID: owner.ExpID,
			Worker:        "test",
			VulnClass:     "TEST",
			Name:          summary,
			Severity:      "high",
			Summary:       summary,
			Evidence:      "candidate evidence",
			Verification:  "candidate",
			AuditPhase:    "S5",
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return finding
	}

	localFirst := recordCandidate(task, "local first")
	localSecond := recordCandidate(task, "local second")
	foreign := recordCandidate(foreignTask, "foreign finding")

	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", fmt.Sprintf("/api/tasks/%s/audit/findings/verification-batch", task.ID), strings.NewReader(string(raw)))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	if r := request(map[string]any{
		"finding_ids":  []int64{localFirst.FindingID},
		"verification": "candidate",
		"evidence":     "invalid final status",
	}); r.Code != 400 {
		t.Fatalf("invalid verification status code = %d, body = %s", r.Code, r.Body.String())
	}

	if r := request(map[string]any{
		"finding_ids":  []int64{localFirst.FindingID},
		"verification": "confirmed",
		"evidence":     "   ",
	}); r.Code != 400 {
		t.Fatalf("empty evidence code = %d, body = %s", r.Code, r.Body.String())
	}

	if r := request(map[string]any{
		"finding_ids":  []int64{localFirst.FindingID, foreign.FindingID},
		"verification": "confirmed",
		"evidence":     "foreign ownership check",
	}); r.Code != 404 {
		t.Fatalf("foreign finding code = %d, body = %s", r.Code, r.Body.String())
	}
	if finding, err := m.pg.GetFinding(localFirst.FindingID); err != nil || finding == nil || finding.Verification != "candidate" {
		t.Fatalf("local finding changed before ownership failure: %+v, %v", finding, err)
	}

	r := request(map[string]any{
		"finding_ids":  []int64{localFirst.FindingID, localSecond.FindingID},
		"verification": "confirmed",
		"evidence":     "batch manual verification",
	})
	if r.Code != 200 {
		t.Fatalf("batch code = %d, body = %s", r.Code, r.Body.String())
	}
	var result struct {
		Updated      int    `json:"updated"`
		Verification string `json:"verification"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Updated != 2 || result.Verification != "confirmed" {
		t.Fatalf("batch result = %+v", result)
	}

	for _, id := range []int64{localFirst.FindingID, localSecond.FindingID} {
		finding, err := m.pg.GetFinding(id)
		if err != nil || finding == nil {
			t.Fatalf("GetFinding(%d) = %+v, %v", id, finding, err)
		}
		if finding.Verification != "confirmed" {
			t.Fatalf("finding %d verification = %q, want confirmed", id, finding.Verification)
		}
	}
}

type fakeAuditVerificationStore struct {
	findings map[int64]*db.DBFinding
	updated  []int64
}

func (f *fakeAuditVerificationStore) GetFinding(id int64) (*db.DBFinding, error) {
	return f.findings[id], nil
}

func (f *fakeAuditVerificationStore) UpdateFindingVerification(
	_ context.Context,
	_ int64,
	findingID int64,
	_ string,
	_ string,
	_ string,
	_ string,
	_ *float64,
) error {
	f.updated = append(f.updated, findingID)
	return nil
}

func TestBuildAuditFindingVerificationBatchPlan(t *testing.T) {
	plan, err := buildAuditFindingVerificationBatchPlan(auditFindingVerificationBatchRequest{
		FindingIDs:   []int64{2, 1, 2, 0},
		Verification: "confirmed",
		Evidence:     " manual review ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.FindingIDs) != 2 || plan.FindingIDs[0] != 2 || plan.FindingIDs[1] != 1 {
		t.Fatalf("finding ids = %v", plan.FindingIDs)
	}
	if plan.Verification != "confirmed" || plan.Method != "manual" || plan.Evidence != "manual review" {
		t.Fatalf("plan = %+v", plan)
	}

	invalid := auditFindingVerificationBatchRequest{
		FindingIDs:   []int64{1},
		Verification: "candidate",
		Evidence:     "proof",
	}
	if _, err := buildAuditFindingVerificationBatchPlan(invalid); err == nil {
		t.Fatal("candidate is not a final verdict")
	}

	emptyEvidence := auditFindingVerificationBatchRequest{
		FindingIDs:   []int64{1},
		Verification: "confirmed",
		Evidence:     " ",
	}
	if _, err := buildAuditFindingVerificationBatchPlan(emptyEvidence); err == nil {
		t.Fatal("blank evidence accepted")
	}

	tooConfident := auditFindingVerificationBatchRequest{
		FindingIDs:   []int64{1},
		Verification: "confirmed",
		Evidence:     "proof",
		Confidence:   func() *float64 { value := 1.1; return &value }(),
	}
	if _, err := buildAuditFindingVerificationBatchPlan(tooConfident); err == nil {
		t.Fatal("confidence above 1 accepted")
	}
}

func TestApplyAuditFindingVerificationBatch(t *testing.T) {
	taskID := int64(10)
	current := func(id int64, verification string) *db.DBFinding {
		owner := taskID
		return &db.DBFinding{ID: id, TaskID: &owner, Verification: verification}
	}
	store := &fakeAuditVerificationStore{findings: map[int64]*db.DBFinding{
		1: current(1, "candidate"),
		2: current(2, "unverified"),
	}}
	plan := auditFindingVerificationBatchPlan{
		FindingIDs: []int64{1, 2}, Verification: "confirmed", Method: "manual", Evidence: "proof",
	}
	if err := applyAuditFindingVerificationBatch(t.Context(), store, taskID, plan); err != nil {
		t.Fatal(err)
	}
	if len(store.updated) != 2 || store.updated[0] != 1 || store.updated[1] != 2 {
		t.Fatalf("updated = %v", store.updated)
	}
}

func TestApplyAuditFindingVerificationBatchRejectsForeignOrFinalFindings(t *testing.T) {
	taskID := int64(10)
	foreignID := int64(11)
	store := &fakeAuditVerificationStore{findings: map[int64]*db.DBFinding{
		1: {ID: 1, TaskID: &foreignID, Verification: "candidate"},
		2: {ID: 2, TaskID: &taskID, Verification: "confirmed"},
	}}
	plan := auditFindingVerificationBatchPlan{
		FindingIDs: []int64{1}, Verification: "confirmed", Method: "manual", Evidence: "proof",
	}
	if err := applyAuditFindingVerificationBatch(t.Context(), store, taskID, plan); err == nil {
		t.Fatal("foreign finding accepted")
	}

	plan.FindingIDs = []int64{2}
	if err := applyAuditFindingVerificationBatch(t.Context(), store, taskID, plan); err == nil {
		t.Fatal("already-final finding accepted")
	}
	if len(store.updated) != 0 {
		t.Fatalf("rejected plan still updated findings: %v", store.updated)
	}
}
