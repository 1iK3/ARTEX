package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/audit"
)

func TestAuditCodeAuditBuiltinAgentsSeeded(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	for key, role := range map[string]string{"code_planner": "planner", "code_worker": "worker"} {
		a, err := d.GetAgentByKey(key)
		if err != nil || a == nil {
			t.Fatalf("agent %s = %+v, %v", key, a, err)
		}
		if a.Role != role || !a.Builtin {
			t.Fatalf("agent %s = role %q builtin=%v", key, a.Role, a.Builtin)
		}
	}
}

func TestAuditUpsertRepositoryAsset(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	stamp := time.Now().UnixNano()
	task, err := d.CreateTask(fmt.Sprintf("repository asset %d", stamp), "repo test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()
	url := fmt.Sprintf("local:audit-fixture-%d", stamp)
	id, err := d.UpsertRepositoryAsset(url, map[string]any{
		"commit": "aaa", "languages": []string{"go"},
	}, task.ID)
	if err != nil || id <= 0 {
		t.Fatalf("first upsert id=%d err=%v", id, err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, id) })
	again, err := d.UpsertRepositoryAsset(url, map[string]any{"commit": "bbb", "depth": "quick"}, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again != id {
		t.Fatalf("upsert created a new row: %d != %d", again, id)
	}
	var assetType, commit, languages string
	var hasTask bool
	if err := d.QueryRow(`
SELECT type, extra->>'commit', (extra->'languages')::text,
       EXISTS(SELECT 1 FROM unnest(task_ids) AS x WHERE x=$2)
FROM assets WHERE id=$1`, id, task.ID).Scan(&assetType, &commit, &languages, &hasTask); err != nil {
		t.Fatal(err)
	}
	if assetType != "repository" || commit != "bbb" || !hasTask {
		t.Fatalf("asset type=%q commit=%q hasTask=%v", assetType, commit, hasTask)
	}
	if languages != `["go"]` {
		t.Fatalf("merged languages = %s", languages)
	}
	var extra map[string]any
	var raw json.RawMessage
	if err := d.QueryRow(`SELECT extra FROM assets WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &extra); err != nil {
		t.Fatal(err)
	}
	if extra["depth"] != "quick" {
		t.Fatalf("extra = %v", extra)
	}
}

func TestAuditUpdateFindingVerification(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	stamp := time.Now().UnixNano()
	task, err := d.CreateTaskWithOptions(fmt.Sprintf("verify finding %d", stamp), "verify", TaskCreateOptions{
		Mode: TaskModeCodeAudit, AuditConfig: json.RawMessage(`{"source_type":"zip","upload_id":"u"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()
	store := d.Exploration(task.ExplorationID)
	nodeID, err := store.AddNode("finding", map[string]any{
		"summary": "candidate", "verification": "candidate", "confidence": 0.4,
	}, 9, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	evidence := json.RawMessage(`{"version":1,"cwe_id":"CWE-89","title":"t","severity":"high","confidence":0.4,"verification":{"status":"candidate"},"location":{"path":"a.go","line":1,"symbol":"f"}}`)
	findingID, duplicate, err := d.AddCodeFinding(CodeFindingInput{
		TaskID: task.ID, NodeID: nodeID, CWEID: "CWE-89", Title: "t", Severity: "high",
		Summary: "candidate", Evidence: "proof", Worker: "code_worker",
		CodePath: "a.go", CodeLine: 1, CodeSymbol: "f", Confidence: 0.4,
		Verification: "candidate", CodeEvidence: evidence,
	})
	if err != nil || duplicate || findingID <= 0 {
		t.Fatalf("AddCodeFinding id=%d duplicate=%v err=%v", findingID, duplicate, err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, findingID) })

	high := 0.9
	if err := d.UpdateFindingVerification(t.Context(), task.ID, findingID, "confirmed", "taint_trace", "independent proof", "alt.go:9", &high); err != nil {
		t.Fatal(err)
	}
	finding, err := d.GetFinding(findingID)
	if err != nil || finding == nil {
		t.Fatalf("GetFinding = %+v, %v", finding, err)
	}
	if finding.Verification != "confirmed" {
		t.Fatalf("verification = %q", finding.Verification)
	}
	var ce map[string]any
	if err := json.Unmarshal(finding.CodeEvidence, &ce); err != nil {
		t.Fatal(err)
	}
	verdict, _ := ce["verification"].(map[string]any)
	if verdict["status"] != "confirmed" || verdict["method"] != "taint_trace" ||
		verdict["reason"] != "independent proof" || verdict["alternative_path"] != "alt.go:9" {
		t.Fatalf("code_evidence verification = %v", verdict)
	}
	if ce["confidence"] != 0.9 {
		t.Fatalf("code_evidence confidence = %v", ce["confidence"])
	}
	node, err := store.GetNode(nodeID)
	if err != nil || node == nil {
		t.Fatalf("node = %+v, %v", node, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["verification"] != "confirmed" || payload["confidence"] != 0.9 {
		t.Fatalf("node payload = %v", payload)
	}

	// Omitted confidence must preserve the previous value.
	if err := d.UpdateFindingVerification(t.Context(), task.ID, findingID, "design_intent", "manual", "design note", "", nil); err != nil {
		t.Fatal(err)
	}
	finding, err = d.GetFinding(findingID)
	if err != nil || finding.Confidence != 0.9 {
		t.Fatalf("nil confidence changed finding: %+v, %v", finding, err)
	}

	// Explicit zero must be persisted (not treated as "omitted").
	zero := 0.0
	if err := d.UpdateFindingVerification(t.Context(), task.ID, findingID, "refuted", "manual", "refuted by design", "", &zero); err != nil {
		t.Fatal(err)
	}
	finding, err = d.GetFinding(findingID)
	if err != nil || finding.Confidence != 0 {
		t.Fatalf("zero confidence not persisted: %+v, %v", finding, err)
	}
	if err := json.Unmarshal(finding.CodeEvidence, &ce); err != nil {
		t.Fatal(err)
	}
	if ce["confidence"] != float64(0) {
		t.Fatalf("code_evidence zero confidence = %v", ce["confidence"])
	}
	node, err = store.GetNode(nodeID)
	if err != nil || node == nil {
		t.Fatalf("node after zero = %+v, %v", node, err)
	}
	payload = nil
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["confidence"] != float64(0) {
		t.Fatalf("node zero confidence = %v", payload["confidence"])
	}

	wrong := 0.5
	if err := d.UpdateFindingVerification(t.Context(), task.ID+999999, findingID, "confirmed", "taint_trace", "proof", "", &wrong); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("wrong-task error = %v, want ErrFindingNotFound", err)
	}
}

func TestAuditCoverageAssignmentAndOwnedMarking(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	stamp := time.Now().UnixNano()
	task, err := d.CreateTaskWithOptions(fmt.Sprintf("coverage ownership %d", stamp), "coverage", TaskCreateOptions{
		Mode: TaskModeCodeAudit, AuditConfig: json.RawMessage(`{"source_type":"zip","upload_id":"u"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()
	session, err := d.CreateAuditSession(AuditSession{TaskID: task.ID, SourceType: "zip", Depth: "quick"})
	if err != nil {
		t.Fatal(err)
	}
	rows := []AuditCoverage{
		{SessionID: session.ID, Round: 1, Kind: audit.CoverageKindSinkSite, SinkKey: "s1", Status: audit.CoverageStatusPlanned},
		{SessionID: session.ID, Round: 1, Kind: audit.CoverageKindSinkSite, SinkKey: "s2", Status: audit.CoverageStatusPlanned},
		{SessionID: session.ID, Round: 1, Kind: audit.CoverageKindSinkSite, SinkKey: "s3", Status: audit.CoverageStatusPlanned},
	}
	if err := d.UpsertAuditCoverage(rows); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM audit_coverage WHERE session_id=$1`, session.ID) })
	n, err := d.AssignAuditCoverage(session.ID, 1, []string{"s1", "s2"}, 101)
	if err != nil || n != 2 {
		t.Fatalf("assign = %d, %v", n, err)
	}
	if n, err := d.AssignAuditCoverage(session.ID, 1, []string{"s2", "s3"}, 102); err != nil || n != 1 {
		t.Fatalf("second assign = %d, %v; s2 must stay owned by 101", n, err)
	}
	listed, err := d.ListAuditCoverage(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string]int64{}
	for _, row := range listed {
		if row.IntentID != nil {
			owners[row.SinkKey] = *row.IntentID
		}
	}
	if owners["s1"] != 101 || owners["s2"] != 101 || owners["s3"] != 102 {
		t.Fatalf("owners = %v", owners)
	}
	n, err = d.MarkAuditCoverageOwned(session.ID, 1, 101, []string{"s1", "s2"}, audit.CoverageStatusScanned, "")
	if err != nil || n != 2 {
		t.Fatalf("mark owned = %d, %v", n, err)
	}
	if n, err := d.MarkAuditCoverageOwned(session.ID, 1, 101, []string{"s3"}, audit.CoverageStatusScanned, ""); err != nil || n != 0 {
		t.Fatalf("foreign mark = %d, %v, want 0", n, err)
	}
	if n, err := d.MarkAuditCoverageOwned(session.ID, 1, 102, []string{"s3"}, audit.CoverageStatusExempt, "no_sinks"); err != nil || n != 1 {
		t.Fatalf("second mark = %d, %v", n, err)
	}
	listed, err = d.ListAuditCoverage(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range listed {
		switch row.SinkKey {
		case "s1", "s2":
			if row.Status != audit.CoverageStatusScanned {
				t.Fatalf("%s status = %q", row.SinkKey, row.Status)
			}
		case "s3":
			if row.Status != audit.CoverageStatusExempt || row.Reason != "no_sinks" {
				t.Fatalf("s3 = %+v", row)
			}
		}
	}
}

func TestAuditReleaseAuditCoverage(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	stamp := time.Now().UnixNano()
	task, err := d.CreateTaskWithOptions(fmt.Sprintf("coverage release %d", stamp), "release", TaskCreateOptions{
		Mode: TaskModeCodeAudit, AuditConfig: json.RawMessage(`{"source_type":"zip","upload_id":"u"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()
	session, err := d.CreateAuditSession(AuditSession{TaskID: task.ID, SourceType: "zip", Depth: "quick"})
	if err != nil {
		t.Fatal(err)
	}
	intentID := int64(4242)
	rows := []AuditCoverage{
		{SessionID: session.ID, Round: 1, Kind: audit.CoverageKindSinkSite, SinkKey: "planned", Status: audit.CoverageStatusPlanned},
		{SessionID: session.ID, Round: 1, Kind: audit.CoverageKindSinkSite, SinkKey: "missed", Status: audit.CoverageStatusMissed},
		{SessionID: session.ID, Round: 1, Kind: audit.CoverageKindSinkSite, SinkKey: "scanned", Status: audit.CoverageStatusScanned},
		{SessionID: session.ID, Round: 1, Kind: audit.CoverageKindSinkSite, SinkKey: "candidate", Status: audit.CoverageStatusCandidate},
	}
	if err := d.UpsertAuditCoverage(rows); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM audit_coverage WHERE session_id=$1`, session.ID) })
	if n, err := d.AssignAuditCoverage(session.ID, 1, []string{"planned", "missed", "scanned", "candidate"}, intentID); err != nil || n != 4 {
		t.Fatalf("assign = %d, %v", n, err)
	}
	if n, err := d.MarkAuditCoverageOwned(session.ID, 1, intentID, []string{"missed"}, audit.CoverageStatusMissed, "budget"); err != nil || n != 1 {
		t.Fatalf("mark missed = %d, %v", n, err)
	}
	released, err := d.ReleaseAuditCoverage(session.ID, 1, intentID)
	if err != nil || released != 2 {
		t.Fatalf("release = %d, %v, want 2", released, err)
	}
	listed, err := d.ListAuditCoverage(session.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range listed {
		switch row.SinkKey {
		case "planned", "missed":
			if row.IntentID != nil {
				t.Fatalf("%s still owned: %v", row.SinkKey, *row.IntentID)
			}
		case "scanned", "candidate":
			if row.IntentID == nil || *row.IntentID != intentID {
				t.Fatalf("%s ownership lost: %+v", row.SinkKey, row)
			}
		}
	}
}
