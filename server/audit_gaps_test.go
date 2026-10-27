package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/artex/db"
)

func TestBuildAuditDetectionSeedIntents(t *testing.T) {
	sites := make([]audit.SinkSite, 0, 30)
	for i := 0; i < 30; i++ {
		sites = append(sites, audit.SinkSite{
			Language: "go", CWE: "CWE-89", Path: "internal/a.go",
			Symbol: "exec", SinkKey: fmt.Sprintf("sink-%02d", i), Line: i + 1,
		})
	}
	sites = append(sites, audit.SinkSite{Language: "java", CWE: "CWE-78", Path: "src/A.java", SinkKey: "java-1"})
	seeds := buildAuditDetectionSeedIntents(sites, 25)
	if len(seeds) != 3 {
		t.Fatalf("seed count = %d, want 3", len(seeds))
	}
	seenKeys := map[string]bool{}
	for _, seed := range seeds {
		if seed.Phase != audit.PhaseDetect || seed.Priority != 8 || len(seed.SinkKeys) == 0 {
			t.Fatalf("seed = %+v", seed)
		}
		if seenKeys[seed.Key] {
			t.Fatalf("duplicate seed key %q", seed.Key)
		}
		seenKeys[seed.Key] = true
		if len(seed.SinkKeys) > 25 {
			t.Fatalf("batch too large: %d", len(seed.SinkKeys))
		}
	}
	if !seenKeys["S4:go:CWE-89:0"] || !seenKeys["S4:go:CWE-89:1"] || !seenKeys["S4:java:CWE-78:0"] {
		t.Fatalf("seed keys = %v", seenKeys)
	}
	payload := auditSeedPayload(seeds[0], 1)
	auditPayload := payload["audit"].(map[string]any)
	if auditPayload["seed_key"] != seeds[0].Key || len(auditPayload["sink_keys"].([]string)) != 25 {
		t.Fatalf("payload = %v", auditPayload)
	}
}

func TestBuildAuditCoverageCandidates(t *testing.T) {
	owned := int64(9)
	rows := []db.AuditCoverage{
		{Kind: audit.CoverageKindSinkSite, Language: "go", CWE: "CWE-89", Module: "internal", SinkKey: "b", Status: audit.CoverageStatusPlanned},
		{Kind: audit.CoverageKindSinkSite, Language: "go", CWE: "CWE-89", Module: "internal", SinkKey: "a", Status: audit.CoverageStatusPlanned},
		{Kind: audit.CoverageKindSinkSite, Language: "go", CWE: "CWE-89", Module: "internal", SinkKey: "c", Status: audit.CoverageStatusPlanned},
		{Kind: audit.CoverageKindSinkSite, Language: "go", CWE: "CWE-89", Module: "internal", SinkKey: "owned", Status: audit.CoverageStatusScanned, IntentID: &owned},
		{Kind: audit.CoverageKindSinkSite, Language: "java", CWE: "CWE-78", Module: "src", SinkKey: "j1", Status: audit.CoverageStatusMissed},
		{Kind: audit.CoverageKindCWE, Language: "go", CWE: "CWE-89", SinkKey: "cwe:go:CWE-89", Status: audit.CoverageStatusPlanned},
	}
	candidates := buildAuditCoverageCandidates(rows, 8, 2)
	if len(candidates) != 3 {
		t.Fatalf("candidates = %+v", candidates)
	}
	if candidates[0].Phase != audit.PhaseDetect || candidates[0].CWE != "CWE-89" || candidates[0].Language != "go" {
		t.Fatalf("candidate[0] = %+v", candidates[0])
	}
	if !reflect.DeepEqual(candidates[0].SinkKeys, []string{"a", "b"}) {
		t.Fatalf("first batch = %v", candidates[0].SinkKeys)
	}
	if !reflect.DeepEqual(candidates[1].SinkKeys, []string{"c"}) {
		t.Fatalf("second batch = %v", candidates[1].SinkKeys)
	}
	if !reflect.DeepEqual(candidates[2].SinkKeys, []string{"j1"}) {
		t.Fatalf("third batch = %v", candidates[2].SinkKeys)
	}
	if len(buildAuditCoverageCandidates(rows, 1, 2)) != 1 {
		t.Fatal("maxBatches limit was not applied")
	}
}

func TestSummarizeAuditPhaseIntents(t *testing.T) {
	node := func(phase string, round int, state string) *db.Node {
		payload, _ := json.Marshal(map[string]any{"audit": map[string]any{"phase": phase, "round": round}})
		return &db.Node{Kind: db.KindIntent, State: state, Payload: payload}
	}
	intents := []*db.Node{
		node(audit.PhaseDetect, 1, "done"),
		node(audit.PhaseDetect, 1, "done"),
		node(audit.PhaseDetect, 2, "open"),  // wrong round: ignored
		node(audit.PhaseProfile, 1, "open"), // different phase: ignored
	}
	if status, complete := summarizeAuditPhaseIntents(intents, audit.PhaseDetect, 1); !complete || status != "done" {
		t.Fatalf("all done = %q/%v", status, complete)
	}
	for _, badState := range []string{"blocked", "exhausted", "stopped"} {
		withBad := append(append([]*db.Node(nil), intents...), node(audit.PhaseDetect, 1, badState))
		if status, complete := summarizeAuditPhaseIntents(withBad, audit.PhaseDetect, 1); !complete || status != "failed" {
			t.Fatalf("%s = %q/%v", badState, status, complete)
		}
	}
	intents = append(intents, node(audit.PhaseDetect, 1, "running"))
	if _, complete := summarizeAuditPhaseIntents(intents, audit.PhaseDetect, 1); complete {
		t.Fatal("running phase must not close")
	}
	retracted := []*db.Node{
		node(audit.PhaseDetect, 1, "done"),
		node(audit.PhaseDetect, 1, "deleted"),
	}
	if status, complete := summarizeAuditPhaseIntents(retracted, audit.PhaseDetect, 1); !complete || status != "done" {
		t.Fatalf("deleted intent should be ignored: %q/%v", status, complete)
	}
	if _, complete := summarizeAuditPhaseIntents(nil, audit.PhaseDetect, 1); complete {
		t.Fatal("empty phase must not close")
	}
}

func TestBuildAuditReceiptGroupsOwnership(t *testing.T) {
	owned := int64(7)
	other := int64(8)
	rows := []db.AuditCoverage{
		{SinkKey: "owned-1", IntentID: &owned},
		{SinkKey: "owned-2", IntentID: &owned},
		{SinkKey: "other", IntentID: &other},
		{SinkKey: "unassigned"},
	}
	receipts := []audit.CoverageReceipt{
		{SinkKey: "owned-1", Status: audit.CoverageStatusScanned},
		{SinkKey: "owned-2", Status: audit.CoverageStatusExempt, Reason: "no_sinks"},
	}
	groups, err := buildAuditReceiptGroups(receipts, rows, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].Status != audit.CoverageStatusScanned || groups[1].Reason != "no_sinks" {
		t.Fatalf("groups = %+v", groups)
	}
	for _, tc := range []struct {
		name     string
		receipts []audit.CoverageReceipt
		want     string
	}{
		{"unknown", []audit.CoverageReceipt{{SinkKey: "missing", Status: audit.CoverageStatusScanned}}, "不在本会话"},
		{"unassigned", []audit.CoverageReceipt{{SinkKey: "unassigned", Status: audit.CoverageStatusScanned}}, "未分配"},
		{"other intent", []audit.CoverageReceipt{{SinkKey: "other", Status: audit.CoverageStatusScanned}}, "未分配"},
		{"duplicate", []audit.CoverageReceipt{{SinkKey: "owned-1", Status: audit.CoverageStatusScanned}, {SinkKey: "owned-1", Status: audit.CoverageStatusBenign}}, "重复"},
		{"candidate no finding", []audit.CoverageReceipt{{SinkKey: "owned-1", Status: audit.CoverageStatusCandidate}}, "finding_id"},
		{"exempt no reason", []audit.CoverageReceipt{{SinkKey: "owned-1", Status: audit.CoverageStatusExempt}}, "reason"},
	} {
		if _, err := buildAuditReceiptGroups(tc.receipts, rows, 7); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s error = %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestAuditTaskWaitingForAdmission(t *testing.T) {
	if !auditTaskWaitingForAdmission(nil) {
		t.Fatal("nil task must wait")
	}
	task := &Task{ID: "1"}
	if auditTaskWaitingForAdmission(task) {
		t.Fatal("plain task should be runnable")
	}
	task.Queued = true
	if !auditTaskWaitingForAdmission(task) {
		t.Fatal("queued task must wait")
	}
	task.Queued = false
	task.Paused = true
	if !auditTaskWaitingForAdmission(task) {
		t.Fatal("paused task must wait")
	}
}

func TestAuditSourceTimeout(t *testing.T) {
	if got := auditSourceTimeout(audit.Config{}); got.Seconds() != 1800 {
		t.Fatalf("default timeout = %s", got)
	}
	cfg := audit.Config{Budgets: map[string]any{"max_source_seconds": float64(42)}}
	if got := auditSourceTimeout(cfg); got.Seconds() != 42 {
		t.Fatalf("configured timeout = %s", got)
	}
	huge := audit.Config{Budgets: map[string]any{"max_source_seconds": float64(999999999)}}
	if got := auditSourceTimeout(huge); got.Seconds() != 24*60*60 {
		t.Fatalf("capped timeout = %s", got)
	}
}

func TestAuditSourceLabelRedactsLocalPath(t *testing.T) {
	root := t.TempDir()
	cfg := audit.Config{SourceType: audit.SourceLocal, LocalPath: filepath.Join(root, "secret-repo")}
	label := auditSourceLabel(cfg)
	if label != "local:secret-repo" || strings.Contains(label, root) {
		t.Fatalf("label = %q", label)
	}
}

func TestAuditSnapshotHelpers(t *testing.T) {
	root := t.TempDir()
	if !auditSnapshotExists(root) || auditSnapshotExists(filepath.Join(root, "missing")) {
		t.Fatal("auditSnapshotExists mismatch")
	}
	if auditCodeGraphIndexExists(root) {
		t.Fatal("unexpected .codegraph index")
	}
	if !auditResumeNeedsReindex(audit.EngineCodeGraph, root) {
		t.Fatal("codegraph resume without .codegraph should reindex")
	}
	if auditResumeNeedsReindex("fallback", root) {
		t.Fatal("fallback resume must not require a CodeGraph index")
	}
	if err := os.Mkdir(filepath.Join(root, ".codegraph"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !auditCodeGraphIndexExists(root) || auditResumeNeedsReindex(audit.EngineCodeGraph, root) {
		t.Fatal(".codegraph index not detected")
	}
}

func TestAuditCoverageClaimValidation(t *testing.T) {
	owned := int64(5)
	rows := []db.AuditCoverage{
		{SinkKey: "free-1", Status: audit.CoverageStatusPlanned},
		{SinkKey: "free-2", Status: audit.CoverageStatusMissed},
		{SinkKey: "owned", Status: audit.CoverageStatusPlanned, IntentID: &owned},
	}
	if err := validateAuditCoverageClaim(rows, []string{"free-1", "free-2"}); err != nil {
		t.Fatalf("valid claim: %v", err)
	}
	for _, tc := range []struct {
		name string
		keys []string
		want string
	}{
		{"unknown", []string{"free-1", "missing"}, "不在本会话"},
		{"owned", []string{"free-1", "owned"}, "已被其他意图认领"},
	} {
		if err := validateAuditCoverageClaim(rows, tc.keys); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s error = %v, want %q", tc.name, err, tc.want)
		}
	}
	keys, err := normalizeAuditClaimKeys([]string{" k2 ", "k1", "k2"})
	if err != nil || !reflect.DeepEqual(keys, []string{"k2", "k1"}) {
		t.Fatalf("normalize keys = %v, %v", keys, err)
	}
	for _, bad := range [][]string{nil, {" "}, {"bad\x00key"}} {
		if _, err := normalizeAuditClaimKeys(bad); err == nil {
			t.Errorf("keys %v should be rejected", bad)
		}
	}
}

func TestAuditStateReleasesCoverage(t *testing.T) {
	for _, state := range []string{"done", "blocked", "exhausted", "stopped", "deleted"} {
		if !auditStateReleasesCoverage(state) {
			t.Errorf("%s should release coverage", state)
		}
	}
	for _, state := range []string{"", "open", "running", "paused"} {
		if auditStateReleasesCoverage(state) {
			t.Errorf("%s must not release coverage", state)
		}
	}
}

func TestAuditKeysEqual(t *testing.T) {
	if !auditKeysEqual([]any{"a", "b"}, []string{"a", "b"}) {
		t.Fatal("equal keys not detected")
	}
	if auditKeysEqual([]any{"b", "a"}, []string{"a", "b"}) {
		t.Fatal("order difference must update payload")
	}
	if auditKeysEqual(nil, []string{"a"}) {
		t.Fatal("nil must not equal non-empty keys")
	}
}
