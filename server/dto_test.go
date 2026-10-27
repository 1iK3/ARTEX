package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestFindingDTOCodeFields(t *testing.T) {
	payload := json.RawMessage(`{
		"vulnclass":"CWE-89",
		"name":"SQL injection in UserDao.find",
		"severity":"high",
		"summary":"tainted query",
		"evidence":{"by":"auditor","poc":"' OR 1=1 --"},
		"cwe_id":"CWE-89",
		"code_path":"src/UserDao.java",
		"code_line":42,
		"code_symbol":"UserDao.find",
		"confidence":0.86,
		"verification":"confirmed",
		"code_evidence":{"version":1,"cwe_id":"CWE-89","verification":{"status":"confirmed"},
			"engines":[{"name":"codeql","query_id":"qs-1","confidence":0.75,"raw_ref":"sarif://run/3"}]}
	}`)
	node := &db.Node{
		ID:        17,
		Kind:      db.KindFinding,
		Payload:   payload,
		CreatedAt: time.Date(2026, time.October, 26, 10, 0, 0, 0, time.UTC),
	}

	dto := findingDTO(node)
	if dto.CWEID != "CWE-89" || dto.CodePath != "src/UserDao.java" || dto.CodeLine != 42 ||
		dto.CodeSymbol != "UserDao.find" || dto.Confidence != 0.86 || dto.Verification != "confirmed" {
		t.Fatalf("code fields lost: %+v", dto)
	}
	if dto.VulnClass != "CWE-89" || dto.Name != "SQL injection in UserDao.find" ||
		dto.Severity != "high" || dto.Summary != "tainted query" {
		t.Fatalf("legacy fields lost: %+v", dto)
	}
	if dto.Evidence != `{"by":"auditor","poc":"' OR 1=1 --"}` {
		t.Fatalf("evidence = %q", dto.Evidence)
	}
	if len(dto.CodeEvidence) != 0 {
		t.Fatalf("list DTO must omit code_evidence: %s", dto.CodeEvidence)
	}
	if len(dto.Engines) != 1 || dto.Engines[0].Name != "codeql" || dto.Engines[0].QueryID != "qs-1" ||
		dto.Engines[0].RawRef != "sarif://run/3" || dto.Engines[0].Confidence != 0.75 {
		t.Fatalf("list DTO engines = %+v", dto.Engines)
	}

	// The detail conversion carries the full evidence blob plus engines.
	detail := findingDTODetail(node)
	var evidence map[string]any
	if err := json.Unmarshal(detail.CodeEvidence, &evidence); err != nil {
		t.Fatalf("detail code_evidence is not JSON: %v", err)
	}
	if evidence["cwe_id"] != "CWE-89" || len(detail.Engines) != 1 {
		t.Fatalf("detail code evidence = %#v engines=%+v", evidence, detail.Engines)
	}

	// The per-task list path must keep compact code fields when it merges meta,
	// but never the full code_evidence blob.
	list := findingDTOsForOwner("7", "task", []*db.Node{node}, map[int64]db.FindingMeta{
		17: {ID: 99, Status: db.FindingConfirmed},
	}, nil)
	if len(list) != 1 || list[0].FindingID != "99" || list[0].CWEID != "CWE-89" ||
		list[0].CodeSymbol != "UserDao.find" || list[0].Verification != "confirmed" {
		t.Fatalf("list DTO lost code fields: %+v", list)
	}
	if len(list[0].CodeEvidence) != 0 {
		t.Fatalf("per-task list must omit code_evidence: %s", list[0].CodeEvidence)
	}
	if len(list[0].Engines) != 1 || list[0].Engines[0].Name != "codeql" {
		t.Fatalf("per-task list engines = %+v", list[0].Engines)
	}

	encoded, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["cwe_id"] != "CWE-89" || wire["code_path"] != "src/UserDao.java" ||
		wire["verification"] != "confirmed" {
		t.Fatalf("wire fields = %#v", wire)
	}
	if _, ok := wire["code_evidence"]; ok {
		t.Fatalf("list wire must omit code_evidence: %#v", wire["code_evidence"])
	}
	engines, ok := wire["engines"].([]any)
	if !ok || len(engines) != 1 {
		t.Fatalf("wire engines = %#v", wire["engines"])
	}

	encodedDetail, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	var detailWire map[string]any
	if err := json.Unmarshal(encodedDetail, &detailWire); err != nil {
		t.Fatal(err)
	}
	if _, ok := detailWire["code_evidence"].(map[string]any); !ok {
		t.Fatalf("detail wire code_evidence = %#v", detailWire["code_evidence"])
	}
}

func TestFindingDTODefaultsVerification(t *testing.T) {
	legacy := findingDTO(&db.Node{
		ID:        18,
		Kind:      db.KindFinding,
		Payload:   json.RawMessage(`{"vulnclass":"xss","severity":"medium","summary":"legacy"}`),
		CreatedAt: time.Date(2026, time.October, 26, 10, 0, 0, 0, time.UTC),
	})
	if legacy.Verification != "unverified" {
		t.Fatalf("legacy node verification = %q, want unverified", legacy.Verification)
	}
	if legacy.CWEID != "" || legacy.CodePath != "" || legacy.CodeEvidence != nil {
		t.Fatalf("legacy node should not invent code fields: %+v", legacy)
	}
}

func TestFindingFromDBCodeFields(t *testing.T) {
	row := &db.DBFinding{
		ID:           19,
		VulnClass:    "CWE-79",
		Name:         "Reflected XSS",
		Severity:     "medium",
		Summary:      "unescaped output",
		Evidence:     "poc",
		Status:       db.FindingPending,
		CWEID:        "CWE-79",
		CodePath:     "src/View.java",
		CodeLine:     9,
		CodeSymbol:   "View.render",
		Confidence:   0.4,
		Verification: "candidate",
		DedupeKey:    "CWE-79|src/View.java|9|render",
		CodeEvidence: json.RawMessage(`{"version":1,"cwe_id":"CWE-79",
			"engines":[{"name":"joern","query_id":"j-1","confidence":0.6,"raw_ref":"joern://cpg/9"}]}`),
		AuditRound: 1,
		AuditPhase: "S4",
		CreatedAt:  time.Date(2026, time.October, 26, 10, 0, 0, 0, time.UTC),
	}
	dto := findingFromDB(row, nil)
	if dto.FindingID != "19" || dto.CWEID != "CWE-79" || dto.CodePath != "src/View.java" ||
		dto.CodeLine != 9 || dto.CodeSymbol != "View.render" || dto.Confidence != 0.4 ||
		dto.Verification != "candidate" {
		t.Fatalf("DB code fields lost: %+v", dto)
	}
	if len(dto.CodeEvidence) != 0 {
		t.Fatalf("list DTO must omit code_evidence: %s", dto.CodeEvidence)
	}
	if len(dto.Engines) != 1 || dto.Engines[0].Name != "joern" || dto.Engines[0].RawRef != "joern://cpg/9" {
		t.Fatalf("DB engines = %+v", dto.Engines)
	}

	detail := findingFromDBDetail(row, nil)
	if len(detail.CodeEvidence) == 0 || !json.Valid(detail.CodeEvidence) {
		t.Fatalf("detail code evidence = %s", detail.CodeEvidence)
	}
	if len(detail.Engines) != 1 || detail.Engines[0].Name != "joern" {
		t.Fatalf("detail engines = %+v", detail.Engines)
	}

	empty := findingFromDB(&db.DBFinding{ID: 20, Status: db.FindingPending}, nil)
	if empty.Verification != "unverified" {
		t.Fatalf("empty verification = %q, want unverified", empty.Verification)
	}
}
