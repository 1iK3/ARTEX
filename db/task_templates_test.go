package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTaskTemplateCRUDAndNormalizedUniqueness(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	name := fmt.Sprintf("Template %d", suffix)
	created, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name:        "  " + strings.ReplaceAll(name, " ", "   ") + "  ",
		Description: "  initial description  ",
		Goal:        "  initial goal  ",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskTemplate(created.ID) })
	if created.Name != name || created.Description != "initial description" || created.Goal != "initial goal" {
		t.Fatalf("template was not normalized: %+v", created)
	}

	if _, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name: strings.ToUpper(name), Description: "duplicate", Goal: "duplicate",
	}); !errors.Is(err, ErrTaskTemplateNameConflict) {
		t.Fatalf("duplicate create error = %v, want %v", err, ErrTaskTemplateNameConflict)
	}

	got, err := d.GetTaskTemplate(created.ID)
	if err != nil || got == nil || got.Name != name {
		t.Fatalf("GetTaskTemplate = %+v, %v", got, err)
	}
	listed, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, template := range listed {
		if template.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("created template %d missing from list", created.ID)
	}

	updatedName := name + " updated"
	updated, err := d.UpdateTaskTemplate(created.ID, TaskTemplateInput{
		Name: updatedName, Description: "new description", Goal: "new goal",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != updatedName || updated.Description != "new description" || updated.Goal != "new goal" {
		t.Fatalf("unexpected updated template: %+v", updated)
	}

	if _, err := d.CreateTaskTemplate(TaskTemplateInput{Name: "", Description: "x", Goal: "y"}); !errors.Is(err, ErrTaskTemplateInvalid) {
		t.Fatalf("empty name error = %v, want %v", err, ErrTaskTemplateInvalid)
	}
	deleted, err := d.DeleteTaskTemplate(created.ID)
	if err != nil || !deleted {
		t.Fatalf("DeleteTaskTemplate = %v, %v", deleted, err)
	}
	deleted, err = d.DeleteTaskTemplate(created.ID)
	if err != nil || deleted {
		t.Fatalf("second DeleteTaskTemplate = %v, %v", deleted, err)
	}
}

func TestTaskTemplateModeAndAuditConfigRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	suffix := time.Now().UnixNano()
	auditJSON := `{"source_type":"git","repo_url":"https://example.com/a.git","depth":"deep","engines":{"codegraph":"required"}}`
	created, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name:        fmt.Sprintf("Audit template %d", suffix),
		Description: "audit description",
		Goal:        "audit goal",
		Mode:        TaskModeCodeAudit,
		AuditConfig: json.RawMessage(auditJSON),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskTemplate(created.ID) })
	if created.Mode != TaskModeCodeAudit {
		t.Fatalf("created mode = %q, want %q", created.Mode, TaskModeCodeAudit)
	}
	assertTemplateJSON(t, created.AuditConfig, auditJSON)

	got, err := d.GetTaskTemplate(created.ID)
	if err != nil || got == nil {
		t.Fatalf("GetTaskTemplate = %+v, %v", got, err)
	}
	if got.Mode != TaskModeCodeAudit {
		t.Fatalf("persisted mode = %q, want %q", got.Mode, TaskModeCodeAudit)
	}
	assertTemplateJSON(t, got.AuditConfig, auditJSON)

	// An explicit empty/whitespace mode must fail and leave the row untouched.
	for _, emptyMode := range []string{"", "   "} {
		emptyMode := emptyMode
		if _, err := d.PatchTaskTemplate(created.ID, TaskTemplatePatch{Mode: &emptyMode}); !errors.Is(err, ErrTaskTemplateInvalid) {
			t.Fatalf("empty mode %q error = %v, want %v", emptyMode, err, ErrTaskTemplateInvalid)
		}
	}
	afterEmpty, err := d.GetTaskTemplate(created.ID)
	if err != nil || afterEmpty == nil {
		t.Fatalf("GetTaskTemplate after empty patch = %+v, %v", afterEmpty, err)
	}
	if afterEmpty.Mode != TaskModeCodeAudit {
		t.Fatalf("empty patch changed mode to %q", afterEmpty.Mode)
	}
	assertTemplateJSON(t, afterEmpty.AuditConfig, auditJSON)

	pentestMode := TaskModePentest
	patched, err := d.PatchTaskTemplate(created.ID, TaskTemplatePatch{
		Mode: &pentestMode, AuditConfig: json.RawMessage(`{}`), SetAuditConfig: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if patched.Mode != TaskModePentest {
		t.Fatalf("patched mode = %q, want %q", patched.Mode, TaskModePentest)
	}
	assertTemplateJSON(t, patched.AuditConfig, `{}`)

	auditMode := "CODE_AUDIT"
	patched, err = d.PatchTaskTemplate(created.ID, TaskTemplatePatch{
		Mode: &auditMode, AuditConfig: json.RawMessage(auditJSON), SetAuditConfig: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if patched.Mode != TaskModeCodeAudit {
		t.Fatalf("patched mode = %q, want %q", patched.Mode, TaskModeCodeAudit)
	}
	assertTemplateJSON(t, patched.AuditConfig, auditJSON)

	if _, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name: fmt.Sprintf("Bad mode template %d", suffix), Description: "d", Goal: "g", Mode: "recon",
	}); !errors.Is(err, ErrTaskTemplateInvalid) {
		t.Fatalf("invalid mode error = %v, want %v", err, ErrTaskTemplateInvalid)
	}
	if _, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name: fmt.Sprintf("Bad audit template %d", suffix), Description: "d", Goal: "g",
		Mode: TaskModeCodeAudit, AuditConfig: json.RawMessage(`[]`),
	}); !errors.Is(err, ErrTaskTemplateInvalid) {
		t.Fatalf("invalid audit_config error = %v, want %v", err, ErrTaskTemplateInvalid)
	}
}

func assertTemplateJSON(t *testing.T, raw json.RawMessage, want string) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(raw, &gotValue); err != nil {
		t.Fatalf("decode audit_config %s: %v", raw, err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("decode wanted JSON: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("audit_config = %s, want %s", raw, want)
	}
}

func TestTaskTemplateDisjointPatchesCompose(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	created, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name:        fmt.Sprintf("Concurrent template %d", time.Now().UnixNano()),
		Description: "initial description",
		Goal:        "initial goal",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskTemplate(created.ID) })

	description := "description from concurrent patch"
	goal := "goal from concurrent patch"
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, patch := range []TaskTemplatePatch{{Description: &description}, {Goal: &goal}} {
		patch := patch
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := d.PatchTaskTemplate(created.ID, patch)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got, err := d.GetTaskTemplate(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Description != description || got.Goal != goal {
		t.Fatalf("disjoint patches lost an update: %+v", got)
	}
}
