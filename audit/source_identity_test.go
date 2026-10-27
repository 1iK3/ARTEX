package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalSourceRefDistinguishesSameBasename(t *testing.T) {
	makeRepo := func() (root, src string) {
		root = t.TempDir()
		src = filepath.Join(root, "repo")
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return root, src
	}
	rootA, srcA := makeRepo()
	rootB, srcB := makeRepo()
	metaA, err := PrepareSource(context.Background(), SourceConfig{
		Type: SourceLocal, LocalPath: srcA, AllowedRoots: []string{rootA},
	}, filepath.Join(t.TempDir(), "snap"))
	if err != nil {
		t.Fatal(err)
	}
	metaB, err := PrepareSource(context.Background(), SourceConfig{
		Type: SourceLocal, LocalPath: srcB, AllowedRoots: []string{rootB},
	}, filepath.Join(t.TempDir(), "snap"))
	if err != nil {
		t.Fatal(err)
	}
	if metaA.SourceRef == metaB.SourceRef {
		t.Fatalf("same-basename local sources collided: %q", metaA.SourceRef)
	}
	for _, ref := range []string{metaA.SourceRef, metaB.SourceRef} {
		if !strings.HasPrefix(ref, "local:repo:") || strings.Contains(ref, rootA) || strings.Contains(ref, rootB) {
			t.Fatalf("unsafe local source ref: %q", ref)
		}
	}
}

func TestZipSourceRefDistinguishesSameBasename(t *testing.T) {
	makeZip := func(body string) string {
		dir := t.TempDir()
		path := filepath.Join(dir, "sample.zip")
		writeAuditTestZip(t, path, []auditTestZipEntry{{name: "A.java", body: body, mode: 0o644}})
		return path
	}
	zipA := makeZip("class A {}\n")
	zipB := makeZip("class B {}\n")
	metaA, err := PrepareSource(context.Background(), SourceConfig{Type: SourceZip, UploadPath: zipA}, filepath.Join(t.TempDir(), "snap"))
	if err != nil {
		t.Fatal(err)
	}
	metaB, err := PrepareSource(context.Background(), SourceConfig{Type: SourceZip, UploadPath: zipB}, filepath.Join(t.TempDir(), "snap"))
	if err != nil {
		t.Fatal(err)
	}
	if metaA.SourceRef == metaB.SourceRef {
		t.Fatalf("same-basename zip sources collided: %q", metaA.SourceRef)
	}
	if !strings.HasPrefix(metaA.SourceRef, "zip:sample.zip:") || strings.Contains(metaA.SourceRef, filepath.Dir(zipA)) {
		t.Fatalf("unsafe zip source ref: %q", metaA.SourceRef)
	}
}

func TestPrepareSourcePropagatesCanceledContext(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "repo")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := PrepareSource(ctx, SourceConfig{
		Type: SourceLocal, LocalPath: src, AllowedRoots: []string{root},
	}, filepath.Join(t.TempDir(), "snap"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PrepareSource canceled context error = %v, want context.Canceled", err)
	}
}

func TestSnapshotCopyCancellation(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "snap")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := copySnapshot(canceled, src, dst, snapshotCopyOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled copy error = %v, want context.Canceled", err)
	}
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if _, err := copySnapshot(expired, src, dst, snapshotCopyOptions{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed-out copy error = %v, want context.DeadlineExceeded", err)
	}
}

func TestZipExtractionCancellation(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "sample.zip")
	writeAuditTestZip(t, zipPath, []auditTestZipEntry{{name: "A.java", body: "class A {}\n", mode: 0o644}})
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := extractZipCtx(canceled, zipPath, filepath.Join(t.TempDir(), "snap"), ZipLimits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled zip error = %v, want context.Canceled", err)
	}
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if _, err := extractZipCtx(expired, zipPath, filepath.Join(t.TempDir(), "snap2"), ZipLimits{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed-out zip error = %v, want context.DeadlineExceeded", err)
	}
}
