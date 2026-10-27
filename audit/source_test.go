package audit

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func createAuditTestDirLink(t *testing.T, target, link string) error {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	} else {
		cmd := exec.Command("cmd", "/C", "mklink", "/J", link, target)
		output, junctionErr := cmd.CombinedOutput()
		if junctionErr == nil {
			return nil
		}
		return fmt.Errorf("symlink failed (%v); junction failed: %v: %s", err, junctionErr, strings.TrimSpace(string(output)))
	}
}

func writeAuditTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readAuditTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func auditTestFileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

type auditTestZipEntry struct {
	name string
	body string
	mode os.FileMode
}

func writeAuditTestZip(t *testing.T, path string, entries []auditTestZipEntry) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir zip parent: %v", err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(file)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		writer, err := zw.CreateHeader(header)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", entry.name, err)
		}
		if _, err := writer.Write([]byte(entry.body)); err != nil {
			t.Fatalf("write zip entry %q: %v", entry.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close zip file: %v", err)
	}
}

func TestPrepareLocalSnapshot(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "project")
	javaBody := "package demo;\nclass A {}\n"
	writeAuditTestFile(t, filepath.Join(src, "src", "main", "java", "A.java"), javaBody)
	writeAuditTestFile(t, filepath.Join(src, "src", "test", "java", "ATest.java"), "package demo;\nclass ATest {}\n")
	writeAuditTestFile(t, filepath.Join(src, "node_modules", "x.js"), "module.exports = 1\n")
	writeAuditTestFile(t, filepath.Join(src, "vendor", "lib.js"), "module.exports = 2\n")
	writeAuditTestFile(t, filepath.Join(src, "dist", "bundle.js"), "bundled\n")
	writeAuditTestFile(t, filepath.Join(src, ".git", "config"), "[core]\n")
	writeAuditTestFile(t, filepath.Join(src, ".github", "workflows", "ci.yml"), "name: ci\n")
	writeAuditTestFile(t, filepath.Join(src, "pom.xml"), "<project/>\n")
	writeAuditTestFile(t, filepath.Join(src, "README.md"), "# demo\n")

	dst := filepath.Join(t.TempDir(), "snapshot")
	meta, err := PrepareSource(context.Background(), SourceConfig{
		Type:         SourceLocal,
		LocalPath:    src,
		AllowedRoots: []string{root},
	}, dst)
	if err != nil {
		t.Fatalf("PrepareSource: %v", err)
	}

	if meta.Type != SourceLocal {
		t.Fatalf("meta.Type = %q, want %q", meta.Type, SourceLocal)
	}
	if !strings.HasPrefix(meta.SourceRef, "local:project:") {
		t.Fatalf("meta.SourceRef = %q, want local:project:<hash>", meta.SourceRef)
	}
	if strings.Contains(meta.SourceRef, root) {
		t.Fatalf("meta.SourceRef leaked the host path: %q", meta.SourceRef)
	}
	if meta.Commit != "" {
		t.Fatalf("local commit = %q, want empty", meta.Commit)
	}
	if meta.Files != 4 {
		t.Fatalf("meta.Files = %d, want 4; warnings=%v", meta.Files, meta.Warnings)
	}
	wantBytes := int64(len(javaBody) + len("name: ci\n") + len("<project/>\n") + len("# demo\n"))
	if meta.Bytes != wantBytes {
		t.Fatalf("meta.Bytes = %d, want %d", meta.Bytes, wantBytes)
	}
	if len(meta.Languages) != 1 || meta.Languages[0] != Java {
		t.Fatalf("meta.Languages = %v, want [java]", meta.Languages)
	}
	if meta.Language != Java {
		t.Fatalf("meta.Language = %q, want java", meta.Language)
	}
	absDst, err := filepath.Abs(dst)
	if err != nil {
		t.Fatal(err)
	}
	if meta.SnapshotPath != filepath.Clean(absDst) {
		t.Fatalf("meta.SnapshotPath = %q, want %q", meta.SnapshotPath, filepath.Clean(absDst))
	}
	if !auditTestFileExists(filepath.Join(dst, "src", "main", "java", "A.java")) {
		t.Fatal("expected java source in snapshot")
	}
	if !auditTestFileExists(filepath.Join(dst, ".github", "workflows", "ci.yml")) {
		t.Fatal(".github config should be included as source data")
	}
	for _, rel := range []string{
		filepath.Join("src", "test"),
		"node_modules",
		"vendor",
		"dist",
		".git",
	} {
		if auditTestFileExists(filepath.Join(dst, rel)) {
			t.Errorf("snapshot unexpectedly contains %s", rel)
		}
	}
	if got := readAuditTestFile(t, filepath.Join(src, "src", "main", "java", "A.java")); got != javaBody {
		t.Fatalf("source was modified: %q", got)
	}
}

func TestSnapshotPermissions(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "project")
	writeAuditTestFile(t, filepath.Join(src, "src", "main", "java", "A.java"), "class A {}\n")
	dst := filepath.Join(t.TempDir(), "snapshot")
	if _, err := PrepareSource(context.Background(), SourceConfig{
		Type: SourceLocal, LocalPath: src, AllowedRoots: []string{root},
	}, dst); err != nil {
		t.Fatalf("PrepareSource: %v", err)
	}
	fileInfo, err := os.Stat(filepath.Join(dst, "src", "main", "java", "A.java"))
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm()&0o222 != 0 {
		t.Fatalf("snapshot file mode = %v, want read-only", fileInfo.Mode())
	}
	dirInfo, err := os.Stat(filepath.Join(dst, "src"))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm()&0o200 == 0 {
		t.Fatalf("snapshot directory mode = %v, want owner-writable for .codegraph metadata", dirInfo.Mode())
	}
}

func TestPrepareLocalSnapshotIncludeFlags(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "project")
	writeAuditTestFile(t, filepath.Join(src, "src", "main", "java", "A.java"), "class A {}\n")
	writeAuditTestFile(t, filepath.Join(src, "src", "test", "java", "ATest.java"), "class ATest {}\n")
	writeAuditTestFile(t, filepath.Join(src, "vendor", "lib", "x.js"), "module.exports = 1\n")
	writeAuditTestFile(t, filepath.Join(src, "node_modules", "x.js"), "module.exports = 2\n")

	dst := filepath.Join(t.TempDir(), "snapshot")
	meta, err := PrepareSource(context.Background(), SourceConfig{
		Type:          SourceLocal,
		LocalPath:     src,
		AllowedRoots:  []string{root},
		IncludeTests:  true,
		IncludeVendor: true,
	}, dst)
	if err != nil {
		t.Fatalf("PrepareSource: %v", err)
	}
	if meta.Files != 3 {
		t.Fatalf("meta.Files = %d, want 3", meta.Files)
	}
	for _, rel := range []string{
		filepath.Join("src", "main", "java", "A.java"),
		filepath.Join("src", "test", "java", "ATest.java"),
		filepath.Join("vendor", "lib", "x.js"),
	} {
		if !auditTestFileExists(filepath.Join(dst, rel)) {
			t.Errorf("expected %s in snapshot", rel)
		}
	}
	if auditTestFileExists(filepath.Join(dst, "node_modules")) {
		t.Fatal("node_modules must always be excluded")
	}
	if len(meta.Languages) != 2 || meta.Languages[0] != Java || meta.Languages[1] != JavaScript {
		t.Fatalf("meta.Languages = %v, want [java javascript]", meta.Languages)
	}
	if meta.Language != Java {
		t.Fatalf("meta.Language = %q, want primary java", meta.Language)
	}
}

func TestPrepareLocalRejectsEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	out := filepath.Join(t.TempDir(), "snapshot")
	_, err := PrepareSource(context.Background(), SourceConfig{
		Type:         SourceLocal,
		LocalPath:    outside,
		AllowedRoots: []string{root},
	}, out)
	if err == nil {
		t.Fatal("expected local path outside allowed roots to be rejected")
	}
	if !strings.Contains(err.Error(), "允许范围") && !strings.Contains(err.Error(), "allowed") {
		t.Fatalf("error = %v, want an allowed-root error", err)
	}
}

func TestPrepareLocalRequiresAllowedRoots(t *testing.T) {
	src := filepath.Join(t.TempDir(), "project")
	writeAuditTestFile(t, filepath.Join(src, "main.go"), "package main\n")
	_, err := PrepareSource(context.Background(), SourceConfig{Type: SourceLocal, LocalPath: src}, filepath.Join(t.TempDir(), "snapshot"))
	if err == nil {
		t.Fatal("expected missing allowed roots error")
	}
	if !strings.Contains(err.Error(), "未配置本地审计根目录") {
		t.Fatalf("error = %v, want missing allowed roots message", err)
	}
}

func TestPrepareLocalRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAuditTestFile(t, filepath.Join(outside, "secret.go"), "package secret\n")
	link := filepath.Join(allowed, "escape")
	if err := createAuditTestDirLink(t, outside, link); err != nil {
		t.Skipf("symlink/junction unavailable: %v", err)
	}
	_, err := PrepareSource(context.Background(), SourceConfig{
		Type:         SourceLocal,
		LocalPath:    link,
		AllowedRoots: []string{allowed},
	}, filepath.Join(t.TempDir(), "snapshot"))
	if err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestPrepareLocalSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "project")
	writeAuditTestFile(t, filepath.Join(src, "main.go"), "package main\n")
	outside := filepath.Join(t.TempDir(), "outside")
	writeAuditTestFile(t, filepath.Join(outside, "secret.txt"), "secret\n")
	if err := createAuditTestDirLink(t, outside, filepath.Join(src, "leak")); err != nil {
		t.Skipf("symlink/junction unavailable: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "snapshot")
	meta, err := PrepareSource(context.Background(), SourceConfig{
		Type:         SourceLocal,
		LocalPath:    src,
		AllowedRoots: []string{root},
	}, dst)
	if err != nil {
		t.Fatalf("PrepareSource: %v", err)
	}
	if auditTestFileExists(filepath.Join(dst, "leak")) {
		t.Fatal("symlink/junction should not be copied into the snapshot")
	}
	if len(meta.Warnings) == 0 || !strings.Contains(strings.Join(meta.Warnings, "\n"), "leak") {
		t.Fatalf("meta.Warnings = %v, want a symlink warning", meta.Warnings)
	}
}

func TestPrepareSourceRequiresEmptyDestination(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "project")
	writeAuditTestFile(t, filepath.Join(src, "main.go"), "package main\n")
	dst := t.TempDir()
	writeAuditTestFile(t, filepath.Join(dst, "sentinel"), "keep me\n")
	_, err := PrepareSource(context.Background(), SourceConfig{
		Type:         SourceLocal,
		LocalPath:    src,
		AllowedRoots: []string{root},
	}, dst)
	if err == nil {
		t.Fatal("expected non-empty destination to be rejected")
	}
	if !strings.Contains(err.Error(), "snapshot destination must be empty") {
		t.Fatalf("error = %v, want snapshot destination must be empty", err)
	}
	if got := readAuditTestFile(t, filepath.Join(dst, "sentinel")); got != "keep me\n" {
		t.Fatalf("destination contents were modified: %q", got)
	}
}

func TestPrepareLocalSnapshotLimits(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "project")
	writeAuditTestFile(t, filepath.Join(src, "a.go"), "package main\n")
	writeAuditTestFile(t, filepath.Join(src, "b.go"), "package main\n")

	tests := []struct {
		name string
		cfg  SourceConfig
	}{
		{name: "files", cfg: SourceConfig{MaxFiles: 1}},
		{name: "bytes", cfg: SourceConfig{MaxBytes: 5}},
		{name: "file bytes", cfg: SourceConfig{MaxFileBytes: 5}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.Type = SourceLocal
			cfg.LocalPath = src
			cfg.AllowedRoots = []string{root}
			_, err := PrepareSource(context.Background(), cfg, filepath.Join(t.TempDir(), "snapshot"))
			if err == nil {
				t.Fatalf("expected %s limit error", tc.name)
			}
		})
	}
}

func TestPrepareLocalSnapshotAllowsEmptyFileAtByteLimit(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "project")
	writeAuditTestFile(t, filepath.Join(src, "a.txt"), "12345")
	writeAuditTestFile(t, filepath.Join(src, "empty.txt"), "")
	dst := filepath.Join(t.TempDir(), "snapshot")
	meta, err := PrepareSource(context.Background(), SourceConfig{
		Type:         SourceLocal,
		LocalPath:    src,
		AllowedRoots: []string{root},
		MaxBytes:     5,
	}, dst)
	if err != nil {
		t.Fatalf("PrepareSource: %v", err)
	}
	if meta.Files != 2 || meta.Bytes != 5 {
		t.Fatalf("meta = files %d bytes %d, want 2/5", meta.Files, meta.Bytes)
	}
}

func TestPrepareZipSnapshot(t *testing.T) {
	base := t.TempDir()
	zipPath := filepath.Join(base, "sample.zip")
	javaBody := "class A {}\n"
	writeAuditTestZip(t, zipPath, []auditTestZipEntry{
		{name: "src/main/java/A.java", body: javaBody, mode: 0o644},
		{name: "README.md", body: "# sample\n", mode: 0o644},
	})
	dst := filepath.Join(base, "snapshot")
	meta, err := PrepareSource(context.Background(), SourceConfig{Type: SourceZip, UploadPath: zipPath}, dst)
	if err != nil {
		t.Fatalf("PrepareSource zip: %v", err)
	}
	if meta.Type != SourceZip {
		t.Fatalf("meta.Type = %q, want zip", meta.Type)
	}
	if !strings.HasPrefix(meta.SourceRef, "zip:sample.zip:") {
		t.Fatalf("meta.SourceRef = %q, want zip:sample.zip:<hash>", meta.SourceRef)
	}
	if strings.Contains(meta.SourceRef, base) {
		t.Fatalf("meta.SourceRef leaked the host path: %q", meta.SourceRef)
	}
	if meta.Files != 2 || meta.Bytes != int64(len(javaBody)+len("# sample\n")) {
		t.Fatalf("meta = files %d bytes %d", meta.Files, meta.Bytes)
	}
	if len(meta.Languages) != 1 || meta.Languages[0] != Java {
		t.Fatalf("meta.Languages = %v, want [java]", meta.Languages)
	}
	if meta.Language != Java {
		t.Fatalf("meta.Language = %q, want java", meta.Language)
	}
	if got := readAuditTestFile(t, filepath.Join(dst, "src", "main", "java", "A.java")); got != javaBody {
		t.Fatalf("zip file content = %q", got)
	}
}

func TestPrepareZipSnapshotAppliesExclusions(t *testing.T) {
	base := t.TempDir()
	zipPath := filepath.Join(base, "project.zip")
	writeAuditTestZip(t, zipPath, []auditTestZipEntry{
		{name: "src/main/java/A.java", body: "class A {}\n"},
		{name: "src/test/java/ATest.java", body: "class ATest {}\n"},
		{name: "vendor/v.js", body: "module.exports = 1\n"},
		{name: "node_modules/x.js", body: "module.exports = 2\n"},
		{name: "dist/bundle.js", body: "bundled\n"},
		{name: ".git/config", body: "[core]\n"},
		{name: ".github/workflows/ci.yml", body: "name: ci\n"},
		{name: "README.md", body: "# project\n"},
	})
	dst := filepath.Join(base, "snapshot")
	meta, err := PrepareSource(context.Background(), SourceConfig{Type: SourceZip, UploadPath: zipPath}, dst)
	if err != nil {
		t.Fatalf("PrepareSource zip: %v", err)
	}
	if meta.Files != 3 {
		t.Fatalf("meta.Files = %d, want 3 (main source, README, .github)", meta.Files)
	}
	for _, rel := range []string{"node_modules", "vendor", filepath.Join("src", "test"), "dist", ".git"} {
		if auditTestFileExists(filepath.Join(dst, rel)) {
			t.Errorf("zip snapshot unexpectedly contains %s", rel)
		}
	}
	if !auditTestFileExists(filepath.Join(dst, "src", "main", "java", "A.java")) ||
		!auditTestFileExists(filepath.Join(dst, ".github", "workflows", "ci.yml")) {
		t.Fatal("zip snapshot lost included source/config files")
	}

	dstIncluded := filepath.Join(base, "snapshot-included")
	meta, err = PrepareSource(context.Background(), SourceConfig{
		Type: SourceZip, UploadPath: zipPath, IncludeTests: true, IncludeVendor: true,
	}, dstIncluded)
	if err != nil {
		t.Fatalf("PrepareSource zip include flags: %v", err)
	}
	if meta.Files != 5 {
		t.Fatalf("include meta.Files = %d, want 5", meta.Files)
	}
	for _, rel := range []string{
		filepath.Join("src", "main", "java", "A.java"),
		filepath.Join("src", "test", "java", "ATest.java"),
		filepath.Join("vendor", "v.js"),
	} {
		if !auditTestFileExists(filepath.Join(dstIncluded, rel)) {
			t.Errorf("include snapshot missing %s", rel)
		}
	}
	if auditTestFileExists(filepath.Join(dstIncluded, "node_modules")) {
		t.Fatal("node_modules must remain excluded for zip snapshots")
	}
}

func TestPrepareSourceRejectsUnsupportedType(t *testing.T) {
	_, err := PrepareSource(context.Background(), SourceConfig{Type: "ftp"}, filepath.Join(t.TempDir(), "snapshot"))
	if err == nil {
		t.Fatal("expected unsupported source type error")
	}
}

func TestValidateGitSourceURL(t *testing.T) {
	valid := []string{
		"https://github.com/org/repo.git",
		"ssh://git@example.com/org/repo.git",
		"git@example.com:org/repo.git",
		"example.com:org/repo.git",
	}
	for _, repoURL := range valid {
		if err := validateGitSourceURL(repoURL); err != nil {
			t.Errorf("validateGitSourceURL(%q) = %v, want nil", repoURL, err)
		}
	}

	invalid := []string{
		"",
		"http://example.com/org/repo.git",
		"file:///tmp/repo.git",
		"ext::sh -c id",
		"git://example.com/org/repo.git",
		"https://user:pass@example.com/org/repo.git",
		"https://user@example.com/org/repo.git",
		"https://-evil.example/repo.git",
		"ssh://-evil.example/repo.git",
		"ssh://user%3Apass@example.com/repo.git",
		"ssh://user%40host@example.com/repo.git",
		"user%3Apass@example.com:org/repo.git",
		"-https://example.com/repo.git",
		"C:/repo",
		`\\server\share\repo`,
		"host with space:repo",
	}
	for _, repoURL := range invalid {
		if err := validateGitSourceURL(repoURL); err == nil {
			t.Errorf("validateGitSourceURL(%q) = nil, want error", repoURL)
		}
	}
}

func TestGitCloneArgsAreConservative(t *testing.T) {
	args, commitRef := gitCloneArgs("https://example.com/org/repo.git", "feature/x", "repo-dir")
	if commitRef {
		t.Fatal("branch ref classified as commit")
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"clone", "--depth=1", "--no-recurse-submodules", "--single-branch",
		"--branch", "feature/x", "--", "https://example.com/org/repo.git", "repo-dir",
	} {
		if !containsString(args, want) && !strings.Contains(joined, want) {
			t.Errorf("clone args missing %q: %v", want, args)
		}
	}
	for _, forbidden := range []string{"--upload-pack", "--config", "--template"} {
		for _, arg := range args {
			if arg == forbidden || strings.HasPrefix(arg, forbidden+"=") {
				t.Errorf("clone args contain forbidden option %q: %v", arg, args)
			}
		}
	}
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || separator+2 >= len(args) || args[separator+1] != "https://example.com/org/repo.git" {
		t.Fatalf("repository URL must follow --: %v", args)
	}

	commitArgs, commitRef := gitCloneArgs("ssh://git@example.com/org/repo.git", strings.Repeat("a", 40), "repo-dir")
	if !commitRef {
		t.Fatal("commit-like ref not classified as commit")
	}
	if containsString(commitArgs, "--branch") {
		t.Fatalf("commit clone must not use --branch: %v", commitArgs)
	}
}

func TestGitSafetyEnv(t *testing.T) {
	hooksDir := t.TempDir()
	env := gitSafetyEnv(hooksDir)
	want := map[string]string{
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_TERMINAL_PROMPT": "0",
		"GIT_LFS_SKIP_SMUDGE": "1",
		"GIT_CONFIG_COUNT":    "3",
		"GIT_CONFIG_KEY_0":    "core.hooksPath",
		"GIT_CONFIG_VALUE_0":  hooksDir,
		"GIT_CONFIG_KEY_1":    "protocol.ext.allow",
		"GIT_CONFIG_VALUE_1":  "never",
		"GIT_CONFIG_KEY_2":    "protocol.file.allow",
		"GIT_CONFIG_VALUE_2":  "never",
	}
	seen := make(map[string]string)
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		seen[key] = value
	}
	for key, value := range want {
		if seen[key] != value {
			t.Errorf("env %s = %q, want %q", key, seen[key], value)
		}
	}
}

func TestPrepareGitCloneFailurePath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	dst := filepath.Join(t.TempDir(), "snapshot")
	_, err := PrepareSource(context.Background(), SourceConfig{
		Type:    SourceGit,
		RepoURL: "https://example.com/org/repo.git",
	}, dst)
	if err == nil {
		t.Fatal("expected git clone failure when git is unavailable")
	}
	if !strings.Contains(err.Error(), "git clone failed") {
		t.Fatalf("error = %v, want git clone failure", err)
	}
	if auditTestFileExists(dst) {
		t.Fatalf("failed clone left destination behind: %s", dst)
	}
}

func TestPrepareGitIntegrationOptional(t *testing.T) {
	repoURL := os.Getenv("ARTEX_AUDIT_GIT_URL")
	if repoURL == "" {
		t.Skip("set ARTEX_AUDIT_GIT_URL (and optionally ARTEX_AUDIT_GIT_REF) to run git integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dst := filepath.Join(t.TempDir(), "snapshot")
	meta, err := PrepareSource(ctx, SourceConfig{
		Type:    SourceGit,
		RepoURL: repoURL,
		Ref:     os.Getenv("ARTEX_AUDIT_GIT_REF"),
	}, dst)
	if err != nil {
		t.Fatalf("PrepareSource git integration: %v", err)
	}
	if meta.Commit == "" || !looksLikeCommitRef(meta.Commit) {
		t.Fatalf("meta.Commit = %q, want SHA", meta.Commit)
	}
	if meta.SnapshotPath != dst {
		t.Fatalf("meta.SnapshotPath = %q, want %q", meta.SnapshotPath, dst)
	}
	if !auditTestFileExists(dst) {
		t.Fatalf("snapshot missing at %s", dst)
	}
}

func TestValidateGitSourceRef(t *testing.T) {
	for _, ref := range []string{"", "main", "refs/tags/v1.0.0", "feature/x", "0123456789abcdef0123456789abcdef01234567"} {
		if err := validateGitSourceRef(ref); err != nil {
			t.Errorf("validateGitSourceRef(%q) = %v, want nil", ref, err)
		}
	}
	for _, ref := range []string{"-main", "--upload-pack=evil", "main branch", "main\ninjected"} {
		if err := validateGitSourceRef(ref); err == nil {
			t.Errorf("validateGitSourceRef(%q) = nil, want error", ref)
		}
	}
}

func TestPrepareGitRejectsBadInputBeforeClone(t *testing.T) {
	tests := []SourceConfig{
		{Type: SourceGit, RepoURL: "file:///tmp/repo.git"},
		{Type: SourceGit, RepoURL: "https://user:pass@example.com/repo.git"},
		{Type: SourceGit, RepoURL: "https://-evil.example/repo.git"},
		{Type: SourceGit, RepoURL: "https://example.com/org/repo.git", Ref: "-main"},
		{Type: SourceGit, RepoURL: "ssh://user%3Apass@example.com/org/repo.git"},
		{Type: SourceGit, RepoURL: "ssh://user%40host@example.com/org/repo.git"},
		{Type: SourceGit, RepoURL: "user%3Apass@example.com:org/repo.git"},
	}
	for _, cfg := range tests {
		_, err := PrepareSource(context.Background(), cfg, filepath.Join(t.TempDir(), "snapshot"))
		if err == nil {
			t.Errorf("PrepareSource(%+v) = nil, want error", cfg)
		}
	}
}

func TestRedactGitSourceRef(t *testing.T) {
	tests := []struct{ input, want string }{
		{"https://example.com/org/repo.git", "https://example.com/org/repo.git"},
		{"https://example.com/org/repo.git?token=secret#frag", "https://example.com/org/repo.git"},
		{"ssh://git:secret@example.com/org/repo.git?x=1", "ssh://git@example.com/org/repo.git"},
		{"ssh://user%3Apass@example.com/org/repo.git", "ssh://user@example.com/org/repo.git"},
		{"ssh://user%40host@example.com/org/repo.git", "ssh://example.com/org/repo.git"},
		{"ssh://user%zz:pass@example.com/org/repo.git", "[invalid git source]"},
		{"user%3Apass@example.com:org/repo.git?x=1#frag", "user@example.com:org/repo.git"},
		{"git@example.com:org/repo.git", "git@example.com:org/repo.git"},
		{"git@example.com:org/repo.git?x=1#frag", "git@example.com:org/repo.git"},
	}
	for _, tc := range tests {
		got := redactGitSourceRef(tc.input)
		if got != tc.want {
			t.Errorf("redactGitSourceRef(%q) = %q, want %q", tc.input, got, tc.want)
		}
		for _, leak := range []string{"secret", "pass", "%3A", "%3a", "%40"} {
			if strings.Contains(got, leak) {
				t.Errorf("redacted source ref leaked credential material %q: %q", leak, got)
			}
		}
	}
}

func TestExtractZipNormal(t *testing.T) {
	base := t.TempDir()
	zipPath := filepath.Join(base, "ok.zip")
	writeAuditTestZip(t, zipPath, []auditTestZipEntry{
		{name: "src/", body: "", mode: os.ModeDir | 0o755},
		{name: "src/main.py", body: "print('ok')\n", mode: 0o644},
	})
	dst := filepath.Join(base, "out")
	if err := ExtractZip(zipPath, dst, ZipLimits{MaxFiles: 10, MaxBytes: 1 << 20, MaxFileBytes: 1 << 20}); err != nil {
		t.Fatalf("ExtractZip: %v", err)
	}
	if got := readAuditTestFile(t, filepath.Join(dst, "src", "main.py")); got != "print('ok')\n" {
		t.Fatalf("extracted content = %q", got)
	}
}

func TestExtractZipRejectsUnsafePaths(t *testing.T) {
	base := t.TempDir()
	tests := []struct {
		name  string
		entry string
	}{
		{name: "dotdot", entry: "../evil.txt"},
		{name: "nested dotdot", entry: "a/../../evil.txt"},
		{name: "absolute slash", entry: "/tmp/evil.txt"},
		{name: "windows drive", entry: "C:/evil.txt"},
		{name: "unc", entry: `\\server\share\evil.txt`},
		{name: "backslash traversal", entry: `..\evil.txt`},
		{name: "backslash separator", entry: `src\evil.txt`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zipPath := filepath.Join(base, strings.ReplaceAll(tc.name, " ", "_")+".zip")
			writeAuditTestZip(t, zipPath, []auditTestZipEntry{{name: tc.entry, body: "evil"}})
			dst := filepath.Join(base, "out-"+strings.ReplaceAll(tc.name, " ", "_"))
			err := ExtractZip(zipPath, dst, ZipLimits{MaxFiles: 10, MaxBytes: 1 << 20, MaxFileBytes: 1 << 20})
			if err == nil {
				t.Fatalf("ExtractZip(%q) = nil, want error", tc.entry)
			}
			if auditTestFileExists(filepath.Join(base, "evil.txt")) {
				t.Fatal("zip traversal wrote outside the destination")
			}
		})
	}
}

func TestExtractZipRejectsSpecialEntries(t *testing.T) {
	base := t.TempDir()
	tests := []struct {
		name string
		mode os.FileMode
	}{
		{name: "symlink", mode: os.ModeSymlink | 0o777},
		{name: "fifo", mode: os.ModeNamedPipe | 0o600},
		{name: "device", mode: os.ModeDevice | 0o600},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zipPath := filepath.Join(base, tc.name+".zip")
			writeAuditTestZip(t, zipPath, []auditTestZipEntry{{name: "special", body: "/etc/passwd", mode: tc.mode}})
			err := ExtractZip(zipPath, filepath.Join(base, "out-"+tc.name), ZipLimits{MaxFiles: 10, MaxBytes: 1 << 20, MaxFileBytes: 1 << 20})
			if err == nil {
				t.Fatalf("expected %s entry rejection", tc.name)
			}
		})
	}
}

func TestExtractZipLimits(t *testing.T) {
	base := t.TempDir()
	zipPath := filepath.Join(base, "limits.zip")
	writeAuditTestZip(t, zipPath, []auditTestZipEntry{
		{name: "a.txt", body: strings.Repeat("a", 64)},
		{name: "b.txt", body: strings.Repeat("b", 64)},
	})

	tests := []struct {
		name   string
		limits ZipLimits
	}{
		{name: "files", limits: ZipLimits{MaxFiles: 1, MaxBytes: 1 << 20, MaxFileBytes: 1 << 20}},
		{name: "bytes", limits: ZipLimits{MaxFiles: 10, MaxBytes: 100, MaxFileBytes: 1 << 20}},
		{name: "file bytes", limits: ZipLimits{MaxFiles: 10, MaxBytes: 1 << 20, MaxFileBytes: 32}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ExtractZip(zipPath, filepath.Join(base, "out-"+tc.name), tc.limits); err == nil {
				t.Fatalf("expected %s limit error", tc.name)
			}
		})
	}
}

func TestExtractZipRejectsCompressionBomb(t *testing.T) {
	base := t.TempDir()
	zipPath := filepath.Join(base, "bomb.zip")
	writeAuditTestZip(t, zipPath, []auditTestZipEntry{
		{name: "bomb.txt", body: strings.Repeat("A", 3<<20)},
	})
	err := ExtractZip(zipPath, filepath.Join(base, "out"), ZipLimits{
		MaxFiles: 10, MaxBytes: 10 << 20, MaxFileBytes: 10 << 20,
	})
	if err == nil {
		t.Fatal("expected compression ratio rejection")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ratio") && !strings.Contains(err.Error(), "压缩比") {
		t.Fatalf("error = %v, want compression ratio error", err)
	}
}

func TestExtractZipRejectsDuplicateAndOverlappingPaths(t *testing.T) {
	base := t.TempDir()
	tests := []struct {
		name    string
		entries []auditTestZipEntry
	}{
		{name: "duplicate", entries: []auditTestZipEntry{{name: "a.txt", body: "1"}, {name: "a.txt", body: "2"}}},
		{name: "duplicate dir", entries: []auditTestZipEntry{{name: "dir/", mode: os.ModeDir | 0o755}, {name: "dir/", mode: os.ModeDir | 0o755}}},
		{name: "file parent", entries: []auditTestZipEntry{{name: "a", body: "1"}, {name: "a/b.txt", body: "2"}}},
		{name: "file then dir", entries: []auditTestZipEntry{{name: "a", body: "1"}, {name: "a/", mode: os.ModeDir | 0o755}}},
		{name: "dir then file", entries: []auditTestZipEntry{{name: "a/", mode: os.ModeDir | 0o755}, {name: "a", body: "1"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zipPath := filepath.Join(base, tc.name+".zip")
			writeAuditTestZip(t, zipPath, tc.entries)
			if err := ExtractZip(zipPath, filepath.Join(base, "out-"+tc.name), ZipLimits{MaxFiles: 10, MaxBytes: 1 << 20, MaxFileBytes: 1 << 20}); err == nil {
				t.Fatalf("expected %s rejection", tc.name)
			}
		})
	}
}

func TestExtractZipRejectsWindowsReservedNames(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"CON", "nul.txt", "dir/COM1.java", "aux.", "conin$"} {
		t.Run(name, func(t *testing.T) {
			zipPath := filepath.Join(base, strings.ReplaceAll(name, "/", "_")+".zip")
			writeAuditTestZip(t, zipPath, []auditTestZipEntry{{name: name, body: "x"}})
			err := ExtractZip(zipPath, filepath.Join(base, "out-"+strings.ReplaceAll(name, "/", "_")), ZipLimits{MaxFiles: 10, MaxBytes: 1 << 20, MaxFileBytes: 1 << 20})
			if err == nil {
				t.Fatalf("ExtractZip(%q) = nil, want reserved-name rejection", name)
			}
		})
	}
}

func TestExtractZipCountsDirectoryEntries(t *testing.T) {
	base := t.TempDir()
	entries := make([]auditTestZipEntry, 0, 25)
	for i := 0; i < 25; i++ {
		entries = append(entries, auditTestZipEntry{name: fmt.Sprintf("dir%02d/", i), mode: os.ModeDir | 0o755})
	}
	zipPath := filepath.Join(base, "dirs.zip")
	writeAuditTestZip(t, zipPath, entries)
	err := ExtractZip(zipPath, filepath.Join(base, "out"), ZipLimits{MaxFiles: 5, MaxBytes: 1 << 20, MaxFileBytes: 1 << 20})
	if err == nil {
		t.Fatal("expected directory entries to count toward MaxFiles")
	}
}

func TestExtractZipNonEmptyDestination(t *testing.T) {
	base := t.TempDir()
	zipPath := filepath.Join(base, "ok.zip")
	writeAuditTestZip(t, zipPath, []auditTestZipEntry{{name: "a.txt", body: "a"}})
	dst := filepath.Join(base, "out")
	writeAuditTestFile(t, filepath.Join(dst, "sentinel"), "keep\n")
	if err := ExtractZip(zipPath, dst, ZipLimits{MaxFiles: 10, MaxBytes: 1 << 20, MaxFileBytes: 1 << 20}); err == nil {
		t.Fatal("expected non-empty destination rejection")
	}
}

func TestSourceLanguagesSortedByFrequency(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "a.py"), "print(1)\n")
	writeAuditTestFile(t, filepath.Join(root, "b.py"), "print(2)\n")
	writeAuditTestFile(t, filepath.Join(root, "c.go"), "package main\n")
	got, err := sourceLanguages(root)
	if err != nil {
		t.Fatalf("sourceLanguages: %v", err)
	}
	if want := []string{Python, Go}; !equalStrings(got, want) {
		t.Fatalf("sourceLanguages = %v, want %v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
