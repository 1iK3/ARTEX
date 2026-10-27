package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSearchSourceRegexAndLineNumbers(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "src", "app.go"), "package app\n\nconst secret = \"x\"\nfunc login() {}\n")
	writeAuditTestFile(t, filepath.Join(root, "docs", "readme.md"), "# docs\nnothing here\n")

	matches, err := SearchSource(context.Background(), root, `secret\s*=`, "", 0)
	if err != nil {
		t.Fatalf("SearchSource: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1: %+v", len(matches), matches)
	}
	got := matches[0]
	if got.Path != "src/app.go" || got.Line != 3 || got.Text != `const secret = "x"` {
		t.Fatalf("match = %+v", got)
	}
}

func TestSearchSourceGlobFilter(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "src", "app.go"), "needle\n")
	writeAuditTestFile(t, filepath.Join(root, "src", "app.ts"), "needle\n")
	writeAuditTestFile(t, filepath.Join(root, "README.md"), "needle\n")

	matches, err := SearchSource(context.Background(), root, "needle", "*.go", 0)
	if err != nil {
		t.Fatalf("SearchSource glob: %v", err)
	}
	if len(matches) != 1 || matches[0].Path != "src/app.go" {
		t.Fatalf("basename glob matches = %+v", matches)
	}

	matches, err = SearchSource(context.Background(), root, "needle", "src/*.ts", 0)
	if err != nil {
		t.Fatalf("SearchSource path glob: %v", err)
	}
	if len(matches) != 1 || matches[0].Path != "src/app.ts" {
		t.Fatalf("path glob matches = %+v", matches)
	}

	if _, err := SearchSource(context.Background(), root, "needle", "[", 0); err == nil {
		t.Fatal("invalid glob must fail")
	}
}

func TestSearchSourceRejectsInvalidRegex(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "a.txt"), "x\n")
	if _, err := SearchSource(context.Background(), root, "(", "", 0); err == nil {
		t.Fatal("invalid regex must fail")
	}
	if _, err := SearchSource(context.Background(), root, "   ", "", 0); err == nil {
		t.Fatal("empty query must fail")
	}
	if _, err := SearchSource(context.Background(), "", "x", "", 0); err == nil {
		t.Fatal("empty root must fail")
	}
}

func TestSearchSourceSkipsBinaryAndNonUTF8(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "text.txt"), "needle\n")
	if err := os.WriteFile(filepath.Join(root, "bin.dat"), []byte("needle\x00needle"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "latin.txt"), []byte{0xff, 0xfe, 'n', 'e', 'e', 'd', 'l', 'e'}, 0o644); err != nil {
		t.Fatal(err)
	}

	matches, err := SearchSource(context.Background(), root, "needle", "", 0)
	if err != nil {
		t.Fatalf("SearchSource: %v", err)
	}
	if len(matches) != 1 || matches[0].Path != "text.txt" {
		t.Fatalf("binary/non-UTF8 files must be skipped: %+v", matches)
	}
}

func TestSearchSourceSkipsVendorBuildDirsAndLimitsResults(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"node_modules", ".git", "build", "vendor", "dist"} {
		writeAuditTestFile(t, filepath.Join(root, dir, "hits.txt"), "needle\nneedle\n")
	}
	writeAuditTestFile(t, filepath.Join(root, "src", "one.txt"), "needle\nneedle\n")

	matches, err := SearchSource(context.Background(), root, "needle", "", 1)
	if err != nil {
		t.Fatalf("SearchSource: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("maxResults not enforced: %+v", matches)
	}
	if matches[0].Path != "src/one.txt" {
		t.Fatalf("searched a skipped directory: %+v", matches)
	}
}

func TestSearchSourceTruncatesLongMatchText(t *testing.T) {
	root := t.TempDir()
	long := "needle-" + strings.Repeat("x", codeSearchMaxLineRunes*2)
	writeAuditTestFile(t, filepath.Join(root, "long.txt"), long+"\n")

	matches, err := SearchSource(context.Background(), root, "needle", "", 0)
	if err != nil {
		t.Fatalf("SearchSource: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %+v", matches)
	}
	if len([]rune(matches[0].Text)) != codeSearchMaxLineRunes+1 || !strings.HasSuffix(matches[0].Text, "…") {
		t.Fatalf("match text not line-capped: %d runes", len([]rune(matches[0].Text)))
	}
}

func TestReadSourceLineRangeAndDefaults(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "a.txt"), "line1\nline2\nline3\nline4\nline5\n")

	content, total, err := ReadSource(context.Background(), root, "a.txt", 2, 4, 0)
	if err != nil {
		t.Fatalf("ReadSource: %v", err)
	}
	if total != 5 {
		t.Fatalf("totalLines = %d, want 5", total)
	}
	if content != "line2\nline3\nline4" {
		t.Fatalf("content = %q", content)
	}

	// start > total: empty content, but total is still reported.
	content, total, err = ReadSource(context.Background(), root, "a.txt", 99, 120, 0)
	if err != nil {
		t.Fatalf("ReadSource out of range: %v", err)
	}
	if content != "" || total != 5 {
		t.Fatalf("out-of-range content=%q total=%d", content, total)
	}

	if _, _, err := ReadSource(context.Background(), root, "a.txt", 4, 2, 0); err == nil {
		t.Fatal("end < start must fail")
	}
}

func TestReadSourceDefaultLineCap(t *testing.T) {
	root := t.TempDir()
	var b strings.Builder
	for i := 1; i <= codeReadDefaultMaxLines+100; i++ {
		b.WriteString(fmt.Sprintf("line-%d\n", i))
	}
	writeAuditTestFile(t, filepath.Join(root, "big.txt"), b.String())

	content, total, err := ReadSource(context.Background(), root, "big.txt", 0, 0, 0)
	if err != nil {
		t.Fatalf("ReadSource: %v", err)
	}
	if total != codeReadDefaultMaxLines+100 {
		t.Fatalf("totalLines = %d", total)
	}
	if !strings.Contains(content, "TRUNCATED") {
		t.Fatalf("missing truncation marker")
	}
	if strings.Contains(content, fmt.Sprintf("line-%d\n", codeReadDefaultMaxLines+1)) {
		t.Fatalf("returned content beyond the default line cap")
	}
	if !strings.Contains(content, fmt.Sprintf("line-%d", codeReadDefaultMaxLines)) {
		t.Fatalf("content did not include the last permitted line")
	}
}

func TestReadSourceMaxBytes(t *testing.T) {
	root := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "a.txt"), strings.Repeat("abcdefghij", 20)+"\n")

	content, total, err := ReadSource(context.Background(), root, "a.txt", 1, 1, 10)
	if err != nil {
		t.Fatalf("ReadSource: %v", err)
	}
	if total != 1 {
		t.Fatalf("totalLines = %d", total)
	}
	if !strings.HasPrefix(content, "abcdefghij") {
		t.Fatalf("content prefix = %q", content)
	}
	if !strings.Contains(content, "TRUNCATED") {
		t.Fatalf("missing byte-cap truncation marker")
	}
}

func TestReadSourceRejectsBinaryInvalidUTF8AndOversized(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bin.dat"), []byte("abc\x00def"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "latin.txt"), []byte{0xff, 0xfe, 'a'}, 0o644); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(root, "huge.bin")
	if err := os.WriteFile(oversized, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(oversized, codeReadMaxFileBytes+1); err != nil {
		t.Fatal(err)
	}

	if _, _, err := ReadSource(context.Background(), root, "bin.dat", 1, 10, 0); err == nil || !strings.Contains(err.Error(), "二进制") {
		t.Fatalf("binary file error = %v", err)
	}
	if _, _, err := ReadSource(context.Background(), root, "latin.txt", 1, 10, 0); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	if _, _, err := ReadSource(context.Background(), root, "huge.bin", 1, 10, 0); err == nil || !strings.Contains(err.Error(), "最大文件大小") {
		t.Fatalf("oversized file error = %v", err)
	}
}

func TestReadSourcePathConfinement(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeAuditTestFile(t, filepath.Join(root, "sub", "a.txt"), "inside\n")
	writeAuditTestFile(t, filepath.Join(outside, "secret.txt"), "outside\n")
	writeAuditTestFile(t, filepath.Join(root, "a.txt"), "root\n")

	cases := []string{
		"../secret.txt",
		"sub/../../secret.txt",
		filepath.Join(outside, "secret.txt"),
		"",
	}
	for _, path := range cases {
		if _, _, err := ReadSource(context.Background(), root, path, 1, 10, 0); err == nil {
			t.Fatalf("ReadSource accepted escaped path %q", path)
		}
	}
	if _, _, err := ReadSource(context.Background(), root, "sub", 1, 10, 0); err == nil {
		t.Fatal("ReadSource accepted a directory")
	}
}

func TestReadSourceSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeAuditTestFile(t, filepath.Join(outside, "secret.txt"), "topsecret\n")
	link := filepath.Join(root, "escape")
	if err := createAuditTestDirLink(t, outside, link); err != nil {
		t.Skipf("directory links unsupported: %v", err)
	}

	if _, _, err := ReadSource(context.Background(), root, "escape/secret.txt", 1, 10, 0); err == nil {
		t.Fatal("ReadSource followed a symlink/junction outside the root")
	}

	matches, err := SearchSource(context.Background(), root, "topsecret", "", 0)
	if err != nil {
		t.Fatalf("SearchSource: %v", err)
	}
	for _, match := range matches {
		if strings.HasPrefix(match.Path, "escape/") {
			t.Fatalf("SearchSource followed a symlink/junction: %+v", match)
		}
	}
}
