package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// SourceMatch is one code_search hit. Path is repository-relative and
// slash-separated; Line is 1-based.
type SourceMatch struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

const (
	// codeSearchDefaultMaxResults is used when the caller omits maxResults.
	codeSearchDefaultMaxResults = 100
	codeSearchMaxResults        = 1_000
	// codeSearchMaxFiles bounds how many candidate files one search may open.
	codeSearchMaxFiles = 20_000
	// codeSearchMaxFileBytes prevents a minified bundle from consuming the walk.
	codeSearchMaxFileBytes = 2 << 20
	// codeSearchMaxLineRunes bounds the reported text of a single match.
	codeSearchMaxLineRunes = 500

	// codeReadDefaultMaxLines / codeReadDefaultMaxBytes are the default slice
	// limits for code_read. Larger files are readable, but a single call never
	// returns more than these limits.
	codeReadDefaultMaxLines = 2_000
	codeReadDefaultMaxBytes = 1 << 20
	// codeReadMaxFileBytes is the hard file-size ceiling; anything larger is
	// rejected rather than read into memory.
	codeReadMaxFileBytes = 16 << 20
)

// codeSearchSkipDirs are build/vendor/VCS directories that never contain the
// project's own source. Test directories are intentionally NOT skipped: an
// audit must be able to reason about test-only sinks.
var codeSearchSkipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".bzr": true, "cvs": true,
	"node_modules": true, "vendor": true, "bower_components": true,
	"dist": true, "build": true, "target": true, "out": true, ".next": true,
	"coverage": true, ".nyc_output": true, "__pycache__": true,
	".venv": true, "venv": true, ".tox": true, ".mypy_cache": true,
	".gradle": true, ".mvn": true, "bin": true, "obj": true,
	// CodeGraph writes its own index/db under the snapshot root; never expose it
	// as audit source text.
	".codegraph": true, ".idea": true, ".vscode": true,
}

// SearchSource walks root and returns up to maxResults regexp matches in text
// files. It never uses a shell or external grep: the walk, binary/UTF-8
// filtering and matching all happen in-process. Files are confined to root
// (symlinks/junctions are skipped), and the reported text is line-capped.
func SearchSource(ctx context.Context, root, query, glob string, maxResults int) ([]SourceMatch, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("code_search: query 不能为空")
	}
	re, err := regexp.Compile(query)
	if err != nil {
		return nil, fmt.Errorf("code_search: 无效的正则表达式 %q: %w", query, err)
	}
	realRoot, err := resolveAuditSourceRoot(root, "code_search")
	if err != nil {
		return nil, err
	}
	glob = strings.TrimSpace(glob)
	if glob != "" {
		if _, err := path.Match(glob, "x"); err != nil {
			return nil, fmt.Errorf("code_search: 无效的 glob %q: %w", glob, err)
		}
	}
	if maxResults <= 0 {
		maxResults = codeSearchDefaultMaxResults
	}
	if maxResults > codeSearchMaxResults {
		maxResults = codeSearchMaxResults
	}
	if ctx == nil {
		ctx = context.Background()
	}

	matches := make([]SourceMatch, 0, maxResults)
	files := 0
	err = filepath.WalkDir(realRoot, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("code_search: 读取 %s 失败: %w", current, walkErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if current == realRoot {
			return nil
		}
		rel, err := filepath.Rel(realRoot, current)
		if err != nil {
			return fmt.Errorf("code_search: 解析相对路径失败: %w", err)
		}
		relSlash := filepath.ToSlash(rel)
		if !pathWithinRoot(current, realRoot) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if codeSearchSkipDirs[strings.ToLower(entry.Name())] || isLinkLike(current) {
				return filepath.SkipDir
			}
			return nil
		}
		if isLinkLike(current) || !entry.Type().IsRegular() {
			return nil
		}
		if glob != "" && !matchSourceGlob(glob, relSlash) {
			return nil
		}
		if files >= codeSearchMaxFiles {
			return filepath.SkipAll
		}
		info, err := entry.Info()
		if err != nil {
			return nil // unreadable metadata: skip this file, keep searching
		}
		if info.Size() > codeSearchMaxFileBytes {
			return nil
		}
		files++
		data, err := os.ReadFile(current)
		if err != nil {
			return nil // unreadable file: skip, do not fail the whole search
		}
		if !isAuditTextFile(data) {
			return nil
		}
		for lineNo, line := range splitAuditLines(data) {
			if lineNo%256 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if !re.MatchString(line) {
				continue
			}
			matches = append(matches, SourceMatch{
				Path: relSlash,
				Line: lineNo + 1,
				Text: truncateAuditRunes(line, codeSearchMaxLineRunes),
			})
			if len(matches) >= maxResults {
				return filepath.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Path != matches[j].Path {
			return matches[i].Path < matches[j].Path
		}
		return matches[i].Line < matches[j].Line
	})
	return matches, nil
}

// ReadSource returns a 1-based inclusive line range from relPath, confined to
// root. The range is capped at codeReadDefaultMaxLines lines and maxBytes bytes
// (default 1 MiB); a truncation marker is appended when either cap or EOF cuts
// the requested range. Binary, non-UTF-8 and oversized files are rejected.
func ReadSource(ctx context.Context, root, relPath string, startLine, endLine, maxBytes int) (string, int, error) {
	realRoot, err := resolveAuditSourceRoot(root, "code_read")
	if err != nil {
		return "", 0, err
	}
	// Reject any explicit .. segment (even a lexically safe "a/../b"): the LLM
	// contract is a plain repository-relative path.
	for _, segment := range strings.Split(strings.ReplaceAll(strings.TrimSpace(relPath), "\\", "/"), "/") {
		if segment == ".." {
			return "", 0, fmt.Errorf("code_read: 路径 %q 不能包含 ..", relPath)
		}
	}
	cleaned, err := normalizeCodePath(relPath)
	if err != nil {
		return "", 0, fmt.Errorf("code_read: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}

	target := filepath.Join(realRoot, filepath.FromSlash(cleaned))
	if !pathWithinRoot(target, realRoot) {
		return "", 0, fmt.Errorf("code_read: 路径 %q 逃逸源码根目录", relPath)
	}
	realTarget, err := resolveLocalRealPath(target)
	if err != nil {
		return "", 0, fmt.Errorf("code_read: %s 不存在或不可解析: %w", cleaned, err)
	}
	if !pathWithinRoot(realTarget, realRoot) {
		return "", 0, fmt.Errorf("code_read: 路径 %q 通过符号链接逃逸源码根目录", relPath)
	}
	info, err := os.Stat(realTarget)
	if err != nil {
		return "", 0, fmt.Errorf("code_read: 读取 %s 失败: %w", cleaned, err)
	}
	if info.IsDir() {
		return "", 0, fmt.Errorf("code_read: %s 是目录，不是文件", cleaned)
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("code_read: %s 不是普通文件", cleaned)
	}
	if info.Size() > codeReadMaxFileBytes {
		return "", 0, fmt.Errorf("code_read: %s 超过最大文件大小 %d 字节", cleaned, codeReadMaxFileBytes)
	}
	data, err := os.ReadFile(realTarget)
	if err != nil {
		return "", 0, fmt.Errorf("code_read: 读取 %s 失败: %w", cleaned, err)
	}
	if len(data) > codeReadMaxFileBytes {
		return "", 0, fmt.Errorf("code_read: %s 超过最大文件大小 %d 字节", cleaned, codeReadMaxFileBytes)
	}
	if isAuditBinary(data) {
		return "", 0, fmt.Errorf("code_read: %s 是二进制文件，不能按文本读取", cleaned)
	}
	if !utf8.Valid(data) {
		return "", 0, fmt.Errorf("code_read: %s 不是有效的 UTF-8 文本", cleaned)
	}

	lines := splitAuditLines(data)
	totalLines := len(lines)
	if startLine <= 0 {
		startLine = 1
	}
	endProvided := endLine > 0
	if endLine <= 0 {
		endLine = startLine + codeReadDefaultMaxLines - 1
	}
	if endLine < startLine {
		return "", totalLines, fmt.Errorf("code_read: end_line (%d) 不能小于 start_line (%d)", endLine, startLine)
	}
	if startLine > totalLines {
		return "", totalLines, nil
	}

	lineCapped := false
	if endLine-startLine+1 > codeReadDefaultMaxLines {
		endLine = startLine + codeReadDefaultMaxLines - 1
		lineCapped = true
	}
	// A caller-selected range that simply ends before EOF is not "truncated".
	// The default window and the hard line cap are, so mark those explicitly.
	if endLine > totalLines {
		endLine = totalLines
	}
	truncated := (!endProvided || lineCapped) && endLine < totalLines
	content := strings.Join(lines[startLine-1:endLine], "\n")

	if maxBytes <= 0 {
		maxBytes = codeReadDefaultMaxBytes
	}
	if maxBytes > codeReadMaxFileBytes {
		maxBytes = codeReadMaxFileBytes
	}
	if len(content) > maxBytes {
		content = truncateAuditUTF8Bytes(content, maxBytes)
		truncated = true
	}
	if truncated {
		content += fmt.Sprintf(
			"\n…[TRUNCATED: requested lines %d-%d of %d; per-call limit %d lines / %d bytes]",
			startLine, endLine, totalLines, codeReadDefaultMaxLines, maxBytes,
		)
	}
	return content, totalLines, nil
}

// resolveAuditSourceRoot validates the source root and returns its real path.
func resolveAuditSourceRoot(root, tool string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("%s: 需要任务源码根目录（audit source root 未配置）", tool)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("%s: 解析源码根目录失败: %w", tool, err)
	}
	realRoot, err := resolveLocalRealPath(abs)
	if err != nil {
		return "", fmt.Errorf("%s: 源码根目录不可解析: %w", tool, err)
	}
	info, err := os.Stat(realRoot)
	if err != nil {
		return "", fmt.Errorf("%s: 读取源码根目录失败: %w", tool, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s: 源码根目录不是目录: %s", tool, realRoot)
	}
	return realRoot, nil
}

// matchSourceGlob applies a shell-style glob. A pattern without a slash matches
// the basename (so "*.go" matches "src/a.go"); a pattern with a slash matches
// the repository-relative slash path.
func matchSourceGlob(glob, relSlash string) bool {
	target := relSlash
	if !strings.Contains(glob, "/") {
		target = path.Base(relSlash)
	}
	ok, err := path.Match(glob, target)
	return err == nil && ok
}

// isAuditTextFile reports whether data looks like a text file safe to regexp
// search: valid UTF-8 and no NUL byte.
func isAuditTextFile(data []byte) bool {
	return !isAuditBinary(data) && utf8.Valid(data)
}

// isAuditBinary reports a NUL byte anywhere in the file, the conventional
// binary-file signal for source trees. Search files are capped at 2 MiB and read
// files at 16 MiB, so a full scan is cheap.
func isAuditBinary(data []byte) bool {
	return bytes.IndexByte(data, 0) >= 0
}

// splitAuditLines splits file content into lines without the phantom trailing
// line produced by a final newline; \r is stripped so CRLF files read cleanly.
func splitAuditLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}

// truncateAuditRunes caps text at max runes, appending an ellipsis.
func truncateAuditRunes(text string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= max {
		return text
	}
	return string(runes[:max]) + "…"
}

// truncateAuditUTF8Bytes cuts s to at most max bytes without splitting a rune.
func truncateAuditUTF8Bytes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}
