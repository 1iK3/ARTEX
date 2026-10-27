package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	defaultSourceMaxBytes     int64 = 2 << 30
	defaultSourceMaxFiles           = 200000
	defaultSourceMaxFileBytes int64 = 10 << 20
)

// SourceConfig describes an audit source. Existing on-disk uploads are passed
// through UploadPath; the audit package never reaches back into the upload
// staging API.
type SourceConfig struct {
	Type          string   `json:"type"`
	RepoURL       string   `json:"repo_url,omitempty"`
	Ref           string   `json:"ref,omitempty"`
	LocalPath     string   `json:"local_path,omitempty"`
	UploadPath    string   `json:"upload_path,omitempty"`
	AllowedRoots  []string `json:"allowed_roots,omitempty"`
	IncludeTests  bool     `json:"include_tests,omitempty"`
	IncludeVendor bool     `json:"include_vendor,omitempty"`
	MaxBytes      int64    `json:"max_bytes,omitempty"`
	MaxFiles      int      `json:"max_files,omitempty"`
	MaxFileBytes  int64    `json:"max_file_bytes,omitempty"`
}

// SourceMeta is the durable, redacted description of an acquired snapshot.
// SnapshotPath is intentionally separate from SourceRef: SourceRef is safe to
// display in reports, while SnapshotPath is the server-side filesystem path.
type SourceMeta struct {
	Type         string   `json:"type"`
	Ref          string   `json:"ref,omitempty"`
	Commit       string   `json:"commit_sha,omitempty"`
	SourceRef    string   `json:"source_ref"`
	Language     string   `json:"language,omitempty"` // primary language
	Languages    []string `json:"languages,omitempty"`
	Bytes        int64    `json:"bytes"`
	Files        int      `json:"files"`
	SnapshotPath string   `json:"snapshot_path"`
	Warnings     []string `json:"warnings,omitempty"`
}

// PrepareSource acquires cfg into a new snapshot at dst. dst must not exist or
// must be an empty directory. Snapshot directories are 0755 and source files
// are read-only 0444; the writable directory mode lets CodeGraph and other
// engines create their own metadata (for example .codegraph) under the
// snapshot root without modifying source files. On failure, a partially
// written destination is removed on a best-effort basis.
func PrepareSource(ctx context.Context, cfg SourceConfig, dst string) (SourceMeta, error) {
	if err := ctx.Err(); err != nil {
		return SourceMeta{}, err
	}
	cfg.Type = strings.ToLower(strings.TrimSpace(cfg.Type))
	cfg.RepoURL = strings.TrimSpace(cfg.RepoURL)
	cfg.Ref = strings.TrimSpace(cfg.Ref)
	cfg.LocalPath = strings.TrimSpace(cfg.LocalPath)
	cfg.UploadPath = strings.TrimSpace(cfg.UploadPath)

	dstPath, err := ensureEmptyDir(dst)
	if err != nil {
		return SourceMeta{}, err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dstPath)
		}
	}()

	applySourceDefaults(&cfg)

	var meta SourceMeta
	switch cfg.Type {
	case SourceLocal:
		meta, err = prepareLocalSource(ctx, cfg, dstPath)
	case SourceZip:
		meta, err = prepareZipSource(ctx, cfg, dstPath)
	case SourceGit:
		meta, err = prepareGitSource(ctx, cfg, dstPath)
	default:
		err = fmt.Errorf("unsupported source type %q (want git|local|zip)", cfg.Type)
	}
	if err != nil {
		return SourceMeta{}, err
	}
	if err := ctx.Err(); err != nil {
		return SourceMeta{}, err
	}
	success = true
	return meta, nil
}

func sourceRefDigest(value string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(value)))
	return hex.EncodeToString(sum[:8])
}

// localSourceRef identifies a local source without exposing its host path. The
// realpath digest keeps two repositories with the same basename distinct.
func localSourceRef(realPath string) string {
	base := filepath.Base(filepath.Clean(realPath))
	return "local:" + base + ":" + sourceRefDigest(realPath)
}

// zipSourceRef identifies an uploaded archive by filename + absolute path digest
// (the requirement permits path-based identity and avoids reading a potentially
// multi-GB archive just for a label).
func zipSourceRef(uploadPath string) string {
	absolute := filepath.Clean(uploadPath)
	if abs, err := filepath.Abs(uploadPath); err == nil {
		absolute = abs
	}
	return "zip:" + filepath.Base(absolute) + ":" + sourceRefDigest(absolute)
}

func applySourceDefaults(cfg *SourceConfig) {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultSourceMaxBytes
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = defaultSourceMaxFiles
	}
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = defaultSourceMaxFileBytes
	}
}

func prepareLocalSource(ctx context.Context, cfg SourceConfig, dst string) (SourceMeta, error) {
	realSource, err := validateLocalSource(cfg.LocalPath, cfg.AllowedRoots)
	if err != nil {
		return SourceMeta{}, err
	}
	realDst, err := resolveLocalRealPath(dst)
	if err != nil {
		return SourceMeta{}, fmt.Errorf("resolve snapshot destination: %w", err)
	}
	if pathWithinRoot(realDst, realSource) || pathWithinRoot(realSource, realDst) {
		return SourceMeta{}, errors.New("snapshot destination must be outside the local source tree")
	}
	if err := ctx.Err(); err != nil {
		return SourceMeta{}, err
	}

	stats, err := copySnapshot(ctx, realSource, dst, snapshotCopyOptions{
		IncludeTests:  cfg.IncludeTests,
		IncludeVendor: cfg.IncludeVendor,
		MaxBytes:      cfg.MaxBytes,
		MaxFiles:      cfg.MaxFiles,
		MaxFileBytes:  cfg.MaxFileBytes,
	})
	if err != nil {
		return SourceMeta{}, err
	}
	languages, err := sourceLanguagesWithOptions(dst, cfg.IncludeTests, cfg.IncludeVendor)
	if err != nil {
		return SourceMeta{}, fmt.Errorf("detect snapshot languages: %w", err)
	}
	return SourceMeta{
		Type:         SourceLocal,
		SourceRef:    localSourceRef(realSource),
		Language:     primaryLanguage(languages),
		Languages:    languages,
		Bytes:        stats.Bytes,
		Files:        stats.Files,
		SnapshotPath: dst,
		Warnings:     stats.Warnings,
	}, nil
}

func prepareZipSource(ctx context.Context, cfg SourceConfig, dst string) (SourceMeta, error) {
	if cfg.UploadPath == "" {
		return SourceMeta{}, errors.New("zip 审计必须提供已上传的 zip 文件")
	}
	if err := ctx.Err(); err != nil {
		return SourceMeta{}, err
	}
	if _, err := extractZipCtx(ctx, cfg.UploadPath, dst, ZipLimits{
		MaxFiles:     cfg.MaxFiles,
		MaxBytes:     cfg.MaxBytes,
		MaxFileBytes: cfg.MaxFileBytes,
	}); err != nil {
		return SourceMeta{}, fmt.Errorf("extract zip snapshot: %w", err)
	}
	if err := pruneSnapshotTree(dst, cfg.IncludeTests, cfg.IncludeVendor); err != nil {
		return SourceMeta{}, err
	}
	if err := ctx.Err(); err != nil {
		return SourceMeta{}, err
	}
	stats, err := snapshotTreeStats(dst)
	if err != nil {
		return SourceMeta{}, fmt.Errorf("inspect zip snapshot: %w", err)
	}
	languages, err := sourceLanguagesWithOptions(dst, cfg.IncludeTests, cfg.IncludeVendor)
	if err != nil {
		return SourceMeta{}, fmt.Errorf("detect snapshot languages: %w", err)
	}
	return SourceMeta{
		Type:         SourceZip,
		SourceRef:    zipSourceRef(cfg.UploadPath),
		Language:     primaryLanguage(languages),
		Languages:    languages,
		Bytes:        stats.Bytes,
		Files:        stats.Files,
		SnapshotPath: dst,
	}, nil
}

func prepareGitSource(ctx context.Context, cfg SourceConfig, dst string) (SourceMeta, error) {
	if err := validateGitSourceURL(cfg.RepoURL); err != nil {
		return SourceMeta{}, err
	}
	if err := validateGitSourceRef(cfg.Ref); err != nil {
		return SourceMeta{}, err
	}
	sourceRef := redactGitSourceRef(cfg.RepoURL)

	staging, err := os.MkdirTemp("", "artex-audit-git-*")
	if err != nil {
		return SourceMeta{}, fmt.Errorf("create git staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	repoDir, commit, err := cloneGitRepository(ctx, cfg.RepoURL, cfg.Ref, staging)
	if err != nil {
		return SourceMeta{}, err
	}
	if err := ctx.Err(); err != nil {
		return SourceMeta{}, err
	}
	stats, err := copySnapshot(ctx, repoDir, dst, snapshotCopyOptions{
		IncludeTests:  cfg.IncludeTests,
		IncludeVendor: cfg.IncludeVendor,
		MaxBytes:      cfg.MaxBytes,
		MaxFiles:      cfg.MaxFiles,
		MaxFileBytes:  cfg.MaxFileBytes,
	})
	if err != nil {
		return SourceMeta{}, err
	}
	languages, err := sourceLanguagesWithOptions(dst, cfg.IncludeTests, cfg.IncludeVendor)
	if err != nil {
		return SourceMeta{}, fmt.Errorf("detect snapshot languages: %w", err)
	}
	return SourceMeta{
		Type:         SourceGit,
		Ref:          cfg.Ref,
		Commit:       commit,
		SourceRef:    sourceRef,
		Language:     primaryLanguage(languages),
		Languages:    languages,
		Bytes:        stats.Bytes,
		Files:        stats.Files,
		SnapshotPath: dst,
		Warnings:     stats.Warnings,
	}, nil
}

func validateLocalSource(localPath string, allowedRoots []string) (string, error) {
	if strings.TrimSpace(localPath) == "" {
		return "", errors.New("local 审计必须提供 local_path")
	}
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		return "", fmt.Errorf("resolve local_path: %w", err)
	}
	realPath, err := resolveLocalRealPath(absPath)
	if err != nil {
		return "", fmt.Errorf("resolve local_path symlinks: %w", err)
	}
	info, err := os.Stat(realPath)
	if err != nil {
		return "", fmt.Errorf("stat local source: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("local source must be a directory: %s", realPath)
	}

	hasConfiguredRoot := false
	for _, root := range allowedRoots {
		if strings.TrimSpace(root) != "" {
			hasConfiguredRoot = true
			break
		}
	}
	if !hasConfiguredRoot {
		return "", errors.New("未配置本地审计根目录（请设置 ARTEX_AUDIT_LOCAL_ROOTS）")
	}
	checkedRoot := false
	for _, root := range allowedRoots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		absRoot, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		realRoot, err := resolveLocalRealPath(absRoot)
		if err != nil {
			continue
		}
		checkedRoot = true
		if pathWithinRoot(realPath, realRoot) {
			return realPath, nil
		}
	}
	if !checkedRoot {
		return "", errors.New("未配置可用的本地审计根目录（请设置 ARTEX_AUDIT_LOCAL_ROOTS）")
	}
	return "", fmt.Errorf("本地目录不在允许范围: %s", realPath)
}

// resolveLocalRealPath resolves ordinary symlinks and, on Windows, junction /
// reparse points that filepath.EvalSymlinks may leave unresolved. The
// component-wise fallback is security relevant: local roots must be checked
// against the real target, not a junction path inside an allowed directory.
func resolveLocalRealPath(input string) (string, error) {
	absPath, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(absPath))
	if err != nil {
		return "", err
	}
	current := filepath.Clean(resolved)
	for i := 0; i < 40; i++ {
		next, changed := resolveFirstReparsePoint(current)
		if !changed {
			return current, nil
		}
		current = next
	}
	return "", fmt.Errorf("too many symbolic links resolving %s", input)
}

func resolveFirstReparsePoint(path string) (string, bool) {
	volume := filepath.VolumeName(path)
	rest := strings.TrimLeft(strings.TrimPrefix(path, volume), `/\`)
	base := volume
	if base == "" {
		base = string(filepath.Separator)
	} else {
		base += string(filepath.Separator)
	}
	parts := strings.FieldsFunc(rest, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	current := base
	for i, part := range parts {
		current = filepath.Join(current, part)
		target, err := os.Readlink(current)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(current), target)
		}
		target = filepath.Clean(target)
		for _, remainder := range parts[i+1:] {
			target = filepath.Join(target, remainder)
		}
		return target, true
	}
	return current, false
}

func isLinkLike(path string) bool {
	if _, err := os.Readlink(path); err == nil {
		return true
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

func validateGitSourceURL(repoURL string) error {
	if strings.TrimSpace(repoURL) == "" {
		return errors.New("git 审计必须提供 repo_url")
	}
	for _, r := range repoURL {
		if r < 0x20 || r == 0x7f {
			return errors.New("git 仓库 URL 不能包含控制字符")
		}
	}
	if err := validateGitRepoURL(repoURL); err != nil {
		return err
	}
	lower := strings.ToLower(repoURL)
	if strings.Contains(lower, "://") {
		parsed, err := url.Parse(repoURL)
		if err != nil {
			return fmt.Errorf("git 仓库 URL 无效: %w", err)
		}
		host := parsed.Hostname()
		if host == "" {
			return errors.New("git 仓库 URL 缺少主机名")
		}
		if strings.HasPrefix(host, "-") {
			return errors.New("git 仓库主机名不能以 - 开头")
		}
	}
	// The scp-like parser in validateGitRepoURL already rejects a leading-dash
	// host. Keep this explicit second check close to source acquisition because
	// ref validation happens here too.
	if !strings.Contains(lower, "://") {
		hostPart := repoURL
		if at := strings.IndexByte(hostPart, '@'); at >= 0 {
			hostPart = hostPart[at+1:]
		}
		if colon := strings.IndexByte(hostPart, ':'); colon >= 0 {
			hostPart = hostPart[:colon]
		}
		if strings.HasPrefix(hostPart, "-") {
			return errors.New("git 仓库主机名不能以 - 开头")
		}
	}
	return nil
}

func validateGitSourceRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	if strings.HasPrefix(ref, "-") {
		return errors.New("git ref 不能以 - 开头")
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return errors.New("git ref 不能包含空白或控制字符")
		}
	}
	return nil
}

var commitRefPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

func looksLikeCommitRef(ref string) bool {
	return commitRefPattern.MatchString(ref)
}

func redactGitSourceRef(repoURL string) string {
	repoURL = strings.TrimSpace(repoURL)
	if strings.Contains(repoURL, "://") {
		parsed, err := url.Parse(repoURL)
		if err != nil {
			return "[invalid git source]"
		}
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		if parsed.User != nil {
			// HTTPS never legitimately carries userinfo in this API. For SSH,
			// retain only a display-safe username and never the password-shaped
			// portion, including percent-encoded colons, @ signs, or controls.
			if strings.EqualFold(parsed.Scheme, "https") {
				parsed.User = nil
			} else {
				parsed.User = safeGitDisplayUser(parsed.User.String())
			}
		}
		return parsed.String()
	}
	return redactSCPLikeSourceRef(repoURL)
}

func safeGitDisplayUser(rawUserInfo string) *url.Userinfo {
	decoded, err := url.PathUnescape(rawUserInfo)
	if err != nil {
		return nil
	}
	if idx := strings.IndexByte(decoded, ':'); idx >= 0 {
		decoded = decoded[:idx]
	}
	if decoded == "" || strings.Contains(decoded, "@") || containsUserInfoControl(decoded) || strings.ContainsAny(decoded, `/\`) {
		return nil
	}
	return url.User(decoded)
}

func redactSCPLikeSourceRef(repoURL string) string {
	if idx := strings.IndexAny(repoURL, "?#"); idx >= 0 {
		repoURL = repoURL[:idx]
	}
	at := strings.IndexByte(repoURL, '@')
	if at < 0 {
		return repoURL
	}
	user := safeGitDisplayUser(repoURL[:at])
	rest := repoURL[at+1:]
	if user == nil {
		return rest
	}
	return user.String() + "@" + rest
}

func cloneGitRepository(ctx context.Context, repoURL, ref, staging string) (string, string, error) {
	hooksDir := filepath.Join(staging, "hooks")
	if err := os.MkdirAll(hooksDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create empty hooks directory: %w", err)
	}
	env := gitSafetyEnv(hooksDir)
	repoDir := filepath.Join(staging, "repo")

	args, commitRef := gitCloneArgs(repoURL, ref, repoDir)
	if _, err := runGit(ctx, staging, env, args...); err != nil {
		return "", "", fmt.Errorf("git clone failed: %w", redactGitCommandError(err, repoURL))
	}

	if commitRef {
		if _, err := runGit(ctx, staging, env, "-C", repoDir, "fetch", "--depth=1", "--quiet", "origin", ref); err != nil {
			return "", "", fmt.Errorf("git fetch commit %q failed: %w", ref, redactGitCommandError(err, repoURL))
		}
		if _, err := runGit(ctx, staging, env, "-C", repoDir, "checkout", "--quiet", "--detach", "FETCH_HEAD"); err != nil {
			return "", "", fmt.Errorf("git checkout commit %q failed: %w", ref, redactGitCommandError(err, repoURL))
		}
	}

	out, err := runGit(ctx, staging, env, "-C", repoDir, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", "", fmt.Errorf("git rev-parse HEAD failed: %w", redactGitCommandError(err, repoURL))
	}
	commit := strings.TrimSpace(out)
	if !looksLikeCommitRef(commit) {
		return "", "", fmt.Errorf("git rev-parse returned an invalid commit SHA %q", commit)
	}
	return repoDir, commit, nil
}

func gitCloneArgs(repoURL, ref, repoDir string) ([]string, bool) {
	args := []string{
		"clone",
		"--depth=1",
		"--no-recurse-submodules",
		"--single-branch",
		"--quiet",
	}
	commitRef := ref != "" && looksLikeCommitRef(ref)
	if ref != "" && !commitRef {
		args = append(args, "--branch", ref)
	}
	args = append(args, "--", repoURL, repoDir)
	return args, commitRef
}

func gitSafetyEnv(hooksDir string) []string {
	drop := map[string]bool{
		"GIT_CONFIG_NOSYSTEM":   true,
		"GIT_TERMINAL_PROMPT":   true,
		"GIT_CONFIG_COUNT":      true,
		"GIT_CONFIG_PARAMETERS": true,
		"GIT_LFS_SKIP_SMUDGE":   true,
	}
	env := make([]string, 0, len(os.Environ())+12)
	for _, item := range os.Environ() {
		key := item
		if idx := strings.IndexByte(item, '='); idx >= 0 {
			key = item[:idx]
		}
		if drop[key] || strings.HasPrefix(key, "GIT_CONFIG_KEY_") || strings.HasPrefix(key, "GIT_CONFIG_VALUE_") {
			continue
		}
		env = append(env, item)
	}
	env = append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_CONFIG_COUNT=3",
		"GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0="+hooksDir,
		"GIT_CONFIG_KEY_1=protocol.ext.allow",
		"GIT_CONFIG_VALUE_1=never",
		"GIT_CONFIG_KEY_2=protocol.file.allow",
		"GIT_CONFIG_VALUE_2=never",
	)
	return env
}

type cappedBuffer struct {
	buf       bytes.Buffer
	remaining int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	written := len(p)
	if b.remaining <= 0 {
		return written, nil
	}
	if len(p) > b.remaining {
		p = p[:b.remaining]
	}
	_, _ = b.buf.Write(p)
	b.remaining -= len(p)
	return written, nil
}

func runGit(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = env
	output := &cappedBuffer{remaining: 16 << 10}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if err != nil {
		message := strings.TrimSpace(output.buf.String())
		if message == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, message)
	}
	return output.buf.String(), nil
}

func redactGitCommandError(err error, repoURL string) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	message = strings.ReplaceAll(message, repoURL, redactGitSourceRef(repoURL))
	if len(message) > 4096 {
		message = message[:4096] + "..."
	}
	return errors.New(message)
}

type snapshotCopyOptions struct {
	IncludeTests  bool
	IncludeVendor bool
	MaxBytes      int64
	MaxFiles      int
	MaxFileBytes  int64
}

type snapshotCopyStats struct {
	Bytes    int64
	Files    int
	Warnings []string
}

func copySnapshot(ctx context.Context, src, dst string, opts snapshotCopyOptions) (snapshotCopyStats, error) {
	info, err := os.Stat(src)
	if err != nil {
		return snapshotCopyStats{}, fmt.Errorf("stat snapshot source: %w", err)
	}
	if !info.IsDir() {
		return snapshotCopyStats{}, fmt.Errorf("snapshot source must be a directory: %s", src)
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultSourceMaxBytes
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = defaultSourceMaxFiles
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = defaultSourceMaxFileBytes
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return snapshotCopyStats{}, err
	}
	stats := snapshotCopyStats{}
	visited := 0
	bytesSinceCheck := int64(0)
	err = filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		visited++
		if visited%200 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if walkErr != nil {
			return fmt.Errorf("walk source %s: %w", path, walkErr)
		}
		if path == src {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return fmt.Errorf("resolve relative source path: %w", err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("source path escapes snapshot root: %s", path)
		}
		relSlash := filepath.ToSlash(rel)
		base := entry.Name()

		if entry.IsDir() {
			if isLinkLike(path) {
				stats.Warnings = append(stats.Warnings, "skipped symlink: "+relSlash)
				return filepath.SkipDir
			}
			if snapshotDirExcluded(base, opts.IncludeVendor) {
				return filepath.SkipDir
			}
			if !opts.IncludeTests && isTestDirectory(base) {
				return filepath.SkipDir
			}
			target := filepath.Join(dst, rel)
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("create snapshot directory %s: %w", relSlash, err)
			}
			return nil
		}
		if isLinkLike(path) {
			stats.Warnings = append(stats.Warnings, "skipped symlink: "+relSlash)
			return nil
		}
		if !entry.Type().IsRegular() {
			stats.Warnings = append(stats.Warnings, "skipped non-regular file: "+relSlash)
			return nil
		}
		if base == ".git" || (!opts.IncludeTests && isTestFile(relSlash, base)) {
			return nil
		}
		if stats.Files+1 > opts.MaxFiles {
			return fmt.Errorf("snapshot exceeds max files (%d) at %s", opts.MaxFiles, relSlash)
		}

		sourceInfo, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat source file %s: %w", relSlash, err)
		}
		if sourceInfo.Size() > opts.MaxFileBytes {
			return fmt.Errorf("snapshot file exceeds max file bytes (%d): %s", opts.MaxFileBytes, relSlash)
		}
		if sourceInfo.Size() > opts.MaxBytes-stats.Bytes {
			return fmt.Errorf("snapshot exceeds max bytes (%d) at %s", opts.MaxBytes, relSlash)
		}

		target := filepath.Join(dst, rel)
		if !pathWithinRoot(target, dst) {
			return fmt.Errorf("snapshot path escapes destination: %s", relSlash)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create snapshot parent for %s: %w", relSlash, err)
		}
		n, err := copyLimitedFile(ctx, path, target, opts.MaxFileBytes, opts.MaxBytes-stats.Bytes)
		if err != nil {
			return fmt.Errorf("copy snapshot file %s: %w", relSlash, err)
		}
		stats.Bytes += n
		stats.Files++
		bytesSinceCheck += n
		if bytesSinceCheck >= auditCopyContextCheckBytes {
			bytesSinceCheck = 0
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return snapshotCopyStats{}, err
	}
	if err := ctx.Err(); err != nil {
		return snapshotCopyStats{}, err
	}
	return stats, nil
}

// auditCopyContextCheckBytes bounds how much data is read between context
// cancellation checks. Large single files are also checked per read chunk by
// auditContextReader.
const auditCopyContextCheckBytes int64 = 64 << 20

type auditContextReader struct {
	ctx    context.Context
	reader io.Reader
	since  int64
}

func (r *auditContextReader) Read(p []byte) (int, error) {
	if r.ctx != nil {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
	}
	n, err := r.reader.Read(p)
	r.since += int64(n)
	if r.ctx != nil && r.since >= auditCopyContextCheckBytes {
		r.since = 0
		if ctxErr := r.ctx.Err(); ctxErr != nil {
			return n, ctxErr
		}
	}
	return n, err
}

func copyLimitedFile(ctx context.Context, src, dst string, maxFileBytes, remainingBytes int64) (int64, error) {
	if remainingBytes < 0 {
		return 0, errors.New("snapshot byte limit reached")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
	input, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer input.Close()
	output, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		_ = output.Close()
		if !committed {
			_ = os.Remove(dst)
		}
	}()

	allowed := maxFileBytes
	if remainingBytes < allowed {
		allowed = remainingBytes
	}
	if allowed < 0 {
		allowed = 0
	}
	n, err := io.Copy(output, io.LimitReader(&auditContextReader{ctx: ctx, reader: input}, allowed+1))
	if err != nil {
		return 0, err
	}
	if n > maxFileBytes {
		return 0, fmt.Errorf("file exceeds max file bytes (%d)", maxFileBytes)
	}
	if n > remainingBytes {
		return 0, fmt.Errorf("snapshot exceeds max bytes (%d)", n)
	}
	if err := output.Close(); err != nil {
		return 0, err
	}
	committed = true
	return n, nil
}

func snapshotDirExcluded(base string, includeVendor bool) bool {
	lower := strings.ToLower(base)
	switch lower {
	case ".git", ".hg", ".svn", ".bzr", "cvs", "node_modules", "dist", "build", "target", "out", ".next":
		return true
	case "vendor":
		return !includeVendor
	}
	return false
}

func isTestDirectory(base string) bool {
	switch strings.ToLower(base) {
	case "test", "tests", "testdata", "__tests__":
		return true
	}
	return false
}

func isTestFile(relSlash, base string) bool {
	lowerBase := strings.ToLower(base)
	lowerPath := strings.ToLower(relSlash)
	if strings.HasSuffix(lowerBase, "_test.go") ||
		strings.HasSuffix(lowerBase, "_test.py") ||
		strings.HasSuffix(lowerBase, "_test.rs") ||
		strings.HasSuffix(lowerBase, "_test.js") ||
		strings.HasSuffix(lowerBase, "_test.ts") ||
		strings.HasSuffix(lowerBase, "_test.tsx") ||
		strings.HasPrefix(lowerBase, "test_") && strings.HasSuffix(lowerBase, ".py") {
		return true
	}
	if strings.Contains(lowerPath, ".test.") || strings.Contains(lowerPath, ".spec.") {
		return true
	}
	if strings.HasSuffix(base, "Test.java") || strings.HasSuffix(base, "Tests.java") || strings.HasSuffix(base, "IT.java") {
		return true
	}
	for _, segment := range strings.Split(lowerPath, "/") {
		if isTestDirectory(segment) {
			return true
		}
	}
	return false
}

var extensionLanguages = map[string]string{
	".java":   Java,
	".kt":     "kotlin",
	".kts":    "kotlin",
	".py":     Python,
	".pyw":    Python,
	".js":     JavaScript,
	".jsx":    JavaScript,
	".mjs":    JavaScript,
	".cjs":    JavaScript,
	".ts":     TypeScript,
	".tsx":    TypeScript,
	".mts":    TypeScript,
	".cts":    TypeScript,
	".go":     Go,
	".rs":     Rust,
	".c":      C,
	".h":      C,
	".cc":     CPP,
	".cpp":    CPP,
	".cxx":    CPP,
	".hpp":    CPP,
	".hh":     CPP,
	".hxx":    CPP,
	".php":    "php",
	".rb":     "ruby",
	".cs":     "csharp",
	".swift":  "swift",
	".scala":  "scala",
	".sh":     "shell",
	".bash":   "shell",
	".zsh":    "shell",
	".fish":   "shell",
	".lua":    "lua",
	".pl":     "perl",
	".pm":     "perl",
	".r":      "r",
	".dart":   "dart",
	".ex":     "elixir",
	".exs":    "elixir",
	".erl":    "erlang",
	".hrl":    "erlang",
	".hs":     "haskell",
	".clj":    "clojure",
	".cljs":   "clojure",
	".groovy": "groovy",
	".vue":    "vue",
	".svelte": "svelte",
	".sql":    "sql",
	".m":      "objective-c",
	".mm":     "objective-c",
}

func languageForFile(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if lang, ok := extensionLanguages[ext]; ok {
		return lang
	}
	return ""
}

// walkSourceTree walks regular source files with the audit package's shared
// exclusion policy. Symlinks and special files are never followed.
func walkSourceTree(root string, includeTests, includeVendor bool, visit func(path, relSlash string) error) error {
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat source root: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source root must be a directory: %s", root)
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk source %s: %w", path, walkErr)
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("resolve source path: %w", err)
		}
		relSlash := filepath.ToSlash(rel)
		if entry.IsDir() {
			if isLinkLike(path) {
				return filepath.SkipDir
			}
			if snapshotDirExcluded(entry.Name(), includeVendor) {
				return filepath.SkipDir
			}
			if !includeTests && isTestDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if isLinkLike(path) || !entry.Type().IsRegular() || entry.Name() == ".git" {
			return nil
		}
		if !includeTests && isTestFile(relSlash, entry.Name()) {
			return nil
		}
		return visit(path, relSlash)
	})
}

func primaryLanguage(languages []string) string {
	if len(languages) == 0 {
		return ""
	}
	return languages[0]
}

func sourceLanguages(root string) ([]string, error) {
	return sourceLanguagesWithOptions(root, false, false)
}

func sourceLanguagesWithOptions(root string, includeTests, includeVendor bool) ([]string, error) {
	counts := make(map[string]int)
	err := walkSourceTree(root, includeTests, includeVendor, func(path, relSlash string) error {
		if language := languageForFile(relSlash); language != "" {
			counts[language]++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	languages := make([]string, 0, len(counts))
	for language := range counts {
		languages = append(languages, language)
	}
	sort.Slice(languages, func(i, j int) bool {
		if counts[languages[i]] != counts[languages[j]] {
			return counts[languages[i]] > counts[languages[j]]
		}
		return languages[i] < languages[j]
	})
	return languages, nil
}

func pruneSnapshotTree(root string, includeTests, includeVendor bool) error {
	return filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk zip snapshot: %w", walkErr)
		}
		if current == root {
			return nil
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return fmt.Errorf("resolve zip snapshot path: %w", err)
		}
		relSlash := filepath.ToSlash(rel)
		if entry.IsDir() {
			if snapshotDirExcluded(entry.Name(), includeVendor) ||
				(!includeTests && isTestDirectory(entry.Name())) ||
				isLinkLike(current) {
				if err := os.RemoveAll(current); err != nil {
					return fmt.Errorf("remove excluded zip snapshot path %s: %w", relSlash, err)
				}
				return filepath.SkipDir
			}
			return nil
		}
		remove := isLinkLike(current) || entry.Name() == ".git"
		if !includeTests && isTestFile(relSlash, entry.Name()) {
			remove = true
		}
		if remove {
			if err := os.Remove(current); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove excluded zip snapshot file %s: %w", relSlash, err)
			}
		}
		return nil
	})
}

func snapshotTreeStats(root string) (snapshotCopyStats, error) {
	var stats snapshotCopyStats
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || isLinkLike(path) || !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stats.Files++
		stats.Bytes += info.Size()
		return nil
	})
	return stats, err
}

func ensureEmptyDir(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("snapshot destination is required")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve snapshot destination: %w", err)
	}
	absPath = filepath.Clean(absPath)
	info, err := os.Lstat(absPath)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("snapshot destination must not be a symlink")
		}
		if !info.IsDir() {
			return "", errors.New("snapshot destination must be a directory")
		}
		entries, err := os.ReadDir(absPath)
		if err != nil {
			return "", fmt.Errorf("read snapshot destination: %w", err)
		}
		if len(entries) > 0 {
			return "", errors.New("snapshot destination must be empty")
		}
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(absPath, 0o755); err != nil {
			return "", fmt.Errorf("create snapshot destination: %w", err)
		}
	default:
		return "", fmt.Errorf("stat snapshot destination: %w", err)
	}
	return absPath, nil
}
