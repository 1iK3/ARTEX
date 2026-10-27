package audit

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ZipLimits bounds safe archive extraction. MaxFiles counts all archive
// entries, including directories. Zero values use the audit source defaults
// (2 GiB, 200000 entries, 10 MiB per file, 100x compression ratio).
type ZipLimits struct {
	MaxFiles            int
	MaxBytes            int64
	MaxFileBytes        int64
	MaxCompressionRatio int
}

const (
	defaultZipMaxFiles            = defaultSourceMaxFiles
	defaultZipMaxBytes            = defaultSourceMaxBytes
	defaultZipMaxFileBytes        = defaultSourceMaxFileBytes
	defaultZipMaxCompressionRatio = 100
	zipRatioGraceBytes            = 1 << 20
)

type zipExtractStats struct {
	Entries int
	Files   int
	Bytes   int64
}

func normalizeZipLimits(limits ZipLimits) ZipLimits {
	if limits.MaxFiles <= 0 {
		limits.MaxFiles = defaultZipMaxFiles
	}
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = defaultZipMaxBytes
	}
	if limits.MaxFileBytes <= 0 {
		limits.MaxFileBytes = defaultZipMaxFileBytes
	}
	if limits.MaxCompressionRatio <= 0 {
		limits.MaxCompressionRatio = defaultZipMaxCompressionRatio
	}
	return limits
}

// ExtractZip safely extracts zipPath into dst. dst must not exist or must be
// empty. Unsafe, duplicate, or over-limit archives fail with an actionable
// error and a best-effort cleanup of the partial destination.
func ExtractZip(zipPath, dst string, limits ZipLimits) error {
	_, err := extractZipCtx(context.Background(), zipPath, dst, limits)
	return err
}

func extractZipCtx(ctx context.Context, zipPath, dst string, limits ZipLimits) (zipExtractStats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zipExtractStats{}, err
	}
	limits = normalizeZipLimits(limits)
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return zipExtractStats{}, fmt.Errorf("open zip: %w", err)
	}
	defer reader.Close()

	dstPath, err := ensureEmptyDir(dst)
	if err != nil {
		return zipExtractStats{}, err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dstPath)
		}
	}()

	seen := make(map[string]byte)
	var stats zipExtractStats

	entriesSinceCheck := 0
	bytesSinceCheck := int64(0)
	for _, entry := range reader.File {
		entriesSinceCheck++
		if entriesSinceCheck >= 200 {
			entriesSinceCheck = 0
			if err := ctx.Err(); err != nil {
				return zipExtractStats{}, err
			}
		}
		stats.Entries++
		if stats.Entries > limits.MaxFiles {
			return zipExtractStats{}, fmt.Errorf("zip exceeds max entries (%d)", limits.MaxFiles)
		}
		rel, isDir, err := safeZipPath(entry)
		if err != nil {
			return zipExtractStats{}, err
		}
		if isDir {
			if rel == "." {
				continue
			}
			if err := checkZipParentFiles(seen, rel); err != nil {
				return zipExtractStats{}, err
			}
			if kind, exists := seen[rel]; exists {
				if kind == 'f' {
					return zipExtractStats{}, fmt.Errorf("zip path conflicts with a file: %s", rel)
				}
				return zipExtractStats{}, fmt.Errorf("zip contains duplicate directory path: %s", rel)
			}
			seen[rel] = 'd'
			target := filepath.Join(dstPath, filepath.FromSlash(rel))
			if !pathWithinRoot(target, dstPath) {
				return zipExtractStats{}, fmt.Errorf("zip path escapes destination: %s", rel)
			}
			if err := ensureZipDir(target, rel); err != nil {
				return zipExtractStats{}, err
			}
			continue
		}

		if rel == "." {
			return zipExtractStats{}, errors.New("zip contains an empty file path")
		}
		if kind, exists := seen[rel]; exists {
			if kind == 'd' {
				return zipExtractStats{}, fmt.Errorf("zip file conflicts with a directory: %s", rel)
			}
			return zipExtractStats{}, fmt.Errorf("zip contains duplicate path: %s", rel)
		}
		if err := checkZipParentFiles(seen, rel); err != nil {
			return zipExtractStats{}, err
		}
		if entry.UncompressedSize64 > uint64(limits.MaxFileBytes) {
			return zipExtractStats{}, fmt.Errorf("zip file exceeds max file bytes (%d): %s", limits.MaxFileBytes, rel)
		}
		declared := int64(entry.UncompressedSize64)
		compressed := int64(entry.CompressedSize64)
		if declared > limits.MaxBytes-stats.Bytes {
			return zipExtractStats{}, fmt.Errorf("zip exceeds max uncompressed bytes (%d) at %s", limits.MaxBytes, rel)
		}
		if err := checkZipCompressionRatio(declared, compressed, limits.MaxCompressionRatio, rel); err != nil {
			return zipExtractStats{}, err
		}

		target := filepath.Join(dstPath, filepath.FromSlash(rel))
		if !pathWithinRoot(target, dstPath) {
			return zipExtractStats{}, fmt.Errorf("zip path escapes destination: %s", rel)
		}
		if err := ensureZipDir(filepath.Dir(target), path.Dir(rel)); err != nil {
			return zipExtractStats{}, err
		}
		if _, err := os.Lstat(target); err == nil {
			return zipExtractStats{}, fmt.Errorf("zip path collides with an existing entry: %s", rel)
		} else if !errors.Is(err, os.ErrNotExist) {
			return zipExtractStats{}, fmt.Errorf("stat zip destination %s: %w", rel, err)
		}

		n, err := extractZipFile(ctx, entry, target, limits.MaxFileBytes, limits.MaxBytes-stats.Bytes)
		if err != nil {
			return zipExtractStats{}, fmt.Errorf("extract zip file %s: %w", rel, err)
		}
		if err := checkZipCompressionRatio(n, compressed, limits.MaxCompressionRatio, rel); err != nil {
			return zipExtractStats{}, err
		}
		seen[rel] = 'f'
		stats.Files++
		stats.Bytes += n
		bytesSinceCheck += n
		if bytesSinceCheck >= auditCopyContextCheckBytes {
			bytesSinceCheck = 0
			if err := ctx.Err(); err != nil {
				return zipExtractStats{}, err
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return zipExtractStats{}, err
	}
	success = true
	return stats, nil
}

func safeZipPath(entry *zip.File) (string, bool, error) {
	rawName := entry.Name
	if rawName == "" {
		return "", false, errors.New("zip contains an entry with an empty name")
	}
	for _, r := range rawName {
		if r == 0 || r < 0x20 || r == 0x7f {
			return "", false, fmt.Errorf("zip path contains a control character: %q", rawName)
		}
	}
	if strings.Contains(rawName, `\`) {
		return "", false, fmt.Errorf("zip path contains a backslash: %q", rawName)
	}
	if strings.HasPrefix(rawName, "/") {
		return "", false, fmt.Errorf("zip path is absolute: %q", rawName)
	}
	if len(rawName) >= 2 && rawName[1] == ':' {
		return "", false, fmt.Errorf("zip path contains a drive letter: %q", rawName)
	}
	if strings.Contains(rawName, ":") {
		return "", false, fmt.Errorf("zip path contains a colon: %q", rawName)
	}

	cleaned := path.Clean(rawName)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false, fmt.Errorf("zip path escapes destination: %q", rawName)
	}
	for _, segment := range strings.Split(rawName, "/") {
		if segment == ".." {
			return "", false, fmt.Errorf("zip path contains ..: %q", rawName)
		}
		if segment == "" || segment == "." {
			continue
		}
		if strings.HasSuffix(segment, " ") || strings.HasSuffix(segment, ".") {
			return "", false, fmt.Errorf("zip path segment has a trailing dot or space: %q", rawName)
		}
		if isWindowsReservedZipSegment(segment) {
			return "", false, fmt.Errorf("zip path uses a reserved device name: %q", rawName)
		}
	}
	if path.IsAbs(cleaned) {
		return "", false, fmt.Errorf("zip path is absolute: %q", rawName)
	}
	if filepath.IsAbs(filepath.FromSlash(cleaned)) {
		return "", false, fmt.Errorf("zip path is absolute: %q", rawName)
	}

	isDir := entry.FileInfo().IsDir() || strings.HasSuffix(rawName, "/")
	mode := entry.Mode()
	if mode&os.ModeSymlink != 0 {
		return "", false, fmt.Errorf("zip contains a symlink: %q", rawName)
	}
	if !isDir {
		if mode&os.ModeNamedPipe != 0 || mode&os.ModeSocket != 0 || mode&os.ModeDevice != 0 || mode&os.ModeCharDevice != 0 || mode&os.ModeIrregular != 0 {
			return "", false, fmt.Errorf("zip contains a non-regular file: %q", rawName)
		}
	}
	return cleaned, isDir, nil
}

func checkZipParentFiles(seen map[string]byte, rel string) error {
	parent := path.Dir(rel)
	for parent != "." && parent != "/" {
		if seen[parent] == 'f' {
			return fmt.Errorf("zip path traverses a file: %s", rel)
		}
		next := path.Dir(parent)
		if next == parent {
			break
		}
		parent = next
	}
	return nil
}

func ensureZipDir(target, rel string) error {
	info, err := os.Lstat(target)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("zip destination contains a symlink: %s", rel)
		}
		if !info.IsDir() {
			return fmt.Errorf("zip path conflicts with a file: %s", rel)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat zip directory %s: %w", rel, err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("create zip directory %s: %w", rel, err)
	}
	return nil
}

func checkZipCompressionRatio(uncompressed, compressed int64, maxRatio int, rel string) error {
	if uncompressed <= zipRatioGraceBytes {
		return nil
	}
	if compressed <= 0 {
		return fmt.Errorf("zip compression ratio is unbounded: %s", rel)
	}
	if float64(uncompressed)/float64(compressed) > float64(maxRatio) {
		return fmt.Errorf("zip compression ratio exceeds %dx: %s", maxRatio, rel)
	}
	return nil
}

func extractZipFile(ctx context.Context, entry *zip.File, target string, maxFileBytes, remainingBytes int64) (int64, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
	input, err := entry.Open()
	if err != nil {
		return 0, err
	}
	defer input.Close()

	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		_ = output.Close()
		if !committed {
			_ = os.Remove(target)
		}
	}()

	if remainingBytes < 0 {
		remainingBytes = 0
	}
	allowed := maxFileBytes
	if remainingBytes < allowed {
		allowed = remainingBytes
	}
	n, err := io.Copy(output, io.LimitReader(&auditContextReader{ctx: ctx, reader: input}, allowed+1))
	if err != nil {
		return 0, err
	}
	if n > maxFileBytes {
		return 0, fmt.Errorf("file exceeds max file bytes (%d)", maxFileBytes)
	}
	if n > remainingBytes {
		return 0, fmt.Errorf("zip exceeds max uncompressed bytes")
	}
	if err := output.Close(); err != nil {
		return 0, err
	}
	committed = true
	return n, nil
}

var windowsReservedZipNames = map[string]struct{}{
	"con": {}, "prn": {}, "aux": {}, "nul": {},
	"conin$": {}, "conout$": {},
	"com1": {}, "com2": {}, "com3": {}, "com4": {}, "com5": {},
	"com6": {}, "com7": {}, "com8": {}, "com9": {},
	"lpt1": {}, "lpt2": {}, "lpt3": {}, "lpt4": {}, "lpt5": {},
	"lpt6": {}, "lpt7": {}, "lpt8": {}, "lpt9": {},
}

func isWindowsReservedZipSegment(segment string) bool {
	trimmed := strings.TrimRight(segment, " .")
	lower := strings.ToLower(trimmed)
	base := lower
	if idx := strings.IndexByte(base, '.'); idx >= 0 {
		base = base[:idx]
	}
	_, reserved := windowsReservedZipNames[base]
	return reserved
}
