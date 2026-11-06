package engines

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/audit"
)

const (
	maxCommandOutputBytes = 8 << 20
	maxErrorOutputBytes   = 2 << 10
)

var (
	semverPattern = regexp.MustCompile(`\b[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.-]+)?\b`)

	engineWindowsPathPattern  = regexp.MustCompile(`(?i)\b[A-Z]:[\\/][^\s"'<>|]*`)
	engineUNCPathPattern      = regexp.MustCompile(`\\\\[^\s"'<>|]+`)
	engineUnixPathPattern     = regexp.MustCompile(`(?:^|[\s"'(=,])(/[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)*)`)
	engineURLUserInfoPattern  = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@`)
	engineUserPassPattern     = regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+-]+:[^\s/@]+@`)
	engineBearerPattern       = regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{10,}`)
	engineSecretAssignPattern = regexp.MustCompile(
		`(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|passwd|authorization|account[_-]?key|sas[_-]?token)\b(\s*[:=]\s*)(["']?)[^\s"',;}]{6,}`,
	)
	engineKnownSecretPattern = regexp.MustCompile(
		`\b(gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b`,
	)
	enginePrivateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
)

// RedactEngineText removes absolute host paths from engine error text before
// it crosses the package boundary. This is defense-in-depth: the server also
// redacts known roots, but adapters must not leak a user profile, temp
// directory, pack cache, or engine installation path in JobResult.Error.
func RedactEngineText(value string) string {
	if value == "" {
		return ""
	}
	value = engineWindowsPathPattern.ReplaceAllString(value, "[redacted-path]")
	value = engineUNCPathPattern.ReplaceAllString(value, "[redacted-path]")
	value = engineUnixPathPattern.ReplaceAllStringFunc(value, func(match string) string {
		index := strings.Index(match, "/")
		if index < 0 {
			return match
		}
		return match[:index] + "[redacted-path]"
	})
	for _, root := range []string{os.TempDir(), os.Getenv("JAVA_HOME")} {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		for _, variant := range []string{root, filepath.ToSlash(root), strings.ReplaceAll(root, `\`, `\\`)} {
			if variant != "" {
				value = strings.ReplaceAll(value, variant, "[redacted-path]")
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		for _, variant := range []string{home, filepath.ToSlash(home), strings.ReplaceAll(home, `\`, `\\`)} {
			if variant != "" {
				value = strings.ReplaceAll(value, variant, "[redacted-path]")
			}
		}
	}
	value = enginePrivateKeyPattern.ReplaceAllString(value, `[REDACTED-PRIVATE-KEY]`)
	value = engineURLUserInfoPattern.ReplaceAllString(value, `${1}[redacted]@`)
	value = engineUserPassPattern.ReplaceAllString(value, `[redacted]@`)
	value = engineBearerPattern.ReplaceAllString(value, `${1}[REDACTED]`)
	value = engineSecretAssignPattern.ReplaceAllString(value, `${1}${2}${3}[REDACTED]`)
	value = engineKnownSecretPattern.ReplaceAllString(value, `[REDACTED]`)
	return value
}

type redactedEngineError struct {
	message string
	cause   error
}

func (e *redactedEngineError) Error() string { return e.message }
func (e *redactedEngineError) Unwrap() error { return e.cause }

func redactEngineError(err error) error {
	if err == nil {
		return nil
	}
	return &redactedEngineError{message: RedactEngineText(err.Error()), cause: err}
}

func redactEngineMessages(messages []string) []string {
	if len(messages) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(messages))
	for _, message := range messages {
		message = strings.TrimSpace(RedactEngineText(message))
		if message != "" {
			out = append(out, message)
		}
	}
	return out
}

func redactEngineMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = RedactEngineText(value)
	}
	return out
}

// limitedBuffer keeps process output bounded while still accepting writes so
// the child process is not blocked by a full pipe.
type limitedBuffer struct {
	buf       bytes.Buffer
	remaining int
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{remaining: limit}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
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

func (b *limitedBuffer) String() string {
	return b.buf.String()
}

func runExec(ctx context.Context, name string, args []string, dir string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	stdout := newLimitedBuffer(maxCommandOutputBytes)
	stderr := newLimitedBuffer(maxCommandOutputBytes)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func executeCommand(ctx context.Context, fn ExecFunc, name string, args []string, dir string, timeout time.Duration) (string, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if fn != nil {
		return fn(ctx, name, args, dir)
	}
	return runExec(ctx, name, args, dir)
}

// classifyExecError maps a process error to a sentinel the manager and server
// can reason about. stderr is retained (bounded) because CodeQL and Joern put
// their useful diagnostics there.
func classifyExecError(ctx context.Context, err error, stderr string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return redactEngineError(fmt.Errorf("%w: %v", ErrUnavailable, err))
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		(ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return redactEngineError(fmt.Errorf("%w: %v", ErrTimeout, err))
	}
	message := strings.TrimSpace(stderr)
	if message != "" {
		return redactEngineError(fmt.Errorf("%w: %s", err, RedactEngineText(truncateForError(message))))
	}
	return redactEngineError(err)
}

func isBinaryMissing(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist)
}

func parseEngineVersion(output string) string {
	return semverPattern.FindString(output)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func truncateForError(value string) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) <= maxErrorOutputBytes {
		return string(runes)
	}
	return string(runes[:maxErrorOutputBytes]) + "..."
}

// safeEngineID reduces an arbitrary query or intent ID to a single filesystem
// component. It never contains a path separator, leading dot, or traversal.
func safeEngineID(id string) string {
	var out strings.Builder
	for _, r := range strings.TrimSpace(id) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == '-', r == '_', r == '.':
			out.WriteRune(r)
		default:
			out.WriteByte('_')
		}
		if out.Len() >= 80 {
			break
		}
	}
	cleaned := strings.Trim(out.String(), "._-")
	if cleaned == "" {
		return "query"
	}
	// Windows reserves device names even with extensions and in subdirectories.
	deviceName := strings.ToLower(cleaned)
	if index := strings.IndexByte(deviceName, '.'); index >= 0 {
		deviceName = deviceName[:index]
	}
	switch deviceName {
	case "con", "prn", "aux", "nul",
		"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
		"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9":
		cleaned = "_" + cleaned
	}
	return cleaned
}

// safeJoin joins elements beneath base and rejects any result that escapes
// base. base must be non-empty.
func safeJoin(base string, elements ...string) (string, error) {
	if strings.TrimSpace(base) == "" {
		return "", errors.New("engine work directory is required")
	}
	absoluteBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolve engine work directory: %w", err)
	}
	parts := make([]string, 0, len(elements)+1)
	parts = append(parts, absoluteBase)
	parts = append(parts, elements...)
	candidate := filepath.Join(parts...)
	relative, err := filepath.Rel(absoluteBase, candidate)
	if err != nil {
		return "", fmt.Errorf("check engine path: %w", err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("engine path escapes work directory: %s", candidate)
	}
	return candidate, nil
}

func engineWorkDir(primary, fallback string) string {
	return firstNonEmpty(primary, fallback)
}

func ensureDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create engine directory: %w", err)
	}
	return nil
}

func normalizeLanguageList(languages []string) []string {
	out := make([]string, 0, len(languages))
	seen := make(map[string]struct{}, len(languages))
	for _, raw := range languages {
		language := normalizeIntentLanguage(raw)
		if language == "" {
			continue
		}
		if _, exists := seen[language]; exists {
			continue
		}
		seen[language] = struct{}{}
		out = append(out, language)
	}
	return out
}

func languageSupported(capabilityLanguages []string, language string) bool {
	if len(capabilityLanguages) == 0 {
		return true
	}
	canonical := normalizeIntentLanguage(language)
	if canonical == "" {
		return false
	}
	for _, raw := range capabilityLanguages {
		supported := normalizeIntentLanguage(raw)
		if supported == canonical {
			return true
		}
		if (canonical == audit.TypeScript && supported == audit.JavaScript) ||
			(canonical == audit.JavaScript && supported == audit.TypeScript) {
			return true
		}
	}
	return false
}

func filterSupportedLanguages(capabilityLanguages, languages []string) []string {
	normalized := normalizeLanguageList(languages)
	out := make([]string, 0, len(normalized))
	for _, language := range normalized {
		if languageSupported(capabilityLanguages, language) {
			out = append(out, language)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func copyStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func copyPrepared(prepared Prepared) Prepared {
	clone := prepared
	clone.Languages = append([]string(nil), prepared.Languages...)
	clone.Paths = copyStringMap(prepared.Paths)
	clone.BuildModes = copyStringMap(prepared.BuildModes)
	clone.Unsupported = copyStringMap(prepared.Unsupported)
	clone.Warnings = append([]string(nil), prepared.Warnings...)
	return clone
}
