package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Audit source types (tasks.audit_config.source_type).
const (
	SourceGit   = "git"
	SourceLocal = "local"
	SourceZip   = "zip"
)

// Audit depth levels. Depth controls the default round budget and whether the
// CodeGraph structural backend may be disabled.
const (
	DepthQuick    = "quick"
	DepthStandard = "standard"
	DepthDeep     = "deep"
)

// CWE scope values (tasks.audit_config.cwe_scope).
const (
	CWEScopeCore     = "core"
	CWEScopeFull     = "full"
	CWEScopeExplicit = "explicit"
)

// Engine names understood by the audit director.
const (
	EngineCodeGraph = "codegraph"
	EngineCodeQL    = "codeql"
	EngineJoern     = "joern"
)

const (
	minAuditRounds = 1
	maxAuditRounds = 10
)

var cweIDPattern = regexp.MustCompile(`^CWE-[0-9]+$`)

// Config is the frozen, create-time configuration of a code-audit task. It is
// stored verbatim in tasks.audit_config and consumed by the audit director.
type Config struct {
	SourceType    string            `json:"source_type"` // git|local|zip
	RepoURL       string            `json:"repo_url,omitempty"`
	Ref           string            `json:"ref,omitempty"`
	LocalPath     string            `json:"local_path,omitempty"`
	UploadID      string            `json:"upload_id,omitempty"`
	Depth         string            `json:"depth"`     // quick|standard|deep
	CWEScope      string            `json:"cwe_scope"` // core|full|explicit
	CWEIDs        []string          `json:"cwe_ids,omitempty"`
	Languages     []string          `json:"languages,omitempty"`
	MaxRounds     int               `json:"max_rounds"`
	Engines       map[string]string `json:"engines,omitempty"` // codegraph: required|auto|off; codeql,joern: auto|off
	Budgets       map[string]any    `json:"budgets,omitempty"`
	IncludeTests  bool              `json:"include_tests,omitempty"`
	IncludeVendor bool              `json:"include_vendor,omitempty"`
}

// DefaultConfig returns the default audit configuration for a depth. An empty
// or unknown depth falls back to deep so callers always get a usable config.
func DefaultConfig(depth string) Config {
	depth = normalizeDepthValue(depth)
	if !validDepth(depth) {
		depth = DepthDeep
	}
	return Config{
		Depth:     depth,
		CWEScope:  CWEScopeCore,
		MaxRounds: roundsForDepth(depth),
		Engines:   defaultEngines(),
	}
}

// NormalizeConfig fills defaults and canonicalizes a config. It is idempotent.
//
// Unknown languages are intentionally retained as trimmed lowercase strings:
// the design allows unsupported languages to create a task that records an
// explicit "language not supported" coverage gap rather than failing creation.
// Recognized language aliases are mapped to their canonical identifier by
// NormalizeLanguage and duplicates are removed while preserving first-seen
// order.
func NormalizeConfig(c Config) Config {
	c.SourceType = strings.ToLower(strings.TrimSpace(c.SourceType))
	c.RepoURL = strings.TrimSpace(c.RepoURL)
	c.Ref = strings.TrimSpace(c.Ref)
	c.LocalPath = strings.TrimSpace(c.LocalPath)
	c.UploadID = strings.TrimSpace(c.UploadID)

	c.Depth = normalizeDepthValue(c.Depth)
	if c.Depth == "" {
		c.Depth = DepthDeep
	}

	c.CWEScope = strings.ToLower(strings.TrimSpace(c.CWEScope))
	if c.CWEScope == "" {
		c.CWEScope = CWEScopeCore
	}

	if c.MaxRounds == 0 {
		c.MaxRounds = roundsForDepth(c.Depth)
	}

	c.CWEIDs = normalizeCWEIDs(c.CWEIDs)
	c.Languages = normalizeLanguages(c.Languages)
	c.Engines = normalizeEngines(c.Engines)
	if c.Budgets != nil {
		budgets := make(map[string]any, len(c.Budgets))
		for name, value := range c.Budgets {
			budgets[name] = value
		}
		c.Budgets = budgets
	}
	return c
}

// ValidateConfig validates an audit config. The config is normalized first, so
// callers may pass a partially populated config (for example only source_type)
// and receive depth/round/engine defaults. Allowed local roots are matched
// lexically against the absolute, cleaned local path; the ingest stage must
// still resolve symlinks before reading files.
func ValidateConfig(c Config, allowedLocalRoots []string) error {
	c = NormalizeConfig(c)

	switch c.SourceType {
	case "":
		return errors.New("source_type 必填（git|local|zip）")
	case SourceGit:
		if err := validateGitRepoURL(c.RepoURL); err != nil {
			return err
		}
	case SourceLocal:
		if err := validateLocalPath(c.LocalPath, allowedLocalRoots); err != nil {
			return err
		}
	case SourceZip:
		if c.UploadID == "" {
			return errors.New("zip 审计必须提供 upload_id")
		}
	default:
		return fmt.Errorf("不支持的 source_type %q（必须是 git|local|zip）", c.SourceType)
	}

	if !validDepth(c.Depth) {
		return fmt.Errorf("无效的 depth %q（quick|standard|deep）", c.Depth)
	}

	switch c.CWEScope {
	case CWEScopeCore, CWEScopeFull:
	case CWEScopeExplicit:
		if len(c.CWEIDs) == 0 {
			return errors.New("cwe_scope=explicit 时必须提供 cwe_ids")
		}
		for _, id := range c.CWEIDs {
			if !cweIDPattern.MatchString(id) {
				return fmt.Errorf("无效的 CWE 编号 %q（应形如 CWE-89）", id)
			}
		}
	default:
		return fmt.Errorf("无效的 cwe_scope %q（core|full|explicit）", c.CWEScope)
	}

	if c.MaxRounds < minAuditRounds || c.MaxRounds > maxAuditRounds {
		return fmt.Errorf("max_rounds 必须在 %d..%d 之间", minAuditRounds, maxAuditRounds)
	}

	for name, value := range c.Engines {
		var allowed string
		switch name {
		case EngineCodeGraph:
			allowed = "required|auto|off"
		case EngineCodeQL, EngineJoern:
			// CodeQL/Joern are optional enrichment engines; only CodeGraph is a
			// required structural-analysis base (for deep audits).
			allowed = "auto|off"
		default:
			return fmt.Errorf("未知的审计引擎 %q", name)
		}
		if value != "auto" && value != "off" && !(name == EngineCodeGraph && value == "required") {
			return fmt.Errorf("无效的 %s 引擎配置 %q（%s）", name, value, allowed)
		}
	}

	if c.Depth == DepthDeep && c.Engines[EngineCodeGraph] == "off" {
		return errors.New("depth=deep 时 engines.codegraph 不能为 off")
	}

	for name, value := range c.Budgets {
		if err := validateBudgetValue(name, value); err != nil {
			return err
		}
	}
	return nil
}

func normalizeDepthValue(depth string) string {
	return strings.ToLower(strings.TrimSpace(depth))
}

func validDepth(depth string) bool {
	switch depth {
	case DepthQuick, DepthStandard, DepthDeep:
		return true
	}
	return false
}

func roundsForDepth(depth string) int {
	switch depth {
	case DepthQuick:
		return 1
	case DepthStandard:
		return 3
	default:
		return 5
	}
}

func defaultEngines() map[string]string {
	return map[string]string{
		EngineCodeGraph: "required",
		EngineCodeQL:    "auto",
		EngineJoern:     "auto",
	}
}

func normalizeEngines(engines map[string]string) map[string]string {
	out := defaultEngines()
	for rawName, rawValue := range engines {
		name := strings.ToLower(strings.TrimSpace(rawName))
		value := strings.ToLower(strings.TrimSpace(rawValue))
		if value == "" {
			switch name {
			case EngineCodeGraph, EngineCodeQL, EngineJoern:
				// Empty value for a known engine means "use the default".
				continue
			}
			// Preserve unknown names so ValidateConfig can reject them even
			// when their value was empty.
		}
		out[name] = value
	}
	return out
}

func normalizeCWEIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func normalizeLanguages(languages []string) []string {
	if len(languages) == 0 {
		return nil
	}
	out := make([]string, 0, len(languages))
	seen := make(map[string]struct{}, len(languages))
	for _, language := range languages {
		language = strings.TrimSpace(language)
		if language == "" {
			continue
		}
		canonical := NormalizeLanguage(language)
		if canonical == "" {
			canonical = strings.ToLower(language)
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out
}

// containsUserInfoControl reports whether decoded URL userinfo contains a
// control character. Encoded controls are rejected before the value reaches
// git, which could otherwise decode them into a credential or option-like
// username.
func containsUserInfoControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func validateGitRepoURL(repoURL string) error {
	if repoURL == "" {
		return errors.New("git 审计必须提供 repo_url")
	}
	if strings.ContainsAny(repoURL, " \t\r\n") {
		return errors.New("git 仓库 URL 不能包含空白字符")
	}
	lower := strings.ToLower(repoURL)
	switch {
	case strings.HasPrefix(lower, "file://"):
		return errors.New("git 仓库只允许 https 或 ssh（禁止 file://）")
	case strings.HasPrefix(lower, "ext::"):
		return errors.New("git 仓库只允许 https 或 ssh（禁止 ext::）")
	}
	if strings.Contains(lower, "://") {
		if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "ssh://") {
			return errors.New("git 仓库只允许 https 或 ssh")
		}
		parsed, err := url.Parse(repoURL)
		if err != nil {
			return fmt.Errorf("git 仓库 URL 无效: %w", err)
		}
		if parsed.Hostname() == "" {
			return errors.New("git 仓库 URL 缺少主机名")
		}
		if parsed.User != nil {
			decodedUserInfo, err := url.PathUnescape(parsed.User.String())
			if err != nil {
				return errors.New("git 仓库 URL 的用户信息编码无效")
			}
			if _, hasPassword := parsed.User.Password(); hasPassword || strings.Contains(decodedUserInfo, ":") {
				return errors.New("git 仓库 URL 不得包含用户名密码凭据")
			}
			if strings.Contains(decodedUserInfo, "@") || containsUserInfoControl(decodedUserInfo) {
				return errors.New("git 仓库 URL 的用户信息包含非法字符")
			}
			if strings.HasPrefix(lower, "https://") {
				return errors.New("git 仓库 URL 不得包含凭据")
			}
			// ssh://git@host/repo is the standard SSH form, so a bare user is
			// allowed there. Credential material must come from ssh-agent.
		}
		return nil
	}
	// scp-like syntax: user@host:path or host:path.
	return validateSCPLikeRepoURL(repoURL)
}

// validateSCPLikeRepoURL validates the scp-like git URL form that Task 8 will
// hand to git. It rejects option injection (leading "-"), credential-shaped
// userinfo (literal or percent-encoded ":" / "@" / controls), multiple "@"
// separators, empty hosts/paths, and malformed hostnames.
func validateSCPLikeRepoURL(repoURL string) error {
	if strings.HasPrefix(repoURL, "-") {
		return errors.New("git 仓库地址不能以 - 开头")
	}
	// A Windows drive path (C:\repo, C:/repo, C:repo) is source_type=local, not
	// a git remote. Reject it before scp parsing mistakes "C" for a host.
	if len(repoURL) >= 2 && repoURL[1] == ':' &&
		((repoURL[0] >= 'a' && repoURL[0] <= 'z') || (repoURL[0] >= 'A' && repoURL[0] <= 'Z')) {
		return errors.New("git 仓库地址不能使用本地文件路径（本地源码请使用 source_type=local）")
	}
	rest := repoURL
	if at := strings.IndexByte(repoURL, '@'); at >= 0 {
		userinfo := repoURL[:at]
		if userinfo == "" {
			return errors.New("git 仓库 scp 地址缺少用户名")
		}
		decodedUserInfo, err := url.PathUnescape(userinfo)
		if err != nil {
			return errors.New("git 仓库 scp 地址的用户信息编码无效")
		}
		if strings.Contains(decodedUserInfo, ":") {
			return errors.New("git 仓库 scp 地址的用户信息不得包含凭据")
		}
		if strings.Contains(decodedUserInfo, "@") || containsUserInfoControl(decodedUserInfo) || strings.ContainsAny(decodedUserInfo, `/\`) {
			return errors.New("git 仓库 scp 地址格式无效")
		}
		rest = repoURL[at+1:]
		if rest == "" || strings.Contains(rest, "@") {
			return errors.New("git 仓库 scp 地址格式无效")
		}
	}
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return errors.New("git 仓库只允许 https 或 ssh")
	}
	host := rest[:colon]
	repoPath := rest[colon+1:]
	if host == "" || repoPath == "" || !validSCPLikeHost(host) {
		return errors.New("git 仓库 scp 地址缺少有效主机名或路径")
	}
	return nil
}

func validSCPLikeHost(host string) bool {
	if host == "" || len(host) > 253 || strings.HasPrefix(host, "-") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return false
			}
		}
	}
	return true
}

func validateLocalPath(localPath string, allowedRoots []string) error {
	if localPath == "" {
		return errors.New("local 审计必须提供 local_path")
	}
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		return fmt.Errorf("local_path 无法解析为绝对路径: %w", err)
	}
	absPath = filepath.Clean(absPath)

	roots := make([]string, 0, len(allowedRoots))
	for _, root := range allowedRoots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		absRoot, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		roots = append(roots, filepath.Clean(absRoot))
	}
	if len(roots) == 0 {
		return errors.New("未配置本地审计根目录（请设置 ARTEX_AUDIT_LOCAL_ROOTS）")
	}
	for _, root := range roots {
		if pathWithinRoot(absPath, root) {
			return nil
		}
	}
	return fmt.Errorf("本地目录不在允许范围: %s", absPath)
}

// pathWithinRoot reports whether path is lexically inside root (or equal to it).
func pathWithinRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func validateBudgetValue(name string, value any) error {
	var number float64
	switch n := value.(type) {
	case int:
		number = float64(n)
	case int8:
		number = float64(n)
	case int16:
		number = float64(n)
	case int32:
		number = float64(n)
	case int64:
		number = float64(n)
	case uint:
		number = float64(n)
	case uint8:
		number = float64(n)
	case uint16:
		number = float64(n)
	case uint32:
		number = float64(n)
	case uint64:
		number = float64(n)
	case float32:
		number = float64(n)
	case float64:
		number = n
	case json.Number:
		parsed, err := n.Float64()
		if err != nil {
			return fmt.Errorf("budget %q 必须是数字", name)
		}
		number = parsed
	default:
		return fmt.Errorf("budget %q 必须是数字", name)
	}
	if math.IsNaN(number) || math.IsInf(number, 0) || number < 0 {
		return fmt.Errorf("budget %q 必须是非负数字", name)
	}
	return nil
}
