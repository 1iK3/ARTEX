package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cases := []struct {
		depth string
		want  string
		round int
	}{
		{"quick", DepthQuick, 1},
		{" standard ", DepthStandard, 3},
		{"deep", DepthDeep, 5},
		{"", DepthDeep, 5},
		{"unknown", DepthDeep, 5},
	}
	for _, tc := range cases {
		cfg := DefaultConfig(tc.depth)
		if cfg.Depth != tc.want {
			t.Errorf("DefaultConfig(%q).Depth = %q, want %q", tc.depth, cfg.Depth, tc.want)
		}
		if cfg.MaxRounds != tc.round {
			t.Errorf("DefaultConfig(%q).MaxRounds = %d, want %d", tc.depth, cfg.MaxRounds, tc.round)
		}
		if cfg.CWEScope != CWEScopeCore {
			t.Errorf("DefaultConfig(%q).CWEScope = %q, want %q", tc.depth, cfg.CWEScope, CWEScopeCore)
		}
		wantEngines := map[string]string{EngineCodeGraph: "required", EngineCodeQL: "auto", EngineJoern: "auto"}
		for name, want := range wantEngines {
			if got := cfg.Engines[name]; got != want {
				t.Errorf("DefaultConfig(%q).Engines[%q] = %q, want %q", tc.depth, name, got, want)
			}
		}
	}
}

func TestNormalizeConfigFillsAndCanonicalizes(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SourceType: " GIT ",
		RepoURL:    "  https://example.com/repo.git  ",
		CWEIDs:     []string{" cwe-89 ", "CWE-89", "", "CWE-78"},
		Languages:  []string{"JS", "node", "Kotlin", "kotlin", "PY", ""},
		Engines:    map[string]string{"CodeGraph": " OFF ", "future": "auto", "joern": ""},
		Budgets:    map[string]any{"max_workers": 3.0},
	})
	if cfg.SourceType != SourceGit {
		t.Fatalf("SourceType = %q, want %q", cfg.SourceType, SourceGit)
	}
	if cfg.RepoURL != "https://example.com/repo.git" {
		t.Fatalf("RepoURL = %q", cfg.RepoURL)
	}
	if cfg.Depth != DepthDeep || cfg.CWEScope != CWEScopeCore || cfg.MaxRounds != 5 {
		t.Fatalf("defaults not filled: depth=%q scope=%q rounds=%d", cfg.Depth, cfg.CWEScope, cfg.MaxRounds)
	}
	if got, want := strings.Join(cfg.CWEIDs, ","), "CWE-89,CWE-78"; got != want {
		t.Fatalf("CWEIDs = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.Languages, ","), "javascript,kotlin,python"; got != want {
		t.Fatalf("Languages = %q, want %q", got, want)
	}
	if cfg.Engines[EngineCodeGraph] != "off" || cfg.Engines[EngineCodeQL] != "auto" ||
		cfg.Engines[EngineJoern] != "auto" || cfg.Engines["future"] != "auto" {
		t.Fatalf("Engines = %#v", cfg.Engines)
	}

	// Normalization must not alias caller-owned collections.
	original := Config{
		CWEIDs:    []string{"CWE-89"},
		Languages: []string{"java"},
		Engines:   map[string]string{EngineCodeQL: "off"},
		Budgets:   map[string]any{"max_workers": 1},
	}
	normalized := NormalizeConfig(original)
	original.CWEIDs[0] = "CWE-999"
	original.Languages[0] = "rust"
	original.Engines[EngineCodeQL] = "required"
	original.Budgets["max_workers"] = 9
	if normalized.CWEIDs[0] != "CWE-89" || normalized.Languages[0] != "java" ||
		normalized.Engines[EngineCodeQL] != "off" || normalized.Budgets["max_workers"] != 1 {
		t.Fatalf("NormalizeConfig aliased input: %+v", normalized)
	}
}

func TestNormalizeConfigRoundDefaults(t *testing.T) {
	for depth, want := range map[string]int{DepthQuick: 1, DepthStandard: 3, DepthDeep: 5} {
		cfg := NormalizeConfig(Config{Depth: depth})
		if cfg.MaxRounds != want {
			t.Errorf("depth %q default rounds = %d, want %d", depth, cfg.MaxRounds, want)
		}
	}
	// An explicit round budget is preserved.
	if got := NormalizeConfig(Config{Depth: DepthDeep, MaxRounds: 2}).MaxRounds; got != 2 {
		t.Fatalf("explicit MaxRounds = %d, want 2", got)
	}
	if got := NormalizeConfig(NormalizeConfig(Config{Depth: DepthQuick})).MaxRounds; got != 1 {
		t.Fatalf("normalization is not idempotent: %d", got)
	}
}

func TestNormalizeAuditWorkerConfig(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SourceType: SourceZip,
		UploadID:   "u",
		Worker: &WorkerConfig{
			Backend: " codex ",
			Mode:    " privileged ",
			Command: "codex",
			Args:    []string{"exec", "--input", "{{input_file}}", "--output-schema", "{{schema_file}}", "--output", "{{output_file}}"},
		},
	})
	if cfg.Worker == nil {
		t.Fatalf("Worker = nil, want normalized config")
	}
	if cfg.Worker.Backend != WorkerBackendCodex || cfg.Worker.Mode != WorkerModePrivileged {
		t.Fatalf("Worker backend/mode = %q/%q, want codex/privileged", cfg.Worker.Backend, cfg.Worker.Mode)
	}
	if cfg.Worker.TimeoutSeconds != DefaultWorkerTimeoutSeconds {
		t.Fatalf("TimeoutSeconds = %d, want %d", cfg.Worker.TimeoutSeconds, DefaultWorkerTimeoutSeconds)
	}
	if cfg.Worker.Cwd != WorkerCwdWorkspace {
		t.Fatalf("Cwd = %q, want %q", cfg.Worker.Cwd, WorkerCwdWorkspace)
	}
}

func TestValidateAuditWorkerConfig(t *testing.T) {
	base := func(worker *WorkerConfig) Config {
		return Config{SourceType: SourceZip, UploadID: "u", Worker: worker}
	}
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"nil worker", base(nil), ""},
		{"builtin", base(&WorkerConfig{Backend: WorkerBackendBuiltin}), ""},
		{"privileged codex", base(&WorkerConfig{
			Backend: WorkerBackendCodex,
			Mode:    WorkerModePrivileged,
			Command: "codex",
			Args:    []string{"exec", "--output-schema", "{{schema_file}}", "{{input_file}}"},
		}), ""},
		{"unknown backend", base(&WorkerConfig{Backend: "semgrep", Command: "x", Args: []string{"{{input_file}}"}}), "未知的 worker backend"},
		{"invalid mode", base(&WorkerConfig{Backend: WorkerBackendCodex, Mode: "auto", Command: "x", Args: []string{"{{input_file}}"}}), "无效的 worker mode"},
		{"builtin command", base(&WorkerConfig{Backend: WorkerBackendBuiltin, Command: "x", Args: []string{"{{input_file}}"}}), "builtin worker 不支持 command"},
		{"missing command", base(&WorkerConfig{Backend: WorkerBackendCodex, Args: []string{"{{input_file}}"}}), "worker command 必填"},
		{"missing args", base(&WorkerConfig{Backend: WorkerBackendCodex, Command: "x"}), "worker args 必填"},
		{"unsupported placeholder", base(&WorkerConfig{Backend: WorkerBackendCodex, Command: "x", Args: []string{"{{goal}}"}}), "不支持的 worker 占位符"},
		{"negative timeout", base(&WorkerConfig{Backend: WorkerBackendCodex, Command: "x", Args: []string{"{{input_file}}"}, TimeoutSeconds: -1}), "worker timeout_seconds"},
		{"timeout too high", base(&WorkerConfig{Backend: WorkerBackendCodex, Command: "x", Args: []string{"{{input_file}}"}, TimeoutSeconds: MaxWorkerTimeoutSeconds + 1}), "worker timeout_seconds"},
		{"empty env key", base(&WorkerConfig{Backend: WorkerBackendCodex, Command: "x", Args: []string{"{{input_file}}"}, Env: map[string]string{"": "v"}}), "worker env key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConfig(tc.cfg, nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateConfig() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateConfig() = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestValidateConfigValid(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "project", "src")
	outside := filepath.Join(root, "..", "outside-project")

	cases := []struct {
		name  string
		cfg   Config
		roots []string
	}{
		{"https git", Config{SourceType: SourceGit, RepoURL: "https://example.com/a.git", Depth: DepthDeep, MaxRounds: 5}, nil},
		{"ssh git", Config{SourceType: SourceGit, RepoURL: "ssh://git@example.com/a.git", Depth: DepthStandard}, nil},
		{"scp-like git", Config{SourceType: SourceGit, RepoURL: "git@github.com:org/repo.git", Depth: DepthQuick}, nil},
		{"git defaults", Config{SourceType: SourceGit, RepoURL: "https://example.com/a.git"}, nil},
		{"local inside", Config{SourceType: SourceLocal, LocalPath: inside, Depth: DepthDeep}, []string{root}},
		{"local equals root", Config{SourceType: SourceLocal, LocalPath: root}, []string{root}},
		{"local relative traversal stays inside", Config{SourceType: SourceLocal, LocalPath: filepath.Join(root, "a", "..", "b")}, []string{root}},
		{"zip", Config{SourceType: SourceZip, UploadID: "stage-123", Depth: DepthQuick}, nil},
		{"explicit cwes", Config{
			SourceType: SourceGit, RepoURL: "https://example.com/a.git", Depth: DepthStandard,
			CWEScope: CWEScopeExplicit, CWEIDs: []string{"CWE-89", "cwe-78", "CWE-89"},
		}, nil},
		{"unknown language allowed", Config{
			SourceType: SourceZip, UploadID: "u", Languages: []string{"Kotlin"},
		}, nil},
		{"non-deep codegraph off", Config{
			SourceType: SourceZip, UploadID: "u", Depth: DepthStandard,
			Engines: map[string]string{EngineCodeGraph: "off"},
		}, nil},
		{"codeql and joern off", Config{
			SourceType: SourceZip, UploadID: "u", Depth: DepthDeep,
			Engines: map[string]string{EngineCodeQL: "off", EngineJoern: "off"},
		}, nil},
		{"budgets", Config{
			SourceType: SourceZip, UploadID: "u",
			Budgets: map[string]any{"max_workers": 3, "max_sink_sites_per_cwe": float64(2000), "ratio": 0.5},
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateConfig(tc.cfg, tc.roots); err != nil {
				t.Fatalf("ValidateConfig() = %v, want nil (outside=%s)", err, outside)
			}
		})
	}
}

func TestValidateConfigInvalid(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "..", "elsewhere")
	deepGit := func() Config {
		return Config{SourceType: SourceGit, RepoURL: "https://example.com/a.git", Depth: DepthDeep}
	}

	cases := []struct {
		name  string
		cfg   Config
		roots []string
		want  string
	}{
		{"missing source", Config{Depth: DepthDeep}, nil, "source_type 必填"},
		{"bad source", Config{SourceType: "svn"}, nil, "不支持的 source_type"},
		{"git missing url", Config{SourceType: SourceGit}, nil, "repo_url"},
		{"file scheme", Config{SourceType: SourceGit, RepoURL: "file:///etc/passwd"}, nil, "只允许 https 或 ssh"},
		{"http scheme", Config{SourceType: SourceGit, RepoURL: "http://example.com/a.git"}, nil, "只允许 https 或 ssh"},
		{"git scheme", Config{SourceType: SourceGit, RepoURL: "git://example.com/a.git"}, nil, "只允许 https 或 ssh"},
		{"ext scheme", Config{SourceType: SourceGit, RepoURL: "ext::sh"}, nil, "只允许 https 或 ssh"},
		{"https credentials", Config{SourceType: SourceGit, RepoURL: "https://user:pass@example.com/a.git"}, nil, "不得包含用户名密码凭据"},
		{"https user only", Config{SourceType: SourceGit, RepoURL: "https://user@example.com/a.git"}, nil, "不得包含凭据"},
		{"ssh password", Config{SourceType: SourceGit, RepoURL: "ssh://git:secret@example.com/a.git"}, nil, "不得包含用户名密码凭据"},
		{"ssh encoded colon password", Config{SourceType: SourceGit, RepoURL: "ssh://user%3Apass@example.com/a.git"}, nil, "不得包含用户名密码凭据"},
		{"https encoded colon password", Config{SourceType: SourceGit, RepoURL: "https://user%3Apass@example.com/a.git"}, nil, "不得包含用户名密码凭据"},
		{"ssh encoded at", Config{SourceType: SourceGit, RepoURL: "ssh://user%40host@example.com/a.git"}, nil, "用户信息包含非法字符"},
		{"ssh encoded control", Config{SourceType: SourceGit, RepoURL: "ssh://user%0Apass@example.com/a.git"}, nil, "用户信息包含非法字符"},
		{"empty host", Config{SourceType: SourceGit, RepoURL: "https:///a.git"}, nil, "缺少主机名"},
		{"local missing path", Config{SourceType: SourceLocal}, []string{root}, "local_path"},
		{"local no roots", Config{SourceType: SourceLocal, LocalPath: root}, nil, "未配置本地审计根目录"},
		{"local outside", Config{SourceType: SourceLocal, LocalPath: outside}, []string{root}, "本地目录不在允许范围"},
		{"zip missing upload", Config{SourceType: SourceZip}, nil, "upload_id"},
		{"invalid depth", Config{SourceType: SourceZip, UploadID: "u", Depth: "huge"}, nil, "无效的 depth"},
		{"invalid scope", Config{SourceType: SourceZip, UploadID: "u", CWEScope: "some"}, nil, "无效的 cwe_scope"},
		{"explicit empty", Config{SourceType: SourceZip, UploadID: "u", CWEScope: CWEScopeExplicit}, nil, "必须提供 cwe_ids"},
		{"explicit malformed", Config{SourceType: SourceZip, UploadID: "u", CWEScope: CWEScopeExplicit, CWEIDs: []string{"89"}}, nil, "无效的 CWE 编号"},
		{"rounds too high", Config{SourceType: SourceZip, UploadID: "u", MaxRounds: 11}, nil, "max_rounds"},
		{"rounds negative", Config{SourceType: SourceZip, UploadID: "u", MaxRounds: -1}, nil, "max_rounds"},
		{"deep codegraph off", func() Config {
			cfg := deepGit()
			cfg.Engines = map[string]string{EngineCodeGraph: "off"}
			return cfg
		}(), nil, "engines.codegraph 不能为 off"},
		{"unknown engine", Config{SourceType: SourceZip, UploadID: "u", Engines: map[string]string{"semgrep": "auto"}}, nil, "未知的审计引擎"},
		{"unknown engine empty value", Config{SourceType: SourceZip, UploadID: "u", Engines: map[string]string{"semgrep": ""}}, nil, "未知的审计引擎"},
		{"invalid engine value", Config{SourceType: SourceZip, UploadID: "u", Engines: map[string]string{EngineCodeGraph: "always"}}, nil, "无效的 codegraph 引擎配置"},
		{"codeql cannot be required", Config{SourceType: SourceZip, UploadID: "u", Engines: map[string]string{EngineCodeQL: "required"}}, nil, "无效的 codeql 引擎配置"},
		{"joern cannot be required", Config{SourceType: SourceZip, UploadID: "u", Engines: map[string]string{EngineJoern: "required"}}, nil, "无效的 joern 引擎配置"},
		{"negative budget", Config{SourceType: SourceZip, UploadID: "u", Budgets: map[string]any{"max_workers": -1.0}}, nil, "budget \"max_workers\" 必须是非负数字"},
		{"non-numeric budget", Config{SourceType: SourceZip, UploadID: "u", Budgets: map[string]any{"max_workers": "three"}}, nil, "budget \"max_workers\" 必须是数字"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConfig(tc.cfg, tc.roots)
			if err == nil {
				t.Fatalf("ValidateConfig() = nil, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateConfig() = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateGitSCPLikeURLs(t *testing.T) {
	valid := []string{
		"git@github.com:org/repo.git",
		"github.com:org/repo.git",
		"user.name@example.com:repo.git",
		"deploy-user@git.internal:team/repo.git",
		"git@host:/absolute/path.git",
		"user@192.168.1.10:repo.git",
	}
	for _, repoURL := range valid {
		t.Run("valid "+repoURL, func(t *testing.T) {
			err := ValidateConfig(Config{SourceType: SourceGit, RepoURL: repoURL, Depth: DepthStandard}, nil)
			if err != nil {
				t.Fatalf("ValidateConfig(%q) = %v, want nil", repoURL, err)
			}
		})
	}

	invalid := []struct {
		repoURL string
		want    string
	}{
		{"-c@host:path", "不能以 - 开头"},
		{"-oProxyCommand=evil@host:path", "不能以 - 开头"},
		{"user:pass@host:path", "用户信息不得包含凭据"},
		{"user:@host:path", "用户信息不得包含凭据"},
		{"user%3Apass@host:path", "用户信息不得包含凭据"},
		{"user%40host@example.com:path", "格式无效"},
		{"user%2Fname@host:path", "格式无效"},
		{"@host:path", "缺少用户名"},
		{"user@:path", "缺少有效主机名或路径"},
		{"user@host:", "缺少有效主机名或路径"},
		{"user@-host:path", "缺少有效主机名或路径"},
		{"user@host..example.com:path", "缺少有效主机名或路径"},
		{"user@host-.example.com:path", "缺少有效主机名或路径"},
		{"user@@host:path", "格式无效"},
		{"user@host/path:repo", "缺少有效主机名或路径"},
		{":path", "缺少有效主机名或路径"},
		{"host", "只允许 https 或 ssh"},
		{`C:\repo`, "本地文件路径"},
		{"C:/repo", "本地文件路径"},
		{"C:repo", "本地文件路径"},
	}
	for _, tc := range invalid {
		t.Run("invalid "+tc.repoURL, func(t *testing.T) {
			err := ValidateConfig(Config{SourceType: SourceGit, RepoURL: tc.repoURL, Depth: DepthStandard}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateConfig(%q) = %v, want substring %q", tc.repoURL, err, tc.want)
			}
		})
	}
}

func TestValidateConfigLocalRootsAllowMultiple(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	cfg := Config{SourceType: SourceLocal, LocalPath: filepath.Join(rootB, "project")}
	if err := ValidateConfig(cfg, []string{rootA, rootB, ""}); err != nil {
		t.Fatalf("ValidateConfig() = %v, want nil", err)
	}
}
