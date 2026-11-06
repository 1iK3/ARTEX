package engines

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/audit"
	"github.com/Autumn-27/norma/llm"
)

const (
	// IntentPromptVersion changes only when the analyst contract or prompt
	// materially changes. It is persisted with every recognized intent.
	IntentPromptVersion = "v2"

	maxIntentAnalystRepairAttempts = 2
	maxLLMIntents                  = 16
	maxLLMPatterns                 = 16
	maxLLMPatternLen               = 128
	maxLLMTitleLen                 = 160
	maxLLMScopeEntries             = 16
	maxLLMScopeLen                 = 512
)

// IntentAnalystProvider is the narrow LLM seam. Model is recorded for audit
// provenance; Complete performs the actual model call.
type IntentAnalystProvider interface {
	Model() string
	Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
}

// IntentAnalyst converts a free-form audit goal into validated detection
// intents. It never accepts engine-native query text.
type IntentAnalyst struct {
	Provider IntentAnalystProvider
}

type IntentAnalystInput struct {
	Goal        string
	Languages   []string
	Registry    audit.Registry
	EngineNames []string
	MaxTokens   int
}

type IntentAnalysisResult struct {
	Intents    []DetectionIntent
	Provenance map[string]any
}

type llmIntentAnalysis struct {
	Intents []llmIntent `json:"intents"`
}

type llmIntent struct {
	Language         string         `json:"language"`
	CWE              string         `json:"cwe"`
	Title            string         `json:"title"`
	QueryKind        string         `json:"query_kind"`
	Sources          []llmPattern   `json:"sources"`
	Sinks            []llmPattern   `json:"sinks"`
	Sanitizers       []llmPattern   `json:"sanitizers"`
	Propagators      []llmPattern   `json:"propagators"`
	Scope            llmScope       `json:"scope"`
	Constraints      llmConstraints `json:"constraints"`
	PreferredEngines []string       `json:"preferred_engines"`
	Priority         int            `json:"priority"`
}

type llmPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Match   string `json:"match"`
}

type llmScope struct {
	Paths   []string `json:"paths"`
	Modules []string `json:"modules"`
	Symbols []string `json:"symbols"`
	Exclude []string `json:"exclude"`
}

type llmConstraints struct {
	Reachable    *bool  `json:"reachable"`
	AuthRequired *bool  `json:"auth_required"`
	MaxResults   int    `json:"max_results"`
	SeverityMin  string `json:"severity_min"`
}

// Analyze performs at most one initial LLM call plus two constrained repairs.
// Invalid structured IR is never converted into executable query text.
func (a *IntentAnalyst) Analyze(ctx context.Context, input IntentAnalystInput) (IntentAnalysisResult, error) {
	if a == nil || a.Provider == nil {
		return IntentAnalysisResult{}, errors.New("engines: intent analyst provider is required")
	}
	goal := strings.TrimSpace(input.Goal)
	if goal == "" {
		return IntentAnalysisResult{}, errors.New("engines: intent analyst goal is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	languages := normalizeLanguageList(input.Languages)
	if len(languages) == 0 {
		return IntentAnalysisResult{}, errors.New("engines: intent analyst requires at least one plan language")
	}
	cweNames := make(map[string]string)
	for _, definition := range input.Registry.CWE {
		id := normalizeCWEID(definition.ID)
		if id != "" {
			cweNames[id] = strings.TrimSpace(definition.Name)
		}
	}
	if len(cweNames) == 0 {
		return IntentAnalysisResult{}, errors.New("engines: intent analyst requires a non-empty CWE whitelist")
	}
	allowedEngines := normalizedEngineSet(input.EngineNames)
	if len(allowedEngines) == 0 {
		for name := range allowedEngines {
			_ = name
		}
		allowedEngines = map[string]struct{}{EngineCodeQL: {}, EngineJoern: {}, EngineCodeGraph: {}}
	}

	var lastErr error
	var repairMessage string
	var lastRaw string
	for attempt := 0; attempt <= maxIntentAnalystRepairAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return intentAnalysisFailure(a.Provider, lastRaw, attempt, err), fmt.Errorf("intent analysis canceled: %w", err)
		}
		request := llm.CompletionRequest{
			System:    []string{intentAnalystSystemPrompt()},
			Messages:  []llm.Message{llm.UserText(intentAnalystUserPrompt(goal, languages, cweNames, allowedEngines))},
			MaxTokens: maxIntentTokens(input.MaxTokens),
			Thinking:  "disabled",
		}
		if attempt > 0 {
			request.Messages = append(request.Messages, llm.UserText(repairMessage))
		}
		message, _, _, err := a.Provider.Complete(ctx, request)
		if err != nil {
			return intentAnalysisFailure(a.Provider, lastRaw, attempt, err), fmt.Errorf("intent analysis LLM call failed: %w", err)
		}
		raw := strings.TrimSpace(message.Text())
		lastRaw = raw
		analysis, err := decodeIntentAnalysis(raw)
		if err == nil {
			err = validateIntentAnalysis(analysis, languages, cweNames, allowedEngines)
		}
		if err == nil {
			intents, err := llmIntentsToDetection(analysis, cweNames, allowedEngines)
			if err == nil {
				return IntentAnalysisResult{
					Intents: intents,
					Provenance: map[string]any{
						"model":              firstNonEmpty(strings.TrimSpace(a.Provider.Model()), "unknown"),
						"prompt_version":     IntentPromptVersion,
						"raw_output_hash":    hashText(raw),
						"recognition_source": "llm",
						"repair_attempts":    attempt,
					},
				}, nil
			}
			lastErr = err
		} else {
			lastErr = err
		}
		if attempt < maxIntentAnalystRepairAttempts {
			repairMessage = "上一次输出未通过校验：" + lastErr.Error() +
				"\n请重新输出 JSON。只允许 schema 内字段，禁止 query_text、query、codeql、cpgql 或其他可执行查询字段。"
		}
	}
	return intentAnalysisFailure(a.Provider, lastRaw, maxIntentAnalystRepairAttempts, lastErr),
		fmt.Errorf("intent analysis failed after %d repairs: %w", maxIntentAnalystRepairAttempts, lastErr)
}

func intentAnalysisFailure(provider IntentAnalystProvider, raw string, attempts int, cause error) IntentAnalysisResult {
	provenance := map[string]any{
		"model":              firstNonEmpty(providerModel(provider), "unknown"),
		"prompt_version":     IntentPromptVersion,
		"recognition_source": "fallback",
		"repair_attempts":    attempts,
	}
	if strings.TrimSpace(raw) != "" {
		provenance["raw_output_hash"] = hashText(raw)
	}
	if cause != nil {
		provenance["error"] = cause.Error()
	}
	return IntentAnalysisResult{Provenance: provenance}
}

func providerModel(provider IntentAnalystProvider) string {
	if provider == nil {
		return ""
	}
	return strings.TrimSpace(provider.Model())
}

func intentAnalystSystemPrompt() string {
	return `你是代码审计意图分析器。只输出一个 JSON 对象，不要 Markdown 或解释。
允许字段：intents[].language/cwe/title/query_kind/sources/sinks/sanitizers/propagators/scope/constraints/preferred_engines/priority。
language 必须来自用户给出的语言白名单；cwe 必须来自用户给出的 CWE 白名单；query_kind 只能是 sink、taint、error_contract、state_transition 或 invariant。
pattern.match 只能是 method_call/type/regex；scope 路径必须是相对路径且不得包含 ..。
sink/taint 继续表达源、汇点和净化规则；error_contract/state_transition/invariant 表达语义审计意图，优先限定 scope.symbols，并在可用时把 preferred_engines 设为 ["codegraph"]。
生成意图时必须主动覆盖：入口点与攻击者可控输入、状态机与错误契约（返回值/错误码 taxonomy、永久错误、临时可恢复状态）、宏展开、调用方契约、固定大小缓冲、重试循环和不变式。
禁止输出 query_text、query、codeql、cpgql 或任何引擎原生查询。你的输出只是结构化意图 IR，不是可执行查询。`
}

func intentAnalystUserPrompt(goal string, languages []string, cwes map[string]string, engines map[string]struct{}) string {
	cweLines := make([]string, 0, len(cwes))
	for id, name := range cwes {
		cweLines = append(cweLines, id+" "+name)
	}
	sort.Strings(cweLines)
	engineNames := make([]string, 0, len(engines))
	for name := range engines {
		engineNames = append(engineNames, name)
	}
	sort.Strings(engineNames)
	return "用户自由目标：" + goal +
		"\n语言白名单：" + strings.Join(languages, ", ") +
		"\nCWE 白名单：\n" + strings.Join(cweLines, "\n") +
		"\n引擎白名单：" + strings.Join(engineNames, ", ") +
		"\n审计方法：优先提出攻击面、状态机、错误契约、宏展开、调用方契约、固定大小缓冲、重试循环和不变式假设。" +
		"\n请输出 intents 数组，最多 16 条。"
}

func decodeIntentAnalysis(raw string) (llmIntentAnalysis, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return llmIntentAnalysis{}, errors.New("empty LLM output")
	}
	if strings.HasPrefix(text, "```") {
		if end := strings.LastIndex(text, "```"); end > 3 {
			text = strings.TrimSpace(text[3:end])
		} else {
			return llmIntentAnalysis{}, errors.New("unterminated JSON code fence")
		}
	}
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end < start {
		return llmIntentAnalysis{}, errors.New("LLM output does not contain a JSON object")
	}
	var analysis llmIntentAnalysis
	decoder := json.NewDecoder(bytes.NewReader([]byte(text[start : end+1])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&analysis); err != nil {
		return llmIntentAnalysis{}, fmt.Errorf("invalid intent JSON: %w", err)
	}
	if decoder.More() {
		return llmIntentAnalysis{}, errors.New("unexpected trailing JSON content")
	}
	return analysis, nil
}

func validateIntentAnalysis(analysis llmIntentAnalysis, languages []string, cwes map[string]string, engines map[string]struct{}) error {
	if len(analysis.Intents) == 0 {
		return errors.New("intent analysis returned no intents")
	}
	if len(analysis.Intents) > maxLLMIntents {
		return fmt.Errorf("intent count %d exceeds %d", len(analysis.Intents), maxLLMIntents)
	}
	languageSet := make(map[string]struct{}, len(languages))
	for _, language := range languages {
		languageSet[language] = struct{}{}
	}
	for index, intent := range analysis.Intents {
		language := normalizeIntentLanguage(intent.Language)
		if _, ok := languageSet[language]; !ok {
			return fmt.Errorf("intent %d language %q is not in plan languages", index+1, intent.Language)
		}
		cwe := normalizeCWEID(intent.CWE)
		if _, ok := cwes[cwe]; !ok {
			return fmt.Errorf("intent %d CWE %q is not in registry whitelist", index+1, intent.CWE)
		}
		queryKind := strings.ToLower(strings.TrimSpace(intent.QueryKind))
		if queryKind != QueryKindSink && queryKind != QueryKindTaint &&
			queryKind != QueryKindErrorContract && queryKind != QueryKindStateTransition && queryKind != QueryKindInvariant {
			return fmt.Errorf("intent %d query kind %q is invalid", index+1, intent.QueryKind)
		}
		if err := validateLLMPatterns("sources", intent.Sources); err != nil {
			return fmt.Errorf("intent %d %w", index+1, err)
		}
		if err := validateLLMPatterns("sinks", intent.Sinks); err != nil {
			return fmt.Errorf("intent %d %w", index+1, err)
		}
		if err := validateLLMPatterns("sanitizers", intent.Sanitizers); err != nil {
			return fmt.Errorf("intent %d %w", index+1, err)
		}
		if err := validateLLMPatterns("propagators", intent.Propagators); err != nil {
			return fmt.Errorf("intent %d %w", index+1, err)
		}
		if queryKind == QueryKindSink && len(intent.Sinks) == 0 {
			return fmt.Errorf("intent %d sink query requires sinks", index+1)
		}
		if queryKind == QueryKindTaint && (len(intent.Sources) == 0 || len(intent.Sinks) == 0) {
			return fmt.Errorf("intent %d taint query requires sources and sinks", index+1)
		}
		if err := validateLLMScope(intent.Scope); err != nil {
			return fmt.Errorf("intent %d %w", index+1, err)
		}
		if intent.Title != "" && len([]rune(strings.TrimSpace(intent.Title))) > maxLLMTitleLen {
			return fmt.Errorf("intent %d title exceeds %d characters", index+1, maxLLMTitleLen)
		}
		if intent.Priority < 0 || intent.Priority > 2000 {
			return fmt.Errorf("intent %d priority %d is outside 0..2000", index+1, intent.Priority)
		}
		if intent.Constraints.MaxResults < 0 || intent.Constraints.MaxResults > 500 {
			return fmt.Errorf("intent %d max_results is outside 0..500", index+1)
		}
		switch strings.ToLower(strings.TrimSpace(intent.Constraints.SeverityMin)) {
		case "", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("intent %d severity_min %q is invalid", index+1, intent.Constraints.SeverityMin)
		}
		for _, rawEngine := range intent.PreferredEngines {
			engine := normalizeEngineName(rawEngine)
			if engine == "" {
				return fmt.Errorf("intent %d engine %q is unknown", index+1, rawEngine)
			}
			if _, ok := engines[engine]; !ok {
				return fmt.Errorf("intent %d engine %q is not enabled", index+1, rawEngine)
			}
		}
	}
	return nil
}

func validateLLMPatterns(field string, patterns []llmPattern) error {
	if len(patterns) > maxLLMPatterns {
		return fmt.Errorf("%s count %d exceeds %d", field, len(patterns), maxLLMPatterns)
	}
	for _, pattern := range patterns {
		text := strings.TrimSpace(pattern.Pattern)
		if len(text) < 3 || len(text) > maxLLMPatternLen {
			return fmt.Errorf("%s pattern length must be 3..%d", field, maxLLMPatternLen)
		}
		if strings.ContainsAny(text, "\r\n\x00") {
			return fmt.Errorf("%s pattern contains control characters", field)
		}
		switch pattern.Match {
		case MatchMethodCall, MatchType, MatchRegex:
		default:
			return fmt.Errorf("%s match %q is invalid", field, pattern.Match)
		}
	}
	return nil
}

func validateLLMScope(scope llmScope) error {
	for field, values := range map[string][]string{
		"paths":   scope.Paths,
		"exclude": scope.Exclude,
		"modules": scope.Modules,
		"symbols": scope.Symbols,
	} {
		if len(values) > maxLLMScopeEntries {
			return fmt.Errorf("scope %s count exceeds %d", field, maxLLMScopeEntries)
		}
		for _, value := range values {
			text := strings.TrimSpace(value)
			if text == "" || len(text) > maxLLMScopeLen {
				return fmt.Errorf("scope %s value is empty or too long", field)
			}
			if strings.ContainsAny(text, "\r\n\x00") {
				return fmt.Errorf("scope %s contains control characters", field)
			}
			if field == "paths" || field == "exclude" {
				cleaned := path.Clean(strings.ReplaceAll(text, "\\", "/"))
				if path.IsAbs(cleaned) || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
					return fmt.Errorf("scope %s value %q escapes the snapshot", field, text)
				}
			}
		}
	}
	return nil
}

func llmIntentsToDetection(analysis llmIntentAnalysis, cweNames map[string]string, engines map[string]struct{}) ([]DetectionIntent, error) {
	out := make([]DetectionIntent, 0, len(analysis.Intents))
	for _, raw := range analysis.Intents {
		language := normalizeIntentLanguage(raw.Language)
		cwe := normalizeCWEID(raw.CWE)
		title := strings.TrimSpace(raw.Title)
		if title == "" {
			title = cweNames[cwe]
		}
		queryKind := strings.ToLower(strings.TrimSpace(raw.QueryKind))
		preferred := make([]string, 0, len(raw.PreferredEngines))
		for _, name := range raw.PreferredEngines {
			if engine := normalizeEngineName(name); engine != "" {
				preferred = append(preferred, engine)
			}
		}
		if queryKind == QueryKindErrorContract || queryKind == QueryKindStateTransition || queryKind == QueryKindInvariant {
			if _, ok := engines[EngineCodeGraph]; ok {
				preferred = []string{EngineCodeGraph}
			}
		}
		if len(preferred) == 0 {
			for engine := range engines {
				preferred = append(preferred, engine)
			}
			sort.Strings(preferred)
		}
		intent := DetectionIntent{
			Origin:           OriginLLM,
			Language:         language,
			CWE:              cwe,
			Title:            title,
			QueryKind:        queryKind,
			Sources:          llmPatternsToPatterns(raw.Sources),
			Sinks:            llmPatternsToPatterns(raw.Sinks),
			Sanitizers:       llmPatternsToPatterns(raw.Sanitizers),
			Propagators:      llmPatternsToPatterns(raw.Propagators),
			Scope:            Scope{Paths: cleanPathList(raw.Scope.Paths), Modules: trimList(raw.Scope.Modules), Symbols: trimList(raw.Scope.Symbols), Exclude: cleanPathList(raw.Scope.Exclude)},
			Constraints:      Constraints{Reachable: raw.Constraints.Reachable, AuthRequired: raw.Constraints.AuthRequired, MaxResults: raw.Constraints.MaxResults, SeverityMin: strings.ToLower(strings.TrimSpace(raw.Constraints.SeverityMin))},
			PreferredEngines: preferred,
			Priority:         raw.Priority,
		}
		if intent.Priority == 0 {
			intent.Priority = 1100
		}
		intent.ID = "llm-" + IntentIRHash(intent)[:20]
		out = append(out, intent)
	}
	return out, nil
}

func llmPatternsToPatterns(patterns []llmPattern) []Pattern {
	out := make([]Pattern, 0, len(patterns))
	for _, pattern := range patterns {
		out = append(out, Pattern{Name: strings.TrimSpace(pattern.Name), Pattern: strings.TrimSpace(pattern.Pattern), Match: pattern.Match})
	}
	return out
}

func cleanPathList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		text := strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
		if text != "" {
			out = append(out, path.Clean(text))
		}
	}
	return out
}

func trimList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if text := strings.TrimSpace(value); text != "" {
			out = append(out, text)
		}
	}
	return out
}

func normalizedEngineSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		if name := normalizeEngineName(value); name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

func maxIntentTokens(value int) int {
	if value <= 0 || value > 4096 {
		return 2048
	}
	return value
}

func hashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
