package agent

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/Autumn-27/artex/audit"
)

// auditIntentSpec is the optional "audit" object accepted by add_intent for
// code-audit tasks. It is stored verbatim (normalized) under the intent payload's
// "audit" key so the director can close phases and audit_progress can batch
// coverage work.
type auditIntentSpec struct {
	Phase        string         `json:"phase"`
	Round        int            `json:"round"`
	CWE          string         `json:"cwe,omitempty"`
	Language     string         `json:"language,omitempty"`
	Scope        map[string]any `json:"scope,omitempty"`
	SinkKeys     []string       `json:"sink_keys,omitempty"`
	FindingIDs   []int64        `json:"finding_ids,omitempty"`
	Deliverables []string       `json:"deliverables,omitempty"`
}

var (
	auditCWEIntentPattern = regexp.MustCompile(`^CWE-[0-9]+$`)
	auditLanguagePattern  = regexp.MustCompile(`^[a-z0-9#+._-]+$`)
)

// Planner-created audit intents target S1-S11; S0 ingest is director-owned and
// cannot be expressed as a planner intent.
var validAuditIntentPhases = map[string]struct{}{
	audit.PhaseProfile: {}, audit.PhaseSurface: {},
	audit.PhaseDataFlow: {}, audit.PhaseDetect: {}, audit.PhaseVerify: {},
	audit.PhaseLogic: {}, audit.PhaseOdinDeep: {}, audit.PhaseDesign: {},
	audit.PhaseDepth: {}, audit.PhasePoC: {}, audit.PhaseReport: {},
}

const (
	maxAuditIntentSinkKeys     = 1000
	maxAuditIntentFindingIDs   = 200
	maxAuditIntentDeliverables = 20
	maxAuditIntentKeyChars     = 512
)

func normalizeAuditIntentSpec(in *auditIntentSpec) (*auditIntentSpec, error) {
	if in == nil {
		return nil, nil
	}
	out := &auditIntentSpec{}
	out.Phase = strings.ToUpper(strings.TrimSpace(in.Phase))
	if out.Phase == "" {
		return nil, fmt.Errorf("audit.phase 不能为空")
	}
	if _, ok := validAuditIntentPhases[out.Phase]; !ok {
		return nil, fmt.Errorf("audit.phase %q 不是有效审计阶段（S1-S11）", in.Phase)
	}
	out.Round = in.Round
	if out.Round == 0 {
		out.Round = 1
	}
	if out.Round < 1 || out.Round > 10 {
		return nil, fmt.Errorf("audit.round 必须在 1-10 之间")
	}

	out.CWE = strings.ToUpper(strings.TrimSpace(in.CWE))
	if out.CWE != "" && !auditCWEIntentPattern.MatchString(out.CWE) {
		return nil, fmt.Errorf("audit.cwe %q 必须形如 CWE-89", in.CWE)
	}

	rawLanguage := strings.ToLower(strings.TrimSpace(in.Language))
	if rawLanguage != "" {
		if !auditLanguagePattern.MatchString(rawLanguage) {
			return nil, fmt.Errorf("audit.language %q 包含非法字符", in.Language)
		}
		if normalized := audit.NormalizeLanguage(rawLanguage); normalized != "" {
			out.Language = normalized
		} else {
			out.Language = rawLanguage
		}
	}

	scope, err := normalizeAuditIntentScope(in.Scope)
	if err != nil {
		return nil, err
	}
	out.Scope = scope
	sinkKeys, err := normalizeAuditIntentStrings(in.SinkKeys, maxAuditIntentSinkKeys, maxAuditIntentKeyChars, "audit.sink_keys")
	if err != nil {
		return nil, err
	}
	out.SinkKeys = sinkKeys
	findingIDs, err := normalizeAuditFindingIDs(in.FindingIDs)
	if err != nil {
		return nil, err
	}
	out.FindingIDs = findingIDs
	deliverables, err := normalizeAuditIntentStrings(in.Deliverables, maxAuditIntentDeliverables, 256, "audit.deliverables")
	if err != nil {
		return nil, err
	}
	out.Deliverables = deliverables
	if out.Phase == audit.PhaseDetect && len(out.SinkKeys) == 0 {
		return nil, fmt.Errorf("S4 检测意图必须提供 audit.sink_keys（没有待扫描站点时不要创建 S4 意图）")
	}
	return out, nil
}

// normalizeAuditFindingIDs dedupes positive finding ids in first-seen order.
// Finding IDs let S5/S8 verification intents target unverified findings without
// inventing sink keys.
func normalizeAuditFindingIDs(in []int64) ([]int64, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > maxAuditIntentFindingIDs {
		return nil, fmt.Errorf("audit.finding_ids 最多 %d 项", maxAuditIntentFindingIDs)
	}
	out := make([]int64, 0, len(in))
	seen := make(map[int64]struct{}, len(in))
	for _, id := range in {
		if id <= 0 {
			return nil, fmt.Errorf("audit.finding_ids 必须是正整数")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

// normalizeAuditIntentStrings trims, rejects control characters, dedupes and
// caps a string array. Errors from the first invalid element are returned with
// the caller-facing field name.
func normalizeAuditIntentStrings(in []string, maxItems, maxChars int, field string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > maxItems {
		return nil, fmt.Errorf("%s 最多 %d 项", field, maxItems)
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if len(value) > maxChars {
			return nil, fmt.Errorf("%s 单项不能超过 %d 字符", field, maxChars)
		}
		for _, r := range value {
			if unicode.IsControl(r) {
				return nil, fmt.Errorf("%s 不能包含控制字符", field)
			}
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func normalizeAuditIntentScope(scope map[string]any) (map[string]any, error) {
	if len(scope) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(scope))
	for key, value := range scope {
		key = strings.TrimSpace(key)
		if key == "" || len(key) > 64 {
			continue
		}
		out[key] = value
	}
	if rawModules, ok := out["modules"]; ok {
		modules := make([]string, 0)
		switch values := rawModules.(type) {
		case []string:
			modules = append(modules, values...)
		case []any:
			for _, raw := range values {
				text, ok := raw.(string)
				if !ok {
					return nil, fmt.Errorf("audit.scope.modules 必须是字符串数组")
				}
				modules = append(modules, text)
			}
		default:
			return nil, fmt.Errorf("audit.scope.modules 必须是字符串数组")
		}
		modules, err := normalizeAuditIntentStrings(modules, 200, 512, "audit.scope.modules")
		if err != nil {
			return nil, err
		}
		out["modules"] = modules
	}
	return out, nil
}

// auditIntentPayload returns nil for absent metadata. Validation errors are
// surfaced by add_intent before any graph node is created.
func auditIntentPayload(spec *auditIntentSpec) (map[string]any, error) {
	normalized, err := normalizeAuditIntentSpec(spec)
	if err != nil {
		return nil, err
	}
	if normalized == nil {
		return nil, nil
	}
	return map[string]any{"audit": normalized}, nil
}
