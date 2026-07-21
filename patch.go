package subscriptionconverter

import (
	"fmt"
	"strings"

	"sigs.k8s.io/yaml"
)

type PatchFormat string

const (
	PatchFormatClashRules PatchFormat = "clash-rules"
	PatchFormatDocument   PatchFormat = "patch"
	PatchFormatSingBox    PatchFormat = "sing-box"
)

type PatchSource struct {
	Source string      `json:"source"`
	Format PatchFormat `json:"format,omitempty"`
}

type DocumentPatch struct {
	Route *RoutePatch `json:"route,omitempty"`
}

type RoutePatch struct {
	RuleSets []RuleSet   `json:"rule_sets,omitempty"`
	Rules    []RouteRule `json:"rules,omitempty"`
	Final    *string     `json:"final,omitempty"`
}

type patchDecodeFunc func([]byte) (DocumentPatch, error)

func patchDecoder(format PatchFormat) (patchDecodeFunc, error) {
	switch normalizePatchFormat(format) {
	case PatchFormatClashRules:
		return decodeClashRulesPatch, nil
	case PatchFormatDocument:
		return decodeDocumentPatch, nil
	case PatchFormatSingBox:
		return decodeSingBoxPatch, nil
	default:
		return nil, fmt.Errorf("unsupported patch format %q (available: clash-rules, patch, sing-box)", format)
	}
}

func normalizePatchFormat(format PatchFormat) PatchFormat {
	switch strings.ToLower(strings.TrimSpace(string(format))) {
	case "", "clash-rules", "clashrules", "clash_rules":
		return PatchFormatClashRules
	case "patch", "document-patch", "document_patch":
		return PatchFormatDocument
	case "sing-box", "singbox", "sing_box":
		return PatchFormatSingBox
	default:
		return PatchFormat(strings.ToLower(strings.TrimSpace(string(format))))
	}
}

// DecodePatch decodes one patch using the requested format. An empty format
// defaults to clash-rules.
func DecodePatch(data []byte, format PatchFormat) (DocumentPatch, error) {
	decoder, err := patchDecoder(format)
	if err != nil {
		return DocumentPatch{}, err
	}
	return decoder(data)
}

// LoadPatches loads and combines patch sources in declaration order.
func LoadPatches(sources []PatchSource) (DocumentPatch, error) {
	combined := DocumentPatch{}
	for index, source := range sources {
		data, err := Load(source.Source)
		if err != nil {
			return DocumentPatch{}, fmt.Errorf("load patch #%d: %w", index+1, err)
		}
		patch, err := DecodePatch(data, source.Format)
		if err != nil {
			return DocumentPatch{}, fmt.Errorf("decode patch #%d: %w", index+1, err)
		}
		combineDocumentPatch(&combined, patch)
	}
	return combined, nil
}

// ApplyPatch prepends route rules and applies explicitly supplied scalar values.
func ApplyPatch(document *Document, patch DocumentPatch) error {
	if document == nil || patch.Route == nil {
		return nil
	}
	if err := validateRoutePatch(*document, *patch.Route); err != nil {
		return err
	}
	document.Route.RuleSets = mergeRuleSets(document.Route.RuleSets, patch.Route.RuleSets)
	rules := make([]RouteRule, 0, len(patch.Route.Rules)+len(document.Route.Rules))
	rules = append(rules, patch.Route.Rules...)
	rules = append(rules, document.Route.Rules...)
	document.Route.Rules = rules
	if patch.Route.Final != nil {
		document.Route.Final = *patch.Route.Final
	}
	return nil
}

type clashRulesPatch struct {
	Rules []string `json:"rules"`
}

func decodeClashRulesPatch(data []byte) (DocumentPatch, error) {
	var input clashRulesPatch
	if err := yaml.UnmarshalStrict(data, &input); err != nil {
		return DocumentPatch{}, fmt.Errorf("decode Clash rules: %w", err)
	}
	if len(input.Rules) == 0 {
		return DocumentPatch{}, fmt.Errorf("Clash rules patch contains no rules")
	}
	route := &RoutePatch{}
	for index, line := range input.Rules {
		rule, final, warning := decodeClashRule(line)
		if warning != "" {
			return DocumentPatch{}, fmt.Errorf("rule #%d: %s", index+1, warning)
		}
		if final != "" {
			if route.Final != nil {
				return DocumentPatch{}, fmt.Errorf("rule #%d: multiple MATCH or FINAL rules", index+1)
			}
			value := final
			route.Final = &value
			continue
		}
		route.Rules = append(route.Rules, rule)
	}
	return DocumentPatch{Route: route}, nil
}

func decodeDocumentPatch(data []byte) (DocumentPatch, error) {
	var patch DocumentPatch
	if err := yaml.UnmarshalStrict(data, &patch); err != nil {
		return DocumentPatch{}, fmt.Errorf("decode document patch: %w", err)
	}
	if patch.Route == nil {
		return DocumentPatch{}, fmt.Errorf("document patch contains no supported sections")
	}
	return patch, nil
}

func combineDocumentPatch(target *DocumentPatch, source DocumentPatch) {
	if source.Route == nil {
		return
	}
	if target.Route == nil {
		target.Route = &RoutePatch{}
	}
	target.Route.Rules = append(target.Route.Rules, source.Route.Rules...)
	target.Route.RuleSets = mergeRuleSets(target.Route.RuleSets, source.Route.RuleSets)
	if source.Route.Final != nil {
		value := *source.Route.Final
		target.Route.Final = &value
	}
}

func validateRoutePatch(document Document, patch RoutePatch) error {
	availableRuleSets := make(map[string]struct{}, len(document.Route.RuleSets)+len(patch.RuleSets))
	for _, ruleSet := range document.Route.RuleSets {
		availableRuleSets[ruleSet.Tag] = struct{}{}
	}
	patchRuleSets := make(map[string]struct{}, len(patch.RuleSets))
	for index, ruleSet := range patch.RuleSets {
		if err := validateRuleSet(ruleSet); err != nil {
			return fmt.Errorf("patch rule-set #%d: %w", index+1, err)
		}
		if _, exists := patchRuleSets[ruleSet.Tag]; exists {
			return fmt.Errorf("patch rule-set #%d: duplicate tag %q", index+1, ruleSet.Tag)
		}
		patchRuleSets[ruleSet.Tag] = struct{}{}
		availableRuleSets[ruleSet.Tag] = struct{}{}
	}
	for index, ruleSet := range patch.RuleSets {
		if ruleSet.DownloadDetour != "" && !documentHasPolicy(document, ruleSet.DownloadDetour) {
			return fmt.Errorf("patch rule-set #%d: unknown download detour %q", index+1, ruleSet.DownloadDetour)
		}
		for matchIndex, match := range ruleSet.Rules {
			if err := validateRuleSetReferences(match, availableRuleSets); err != nil {
				return fmt.Errorf("patch rule-set #%d rule #%d: %w", index+1, matchIndex+1, err)
			}
		}
	}
	for index, rule := range patch.Rules {
		if err := validateRuleSetReferences(rule.Match, availableRuleSets); err != nil {
			return fmt.Errorf("patch route rule #%d: %w", index+1, err)
		}
		switch rule.Action.Type {
		case RouteActionReject:
			if rule.Action.Target != "" {
				return fmt.Errorf("patch route rule #%d: reject action cannot have a target", index+1)
			}
		case RouteActionRoute:
			if !documentHasPolicy(document, rule.Action.Target) {
				return fmt.Errorf("patch route rule #%d: unknown policy %q", index+1, rule.Action.Target)
			}
		default:
			return fmt.Errorf("patch route rule #%d: unsupported action %q", index+1, rule.Action.Type)
		}
	}
	if patch.Final != nil && !documentHasPolicy(document, *patch.Final) {
		return fmt.Errorf("patch route final: unknown policy %q", *patch.Final)
	}
	return nil
}

func validateRuleSet(ruleSet RuleSet) error {
	if ruleSet.Tag == "" {
		return fmt.Errorf("tag is required")
	}
	switch ruleSet.Type {
	case RuleSetInline:
		if len(ruleSet.Rules) == 0 {
			return fmt.Errorf("inline rule-set %q requires rules", ruleSet.Tag)
		}
	case RuleSetLocal:
		if ruleSet.Path == "" {
			return fmt.Errorf("local rule-set %q requires path", ruleSet.Tag)
		}
	case RuleSetRemote:
		if ruleSet.URL == "" {
			return fmt.Errorf("remote rule-set %q requires URL", ruleSet.Tag)
		}
	default:
		return fmt.Errorf("rule-set %q has unsupported type %q", ruleSet.Tag, ruleSet.Type)
	}
	return nil
}

func validateRuleSetReferences(match RouteMatch, available map[string]struct{}) error {
	for _, tag := range match.RuleSets {
		if _, exists := available[tag]; !exists {
			return fmt.Errorf("unknown rule-set %q", tag)
		}
	}
	return nil
}

func mergeRuleSets(base, overrides []RuleSet) []RuleSet {
	result := append([]RuleSet(nil), base...)
	positions := make(map[string]int, len(result))
	for index, ruleSet := range result {
		positions[ruleSet.Tag] = index
	}
	for _, ruleSet := range overrides {
		if index, exists := positions[ruleSet.Tag]; exists {
			result[index] = ruleSet
			continue
		}
		positions[ruleSet.Tag] = len(result)
		result = append(result, ruleSet)
	}
	return result
}

func documentHasPolicy(document Document, policy string) bool {
	if strings.EqualFold(policy, "DIRECT") || strings.EqualFold(policy, "proxy") {
		return true
	}
	for _, node := range document.Nodes {
		if node.Name == policy {
			return true
		}
	}
	for _, group := range document.Groups {
		if group.Name == policy {
			return true
		}
	}
	return false
}
