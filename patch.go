package subscriptionconverter

import (
	"fmt"
	"net/netip"
	"strings"

	"sigs.k8s.io/yaml"
)

type PatchFormat string

const (
	PatchFormatClash    PatchFormat = "clash"
	PatchFormatDocument PatchFormat = "patch"
	PatchFormatSingBox  PatchFormat = "sing-box"
)

type PatchSource struct {
	Format PatchFormat `json:"format,omitempty"`
	Source
}

type DocumentPatch struct {
	Warnings []string    `json:"-"`
	Inbounds *[]Inbound  `json:"inbounds,omitempty"`
	DNS      *DNSConfig  `json:"dns,omitempty"`
	Nodes    []Node      `json:"nodes,omitempty"`
	Groups   []Group     `json:"groups,omitempty"`
	Route    *RoutePatch `json:"route,omitempty"`
}

type RoutePatch struct {
	RuleSets []RuleSet   `json:"rule_sets,omitempty"`
	Rules    []RouteRule `json:"rules,omitempty"`
	Final    *string     `json:"final,omitempty"`
}

type PatchCodec interface {
	PatchFormats() []PatchFormat
	DecodePatch([]byte, PatchFormat, DecodeOptions) (DocumentPatch, error)
}

func normalizePatchFormat(format PatchFormat) PatchFormat {
	switch strings.ToLower(strings.TrimSpace(string(format))) {
	case "", "clash":
		return PatchFormatClash
	case "patch", "document-patch", "document_patch":
		return PatchFormatDocument
	case "sing-box", "singbox", "sing_box":
		return PatchFormatSingBox
	default:
		return PatchFormat(strings.ToLower(strings.TrimSpace(string(format))))
	}
}

// DecodePatch decodes one patch using the requested format. An empty format
// defaults to clash.
func (c *Converter) DecodePatch(data []byte, format PatchFormat) (DocumentPatch, error) {
	return c.decodePatch(data, format, DecodeOptions{})
}

func (c *Converter) decodePatch(data []byte, format PatchFormat, options DecodeOptions) (DocumentPatch, error) {
	format = normalizePatchFormat(format)
	if format == PatchFormatDocument {
		return decodeDocumentPatch(data)
	}
	decoder := c.patches[format]
	if decoder == nil {
		return DocumentPatch{}, fmt.Errorf("unsupported patch format %q", format)
	}
	return decoder.DecodePatch(data, format, options)
}

func (c *Converter) LoadPatches(loader Loader, sources []PatchSource) (DocumentPatch, error) {
	if loader == nil {
		loader = defaultLoader
	}
	combined := DocumentPatch{}
	for index, source := range sources {
		data, err := loader.Load(source.Source)
		if err != nil {
			return DocumentPatch{}, fmt.Errorf("load patch #%d: %w", index+1, err)
		}
		patch, err := c.decodePatch(data, source.Format, DecodeOptions{
			Loader: loader, BaseDirectory: SourceBaseDirectory(source.Location),
		})
		if err != nil {
			return DocumentPatch{}, fmt.Errorf("decode patch #%d: %w", index+1, err)
		}
		combineDocumentPatch(&combined, patch)
	}
	return combined, nil
}

// ApplyPatch replaces explicitly supplied inbounds, prepends route rules, and
// applies explicitly supplied scalar values.
func ApplyPatch(document *Document, patch DocumentPatch) error {
	if document == nil {
		return nil
	}
	if patch.Inbounds != nil {
		if err := ValidateInbounds(*patch.Inbounds); err != nil {
			return fmt.Errorf("patch inbounds: %w", err)
		}
	}
	candidate := *document
	candidate.Nodes = mergeNodes(document.Nodes, patch.Nodes)
	candidate.Groups = mergeGroups(document.Groups, patch.Groups)
	if patch.DNS != nil {
		candidate.DNS = *patch.DNS
		candidate.Route.DefaultDomainResolver = FirstNonEmpty(patch.DNS.ProxyResolver, patch.DNS.Final)
	}
	if patch.Route != nil {
		if err := validateRoutePatch(candidate, *patch.Route); err != nil {
			return err
		}
	}
	if patch.Inbounds != nil {
		document.Inbounds = cloneInbounds(*patch.Inbounds)
	}
	document.Nodes = candidate.Nodes
	document.Groups = candidate.Groups
	if patch.DNS != nil {
		document.DNS = candidate.DNS
		document.Route.DefaultDomainResolver = candidate.Route.DefaultDomainResolver
	}
	if patch.Route == nil {
		return nil
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

func decodeDocumentPatch(data []byte) (DocumentPatch, error) {
	var patch DocumentPatch
	if err := yaml.UnmarshalStrict(data, &patch); err != nil {
		return DocumentPatch{}, fmt.Errorf("decode document patch: %w", err)
	}
	if patch.Inbounds == nil && patch.DNS == nil && len(patch.Nodes) == 0 && len(patch.Groups) == 0 && patch.Route == nil {
		return DocumentPatch{}, fmt.Errorf("document patch contains no supported sections")
	}
	return patch, nil
}

func combineDocumentPatch(target *DocumentPatch, source DocumentPatch) {
	target.Warnings = append(target.Warnings, source.Warnings...)
	if source.Inbounds != nil {
		inbounds := cloneInbounds(*source.Inbounds)
		target.Inbounds = &inbounds
	}
	if source.DNS != nil {
		dns := *source.DNS
		target.DNS = &dns
	}
	target.Nodes = mergeNodes(target.Nodes, source.Nodes)
	target.Groups = mergeGroups(target.Groups, source.Groups)
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

func mergeNodes(base, overrides []Node) []Node {
	result := append([]Node(nil), base...)
	positions := make(map[string]int, len(result))
	for index, node := range result {
		positions[node.Name] = index
	}
	for _, node := range overrides {
		if index, exists := positions[node.Name]; exists {
			result[index] = node
		} else {
			positions[node.Name] = len(result)
			result = append(result, node)
		}
	}
	return result
}

func mergeGroups(base, overrides []Group) []Group {
	result := append([]Group(nil), base...)
	positions := make(map[string]int, len(result))
	for index, group := range result {
		positions[group.Name] = index
	}
	for _, group := range overrides {
		if index, exists := positions[group.Name]; exists {
			result[index] = group
		} else {
			positions[group.Name] = len(result)
			result = append(result, group)
		}
	}
	return result
}

func ValidateInbounds(inbounds []Inbound) error {
	seenTags := make(map[string]struct{}, len(inbounds))
	for index, inbound := range inbounds {
		field := fmt.Sprintf("inbound #%d", index+1)
		if inbound.Tag == "" {
			return fmt.Errorf("%s: tag is required", field)
		}
		if _, exists := seenTags[inbound.Tag]; exists {
			return fmt.Errorf("%s: duplicate tag %q", field, inbound.Tag)
		}
		seenTags[inbound.Tag] = struct{}{}
		switch inbound.Type {
		case InboundTUN:
			if inbound.TUN == nil {
				return fmt.Errorf("%s: tun options are required", field)
			}
			if len(inbound.TUN.Addresses) == 0 {
				return fmt.Errorf("%s: at least one address is required", field)
			}
			if inbound.Listen != "" || inbound.ListenPort != 0 || len(inbound.Users) > 0 || inbound.SetSystemProxy {
				return fmt.Errorf("%s: proxy listener fields are not supported for tun", field)
			}
			switch inbound.TUN.Stack {
			case "", TUNStackSystem, TUNStackGVisor, TUNStackMixed:
			default:
				return fmt.Errorf("%s: unsupported tun stack %q", field, inbound.TUN.Stack)
			}
		case InboundMixed, InboundSOCKS, InboundHTTP:
			if inbound.TUN != nil {
				return fmt.Errorf("%s: tun options are only supported for tun", field)
			}
			if _, err := netip.ParseAddr(inbound.Listen); err != nil {
				return fmt.Errorf("%s: invalid listen address %q", field, inbound.Listen)
			}
			if inbound.ListenPort == 0 {
				return fmt.Errorf("%s: listen_port is required", field)
			}
			if inbound.SetSystemProxy && inbound.Type != InboundMixed {
				return fmt.Errorf("%s: set_system_proxy is only supported for mixed", field)
			}
			seenUsers := make(map[string]struct{}, len(inbound.Users))
			for userIndex, user := range inbound.Users {
				if user.Username == "" || user.Password == "" {
					return fmt.Errorf("%s user #%d: username and password are required", field, userIndex+1)
				}
				if _, exists := seenUsers[user.Username]; exists {
					return fmt.Errorf("%s user #%d: duplicate username %q", field, userIndex+1, user.Username)
				}
				seenUsers[user.Username] = struct{}{}
			}
		default:
			return fmt.Errorf("%s: unsupported type %q", field, inbound.Type)
		}
	}
	return nil
}

func cloneInbounds(source []Inbound) []Inbound {
	result := make([]Inbound, len(source))
	copy(result, source)
	for index := range result {
		result[index].Users = append([]InboundUser(nil), source[index].Users...)
		if source[index].TUN != nil {
			tun := *source[index].TUN
			tun.Addresses = append([]netip.Prefix(nil), source[index].TUN.Addresses...)
			result[index].TUN = &tun
		}
	}
	return result
}

func validateRoutePatch(document Document, patch RoutePatch) error {
	availableRuleSets := make(map[string]struct{}, len(document.Route.RuleSets)+len(patch.RuleSets))
	for _, ruleSet := range document.Route.RuleSets {
		availableRuleSets[ruleSet.Tag] = struct{}{}
	}
	patchRuleSets := make(map[string]struct{}, len(patch.RuleSets))
	for index, ruleSet := range patch.RuleSets {
		if err := ValidateRuleSet(ruleSet); err != nil {
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

func ValidateRuleSet(ruleSet RuleSet) error {
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
	if strings.EqualFold(policy, "DIRECT") || strings.EqualFold(policy, "REJECT") || strings.EqualFold(policy, "REJECT-DROP") || strings.EqualFold(policy, "proxy") {
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
