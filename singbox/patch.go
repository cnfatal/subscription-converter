package singbox

import (
	"fmt"
	. "github.com/cnfatal/subscription-converter"
	"net/netip"
	"strings"

	"sigs.k8s.io/yaml"
)

// These private DTOs intentionally contain only the sing-box route fields that
// can be applied as a DocumentPatch. The complete public config lives in the
// singbox package.
type singBoxPatchConfig struct {
	Log          any                `json:"log,omitempty"`
	DNS          any                `json:"dns,omitempty"`
	Inbounds     *[]SingBoxInbound  `json:"inbounds,omitempty"`
	Outbounds    any                `json:"outbounds,omitempty"`
	Experimental any                `json:"experimental,omitempty"`
	Route        *singBoxPatchRoute `json:"route,omitempty"`
}

type singBoxPatchRoute struct {
	RuleSets []singBoxPatchRuleSet `json:"rule_set,omitempty"`
	Rules    []singBoxPatchRule    `json:"rules,omitempty"`
	Final    string                `json:"final,omitempty"`
}

type singBoxPatchRuleSet struct {
	Type           string             `json:"type,omitempty"`
	Tag            string             `json:"tag"`
	Format         string             `json:"format,omitempty"`
	URL            string             `json:"url,omitempty"`
	Path           string             `json:"path,omitempty"`
	UpdateInterval string             `json:"update_interval,omitempty"`
	DownloadDetour string             `json:"download_detour,omitempty"`
	Rules          []singBoxPatchRule `json:"rules,omitempty"`
}

type singBoxPatchRule struct {
	Domains        []string `json:"domain,omitempty"`
	DomainSuffixes []string `json:"domain_suffix,omitempty"`
	DomainKeywords []string `json:"domain_keyword,omitempty"`
	RuleSets       []string `json:"rule_set,omitempty"`
	IPCIDRs        []string `json:"ip_cidr,omitempty"`
	SourceIPCIDRs  []string `json:"source_ip_cidr,omitempty"`
	ProcessNames   []string `json:"process_name,omitempty"`
	ProcessPaths   []string `json:"process_path,omitempty"`
	Networks       []string `json:"network,omitempty"`
	Ports          []uint16 `json:"port,omitempty"`
	SourcePorts    []uint16 `json:"source_port,omitempty"`
	Protocols      []string `json:"protocol,omitempty"`
	IPIsPrivate    bool     `json:"ip_is_private,omitempty"`
	Action         string   `json:"action,omitempty"`
	Outbound       string   `json:"outbound,omitempty"`
}

func (SingBoxCodec) PatchFormats() []PatchFormat {
	return []PatchFormat{PatchFormatSingBox}
}

func (SingBoxCodec) DecodePatch(data []byte, _ PatchFormat, _ DecodeOptions) (DocumentPatch, error) {
	var input singBoxPatchConfig
	if err := yaml.UnmarshalStrict(data, &input); err != nil {
		return DocumentPatch{}, fmt.Errorf("decode sing-box patch: %w", err)
	}
	if input.Inbounds == nil && input.Route == nil {
		return DocumentPatch{}, fmt.Errorf("sing-box patch contains no supported sections")
	}
	patch := DocumentPatch{}
	if input.Inbounds != nil {
		inbounds := make([]Inbound, 0, len(*input.Inbounds))
		for index, inputInbound := range *input.Inbounds {
			inbound, err := inputInbound.documentInbound()
			if err != nil {
				return DocumentPatch{}, fmt.Errorf("sing-box inbound #%d: %w", index+1, err)
			}
			inbounds = append(inbounds, inbound)
		}
		patch.Inbounds = &inbounds
	}
	if input.Route == nil {
		return patch, nil
	}
	route := &RoutePatch{}
	if input.Route.Final != "" {
		final := input.Route.Final
		route.Final = &final
	}
	for index, inputRuleSet := range input.Route.RuleSets {
		ruleSet, err := inputRuleSet.documentRuleSet()
		if err != nil {
			return DocumentPatch{}, fmt.Errorf("sing-box rule-set #%d: %w", index+1, err)
		}
		route.RuleSets = append(route.RuleSets, ruleSet)
	}
	for index, inputRule := range input.Route.Rules {
		rule, err := inputRule.documentRouteRule()
		if err != nil {
			return DocumentPatch{}, fmt.Errorf("sing-box route rule #%d: %w", index+1, err)
		}
		route.Rules = append(route.Rules, rule)
	}
	patch.Route = route
	return patch, nil
}

func (inbound SingBoxInbound) documentInbound() (Inbound, error) {
	result := Inbound{
		Type:           InboundType(inbound.Type),
		Tag:            inbound.Tag,
		Listen:         inbound.Listen,
		ListenPort:     inbound.ListenPort,
		SetSystemProxy: inbound.SetSystemProxy,
	}
	for _, user := range inbound.Users {
		result.Users = append(result.Users, InboundUser{Username: user.Username, Password: user.Password})
	}
	if inbound.Type == SingBoxInboundTUN {
		addresses, err := parsePrefixes(inbound.Address)
		if err != nil {
			return Inbound{}, fmt.Errorf("address: %w", err)
		}
		result.TUN = &TUNConfig{
			Addresses: addresses, AutoRoute: inbound.AutoRoute, StrictRoute: inbound.StrictRoute,
			Stack: TUNStack(inbound.Stack), MTU: inbound.MTU,
		}
	}
	return result, nil
}

func (ruleSet singBoxPatchRuleSet) documentRuleSet() (RuleSet, error) {
	ruleSetType := RuleSetType(ruleSet.Type)
	if ruleSetType == "" && len(ruleSet.Rules) > 0 {
		ruleSetType = RuleSetInline
	}
	result := RuleSet{
		Type: ruleSetType, Tag: ruleSet.Tag, Format: RuleSetFormat(ruleSet.Format),
		URL: ruleSet.URL, Path: ruleSet.Path, UpdateInterval: ruleSet.UpdateInterval,
		DownloadDetour: ruleSet.DownloadDetour,
	}
	for index, inputRule := range ruleSet.Rules {
		if inputRule.Action != "" || inputRule.Outbound != "" {
			return RuleSet{}, fmt.Errorf("inline rule #%d cannot contain action or outbound", index+1)
		}
		match, err := inputRule.documentMatch()
		if err != nil {
			return RuleSet{}, fmt.Errorf("inline rule #%d: %w", index+1, err)
		}
		result.Rules = append(result.Rules, match)
	}
	if err := ValidateRuleSet(result); err != nil {
		return RuleSet{}, err
	}
	return result, nil
}

func (rule singBoxPatchRule) documentRouteRule() (RouteRule, error) {
	match, err := rule.documentMatch()
	if err != nil {
		return RouteRule{}, err
	}
	action := rule.Action
	if action == "" {
		action = "route"
	}
	switch action {
	case "route":
		if rule.Outbound == "" {
			return RouteRule{}, fmt.Errorf("route action requires outbound")
		}
		return RouteRule{Match: match, Action: RouteAction{Type: RouteActionRoute, Target: rule.Outbound}}, nil
	case "reject":
		if rule.Outbound != "" {
			return RouteRule{}, fmt.Errorf("reject action cannot contain outbound")
		}
		return RouteRule{Match: match, Action: RouteAction{Type: RouteActionReject}}, nil
	default:
		return RouteRule{}, fmt.Errorf("unsupported action %q", action)
	}
}

func (rule singBoxPatchRule) documentMatch() (RouteMatch, error) {
	match := RouteMatch{
		Domains: rule.Domains, DomainSuffixes: rule.DomainSuffixes,
		DomainKeywords: rule.DomainKeywords, RuleSets: rule.RuleSets,
		ProcessNames: rule.ProcessNames, ProcessPaths: rule.ProcessPaths,
		Ports: rule.Ports, SourcePorts: rule.SourcePorts,
		Protocols: rule.Protocols, IPIsPrivate: rule.IPIsPrivate,
	}
	for _, network := range rule.Networks {
		match.Networks = append(match.Networks, Network(network))
	}
	for _, network := range match.Networks {
		if network != NetworkTCP && network != NetworkUDP {
			return RouteMatch{}, fmt.Errorf("unsupported network %q", network)
		}
	}
	var err error
	if match.IPCIDRs, err = parsePrefixes(rule.IPCIDRs); err != nil {
		return RouteMatch{}, fmt.Errorf("ip_cidr: %w", err)
	}
	if match.SourceIPCIDRs, err = parsePrefixes(rule.SourceIPCIDRs); err != nil {
		return RouteMatch{}, fmt.Errorf("source_ip_cidr: %w", err)
	}
	return match, nil
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, fmt.Errorf("invalid prefix %q", value)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		result = append(result, prefix)
	}
	return result, nil
}
