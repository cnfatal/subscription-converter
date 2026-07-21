package subscriptionconverter

import (
	"fmt"
	"net/netip"
	"strings"

	"sigs.k8s.io/yaml"
)

func decodeSingBoxPatch(data []byte) (DocumentPatch, error) {
	var input SingBoxConfig
	if err := yaml.UnmarshalStrict(data, &input); err != nil {
		return DocumentPatch{}, fmt.Errorf("decode sing-box patch: %w", err)
	}
	if input.Route == nil {
		return DocumentPatch{}, fmt.Errorf("sing-box patch contains no supported sections")
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
	return DocumentPatch{Route: route}, nil
}

func (ruleSet SingBoxRuleSet) documentRuleSet() (RuleSet, error) {
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
	if err := validateRuleSet(result); err != nil {
		return RuleSet{}, err
	}
	return result, nil
}

func (rule SingBoxRouteRule) documentRouteRule() (RouteRule, error) {
	match, err := rule.documentMatch()
	if err != nil {
		return RouteRule{}, err
	}
	action := rule.Action
	if action == "" {
		action = SingBoxRuleActionRoute
	}
	switch action {
	case SingBoxRuleActionRoute:
		if rule.Outbound == "" {
			return RouteRule{}, fmt.Errorf("route action requires outbound")
		}
		return RouteRule{Match: match, Action: RouteAction{Type: RouteActionRoute, Target: rule.Outbound}}, nil
	case SingBoxRuleActionReject:
		if rule.Outbound != "" {
			return RouteRule{}, fmt.Errorf("reject action cannot contain outbound")
		}
		return RouteRule{Match: match, Action: RouteAction{Type: RouteActionReject}}, nil
	default:
		return RouteRule{}, fmt.Errorf("unsupported action %q", action)
	}
}

func (rule SingBoxRouteRule) documentMatch() (RouteMatch, error) {
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
