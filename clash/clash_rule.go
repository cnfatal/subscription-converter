package clash

import (
	"fmt"
	. "github.com/cnfatal/subscription-converter"
	"net/netip"
	"strconv"
	"strings"
)

func clashGroupType(value string) (GroupType, bool) {
	switch strings.ToLower(value) {
	case "select":
		return GroupSelector, true
	case "url-test":
		return GroupURLTest, true
	case "fallback":
		return GroupFallback, true
	case "load-balance":
		return GroupLoadBalance, true
	case "relay":
		return GroupRelay, true
	default:
		return "", false
	}
}

func decodeClashRule(line string) (RouteRule, string, string) {
	parts := SplitRule(line)
	if len(parts) < 2 {
		return RouteRule{}, "", fmt.Sprintf("invalid rule skipped: %q", line)
	}
	typeName := strings.ToUpper(parts[0])
	if typeName == "MATCH" || typeName == "FINAL" {
		return RouteRule{}, parts[1], ""
	}
	if len(parts) < 3 {
		return RouteRule{}, "", fmt.Sprintf("invalid rule skipped: %q", line)
	}
	rule := RouteRule{Action: routeAction(parts[2])}
	value := parts[1]
	switch typeName {
	case "DOMAIN":
		rule.Match.Domains = []string{value}
	case "DOMAIN-SUFFIX":
		rule.Match.DomainSuffixes = []string{value}
	case "DOMAIN-KEYWORD":
		rule.Match.DomainKeywords = []string{value}
	case "RULE-SET":
		rule.Match.RuleSets = []string{value}
	case "GEOIP":
		rule.Match.GeoIPCodes = []string{strings.ToLower(value)}
	case "GEOSITE":
		rule.Match.GeoSiteCodes = []string{strings.ToLower(value)}
	case "IP-CIDR", "IP-CIDR6":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return RouteRule{}, "", fmt.Sprintf("rule %s,%s skipped: invalid CIDR", typeName, value)
		}
		rule.Match.IPCIDRs = []netip.Prefix{prefix}
	case "SRC-IP-CIDR":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return RouteRule{}, "", fmt.Sprintf("rule %s,%s skipped: invalid CIDR", typeName, value)
		}
		rule.Match.SourceIPCIDRs = []netip.Prefix{prefix}
	case "PROCESS-NAME":
		rule.Match.ProcessNames = []string{value}
	case "PROCESS-PATH":
		rule.Match.ProcessPaths = []string{value}
	case "NETWORK":
		network := Network(strings.ToLower(value))
		if network != NetworkTCP && network != NetworkUDP {
			return RouteRule{}, "", fmt.Sprintf("rule %s,%s skipped: unsupported network", typeName, value)
		}
		rule.Match.Networks = []Network{network}
	case "DST-PORT", "SRC-PORT":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return RouteRule{}, "", fmt.Sprintf("rule %s,%s skipped: invalid port", typeName, value)
		}
		if typeName == "DST-PORT" {
			rule.Match.Ports = []uint16{uint16(port)}
		} else {
			rule.Match.SourcePorts = []uint16{uint16(port)}
		}
	default:
		return RouteRule{}, "", fmt.Sprintf("rule %s,%s skipped: unsupported rule type", typeName, value)
	}
	return rule, "", ""
}

func routeAction(policy string) RouteAction {
	if strings.EqualFold(policy, "REJECT") || strings.EqualFold(policy, "REJECT-DROP") {
		return RouteAction{Type: RouteActionReject}
	}
	return RouteAction{Type: RouteActionRoute, Target: policy}
}
