package clash

import (
	"fmt"
	. "github.com/cnfatal/subscription-converter"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func (c ClashDNSConfig) documentDNS() (DNSConfig, []string) {
	config := DNSConfig{Strategy: DNSStrategyDefault}
	if !c.IPv6 {
		config.Strategy = DNSStrategyPreferIPv4
	}
	var warnings []string
	serverTags := map[string]string{}
	addServer := func(raw string) string {
		if tag := serverTags[raw]; tag != "" {
			return tag
		}
		server, err := parseClashDNSServer(raw, fmt.Sprintf("dns-%d", len(config.Servers)+1))
		if err != nil {
			warnings = append(warnings, err.Error())
			return ""
		}
		config.Servers = append(config.Servers, server)
		serverTags[raw] = server.Tag
		return server.Tag
	}
	for _, raw := range c.NameServers {
		if tag := addServer(raw); config.Final == "" {
			config.Final = tag
		}
	}
	primary := config.Final
	for _, raw := range c.DefaultNameServers {
		addServer(raw)
	}
	for _, raw := range c.ProxyServerNameServers {
		if tag := addServer(raw); config.ProxyResolver == "" {
			config.ProxyResolver = tag
		}
	}
	if config.ProxyResolver == "" {
		config.ProxyResolver = primary
	}
	for _, raw := range c.DirectNameServers {
		if tag := addServer(raw); config.DirectResolver == "" {
			config.DirectResolver = tag
		}
	}
	patterns := make([]string, 0, len(c.NameServerPolicy))
	for pattern := range c.NameServerPolicy {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	for _, pattern := range patterns {
		servers := c.NameServerPolicy[pattern]
		if len(servers) == 0 {
			continue
		}
		tag := addServer(servers[0])
		if tag == "" {
			continue
		}
		match, ok := dnsPatternMatch(pattern)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("DNS policy %q skipped: unsupported matcher", pattern))
			continue
		}
		config.Rules = append(config.Rules, DNSRule{Match: match, Action: DNSActionRoute, Server: tag})
	}
	if len(c.ProxyServerNameServerPolicy) > 0 {
		warnings = append(warnings, "proxy-server-nameserver-policy cannot be scoped to outbound server resolution in sing-box and was omitted")
	}
	if c.DirectNameServerFollowPolicy {
		warnings = append(warnings, "direct-nameserver-follow-policy has no exact sing-box equivalent; direct-nameserver takes precedence")
	}

	fallbackTag := ""
	for _, raw := range c.Fallback {
		if tag := addServer(raw); fallbackTag == "" {
			fallbackTag = tag
		}
	}
	if fallbackTag != "" {
		geoIPEnabled := true
		if c.FallbackFilter.GeoIP != nil {
			geoIPEnabled = *c.FallbackFilter.GeoIP
		}
		if strings.EqualFold(c.EnhancedMode, "fake-ip") {
			warnings = append(warnings, "Clash DNS fallback selection cannot be represented behind the sing-box FakeIP server and was omitted")
		} else {
			for _, pattern := range append(append([]string(nil), c.FallbackFilter.Domains...), geositePatterns(c.FallbackFilter.GeoSite)...) {
				if match, ok := dnsPatternMatch(pattern); ok {
					config.Rules = append(config.Rules, DNSRule{Match: match, Action: DNSActionRoute, Server: fallbackTag})
				}
			}
			responseMatch := DNSMatch{}
			for _, value := range c.FallbackFilter.IPCIDRs {
				prefix, err := netip.ParsePrefix(value)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("DNS fallback CIDR %q skipped: invalid CIDR", value))
					continue
				}
				responseMatch.IPCIDRs = append(responseMatch.IPCIDRs, prefix)
			}
			if len(responseMatch.IPCIDRs) > 0 {
				config.Rules = append(config.Rules, DNSRule{Match: responseMatch, Action: DNSActionRoute, Server: fallbackTag})
			}
			if geoIPEnabled {
				code := strings.ToLower(FirstNonEmpty(c.FallbackFilter.GeoIPCode, "cn"))
				config.Rules = append(config.Rules, DNSRule{
					Match: DNSMatch{RuleSets: []string{"geoip-" + code}}, Action: DNSActionRoute,
					Server: fallbackTag, Invert: true,
				})
			}
		}
	}

	if strings.EqualFold(c.EnhancedMode, "fake-ip") {
		fakeTag := "fakeip"
		config.Servers = append(config.Servers, DNSServer{
			Tag: fakeTag, Type: DNSServerFakeIP,
			Inet4Range: FirstNonEmpty(c.FakeIPRange, "198.18.0.0/15"), Inet6Range: c.FakeIPRange6,
		})
		switch strings.ToLower(c.FakeIPFilterMode) {
		case "rule":
			for index, line := range c.FakeIPFilter {
				rule, final, warning := decodeClashRule(line)
				if warning != "" {
					warnings = append(warnings, fmt.Sprintf("FakeIP rule #%d skipped: %s", index+1, warning))
					continue
				}
				target := final
				match := DNSMatch{}
				if final == "" {
					target = rule.Action.Target
					match = dnsMatchFromRoute(rule.Match)
				}
				server := primary
				if strings.EqualFold(target, "fake-ip") {
					server = fakeTag
				} else if !strings.EqualFold(target, "real-ip") {
					warnings = append(warnings, fmt.Sprintf("FakeIP rule #%d skipped: unsupported action %q", index+1, target))
					continue
				}
				config.Rules = append(config.Rules, DNSRule{Match: match, Action: DNSActionRoute, Server: server})
			}
		case "whitelist":
			for _, pattern := range c.FakeIPFilter {
				if match, ok := dnsPatternMatch(pattern); ok {
					config.Rules = append(config.Rules, DNSRule{Match: match, Action: DNSActionRoute, Server: fakeTag})
				} else {
					warnings = append(warnings, fmt.Sprintf("FakeIP filter %q skipped: unsupported matcher", pattern))
				}
			}
		case "", "blacklist":
			for _, pattern := range c.FakeIPFilter {
				if match, ok := dnsPatternMatch(pattern); ok {
					config.Rules = append(config.Rules, DNSRule{Match: match, Action: DNSActionRoute, Server: primary})
				} else {
					warnings = append(warnings, fmt.Sprintf("FakeIP filter %q skipped: unsupported matcher", pattern))
				}
			}
			config.Rules = append(config.Rules, DNSRule{Action: DNSActionRoute, Server: fakeTag})
		default:
			warnings = append(warnings, fmt.Sprintf("unsupported fake-ip-filter-mode %q; blacklist was used", c.FakeIPFilterMode))
			config.Rules = append(config.Rules, DNSRule{Action: DNSActionRoute, Server: fakeTag})
		}
		config.Final = primary
		config.StoreFakeIP = true
	}
	return config, warnings
}

func dnsMatchFromRoute(match RouteMatch) DNSMatch {
	ruleSets := append([]string(nil), match.RuleSets...)
	for _, code := range match.GeoSiteCodes {
		if code = strings.ToLower(strings.TrimSpace(code)); code != "" {
			ruleSets = append(ruleSets, "geosite-"+code)
		}
	}
	return DNSMatch{
		Domains: match.Domains, DomainSuffixes: match.DomainSuffixes,
		DomainKeywords: match.DomainKeywords, RuleSets: uniqueStrings(ruleSets),
	}
}

func geositePatterns(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, "geosite:"+value)
		}
	}
	return result
}

func parseClashDNSServer(raw, tag string) (DNSServer, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DNSServer{}, fmt.Errorf("empty Clash DNS server skipped")
	}
	if strings.EqualFold(raw, "system") {
		return DNSServer{Tag: tag, Type: DNSServerLocal}, nil
	}
	value := raw
	if !strings.Contains(value, "://") {
		value = "udp://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return DNSServer{}, fmt.Errorf("DNS server %q skipped: %w", raw, err)
	}
	types := map[string]DNSServerType{
		"udp": DNSServerUDP, "tcp": DNSServerTCP, "tls": DNSServerTLS,
		"quic": DNSServerQUIC, "https": DNSServerHTTPS, "h3": DNSServerHTTP3,
		"dhcp": DNSServerDHCP,
	}
	serverType, ok := types[strings.ToLower(parsed.Scheme)]
	if !ok {
		return DNSServer{}, fmt.Errorf("DNS server %q skipped: unsupported scheme %q", raw, parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" && serverType == DNSServerDHCP {
		host = parsed.Host
	}
	server := DNSServer{Tag: tag, Type: serverType, Server: host, Path: parsed.EscapedPath()}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return DNSServer{}, fmt.Errorf("DNS server %q skipped: invalid port", raw)
		}
		server.ServerPort = uint16(value)
	}
	return server, nil
}

func dnsPatternMatch(pattern string) (DNSMatch, bool) {
	pattern = strings.TrimSpace(pattern)
	lower := strings.ToLower(pattern)
	if after, ok := strings.CutPrefix(lower, "geosite:"); ok && after != "" {
		return DNSMatch{RuleSets: []string{"geosite-" + after}}, true
	}
	if strings.HasPrefix(lower, "rule-set:") && len(pattern) > len("rule-set:") {
		after := pattern[len("rule-set:"):]
		return DNSMatch{RuleSets: []string{after}}, true
	}
	if after, ok := strings.CutPrefix(pattern, "+."); ok {
		return DNSMatch{DomainSuffixes: []string{after}}, true
	}
	if after, ok := strings.CutPrefix(pattern, "*."); ok {
		return DNSMatch{DomainSuffixes: []string{after}}, true
	}
	return DNSMatch{Domains: []string{pattern}}, pattern != ""
}
