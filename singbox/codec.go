package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	. "github.com/cnfatal/subscription-converter"
)

type SingBoxCodec struct{}

var _ Codec = SingBoxCodec{}

func (SingBoxCodec) Format() string { return "sing-box" }

func (SingBoxCodec) Recognize(data []byte) Recognition {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed[0] != '{' {
		return RecognitionNone
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return RecognitionPossible
	}
	for _, key := range []string{"inbounds", "outbounds", "endpoints", "route", "dns", "experimental"} {
		if _, exists := root[key]; exists {
			return RecognitionExact
		}
	}
	return RecognitionNone
}

func (SingBoxCodec) Decode([]byte, DecodeOptions) (*Document, []string, error) {
	return nil, nil, ErrDecodeUnsupported
}

func (SingBoxCodec) Encode(doc Document, _ EncodeOptions) ([]byte, []string, error) {
	var warnings []string
	inbounds := effectiveInbounds(doc)
	if err := ValidateInbounds(inbounds); err != nil {
		return nil, warnings, fmt.Errorf("encode sing-box inbounds: %w", err)
	}
	for _, inbound := range inbounds {
		if inbound.Type == InboundTUN || len(inbound.Users) > 0 {
			continue
		}
		address, _ := netip.ParseAddr(inbound.Listen)
		if !address.IsLoopback() {
			warnings = append(warnings, fmt.Sprintf("inbound %q listens on non-loopback address %s without authentication", inbound.Tag, inbound.Listen))
		}
	}
	tags := buildTags(doc)
	dns := doc.DNS
	if len(dns.Servers) == 0 {
		dns = DefaultDocument().DNS
	}
	resolver := doc.Route.DefaultDomainResolver
	if resolver == "" {
		resolver = dns.Final
	}
	if resolver == "" && len(dns.Servers) > 0 {
		resolver = dns.Servers[0].Tag
	}

	outbounds := make([]map[string]any, 0, len(doc.Nodes)+len(doc.Groups)+3)
	selectable := make([]string, 0, len(doc.Nodes)+len(doc.Groups))
	nodeOutbounds := make(map[string]map[string]any, len(doc.Nodes))
	for _, node := range doc.Nodes {
		outbound, err := convertNode(node, tags[node.Name], resolver)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		outbounds = append(outbounds, outbound)
		nodeOutbounds[node.Name] = outbound
		selectable = append(selectable, tags[node.Name])
	}
	directOutbound := map[string]any{"type": "direct", "tag": "direct"}
	if dns.DirectResolver != "" {
		directOutbound["domain_resolver"] = dns.DirectResolver
	}
	outbounds = append(outbounds, directOutbound)
	outbounds = append(outbounds, map[string]any{"type": "block", "tag": "reject"})

	var groupTags []string
	for _, group := range doc.Groups {
		if group.Type == GroupRelay {
			relayOutbounds, relayWarnings := convertRelayGroup(group, tags, nodeOutbounds)
			warnings = append(warnings, relayWarnings...)
			if len(relayOutbounds) == 0 {
				continue
			}
			outbounds = append(outbounds, relayOutbounds...)
			groupTags = append(groupTags, tags[group.Name])
			continue
		}
		outbound, groupWarnings := convertGroup(group, tags)
		warnings = append(warnings, groupWarnings...)
		if outbound == nil {
			continue
		}
		outbounds = append(outbounds, outbound)
		groupTags = append(groupTags, tags[group.Name])
	}
	if len(groupTags) > 0 {
		selectable = groupTags
	}
	if len(selectable) == 0 {
		return nil, warnings, fmt.Errorf("no supported proxies remain after conversion")
	}
	outbounds = append(outbounds, map[string]any{
		"type": "selector", "tag": "proxy", "outbounds": selectable,
	})

	routeRules := []SingBoxRouteRule{
		{Action: SingBoxRuleActionSniff},
		{Protocols: []string{"dns"}, Action: SingBoxRuleActionHijackDNS},
		{IPIsPrivate: true, Outbound: "direct"},
	}
	for _, rule := range doc.Route.Rules {
		converted, warning := convertRouteRule(rule, tags)
		if warning != "" {
			warnings = append(warnings, warning)
			continue
		}
		routeRules = append(routeRules, converted)
	}
	final := policyTag(doc.Route.Final, tags)
	if final == "" || final == "reject" {
		final = "proxy"
	}

	logConfig := doc.Log
	if logConfig.Level == "" {
		logConfig = DefaultDocument().Log
	}
	route := SingBoxRouteConfig{
		Rules: routeRules, Final: final,
		AutoDetectInterface:   doc.Route.AutoDetectInterface,
		DefaultDomainResolver: resolver,
	}
	route.RuleSets = encodeRuleSets(doc.Route.RuleSets, doc.Route.Rules, dns, tags)
	config := map[string]any{
		"log":       encodeLog(logConfig),
		"dns":       encodeDNS(dns, tags),
		"outbounds": outbounds,
		"route":     route,
	}
	if len(inbounds) > 0 {
		encodedInbounds := make([]map[string]any, 0, len(inbounds))
		for _, inbound := range inbounds {
			encodedInbounds = append(encodedInbounds, encodeInbound(inbound))
		}
		config["inbounds"] = encodedInbounds
	}
	if dns.StoreFakeIP {
		config["experimental"] = map[string]any{
			"cache_file": map[string]any{"enabled": true, "store_fakeip": true},
		}
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, warnings, fmt.Errorf("encode sing-box JSON: %w", err)
	}
	return append(data, '\n'), warnings, nil
}

func effectiveInbounds(doc Document) []Inbound {
	if doc.Inbounds != nil || !doc.TUN.Enabled {
		return doc.Inbounds
	}
	tun := doc.TUN
	return []Inbound{{Type: InboundTUN, Tag: tun.Tag, TUN: &TUNConfig{
		Addresses: tun.Addresses, AutoRoute: tun.AutoRoute, StrictRoute: tun.StrictRoute,
		Stack: tun.Stack, MTU: tun.MTU,
	}}}
}

func buildTags(doc Document) map[string]string {
	result := map[string]string{}
	used := map[string]struct{}{"direct": {}, "proxy": {}, "reject": {}}
	allocate := func(name string) {
		if _, exists := result[name]; exists {
			return
		}
		candidate := name
		if strings.EqualFold(candidate, "DIRECT") || strings.EqualFold(candidate, "REJECT") || strings.EqualFold(candidate, "proxy") || candidate == "" {
			candidate = name + "-proxy"
		}
		base := candidate
		for index := 2; ; index++ {
			if _, exists := used[candidate]; !exists {
				break
			}
			candidate = fmt.Sprintf("%s-%d", base, index)
		}
		used[candidate] = struct{}{}
		result[name] = candidate
	}
	for _, node := range doc.Nodes {
		allocate(node.Name)
	}
	for _, group := range doc.Groups {
		allocate(group.Name)
	}
	return result
}

func convertNode(node Node, tag, resolver string) (map[string]any, error) {
	result := map[string]any{"tag": tag, "server": node.Server}
	if node.Port > 0 {
		result["server_port"] = node.Port
	}
	if net.ParseIP(node.Server) == nil && resolver != "" {
		result["domain_resolver"] = resolver
	}

	switch node.Type {
	case ProtocolShadowsocks:
		if node.Shadowsocks == nil {
			return nil, missingNodeOptions(node)
		}
		options := node.Shadowsocks
		result["type"], result["method"], result["password"] = "shadowsocks", options.Method, options.Password
		putString(result, "plugin", options.Plugin)
		putString(result, "plugin_options", options.PluginOptions)
	case ProtocolVMess:
		if node.VMess == nil {
			return nil, missingNodeOptions(node)
		}
		options := node.VMess
		result["type"], result["uuid"] = "vmess", options.UUID
		putString(result, "security", options.Security)
		if options.AlterID != 0 {
			result["alter_id"] = options.AlterID
		}
		if options.GlobalPadding {
			result["global_padding"] = true
		}
		if options.AuthenticatedLength {
			result["authenticated_length"] = true
		}
	case ProtocolVLESS:
		if node.VLESS == nil {
			return nil, missingNodeOptions(node)
		}
		if encryption := strings.TrimSpace(node.VLESS.Encryption); encryption != "" && !strings.EqualFold(encryption, "none") {
			return nil, fmt.Errorf("proxy %q skipped: VLESS encryption %q is not supported by sing-box", node.Name, encryption)
		}
		result["type"], result["uuid"] = "vless", node.VLESS.UUID
		putString(result, "flow", node.VLESS.Flow)
	case ProtocolTrojan:
		if node.Trojan == nil {
			return nil, missingNodeOptions(node)
		}
		result["type"], result["password"] = "trojan", node.Trojan.Password
	case ProtocolHysteria2:
		if node.Hysteria2 == nil {
			return nil, missingNodeOptions(node)
		}
		options := node.Hysteria2
		result["type"], result["password"] = "hysteria2", options.Password
		if len(options.ServerPorts) > 0 {
			result["server_ports"] = options.ServerPorts
		}
		putString(result, "hop_interval", options.HopInterval)
		putString(result, "hop_interval_max", options.HopIntervalMax)
		if options.UpMbps > 0 {
			result["up_mbps"] = options.UpMbps
		}
		if options.DownMbps > 0 {
			result["down_mbps"] = options.DownMbps
		}
		if options.ObfsPassword != "" {
			result["obfs"] = map[string]any{"type": "salamander", "password": options.ObfsPassword}
		}
	case ProtocolAnyTLS:
		if node.AnyTLS == nil {
			return nil, missingNodeOptions(node)
		}
		options := node.AnyTLS
		result["type"], result["password"] = "anytls", options.Password
		putString(result, "idle_session_check_interval", options.IdleSessionCheckInterval)
		putString(result, "idle_session_timeout", options.IdleSessionTimeout)
		if options.MinIdleSession > 0 {
			result["min_idle_session"] = options.MinIdleSession
		}
	case ProtocolTUIC:
		if node.TUIC == nil {
			return nil, missingNodeOptions(node)
		}
		result["type"], result["uuid"], result["password"] = "tuic", node.TUIC.UUID, node.TUIC.Password
		putString(result, "congestion_control", node.TUIC.CongestionControl)
		putString(result, "udp_relay_mode", node.TUIC.UDPRelayMode)
	case ProtocolSOCKS:
		if node.SOCKS == nil {
			return nil, missingNodeOptions(node)
		}
		result["type"] = "socks"
		putString(result, "username", node.SOCKS.Username)
		putString(result, "password", node.SOCKS.Password)
	case ProtocolHTTP:
		if node.HTTP == nil {
			return nil, missingNodeOptions(node)
		}
		result["type"] = "http"
		putString(result, "username", node.HTTP.Username)
		putString(result, "password", node.HTTP.Password)
	default:
		return nil, fmt.Errorf("proxy %q skipped: unsupported protocol %q", node.Name, node.Type)
	}

	if node.TLS != nil {
		result["tls"] = encodeTLS(*node.TLS)
	}
	if node.Transport != nil {
		result["transport"] = encodeTransport(*node.Transport)
	}
	return result, nil
}

func missingNodeOptions(node Node) error {
	return fmt.Errorf("proxy %q skipped: %s options are missing", node.Name, node.Type)
}

func encodeTLS(tls TLSOptions) map[string]any {
	result := map[string]any{"enabled": true}
	putString(result, "server_name", tls.ServerName)
	if tls.Insecure {
		result["insecure"] = true
	}
	if len(tls.ALPN) > 0 {
		result["alpn"] = tls.ALPN
	}
	if tls.Fingerprint != "" {
		result["utls"] = map[string]any{"enabled": true, "fingerprint": tls.Fingerprint}
	}
	if tls.Reality != nil {
		reality := map[string]any{"enabled": true, "public_key": tls.Reality.PublicKey}
		putString(reality, "short_id", tls.Reality.ShortID)
		result["reality"] = reality
	}
	return result
}

func encodeTransport(transport Transport) map[string]any {
	result := map[string]any{"type": transport.Type}
	switch transport.Type {
	case TransportWebSocket:
		putString(result, "path", transport.Path)
		if len(transport.Headers) > 0 {
			result["headers"] = transport.Headers
		}
		if transport.MaxEarlyData > 0 {
			result["max_early_data"] = transport.MaxEarlyData
		}
		putString(result, "early_data_header_name", transport.EarlyDataHeaderName)
	case TransportGRPC:
		putString(result, "service_name", transport.ServiceName)
	case TransportHTTP:
		if len(transport.Hosts) > 0 {
			result["host"] = transport.Hosts
		}
		putString(result, "path", transport.Path)
	case TransportHTTPUpgrade:
		putString(result, "path", transport.Path)
		if len(transport.Headers) > 0 {
			result["headers"] = transport.Headers
		}
	}
	return result
}

func convertGroup(group Group, tags map[string]string) (map[string]any, []string) {
	var warnings []string
	members := make([]string, 0, len(group.Members))
	for _, member := range group.Members {
		switch {
		case strings.EqualFold(member, "DIRECT"):
			members = append(members, "direct")
		case strings.EqualFold(member, "REJECT"):
			members = append(members, "reject")
		case tags[member] != "":
			members = append(members, tags[member])
		default:
			warnings = append(warnings, fmt.Sprintf("group %q: unknown member %q omitted", group.Name, member))
		}
	}
	if len(members) == 0 {
		warnings = append(warnings, fmt.Sprintf("group %q skipped: no usable members", group.Name))
		return nil, warnings
	}
	result := map[string]any{"tag": tags[group.Name], "outbounds": members}
	switch group.Type {
	case GroupSelector:
		result["type"] = "selector"
	case GroupURLTest:
		result["type"] = "urltest"
		putString(result, "url", group.URL)
		if group.Interval > 0 {
			result["interval"] = group.Interval.String()
		}
		if group.Tolerance > 0 {
			result["tolerance"] = group.Tolerance
		}
	case GroupFallback:
		result["type"] = "urltest"
		putString(result, "url", group.URL)
		if group.Interval > 0 {
			result["interval"] = group.Interval.String()
		}
		if group.Tolerance > 0 {
			result["tolerance"] = group.Tolerance
		}
		warnings = append(warnings, fmt.Sprintf("group %q: fallback approximated with urltest; ordered failover is not available in sing-box", group.Name))
	case GroupLoadBalance:
		result["type"] = "selector"
		warnings = append(warnings, fmt.Sprintf("group %q: load-balance strategy %q downgraded to selector; sing-box has no equivalent balancer", group.Name, group.Strategy))
	default:
		warnings = append(warnings, fmt.Sprintf("group %q skipped: unsupported type %q", group.Name, group.Type))
		return nil, warnings
	}
	return result, warnings
}

func convertRelayGroup(group Group, tags map[string]string, nodes map[string]map[string]any) ([]map[string]any, []string) {
	if len(group.Members) == 0 {
		return nil, []string{fmt.Sprintf("group %q skipped: relay has no members", group.Name)}
	}
	result := make([]map[string]any, 0, len(group.Members))
	previous := ""
	for index, member := range group.Members {
		template := nodes[member]
		if template == nil {
			return nil, []string{fmt.Sprintf("group %q skipped: relay member %q must be a proxy node", group.Name, member)}
		}
		outbound := make(map[string]any, len(template)+1)
		for key, value := range template {
			outbound[key] = value
		}
		tag := fmt.Sprintf("%s-hop-%d", tags[group.Name], index+1)
		if index == len(group.Members)-1 {
			tag = tags[group.Name]
		}
		outbound["tag"] = tag
		if previous != "" {
			outbound["detour"] = previous
		}
		previous = tag
		result = append(result, outbound)
	}
	return result, nil
}

func convertRouteRule(rule RouteRule, tags map[string]string) (SingBoxRouteRule, string) {
	result, warning := convertRouteMatch(rule.Match)
	if warning != "" {
		return SingBoxRouteRule{}, warning
	}
	if rule.Action.Type == RouteActionReject {
		result.Action = SingBoxRuleActionReject
	} else {
		policy := policyTag(rule.Action.Target, tags)
		if policy == "" {
			return SingBoxRouteRule{}, fmt.Sprintf("route rule skipped: unknown policy %q", rule.Action.Target)
		}
		result.Outbound = policy
	}
	return result, ""
}

func convertRouteMatch(match RouteMatch) (SingBoxRouteRule, string) {
	ruleSetTags := append([]string(nil), match.RuleSets...)
	for _, code := range match.GeoIPCodes {
		if code = strings.ToLower(strings.TrimSpace(code)); code != "" {
			ruleSetTags = append(ruleSetTags, "geoip-"+code)
		}
	}
	for _, code := range match.GeoSiteCodes {
		if code = strings.ToLower(strings.TrimSpace(code)); code != "" {
			ruleSetTags = append(ruleSetTags, "geosite-"+code)
		}
	}
	networks := make([]SingBoxNetwork, len(match.Networks))
	for index, network := range match.Networks {
		networks[index] = SingBoxNetwork(network)
	}
	return SingBoxRouteRule{
		Domains: match.Domains, DomainSuffixes: match.DomainSuffixes,
		DomainKeywords: match.DomainKeywords, RuleSets: uniqueStrings(ruleSetTags),
		IPCIDRs: prefixStrings(match.IPCIDRs), SourceIPCIDRs: prefixStrings(match.SourceIPCIDRs),
		ProcessNames: match.ProcessNames, ProcessPaths: match.ProcessPaths,
		Networks: networks, Ports: match.Ports, SourcePorts: match.SourcePorts,
		Protocols: match.Protocols, IPIsPrivate: match.IPIsPrivate,
	}, ""
}

func encodeRuleSets(ruleSets []RuleSet, rules []RouteRule, dns DNSConfig, tags map[string]string) []SingBoxRuleSet {
	seen := make(map[string]struct{}, len(ruleSets))
	result := make([]SingBoxRuleSet, 0, len(ruleSets))
	for _, ruleSet := range ruleSets {
		encoded := SingBoxRuleSet{
			Type: SingBoxRuleSetType(ruleSet.Type), Tag: ruleSet.Tag,
			Format: SingBoxRuleSetFormat(ruleSet.Format),
			URL:    ruleSet.URL, Path: ruleSet.Path, UpdateInterval: ruleSet.UpdateInterval,
			DownloadDetour: policyTag(ruleSet.DownloadDetour, tags),
		}
		if encoded.DownloadDetour == "" {
			encoded.DownloadDetour = ruleSet.DownloadDetour
		}
		for _, match := range ruleSet.Rules {
			encodedMatch, _ := convertRouteMatch(match)
			encoded.Rules = append(encoded.Rules, encodedMatch)
		}
		result = append(result, encoded)
		seen[ruleSet.Tag] = struct{}{}
	}
	for _, rule := range rules {
		for _, code := range rule.Match.GeoIPCodes {
			code = strings.ToLower(strings.TrimSpace(code))
			if code == "" {
				continue
			}
			tag := "geoip-" + code
			if _, exists := seen[tag]; exists {
				continue
			}
			seen[tag] = struct{}{}
			result = append(result, SingBoxRuleSet{
				Type: SingBoxRuleSetType(RuleSetRemote), Tag: tag,
				Format:         SingBoxRuleSetFormat(RuleSetFormatBinary),
				URL:            "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/" + tag + ".srs",
				DownloadDetour: "proxy",
			})
		}
		for _, code := range rule.Match.GeoSiteCodes {
			code = strings.ToLower(strings.TrimSpace(code))
			if code == "" {
				continue
			}
			tag := "geosite-" + code
			if _, exists := seen[tag]; exists {
				continue
			}
			seen[tag] = struct{}{}
			result = append(result, SingBoxRuleSet{
				Type: SingBoxRuleSetType(RuleSetRemote), Tag: tag,
				Format:         SingBoxRuleSetFormat(RuleSetFormatBinary),
				URL:            "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-" + url.PathEscape(code) + ".srs",
				DownloadDetour: "proxy",
			})
		}
		for _, tag := range rule.Match.RuleSets {
			result = appendGeneratedRuleSetTag(result, seen, tag)
		}
	}
	for _, ruleSet := range ruleSets {
		for _, match := range ruleSet.Rules {
			result = appendGeneratedGeoRuleSets(result, seen, match)
		}
	}
	for _, rule := range dns.Rules {
		for _, tag := range rule.Match.RuleSets {
			result = appendGeneratedRuleSetTag(result, seen, tag)
		}
	}
	return result
}

func appendGeneratedGeoRuleSets(result []SingBoxRuleSet, seen map[string]struct{}, match RouteMatch) []SingBoxRuleSet {
	for _, code := range match.GeoIPCodes {
		result = appendGeneratedRuleSetTag(result, seen, "geoip-"+strings.ToLower(strings.TrimSpace(code)))
	}
	for _, code := range match.GeoSiteCodes {
		result = appendGeneratedRuleSetTag(result, seen, "geosite-"+strings.ToLower(strings.TrimSpace(code)))
	}
	return result
}

func appendGeneratedRuleSetTag(result []SingBoxRuleSet, seen map[string]struct{}, tag string) []SingBoxRuleSet {
	if tag == "" {
		return result
	}
	if _, exists := seen[tag]; exists {
		return result
	}
	var repository string
	switch {
	case strings.HasPrefix(tag, "geoip-"):
		repository = "sing-geoip"
	case strings.HasPrefix(tag, "geosite-"):
		repository = "sing-geosite"
	default:
		return result
	}
	seen[tag] = struct{}{}
	return append(result, SingBoxRuleSet{
		Type: SingBoxRuleSetType(RuleSetRemote), Tag: tag,
		Format:         SingBoxRuleSetFormat(RuleSetFormatBinary),
		URL:            "https://raw.githubusercontent.com/SagerNet/" + repository + "/rule-set/" + url.PathEscape(tag) + ".srs",
		DownloadDetour: "proxy",
	})
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func encodeLog(config LogConfig) map[string]any {
	return map[string]any{"level": config.Level, "timestamp": config.Timestamp}
}

func encodeDNS(config DNSConfig, tags map[string]string) map[string]any {
	servers := make([]map[string]any, 0, len(config.Servers))
	for _, server := range config.Servers {
		item := map[string]any{"type": server.Type, "tag": server.Tag}
		putString(item, "server", server.Server)
		if server.ServerPort > 0 {
			item["server_port"] = server.ServerPort
		}
		putString(item, "path", server.Path)
		putString(item, "inet4_range", server.Inet4Range)
		putString(item, "inet6_range", server.Inet6Range)
		if server.Detour != "" {
			detour := policyTag(server.Detour, tags)
			if detour == "" {
				detour = server.Detour
			}
			item["detour"] = detour
		}
		servers = append(servers, item)
	}
	rules := make([]map[string]any, 0, len(config.Rules))
	for _, rule := range config.Rules {
		action := rule.Action
		if action == "" {
			action = DNSActionRoute
		}
		item := map[string]any{"action": action}
		putString(item, "server", rule.Server)
		putStrings(item, "domain", rule.Match.Domains)
		putStrings(item, "domain_suffix", rule.Match.DomainSuffixes)
		putStrings(item, "domain_keyword", rule.Match.DomainKeywords)
		putStrings(item, "rule_set", rule.Match.RuleSets)
		putStrings(item, "outbound", rule.Match.OutboundTags)
		putStrings(item, "ip_cidr", prefixStrings(rule.Match.IPCIDRs))
		if rule.MatchResponse {
			item["match_response"] = true
		}
		if rule.Invert {
			item["invert"] = true
		}
		rules = append(rules, item)
	}
	result := map[string]any{"servers": servers}
	putString(result, "final", config.Final)
	if config.Strategy != "" && config.Strategy != DNSStrategyDefault {
		result["strategy"] = config.Strategy
	}
	if len(rules) > 0 {
		result["rules"] = rules
	}
	if config.DisableCache {
		result["disable_cache"] = true
	}
	if config.DisableExpire {
		result["disable_expire"] = true
	}
	return result
}

func encodeInbound(inbound Inbound) map[string]any {
	result := map[string]any{"type": inbound.Type, "tag": inbound.Tag}
	if inbound.Type == InboundTUN {
		config := inbound.TUN
		result["address"] = prefixStrings(config.Addresses)
		result["auto_route"] = config.AutoRoute
		result["strict_route"] = config.StrictRoute
		if config.Stack != "" {
			result["stack"] = config.Stack
		}
		if config.MTU > 0 {
			result["mtu"] = config.MTU
		}
		return result
	}
	result["listen"] = inbound.Listen
	result["listen_port"] = inbound.ListenPort
	if len(inbound.Users) > 0 {
		result["users"] = inbound.Users
	}
	if inbound.SetSystemProxy {
		result["set_system_proxy"] = true
	}
	return result
}

func policyTag(policy string, tags map[string]string) string {
	switch {
	case strings.EqualFold(policy, "DIRECT"):
		return "direct"
	case strings.EqualFold(policy, "REJECT"), strings.EqualFold(policy, "REJECT-DROP"):
		return "reject"
	case strings.EqualFold(policy, "proxy"):
		return "proxy"
	default:
		return tags[policy]
	}
}

func prefixStrings(values []netip.Prefix) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func putString(target map[string]any, key, value string) {
	if value != "" {
		target[key] = value
	}
}

func putStrings(target map[string]any, key string, values []string) {
	if len(values) > 0 {
		target[key] = values
	}
}
