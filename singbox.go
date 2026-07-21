package subscriptionconverter

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// SingBoxConfig is the strongly typed sing-box configuration accepted by the
// converter. When used as a patch, currently only Route is merged.
type SingBoxConfig struct {
	Log       *SingBoxLogConfig   `json:"log,omitempty"`
	DNS       *SingBoxDNSConfig   `json:"dns,omitempty"`
	Inbounds  []SingBoxInbound    `json:"inbounds,omitempty"`
	Outbounds []SingBoxOutbound   `json:"outbounds,omitempty"`
	Route     *SingBoxRouteConfig `json:"route,omitempty"`
}

type SingBoxLogConfig struct {
	Level     SingBoxLogLevel `json:"level,omitempty"`
	Timestamp bool            `json:"timestamp,omitempty"`
}

type SingBoxLogLevel string

const (
	SingBoxLogLevelTrace SingBoxLogLevel = "trace"
	SingBoxLogLevelDebug SingBoxLogLevel = "debug"
	SingBoxLogLevelInfo  SingBoxLogLevel = "info"
	SingBoxLogLevelWarn  SingBoxLogLevel = "warn"
	SingBoxLogLevelError SingBoxLogLevel = "error"
)

type SingBoxDNSServer struct {
	Type       SingBoxDNSServerType `json:"type"`
	Tag        string               `json:"tag"`
	Server     string               `json:"server,omitempty"`
	ServerPort uint16               `json:"server_port,omitempty"`
	Path       string               `json:"path,omitempty"`
	Detour     string               `json:"detour,omitempty"`
}

type SingBoxDNSServerType string

const (
	SingBoxDNSLocal SingBoxDNSServerType = "local"
	SingBoxDNSUDP   SingBoxDNSServerType = "udp"
	SingBoxDNSTCP   SingBoxDNSServerType = "tcp"
	SingBoxDNSTLS   SingBoxDNSServerType = "tls"
	SingBoxDNSQUIC  SingBoxDNSServerType = "quic"
	SingBoxDNSHTTPS SingBoxDNSServerType = "https"
)

type SingBoxDNSRule struct {
	Domains        []string `json:"domain,omitempty"`
	DomainSuffixes []string `json:"domain_suffix,omitempty"`
	DomainKeywords []string `json:"domain_keyword,omitempty"`
	RuleSets       []string `json:"rule_set,omitempty"`
	Outbounds      []string `json:"outbound,omitempty"`
	Action         string   `json:"action,omitempty"`
	Server         string   `json:"server,omitempty"`
}

type SingBoxDNSConfig struct {
	Servers       []SingBoxDNSServer `json:"servers,omitempty"`
	Rules         []SingBoxDNSRule   `json:"rules,omitempty"`
	Final         string             `json:"final,omitempty"`
	Strategy      SingBoxDNSStrategy `json:"strategy,omitempty"`
	DisableCache  bool               `json:"disable_cache,omitempty"`
	DisableExpire bool               `json:"disable_expire,omitempty"`
}

type SingBoxDNSStrategy string

const (
	SingBoxDNSPreferIPv4 SingBoxDNSStrategy = "prefer_ipv4"
	SingBoxDNSPreferIPv6 SingBoxDNSStrategy = "prefer_ipv6"
	SingBoxDNSIPv4Only   SingBoxDNSStrategy = "ipv4_only"
	SingBoxDNSIPv6Only   SingBoxDNSStrategy = "ipv6_only"
)

type SingBoxInbound struct {
	Type        SingBoxInboundType `json:"type"`
	Tag         string             `json:"tag,omitempty"`
	Address     []string           `json:"address,omitempty"`
	AutoRoute   bool               `json:"auto_route,omitempty"`
	StrictRoute bool               `json:"strict_route,omitempty"`
	Stack       SingBoxTUNStack    `json:"stack,omitempty"`
	MTU         uint32             `json:"mtu,omitempty"`
}

type SingBoxInboundType string
type SingBoxTUNStack string

const (
	SingBoxInboundTUN SingBoxInboundType = "tun"
	SingBoxTUNSystem  SingBoxTUNStack    = "system"
	SingBoxTUNGVisor  SingBoxTUNStack    = "gvisor"
	SingBoxTUNMixed   SingBoxTUNStack    = "mixed"
)

type SingBoxOutbound struct {
	Type                SingBoxOutboundType `json:"type"`
	Tag                 string              `json:"tag"`
	Server              string              `json:"server,omitempty"`
	ServerPort          uint16              `json:"server_port,omitempty"`
	DomainResolver      string              `json:"domain_resolver,omitempty"`
	Outbounds           []string            `json:"outbounds,omitempty"`
	URL                 string              `json:"url,omitempty"`
	Interval            string              `json:"interval,omitempty"`
	Method              string              `json:"method,omitempty"`
	Password            string              `json:"password,omitempty"`
	Username            string              `json:"username,omitempty"`
	UUID                string              `json:"uuid,omitempty"`
	Security            string              `json:"security,omitempty"`
	AlterID             int                 `json:"alter_id,omitempty"`
	Flow                string              `json:"flow,omitempty"`
	Plugin              string              `json:"plugin,omitempty"`
	PluginOptions       string              `json:"plugin_options,omitempty"`
	GlobalPadding       bool                `json:"global_padding,omitempty"`
	AuthenticatedLength bool                `json:"authenticated_length,omitempty"`
	UpMbps              int                 `json:"up_mbps,omitempty"`
	DownMbps            int                 `json:"down_mbps,omitempty"`
	CongestionControl   string              `json:"congestion_control,omitempty"`
	UDPRelayMode        string              `json:"udp_relay_mode,omitempty"`
	Obfs                *SingBoxObfs        `json:"obfs,omitempty"`
	TLS                 *SingBoxTLS         `json:"tls,omitempty"`
	Transport           *SingBoxTransport   `json:"transport,omitempty"`
}

type SingBoxOutboundType string

const (
	SingBoxOutboundDirect      SingBoxOutboundType = "direct"
	SingBoxOutboundShadowsocks SingBoxOutboundType = "shadowsocks"
	SingBoxOutboundVMess       SingBoxOutboundType = "vmess"
	SingBoxOutboundVLESS       SingBoxOutboundType = "vless"
	SingBoxOutboundTrojan      SingBoxOutboundType = "trojan"
	SingBoxOutboundHysteria2   SingBoxOutboundType = "hysteria2"
	SingBoxOutboundTUIC        SingBoxOutboundType = "tuic"
	SingBoxOutboundSOCKS       SingBoxOutboundType = "socks"
	SingBoxOutboundHTTP        SingBoxOutboundType = "http"
	SingBoxOutboundSelector    SingBoxOutboundType = "selector"
	SingBoxOutboundURLTest     SingBoxOutboundType = "urltest"
)

type SingBoxObfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type SingBoxTLS struct {
	Enabled    bool            `json:"enabled"`
	ServerName string          `json:"server_name,omitempty"`
	Insecure   bool            `json:"insecure,omitempty"`
	ALPN       []string        `json:"alpn,omitempty"`
	UTLS       *SingBoxUTLS    `json:"utls,omitempty"`
	Reality    *SingBoxReality `json:"reality,omitempty"`
}

type SingBoxUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type SingBoxReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type SingBoxTransport struct {
	Type                SingBoxTransportType `json:"type"`
	Path                string               `json:"path,omitempty"`
	Headers             map[string]string    `json:"headers,omitempty"`
	MaxEarlyData        uint32               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string               `json:"early_data_header_name,omitempty"`
	ServiceName         string               `json:"service_name,omitempty"`
	Hosts               []string             `json:"host,omitempty"`
}

type SingBoxTransportType string

const (
	SingBoxTransportWebSocket   SingBoxTransportType = "ws"
	SingBoxTransportGRPC        SingBoxTransportType = "grpc"
	SingBoxTransportHTTP        SingBoxTransportType = "http"
	SingBoxTransportHTTPUpgrade SingBoxTransportType = "httpupgrade"
)

type SingBoxRuleAction string

const (
	SingBoxRuleActionRoute     SingBoxRuleAction = "route"
	SingBoxRuleActionReject    SingBoxRuleAction = "reject"
	SingBoxRuleActionSniff     SingBoxRuleAction = "sniff"
	SingBoxRuleActionHijackDNS SingBoxRuleAction = "hijack-dns"
)

type SingBoxRouteConfig struct {
	RuleSets              []SingBoxRuleSet   `json:"rule_set,omitempty"`
	Rules                 []SingBoxRouteRule `json:"rules"`
	Final                 string             `json:"final,omitempty"`
	AutoDetectInterface   bool               `json:"auto_detect_interface,omitempty"`
	DefaultDomainResolver string             `json:"default_domain_resolver,omitempty"`
}

type SingBoxRuleSet struct {
	Type           SingBoxRuleSetType   `json:"type"`
	Tag            string               `json:"tag"`
	Format         SingBoxRuleSetFormat `json:"format,omitempty"`
	URL            string               `json:"url,omitempty"`
	Path           string               `json:"path,omitempty"`
	UpdateInterval string               `json:"update_interval,omitempty"`
	DownloadDetour string               `json:"download_detour,omitempty"`
	Rules          []SingBoxRouteRule   `json:"rules,omitempty"`
}

type SingBoxRuleSetType string
type SingBoxRuleSetFormat string

const (
	SingBoxRuleSetInline SingBoxRuleSetType = "inline"
	SingBoxRuleSetLocal  SingBoxRuleSetType = "local"
	SingBoxRuleSetRemote SingBoxRuleSetType = "remote"

	SingBoxRuleSetSource SingBoxRuleSetFormat = "source"
	SingBoxRuleSetBinary SingBoxRuleSetFormat = "binary"
)

// SingBoxRouteRule contains the sing-box match fields supported by Document.
// Slice fields intentionally use sing-box's canonical array representation.
type SingBoxRouteRule struct {
	Domains        []string          `json:"domain,omitempty"`
	DomainSuffixes []string          `json:"domain_suffix,omitempty"`
	DomainKeywords []string          `json:"domain_keyword,omitempty"`
	RuleSets       []string          `json:"rule_set,omitempty"`
	IPCIDRs        []string          `json:"ip_cidr,omitempty"`
	SourceIPCIDRs  []string          `json:"source_ip_cidr,omitempty"`
	ProcessNames   []string          `json:"process_name,omitempty"`
	ProcessPaths   []string          `json:"process_path,omitempty"`
	Networks       []SingBoxNetwork  `json:"network,omitempty"`
	Ports          []uint16          `json:"port,omitempty"`
	SourcePorts    []uint16          `json:"source_port,omitempty"`
	Protocols      []string          `json:"protocol,omitempty"`
	IPIsPrivate    bool              `json:"ip_is_private,omitempty"`
	Action         SingBoxRuleAction `json:"action,omitempty"`
	Outbound       string            `json:"outbound,omitempty"`
}

type SingBoxNetwork string

const (
	SingBoxNetworkTCP SingBoxNetwork = "tcp"
	SingBoxNetworkUDP SingBoxNetwork = "udp"
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
	tags := buildTags(doc)
	dns := doc.DNS
	if len(dns.Servers) == 0 {
		dns = defaultDocument().DNS
	}
	resolver := doc.Route.DefaultDomainResolver
	if resolver == "" {
		resolver = dns.Final
	}
	if resolver == "" && len(dns.Servers) > 0 {
		resolver = dns.Servers[0].Tag
	}

	outbounds := make([]map[string]any, 0, len(doc.Nodes)+len(doc.Groups)+2)
	selectable := make([]string, 0, len(doc.Nodes)+len(doc.Groups))
	for _, node := range doc.Nodes {
		outbound, err := convertNode(node, tags[node.Name], resolver)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		outbounds = append(outbounds, outbound)
		selectable = append(selectable, tags[node.Name])
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	var groupTags []string
	for _, group := range doc.Groups {
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
		logConfig = defaultDocument().Log
	}
	route := SingBoxRouteConfig{
		Rules: routeRules, Final: final,
		AutoDetectInterface:   doc.Route.AutoDetectInterface,
		DefaultDomainResolver: resolver,
	}
	route.RuleSets = encodeRuleSets(doc.Route.RuleSets, doc.Route.Rules, tags)
	config := map[string]any{
		"log":       encodeLog(logConfig),
		"dns":       encodeDNS(dns, tags),
		"outbounds": outbounds,
		"route":     route,
	}
	if doc.TUN.Enabled {
		config["inbounds"] = []map[string]any{encodeTUN(doc.TUN)}
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, warnings, fmt.Errorf("encode sing-box JSON: %w", err)
	}
	return append(data, '\n'), warnings, nil
}

func buildTags(doc Document) map[string]string {
	result := map[string]string{}
	used := map[string]struct{}{"direct": {}, "proxy": {}}
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
	result := map[string]any{"tag": tag, "server": node.Server, "server_port": node.Port}
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
		if options.UpMbps > 0 {
			result["up_mbps"] = options.UpMbps
		}
		if options.DownMbps > 0 {
			result["down_mbps"] = options.DownMbps
		}
		if options.ObfsPassword != "" {
			result["obfs"] = map[string]any{"type": "salamander", "password": options.ObfsPassword}
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
			warnings = append(warnings, fmt.Sprintf("group %q: REJECT member omitted", group.Name))
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
	case GroupFallback, GroupLoadBalance:
		result["type"] = "selector"
		warnings = append(warnings, fmt.Sprintf("group %q: %s downgraded to selector", group.Name, group.Type))
	default:
		warnings = append(warnings, fmt.Sprintf("group %q skipped: unsupported type %q", group.Name, group.Type))
		return nil, warnings
	}
	return result, warnings
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

func encodeRuleSets(ruleSets []RuleSet, rules []RouteRule, tags map[string]string) []SingBoxRuleSet {
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
	}
	return result
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
		item := map[string]any{"action": "route", "server": rule.Server}
		putStrings(item, "domain", rule.Match.Domains)
		putStrings(item, "domain_suffix", rule.Match.DomainSuffixes)
		putStrings(item, "domain_keyword", rule.Match.DomainKeywords)
		putStrings(item, "rule_set", rule.Match.RuleSets)
		putStrings(item, "outbound", rule.Match.OutboundTags)
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

func encodeTUN(config TUNConfig) map[string]any {
	addresses := prefixStrings(config.Addresses)
	result := map[string]any{
		"type": "tun", "tag": config.Tag, "address": addresses,
		"auto_route": config.AutoRoute, "strict_route": config.StrictRoute,
	}
	if config.Stack != "" {
		result["stack"] = config.Stack
	}
	if config.MTU > 0 {
		result["mtu"] = config.MTU
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
