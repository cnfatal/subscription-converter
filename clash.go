package subscriptionconverter

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

type ClashCodec struct{}

var _ Codec = ClashCodec{}

func (ClashCodec) Format() string {
	return "clash"
}

func (ClashCodec) Recognize(data []byte) Recognition {
	content := "\n" + strings.ToLower(strings.TrimSpace(string(data)))
	for _, marker := range []string{"\nproxies:", "\nproxy-groups:", "\nproxy-providers:", "\nrules:"} {
		if strings.Contains(content, marker) {
			return RecognitionExact
		}
	}
	return RecognitionNone
}

func (ClashCodec) Encode(Document, EncodeOptions) ([]byte, []string, error) {
	return nil, nil, ErrEncodeUnsupported
}

type ClashConfig struct {
	Proxies        []ClashProxy                  `json:"proxies"`
	ProxyGroups    []ClashProxyGroup             `json:"proxy-groups"`
	ProxyProviders map[string]ClashProxyProvider `json:"proxy-providers"`
	DNS            *ClashDNSConfig               `json:"dns,omitempty"`
	Rules          []string                      `json:"rules"`
}

type ClashDNSConfig struct {
	Enable           bool                        `json:"enable"`
	IPv6             bool                        `json:"ipv6"`
	Listen           string                      `json:"listen,omitempty"`
	EnhancedMode     string                      `json:"enhanced-mode,omitempty"`
	NameServers      []string                    `json:"nameserver"`
	Fallback         []string                    `json:"fallback"`
	NameServerPolicy map[string]ClashNameServers `json:"nameserver-policy"`
	FakeIPRange      string                      `json:"fake-ip-range,omitempty"`
	FakeIPFilter     []string                    `json:"fake-ip-filter"`
}

// ClashNameServers accepts either one server or a list in nameserver-policy.
type ClashNameServers []string

func (s *ClashNameServers) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		*s = ClashNameServers{value}
		return nil
	}
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	*s = values
	return nil
}

type ClashProxyType string

const (
	ClashProxyShadowsocks ClashProxyType = "ss"
	ClashProxyVMess       ClashProxyType = "vmess"
	ClashProxyVLESS       ClashProxyType = "vless"
	ClashProxyTrojan      ClashProxyType = "trojan"
	ClashProxyHysteria2   ClashProxyType = "hysteria2"
	ClashProxyTUIC        ClashProxyType = "tuic"
	ClashProxySOCKS5      ClashProxyType = "socks5"
	ClashProxyHTTP        ClashProxyType = "http"
)

type ClashProxy struct {
	Name   string         `json:"name"`
	Type   ClashProxyType `json:"type"`
	Server string         `json:"server"`
	Port   uint16         `json:"port"`

	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	Cipher   string `json:"cipher,omitempty"`
	Flow     string `json:"flow,omitempty"`

	Plugin     string         `json:"plugin,omitempty"`
	PluginOpts map[string]any `json:"plugin-opts,omitempty"`

	AlterID             int  `json:"alterId,omitempty"`
	GlobalPadding       bool `json:"global-padding,omitempty"`
	AuthenticatedLength bool `json:"authenticated-length,omitempty"`

	TLS               *bool    `json:"tls,omitempty"`
	ServerName        string   `json:"servername,omitempty"`
	LegacyServerName  string   `json:"server-name,omitempty"`
	SNI               string   `json:"sni,omitempty"`
	SkipCertVerify    bool     `json:"skip-cert-verify,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	ClientFingerprint string   `json:"client-fingerprint,omitempty"`
	Fingerprint       string   `json:"fingerprint,omitempty"`

	Network           string                   `json:"network,omitempty"`
	WebSocket         *ClashWebSocketOptions   `json:"ws-opts,omitempty"`
	GRPC              *ClashGRPCOptions        `json:"grpc-opts,omitempty"`
	HTTP2             *ClashHTTP2Options       `json:"h2-opts,omitempty"`
	HTTPUpgrade       *ClashHTTPUpgradeOptions `json:"http-upgrade-opts,omitempty"`
	Auth              string                   `json:"auth,omitempty"`
	Up                int                      `json:"up,omitempty"`
	Down              int                      `json:"down,omitempty"`
	UpMbps            int                      `json:"up-mbps,omitempty"`
	DownMbps          int                      `json:"down-mbps,omitempty"`
	ObfsPassword      string                   `json:"obfs-password,omitempty"`
	CongestionControl string                   `json:"congestion-controller,omitempty"`
	UDPRelayMode      string                   `json:"udp-relay-mode,omitempty"`
}

type ClashWebSocketOptions struct {
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	MaxEarlyData        int               `json:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `json:"early-data-header-name,omitempty"`
}

type ClashGRPCOptions struct {
	ServiceName string `json:"grpc-service-name,omitempty"`
}

type ClashHTTP2Options struct {
	Host []string `json:"host,omitempty"`
	Path string   `json:"path,omitempty"`
}

type ClashHTTPUpgradeOptions struct {
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type ClashProxyGroup struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Proxies   []string `json:"proxies"`
	URL       string   `json:"url,omitempty"`
	Interval  int      `json:"interval,omitempty"`
	Tolerance int      `json:"tolerance,omitempty"`
	Lazy      bool     `json:"lazy,omitempty"`
}

type ClashProxyProvider struct {
	Type        string                    `json:"type"`
	URL         string                    `json:"url,omitempty"`
	Path        string                    `json:"path,omitempty"`
	Interval    int                       `json:"interval,omitempty"`
	HealthCheck *ClashProviderHealthCheck `json:"health-check,omitempty"`
}

type ClashProviderHealthCheck struct {
	Enable   bool   `json:"enable,omitempty"`
	URL      string `json:"url,omitempty"`
	Interval int    `json:"interval,omitempty"`
}

func (ClashCodec) Decode(data []byte, _ DecodeOptions) (*Document, []string, error) {
	var input ClashConfig
	if err := yaml.Unmarshal(data, &input); err != nil {
		return nil, nil, fmt.Errorf("decode Clash YAML: %w", err)
	}
	if len(input.Proxies) == 0 {
		return nil, nil, fmt.Errorf("Clash configuration contains no proxies")
	}

	doc := defaultDocument()
	var warnings []string
	seen := map[string]struct{}{}
	for index, proxy := range input.Proxies {
		if proxy.Name == "" || proxy.Type == "" || proxy.Server == "" || proxy.Port == 0 {
			warnings = append(warnings, fmt.Sprintf("proxy #%d skipped: name, type, server, and port are required", index+1))
			continue
		}
		if _, exists := seen[proxy.Name]; exists {
			warnings = append(warnings, fmt.Sprintf("duplicate proxy %q skipped", proxy.Name))
			continue
		}
		seen[proxy.Name] = struct{}{}
		node, warning := proxy.node()
		if warning != "" {
			warnings = append(warnings, warning)
			continue
		}
		doc.Nodes = append(doc.Nodes, node)
	}

	for index, group := range input.ProxyGroups {
		if group.Name == "" || group.Type == "" {
			warnings = append(warnings, fmt.Sprintf("proxy group #%d skipped: name and type are required", index+1))
			continue
		}
		groupType, ok := clashGroupType(group.Type)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("proxy group %q skipped: unsupported type %q", group.Name, group.Type))
			continue
		}
		doc.Groups = append(doc.Groups, Group{
			Name: group.Name, Type: groupType, Members: group.Proxies,
			URL: group.URL, Interval: time.Duration(group.Interval) * time.Second,
		})
	}

	if input.DNS != nil && input.DNS.Enable {
		dns, dnsWarnings := input.DNS.documentDNS()
		warnings = append(warnings, dnsWarnings...)
		if len(dns.Servers) > 0 {
			doc.DNS = dns
			doc.Route.DefaultDomainResolver = dns.Final
		}
	}

	for _, line := range input.Rules {
		rule, final, warning := decodeClashRule(line)
		if warning != "" {
			warnings = append(warnings, warning)
			continue
		}
		if final != "" {
			doc.Route.Final = final
		} else {
			doc.Route.Rules = append(doc.Route.Rules, rule)
		}
	}
	return &doc, warnings, nil
}

func defaultDocument() Document {
	prefix := netip.MustParsePrefix("172.19.0.1/30")
	return Document{
		Log: LogConfig{Level: LogLevelInfo, Timestamp: true},
		DNS: DNSConfig{
			Servers: []DNSServer{
				{Tag: "local", Type: DNSServerLocal},
				{Tag: "remote", Type: DNSServerHTTPS, Server: "1.1.1.1", ServerPort: 443, Path: "/dns-query", Detour: "proxy"},
			},
			Final: "remote", Strategy: DNSStrategyPreferIPv4,
		},
		TUN:   TUNConfig{Enabled: true, Tag: "tun-in", Addresses: []netip.Prefix{prefix}, AutoRoute: true, StrictRoute: true},
		Route: RouteConfig{Final: "proxy", AutoDetectInterface: true, DefaultDomainResolver: "local"},
	}
}

func (p ClashProxy) node() (Node, string) {
	node := Node{Name: p.Name, Server: p.Server, Port: p.Port}
	defaultTLS := p.Type == ClashProxyTrojan || p.Type == ClashProxyHysteria2 || p.Type == ClashProxyTUIC
	tlsEnabled := defaultTLS
	if p.TLS != nil {
		tlsEnabled = *p.TLS
	}
	if tlsEnabled {
		node.TLS = &TLSOptions{
			ServerName: FirstNonEmpty(p.ServerName, p.LegacyServerName, p.SNI),
			Insecure:   p.SkipCertVerify, ALPN: p.ALPN,
			Fingerprint: FirstNonEmpty(p.ClientFingerprint, p.Fingerprint),
		}
	}
	node.Transport = p.transport()

	switch p.Type {
	case ClashProxyShadowsocks:
		node.Type = ProtocolShadowsocks
		node.Shadowsocks = &ShadowsocksOptions{Method: p.Cipher, Password: p.Password, Plugin: p.Plugin, PluginOptions: FlattenOptions(p.PluginOpts)}
	case ClashProxyVMess:
		node.Type = ProtocolVMess
		node.VMess = &VMessOptions{UUID: p.UUID, Security: p.Cipher, AlterID: p.AlterID, GlobalPadding: p.GlobalPadding, AuthenticatedLength: p.AuthenticatedLength}
	case ClashProxyVLESS:
		node.Type = ProtocolVLESS
		node.VLESS = &VLESSOptions{UUID: p.UUID, Flow: p.Flow}
	case ClashProxyTrojan:
		node.Type = ProtocolTrojan
		node.Trojan = &TrojanOptions{Password: p.Password}
	case ClashProxyHysteria2:
		node.Type = ProtocolHysteria2
		node.Hysteria2 = &Hysteria2Options{Password: FirstNonEmpty(p.Password, p.Auth), UpMbps: firstPositive(p.UpMbps, p.Up), DownMbps: firstPositive(p.DownMbps, p.Down), ObfsPassword: p.ObfsPassword}
	case ClashProxyTUIC:
		node.Type = ProtocolTUIC
		node.TUIC = &TUICOptions{UUID: p.UUID, Password: p.Password, CongestionControl: p.CongestionControl, UDPRelayMode: p.UDPRelayMode}
	case ClashProxySOCKS5:
		node.Type = ProtocolSOCKS
		node.SOCKS = &SOCKSOptions{Username: p.Username, Password: p.Password}
	case ClashProxyHTTP:
		node.Type = ProtocolHTTP
		node.HTTP = &HTTPOptions{Username: p.Username, Password: p.Password}
	default:
		return Node{}, fmt.Sprintf("proxy %q skipped: unsupported protocol %q", p.Name, p.Type)
	}
	return node, ""
}

func (p ClashProxy) transport() *Transport {
	switch strings.ToLower(p.Network) {
	case "ws":
		transport := &Transport{Type: TransportWebSocket}
		if p.WebSocket == nil {
			return transport
		}
		transport.Path = p.WebSocket.Path
		transport.Headers = p.WebSocket.Headers
		transport.MaxEarlyData = uint32(max(p.WebSocket.MaxEarlyData, 0))
		transport.EarlyDataHeaderName = p.WebSocket.EarlyDataHeaderName
		return transport
	case "grpc":
		transport := &Transport{Type: TransportGRPC}
		if p.GRPC == nil {
			return transport
		}
		transport.ServiceName = p.GRPC.ServiceName
		return transport
	case "http", "h2":
		transport := &Transport{Type: TransportHTTP}
		if p.HTTP2 == nil {
			return transport
		}
		transport.Hosts = p.HTTP2.Host
		transport.Path = p.HTTP2.Path
		return transport
	case "httpupgrade":
		transport := &Transport{Type: TransportHTTPUpgrade}
		if p.HTTPUpgrade == nil {
			return transport
		}
		transport.Path = p.HTTPUpgrade.Path
		transport.Headers = p.HTTPUpgrade.Headers
		return transport
	default:
		return nil
	}
}

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
	case "GEOIP":
		rule.Match.GeoIPCodes = []string{strings.ToLower(value)}
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
		config.Rules = append(config.Rules, DNSRule{Match: match, Server: tag})
	}
	if len(c.Fallback) > 0 {
		warnings = append(warnings, "Clash DNS fallback filter semantics are not representable and were omitted")
	}
	if strings.EqualFold(c.EnhancedMode, "fake-ip") {
		warnings = append(warnings, "Clash fake-ip DNS mode is not enabled in the converted configuration")
	}
	return config, warnings
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
	if strings.HasPrefix(lower, "geosite:") || strings.HasPrefix(lower, "rule-set:") {
		return DNSMatch{}, false
	}
	if after, ok := strings.CutPrefix(pattern, "+."); ok {
		return DNSMatch{DomainSuffixes: []string{after}}, true
	}
	if after, ok := strings.CutPrefix(pattern, "*."); ok {
		return DNSMatch{DomainSuffixes: []string{after}}, true
	}
	return DNSMatch{Domains: []string{pattern}}, pattern != ""
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
