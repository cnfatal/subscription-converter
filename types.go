package subscriptionconverter

import (
	"net/netip"
	"time"
)

// Document is the format-neutral configuration passed between codecs.
// It models configuration semantics instead of the field layout of any one client.
type Document struct {
	Log      LogConfig `json:"log"`
	DNS      DNSConfig `json:"dns"`
	Inbounds []Inbound `json:"inbounds"`
	// TUN is retained for source compatibility. New code should use Inbounds.
	TUN    TUNConfig   `json:"tun,omitempty"`
	Nodes  []Node      `json:"nodes"`
	Groups []Group     `json:"groups"`
	Route  RouteConfig `json:"route"`
}

type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
	LogLevelPanic LogLevel = "panic"
)

type LogConfig struct {
	Level     LogLevel `json:"level"`
	Timestamp bool     `json:"timestamp"`
}

type DNSStrategy string

const (
	DNSStrategyDefault    DNSStrategy = "default"
	DNSStrategyPreferIPv4 DNSStrategy = "prefer_ipv4"
	DNSStrategyPreferIPv6 DNSStrategy = "prefer_ipv6"
	DNSStrategyIPv4Only   DNSStrategy = "ipv4_only"
	DNSStrategyIPv6Only   DNSStrategy = "ipv6_only"
)

type DNSServerType string

const (
	DNSServerLocal  DNSServerType = "local"
	DNSServerHosts  DNSServerType = "hosts"
	DNSServerUDP    DNSServerType = "udp"
	DNSServerTCP    DNSServerType = "tcp"
	DNSServerTLS    DNSServerType = "tls"
	DNSServerQUIC   DNSServerType = "quic"
	DNSServerHTTPS  DNSServerType = "https"
	DNSServerHTTP3  DNSServerType = "h3"
	DNSServerDHCP   DNSServerType = "dhcp"
	DNSServerMDNS   DNSServerType = "mdns"
	DNSServerFakeIP DNSServerType = "fakeip"
)

type DNSServer struct {
	Tag        string        `json:"tag"`
	Type       DNSServerType `json:"type"`
	Server     string        `json:"server,omitempty"`
	ServerPort uint16        `json:"server_port,omitempty"`
	Path       string        `json:"path,omitempty"`
	Detour     string        `json:"detour,omitempty"`
	Inet4Range string        `json:"inet4_range,omitempty"`
	Inet6Range string        `json:"inet6_range,omitempty"`
}

type DNSRule struct {
	Match         DNSMatch      `json:"match"`
	Action        DNSActionType `json:"action,omitempty"`
	Server        string        `json:"server,omitempty"`
	MatchResponse bool          `json:"match_response,omitempty"`
	Invert        bool          `json:"invert,omitempty"`
}

type DNSActionType string

const (
	DNSActionRoute    DNSActionType = "route"
	DNSActionEvaluate DNSActionType = "evaluate"
	DNSActionRespond  DNSActionType = "respond"
)

type DNSMatch struct {
	Domains        []string       `json:"domains,omitempty"`
	DomainSuffixes []string       `json:"domain_suffixes,omitempty"`
	DomainKeywords []string       `json:"domain_keywords,omitempty"`
	RuleSets       []string       `json:"rule_sets,omitempty"`
	OutboundTags   []string       `json:"outbound_tags,omitempty"`
	IPCIDRs        []netip.Prefix `json:"ip_cidrs,omitempty"`
}

type DNSConfig struct {
	Servers        []DNSServer `json:"servers"`
	Rules          []DNSRule   `json:"rules,omitempty"`
	Final          string      `json:"final,omitempty"`
	Strategy       DNSStrategy `json:"strategy,omitempty"`
	DisableCache   bool        `json:"disable_cache,omitempty"`
	DisableExpire  bool        `json:"disable_expire,omitempty"`
	ProxyResolver  string      `json:"proxy_resolver,omitempty"`
	DirectResolver string      `json:"direct_resolver,omitempty"`
	StoreFakeIP    bool        `json:"store_fakeip,omitempty"`
}

type TUNStack string

const (
	TUNStackSystem TUNStack = "system"
	TUNStackGVisor TUNStack = "gvisor"
	TUNStackMixed  TUNStack = "mixed"
)

type TUNConfig struct {
	// Enabled and Tag are used by the legacy Document.TUN compatibility path.
	Enabled     bool           `json:"enabled,omitempty"`
	Tag         string         `json:"tag,omitempty"`
	Addresses   []netip.Prefix `json:"addresses"`
	AutoRoute   bool           `json:"auto_route"`
	StrictRoute bool           `json:"strict_route"`
	Stack       TUNStack       `json:"stack,omitempty"`
	MTU         uint32         `json:"mtu,omitempty"`
}

type InboundType string

const (
	InboundTUN   InboundType = "tun"
	InboundMixed InboundType = "mixed"
	InboundSOCKS InboundType = "socks"
	InboundHTTP  InboundType = "http"
)

type Inbound struct {
	Type           InboundType   `json:"type"`
	Tag            string        `json:"tag"`
	Listen         string        `json:"listen,omitempty"`
	ListenPort     uint16        `json:"listen_port,omitempty"`
	Users          []InboundUser `json:"users,omitempty"`
	SetSystemProxy bool          `json:"set_system_proxy,omitempty"`
	TUN            *TUNConfig    `json:"tun,omitempty"`
}

type InboundUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Protocol string

const (
	ProtocolShadowsocks Protocol = "shadowsocks"
	ProtocolVMess       Protocol = "vmess"
	ProtocolVLESS       Protocol = "vless"
	ProtocolTrojan      Protocol = "trojan"
	ProtocolHysteria2   Protocol = "hysteria2"
	ProtocolAnyTLS      Protocol = "anytls"
	ProtocolTUIC        Protocol = "tuic"
	ProtocolSOCKS       Protocol = "socks"
	ProtocolHTTP        Protocol = "http"
)

// Node is a strongly typed tagged union. Type selects the matching protocol
// options field; common endpoint properties stay directly on the node.
type Node struct {
	Name      string      `json:"name"`
	Type      Protocol    `json:"type"`
	Server    string      `json:"server"`
	Port      uint16      `json:"port"`
	TLS       *TLSOptions `json:"tls,omitempty"`
	Transport *Transport  `json:"transport,omitempty"`

	Shadowsocks *ShadowsocksOptions `json:"shadowsocks,omitempty"`
	VMess       *VMessOptions       `json:"vmess,omitempty"`
	VLESS       *VLESSOptions       `json:"vless,omitempty"`
	Trojan      *TrojanOptions      `json:"trojan,omitempty"`
	Hysteria2   *Hysteria2Options   `json:"hysteria2,omitempty"`
	AnyTLS      *AnyTLSOptions      `json:"anytls,omitempty"`
	TUIC        *TUICOptions        `json:"tuic,omitempty"`
	SOCKS       *SOCKSOptions       `json:"socks,omitempty"`
	HTTP        *HTTPOptions        `json:"http,omitempty"`
}

type TLSOptions struct {
	ServerName  string          `json:"server_name,omitempty"`
	Insecure    bool            `json:"insecure,omitempty"`
	ALPN        []string        `json:"alpn,omitempty"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Reality     *RealityOptions `json:"reality,omitempty"`
}

type RealityOptions struct {
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type TransportType string

const (
	TransportWebSocket   TransportType = "ws"
	TransportGRPC        TransportType = "grpc"
	TransportHTTP        TransportType = "http"
	TransportHTTPUpgrade TransportType = "httpupgrade"
)

type Transport struct {
	Type                TransportType     `json:"type"`
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	MaxEarlyData        uint32            `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
	ServiceName         string            `json:"service_name,omitempty"`
	Hosts               []string          `json:"hosts,omitempty"`
}

type ShadowsocksOptions struct {
	Method        string `json:"method"`
	Password      string `json:"password"`
	Plugin        string `json:"plugin,omitempty"`
	PluginOptions string `json:"plugin_options,omitempty"`
}

type VMessOptions struct {
	UUID                string `json:"uuid"`
	Security            string `json:"security,omitempty"`
	AlterID             int    `json:"alter_id,omitempty"`
	GlobalPadding       bool   `json:"global_padding,omitempty"`
	AuthenticatedLength bool   `json:"authenticated_length,omitempty"`
}

type VLESSOptions struct {
	UUID       string `json:"uuid"`
	Flow       string `json:"flow,omitempty"`
	Encryption string `json:"encryption,omitempty"`
}

type TrojanOptions struct {
	Password string `json:"password"`
}

type Hysteria2Options struct {
	Password       string   `json:"password"`
	ServerPorts    []string `json:"server_ports,omitempty"`
	HopInterval    string   `json:"hop_interval,omitempty"`
	HopIntervalMax string   `json:"hop_interval_max,omitempty"`
	UpMbps         int      `json:"up_mbps,omitempty"`
	DownMbps       int      `json:"down_mbps,omitempty"`
	ObfsPassword   string   `json:"obfs_password,omitempty"`
}

type AnyTLSOptions struct {
	Password                 string `json:"password"`
	IdleSessionCheckInterval string `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       string `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int    `json:"min_idle_session,omitempty"`
}

type TUICOptions struct {
	UUID              string `json:"uuid"`
	Password          string `json:"password"`
	CongestionControl string `json:"congestion_control,omitempty"`
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`
}

type SOCKSOptions struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type HTTPOptions struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type GroupType string

const (
	GroupSelector    GroupType = "selector"
	GroupURLTest     GroupType = "urltest"
	GroupFallback    GroupType = "fallback"
	GroupLoadBalance GroupType = "load-balance"
	GroupRelay       GroupType = "relay"
)

type Group struct {
	Name      string        `json:"name"`
	Type      GroupType     `json:"type"`
	Members   []string      `json:"members"`
	URL       string        `json:"url,omitempty"`
	Interval  time.Duration `json:"interval,omitempty"`
	Tolerance int           `json:"tolerance,omitempty"`
	Lazy      bool          `json:"lazy,omitempty"`
	Strategy  string        `json:"strategy,omitempty"`
}

type Network string

const (
	NetworkTCP Network = "tcp"
	NetworkUDP Network = "udp"
)

type RouteActionType string

const (
	RouteActionRoute  RouteActionType = "route"
	RouteActionReject RouteActionType = "reject"
)

type RouteAction struct {
	Type   RouteActionType `json:"type"`
	Target string          `json:"target,omitempty"`
}

type RuleSetType string

const (
	RuleSetInline RuleSetType = "inline"
	RuleSetLocal  RuleSetType = "local"
	RuleSetRemote RuleSetType = "remote"
)

type RuleSetFormat string

const (
	RuleSetFormatSource RuleSetFormat = "source"
	RuleSetFormatBinary RuleSetFormat = "binary"
)

// RuleSet is a format-neutral route rule-set definition.
type RuleSet struct {
	Type           RuleSetType   `json:"type"`
	Tag            string        `json:"tag"`
	Format         RuleSetFormat `json:"format,omitempty"`
	URL            string        `json:"url,omitempty"`
	Path           string        `json:"path,omitempty"`
	UpdateInterval string        `json:"update_interval,omitempty"`
	DownloadDetour string        `json:"download_detour,omitempty"`
	Rules          []RouteMatch  `json:"rules,omitempty"`
}

type RouteMatch struct {
	Domains        []string       `json:"domains,omitempty"`
	DomainSuffixes []string       `json:"domain_suffixes,omitempty"`
	DomainKeywords []string       `json:"domain_keywords,omitempty"`
	GeoIPCodes     []string       `json:"geoip_codes,omitempty"`
	GeoSiteCodes   []string       `json:"geosite_codes,omitempty"`
	RuleSets       []string       `json:"rule_sets,omitempty"`
	IPCIDRs        []netip.Prefix `json:"ip_cidrs,omitempty"`
	SourceIPCIDRs  []netip.Prefix `json:"source_ip_cidrs,omitempty"`
	ProcessNames   []string       `json:"process_names,omitempty"`
	ProcessPaths   []string       `json:"process_paths,omitempty"`
	Networks       []Network      `json:"networks,omitempty"`
	Ports          []uint16       `json:"ports,omitempty"`
	SourcePorts    []uint16       `json:"source_ports,omitempty"`
	Protocols      []string       `json:"protocols,omitempty"`
	IPIsPrivate    bool           `json:"ip_is_private,omitempty"`
}

type RouteRule struct {
	Match  RouteMatch  `json:"match"`
	Action RouteAction `json:"action"`
}

type RouteConfig struct {
	RuleSets              []RuleSet   `json:"rule_sets,omitempty"`
	Rules                 []RouteRule `json:"rules,omitempty"`
	Final                 string      `json:"final,omitempty"`
	AutoDetectInterface   bool        `json:"auto_detect_interface,omitempty"`
	DefaultDomainResolver string      `json:"default_domain_resolver,omitempty"`
}
