package singbox

// SingBoxConfig is the strongly typed sing-box configuration accepted by the
// converter. When used as a patch, currently only Route is merged.
type SingBoxConfig struct {
	Log          *SingBoxLogConfig          `json:"log,omitempty"`
	DNS          *SingBoxDNSConfig          `json:"dns,omitempty"`
	Inbounds     []SingBoxInbound           `json:"inbounds,omitempty"`
	Outbounds    []SingBoxOutbound          `json:"outbounds,omitempty"`
	Route        *SingBoxRouteConfig        `json:"route,omitempty"`
	Experimental *SingBoxExperimentalConfig `json:"experimental,omitempty"`
}

type SingBoxExperimentalConfig struct {
	CacheFile *SingBoxCacheFile `json:"cache_file,omitempty"`
}

type SingBoxCacheFile struct {
	Enabled     bool   `json:"enabled"`
	Path        string `json:"path,omitempty"`
	StoreFakeIP bool   `json:"store_fakeip,omitempty"`
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
	Inet4Range string               `json:"inet4_range,omitempty"`
	Inet6Range string               `json:"inet6_range,omitempty"`
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
	IPCIDRs        []string `json:"ip_cidr,omitempty"`
	MatchResponse  bool     `json:"match_response,omitempty"`
	Invert         bool     `json:"invert,omitempty"`
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
	Type                     SingBoxOutboundType `json:"type"`
	Tag                      string              `json:"tag"`
	Server                   string              `json:"server,omitempty"`
	ServerPort               uint16              `json:"server_port,omitempty"`
	ServerPorts              []string            `json:"server_ports,omitempty"`
	DomainResolver           string              `json:"domain_resolver,omitempty"`
	Detour                   string              `json:"detour,omitempty"`
	Outbounds                []string            `json:"outbounds,omitempty"`
	URL                      string              `json:"url,omitempty"`
	Interval                 string              `json:"interval,omitempty"`
	Tolerance                int                 `json:"tolerance,omitempty"`
	Method                   string              `json:"method,omitempty"`
	Password                 string              `json:"password,omitempty"`
	Username                 string              `json:"username,omitempty"`
	UUID                     string              `json:"uuid,omitempty"`
	Security                 string              `json:"security,omitempty"`
	AlterID                  int                 `json:"alter_id,omitempty"`
	Flow                     string              `json:"flow,omitempty"`
	Plugin                   string              `json:"plugin,omitempty"`
	PluginOptions            string              `json:"plugin_options,omitempty"`
	GlobalPadding            bool                `json:"global_padding,omitempty"`
	AuthenticatedLength      bool                `json:"authenticated_length,omitempty"`
	UpMbps                   int                 `json:"up_mbps,omitempty"`
	DownMbps                 int                 `json:"down_mbps,omitempty"`
	HopInterval              string              `json:"hop_interval,omitempty"`
	HopIntervalMax           string              `json:"hop_interval_max,omitempty"`
	IdleSessionCheckInterval string              `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       string              `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int                 `json:"min_idle_session,omitempty"`
	CongestionControl        string              `json:"congestion_control,omitempty"`
	UDPRelayMode             string              `json:"udp_relay_mode,omitempty"`
	Obfs                     *SingBoxObfs        `json:"obfs,omitempty"`
	TLS                      *SingBoxTLS         `json:"tls,omitempty"`
	Transport                *SingBoxTransport   `json:"transport,omitempty"`
}

type SingBoxOutboundType string

const (
	SingBoxOutboundDirect      SingBoxOutboundType = "direct"
	SingBoxOutboundBlock       SingBoxOutboundType = "block"
	SingBoxOutboundShadowsocks SingBoxOutboundType = "shadowsocks"
	SingBoxOutboundVMess       SingBoxOutboundType = "vmess"
	SingBoxOutboundVLESS       SingBoxOutboundType = "vless"
	SingBoxOutboundTrojan      SingBoxOutboundType = "trojan"
	SingBoxOutboundHysteria2   SingBoxOutboundType = "hysteria2"
	SingBoxOutboundAnyTLS      SingBoxOutboundType = "anytls"
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
