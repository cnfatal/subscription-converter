package clash

import (
	"encoding/json"
	"fmt"
	. "github.com/cnfatal/subscription-converter"
	"strings"
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
	RuleProviders  map[string]ClashRuleProvider  `json:"rule-providers"`
	DNS            *ClashDNSConfig               `json:"dns,omitempty"`
	Rules          []string                      `json:"rules"`
}

type ClashDNSConfig struct {
	Enable                       bool                        `json:"enable"`
	IPv6                         bool                        `json:"ipv6"`
	Listen                       string                      `json:"listen,omitempty"`
	EnhancedMode                 string                      `json:"enhanced-mode,omitempty"`
	NameServers                  []string                    `json:"nameserver"`
	DefaultNameServers           []string                    `json:"default-nameserver,omitempty"`
	Fallback                     []string                    `json:"fallback"`
	NameServerPolicy             map[string]ClashNameServers `json:"nameserver-policy"`
	ProxyServerNameServers       []string                    `json:"proxy-server-nameserver,omitempty"`
	ProxyServerNameServerPolicy  map[string]ClashNameServers `json:"proxy-server-nameserver-policy,omitempty"`
	DirectNameServers            []string                    `json:"direct-nameserver,omitempty"`
	DirectNameServerFollowPolicy bool                        `json:"direct-nameserver-follow-policy,omitempty"`
	FakeIPRange                  string                      `json:"fake-ip-range,omitempty"`
	FakeIPRange6                 string                      `json:"fake-ip-range6,omitempty"`
	FakeIPFilter                 []string                    `json:"fake-ip-filter"`
	FakeIPFilterMode             string                      `json:"fake-ip-filter-mode,omitempty"`
	FallbackFilter               ClashDNSFallbackFilter      `json:"fallback-filter,omitempty"`
}

type ClashDNSFallbackFilter struct {
	GeoIP     *bool    `json:"geoip,omitempty"`
	GeoIPCode string   `json:"geoip-code,omitempty"`
	GeoSite   []string `json:"geosite,omitempty"`
	IPCIDRs   []string `json:"ipcidr,omitempty"`
	Domains   []string `json:"domain,omitempty"`
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
	ClashProxyAnyTLS      ClashProxyType = "anytls"
	ClashProxyTUIC        ClashProxyType = "tuic"
	ClashProxySOCKS5      ClashProxyType = "socks5"
	ClashProxyHTTP        ClashProxyType = "http"
)

type ClashProxy struct {
	Name   string         `json:"name"`
	Type   ClashProxyType `json:"type"`
	Server string         `json:"server"`
	Port   uint16         `json:"port"`

	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	Flow       string `json:"flow,omitempty"`
	Encryption string `json:"encryption,omitempty"`

	Plugin     string         `json:"plugin,omitempty"`
	PluginOpts map[string]any `json:"plugin-opts,omitempty"`

	AlterID             int  `json:"alterId,omitempty"`
	GlobalPadding       bool `json:"global-padding,omitempty"`
	AuthenticatedLength bool `json:"authenticated-length,omitempty"`

	TLS               *bool                `json:"tls,omitempty"`
	ServerName        string               `json:"servername,omitempty"`
	LegacyServerName  string               `json:"server-name,omitempty"`
	SNI               string               `json:"sni,omitempty"`
	SkipCertVerify    bool                 `json:"skip-cert-verify,omitempty"`
	ALPN              []string             `json:"alpn,omitempty"`
	ClientFingerprint string               `json:"client-fingerprint,omitempty"`
	Fingerprint       string               `json:"fingerprint,omitempty"`
	Reality           *ClashRealityOptions `json:"reality-opts,omitempty"`

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
	Ports             ClashPortRanges          `json:"ports,omitempty"`
	HopInterval       ClashHopInterval         `json:"hop-interval,omitempty"`
}

type ClashRealityOptions struct {
	PublicKey string `json:"public-key"`
	ShortID   string `json:"short-id,omitempty"`
}

type ClashPortRanges []string

func (p *ClashPortRanges) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				*p = append(*p, normalizePortRange(item))
			}
		}
		return nil
	}
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			*p = append(*p, normalizePortRange(value))
		}
	}
	return nil
}

func normalizePortRange(value string) string {
	if start, end, ok := strings.Cut(value, "-"); ok {
		return strings.TrimSpace(start) + ":" + strings.TrimSpace(end)
	}
	return value
}

type ClashHopInterval struct {
	Min string
	Max string
}

func (i *ClashHopInterval) UnmarshalJSON(data []byte) error {
	var seconds int
	if err := json.Unmarshal(data, &seconds); err == nil {
		i.Min = fmt.Sprintf("%ds", seconds)
		return nil
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	parts := strings.SplitN(strings.TrimSpace(value), "-", 2)
	i.Min = durationSeconds(parts[0])
	if len(parts) == 2 {
		i.Max = durationSeconds(parts[1])
	}
	return nil
}

func durationSeconds(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return value
	}
	return value + "s"
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
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Proxies       []string `json:"proxies"`
	Use           []string `json:"use,omitempty"`
	URL           string   `json:"url,omitempty"`
	Interval      int      `json:"interval,omitempty"`
	Tolerance     int      `json:"tolerance,omitempty"`
	Lazy          bool     `json:"lazy,omitempty"`
	Strategy      string   `json:"strategy,omitempty"`
	Filter        string   `json:"filter,omitempty"`
	ExcludeFilter string   `json:"exclude-filter,omitempty"`
}

type ClashProxyProvider struct {
	Type          string                    `json:"type"`
	URL           string                    `json:"url,omitempty"`
	Path          string                    `json:"path,omitempty"`
	Interval      int                       `json:"interval,omitempty"`
	Proxy         string                    `json:"proxy,omitempty"`
	Header        HTTPHeaders               `json:"header,omitempty"`
	Filter        string                    `json:"filter,omitempty"`
	ExcludeFilter string                    `json:"exclude-filter,omitempty"`
	ExcludeType   string                    `json:"exclude-type,omitempty"`
	Payload       []ClashProxy              `json:"payload,omitempty"`
	Override      *ClashProviderOverride    `json:"override,omitempty"`
	HealthCheck   *ClashProviderHealthCheck `json:"health-check,omitempty"`
}

type ClashProviderOverride struct {
	AdditionalPrefix string `json:"additional-prefix,omitempty"`
	AdditionalSuffix string `json:"additional-suffix,omitempty"`
	SkipCertVerify   *bool  `json:"skip-cert-verify,omitempty"`
}

type ClashProviderHealthCheck struct {
	Enable   bool   `json:"enable,omitempty"`
	URL      string `json:"url,omitempty"`
	Interval int    `json:"interval,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
	Lazy     bool   `json:"lazy,omitempty"`
}

type ClashRuleProvider struct {
	Type     string      `json:"type"`
	Behavior string      `json:"behavior"`
	Format   string      `json:"format,omitempty"`
	URL      string      `json:"url,omitempty"`
	Path     string      `json:"path,omitempty"`
	Interval int         `json:"interval,omitempty"`
	Proxy    string      `json:"proxy,omitempty"`
	Header   HTTPHeaders `json:"header,omitempty"`
	Payload  []string    `json:"payload,omitempty"`
}
