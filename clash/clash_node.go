package clash

import (
	"fmt"
	. "github.com/cnfatal/subscription-converter"
	"strings"
)

func (p ClashProxy) node() (Node, string) {
	node := Node{Name: p.Name, Server: p.Server, Port: p.Port}
	defaultTLS := p.Type == ClashProxyTrojan || p.Type == ClashProxyHysteria2 || p.Type == ClashProxyAnyTLS || p.Type == ClashProxyTUIC || p.Reality != nil
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
		if p.Reality != nil {
			node.TLS.Reality = &RealityOptions{PublicKey: p.Reality.PublicKey, ShortID: p.Reality.ShortID}
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
		node.VLESS = &VLESSOptions{UUID: p.UUID, Flow: p.Flow, Encryption: p.Encryption}
	case ClashProxyTrojan:
		node.Type = ProtocolTrojan
		node.Trojan = &TrojanOptions{Password: p.Password}
	case ClashProxyHysteria2:
		node.Type = ProtocolHysteria2
		node.Hysteria2 = &Hysteria2Options{
			Password: FirstNonEmpty(p.Password, p.Auth), ServerPorts: []string(p.Ports),
			HopInterval: p.HopInterval.Min, HopIntervalMax: p.HopInterval.Max,
			UpMbps: firstPositive(p.UpMbps, p.Up), DownMbps: firstPositive(p.DownMbps, p.Down),
			ObfsPassword: p.ObfsPassword,
		}
	case ClashProxyAnyTLS:
		node.Type = ProtocolAnyTLS
		node.AnyTLS = &AnyTLSOptions{Password: p.Password}
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

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
