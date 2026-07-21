package subscriptionconverter

import "net/netip"

// DefaultDocument returns the baseline shared configuration used by codecs.
func DefaultDocument() Document {
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
