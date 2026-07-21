package clash_test

import (
	"encoding/json"
	"fmt"
	"github.com/cnfatal/subscription-converter/clash"
	"github.com/cnfatal/subscription-converter/singbox"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
	"sigs.k8s.io/yaml"
)

func TestClashProvidersAreResolved(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test" {
			http.Error(writer, "missing authorization", http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/proxies":
			_, _ = writer.Write([]byte("proxies:\n  - {name: provider-ss, type: ss, server: 192.0.2.20, port: 8388, cipher: aes-128-gcm, password: secret}\n"))
		case "/rules":
			_, _ = writer.Write([]byte("payload:\n  - DOMAIN-SUFFIX,provider.example\n"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	input := fmt.Sprintf(`
proxies:
  - {name: inline-ss, type: ss, server: 192.0.2.10, port: 8388, cipher: aes-128-gcm, password: secret}
proxy-providers:
  remote:
    type: http
    url: %[1]s/proxies
    header: {Authorization: "Bearer test"}
    filter: provider
proxy-groups:
  - {name: Proxy, type: select, proxies: [inline-ss], use: [remote]}
rule-providers:
  remote-rules:
    type: http
    behavior: classical
    format: yaml
    url: %[1]s/rules
    header: {Authorization: "Bearer test"}
rules:
  - RULE-SET,remote-rules,Proxy
  - GEOSITE,github,Proxy
  - MATCH,Proxy
`, server.URL)
	document, warnings, err := (clash.ClashCodec{}).Decode([]byte(input), subscriptionconverter.DecodeOptions{Loader: subscriptionconverter.NewLoader(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 || len(document.Nodes) != 2 || len(document.Groups) != 1 {
		t.Fatalf("unexpected provider document: warnings=%v document=%#v", warnings, document)
	}
	if got := document.Groups[0].Members; len(got) != 2 || got[1] != "provider-ss" {
		t.Fatalf("provider members were not expanded: %v", got)
	}
	if len(document.Route.RuleSets) != 1 || document.Route.RuleSets[0].Tag != "remote-rules" || len(document.Route.RuleSets[0].Rules) != 1 {
		t.Fatalf("rule provider was not expanded: %#v", document.Route.RuleSets)
	}
	output, encodeWarnings, err := (singbox.SingBoxCodec{}).Encode(*document, subscriptionconverter.EncodeOptions{})
	if err != nil || len(encodeWarnings) != 0 {
		t.Fatalf("encode provider document: warnings=%v err=%v", encodeWarnings, err)
	}
	var config singbox.SingBoxConfig
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatal(err)
	}
	if config.Route == nil || len(config.Route.RuleSets) != 2 || config.Route.RuleSets[0].Type != singbox.SingBoxRuleSetInline {
		t.Fatalf("unexpected encoded provider rule-sets: %#v", config.Route)
	}
}

func TestClashConfigStrongTypes(t *testing.T) {
	var config clash.ClashConfig
	if err := yaml.Unmarshal(readFixture(t), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Proxies) != 5 || len(config.ProxyGroups) != 2 {
		t.Fatalf("unexpected config sizes: %#v", config)
	}
	vless := config.Proxies[1]
	if vless.Type != clash.ClashProxyVLESS || vless.Port != 443 {
		t.Fatalf("unexpected typed proxy: %#v", vless)
	}
	if vless.WebSocket == nil || vless.WebSocket.Path != "/ws" {
		t.Fatalf("unexpected WebSocket options: %#v", vless.WebSocket)
	}
	if vless.WebSocket.Headers["Host"] != "example.com" {
		t.Fatalf("unexpected WebSocket headers: %#v", vless.WebSocket.Headers)
	}
	if vless.Reality == nil || vless.Reality.ShortID != "0123456789abcdef" {
		t.Fatalf("unexpected Reality options: %#v", vless.Reality)
	}
	if got := config.Proxies[4]; len(got.Ports) != 1 || got.Ports[0] != "10000:20000" || got.HopInterval.Min != "30s" {
		t.Fatalf("unexpected Hysteria2 port hopping: %#v", got)
	}
	if config.ProxyGroups[0].Type != "url-test" {
		t.Fatalf("unexpected typed group: %#v", config.ProxyGroups[0])
	}
}

func TestClashDecodeBuildsStrongDocument(t *testing.T) {
	decoded, warnings, err := (clash.ClashCodec{}).Decode(
		readFixture(t), subscriptionconverter.DecodeOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	vless := decoded.Nodes[1]
	if vless.Type != subscriptionconverter.ProtocolVLESS || vless.VLESS == nil {
		t.Fatalf("expected typed VLESS node, got %#v", vless)
	}
	if vless.TLS == nil || vless.TLS.ServerName != "example.com" {
		t.Fatalf("unexpected TLS options: %#v", vless.TLS)
	}
	if vless.TLS.Reality == nil || vless.TLS.Reality.PublicKey == "" {
		t.Fatalf("missing Reality options: %#v", vless.TLS)
	}
	if vless.VLESS == nil || vless.VLESS.Encryption != "none" {
		t.Fatalf("unexpected VLESS encryption: %#v", vless.VLESS)
	}
	if decoded.Nodes[3].Type != subscriptionconverter.ProtocolAnyTLS || decoded.Nodes[3].AnyTLS == nil {
		t.Fatalf("unexpected AnyTLS node: %#v", decoded.Nodes[3])
	}
	if decoded.Nodes[4].Type != subscriptionconverter.ProtocolHysteria2 || decoded.Nodes[4].Hysteria2.HopInterval != "30s" {
		t.Fatalf("unexpected Hysteria2 node: %#v", decoded.Nodes[4])
	}
	if vless.Transport == nil || vless.Transport.Type != subscriptionconverter.TransportWebSocket || vless.Transport.Path != "/ws" {
		t.Fatalf("unexpected transport: %#v", vless.Transport)
	}
	if len(decoded.Route.Rules) != 4 || decoded.Route.Final != "Main" || len(decoded.Route.Rules[3].Match.GeoSiteCodes) != 1 {
		t.Fatalf("unexpected route: %#v", decoded.Route)
	}
	if len(decoded.Inbounds) != 1 || decoded.Inbounds[0].Type != subscriptionconverter.InboundTUN || decoded.Inbounds[0].TUN == nil || len(decoded.DNS.Servers) != 6 || decoded.DNS.Final != "dns-1" || !decoded.DNS.StoreFakeIP {
		t.Fatalf("expected typed TUN inbound and DNS config: %#v %#v", decoded.Inbounds, decoded.DNS)
	}
}

func TestModernClashProtocolsEncodeToSingBox(t *testing.T) {
	document, warnings, err := (clash.ClashCodec{}).Decode(readFixture(t), subscriptionconverter.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	output, warnings, err := (singbox.SingBoxCodec{}).Encode(*document, subscriptionconverter.EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected encode warnings: %v", warnings)
	}
	var config singbox.SingBoxConfig
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatal(err)
	}
	outbounds := make(map[string]singbox.SingBoxOutbound, len(config.Outbounds))
	for _, outbound := range config.Outbounds {
		outbounds[outbound.Tag] = outbound
	}
	if outbound := outbounds["anytls-sg"]; outbound.Type != singbox.SingBoxOutboundAnyTLS || outbound.TLS == nil {
		t.Fatalf("unexpected AnyTLS outbound: %#v", outbound)
	}
	if outbound := outbounds["hysteria2-de"]; len(outbound.ServerPorts) != 1 || outbound.HopInterval != "30s" {
		t.Fatalf("unexpected Hysteria2 outbound: %#v", outbound)
	}
	if outbound := outbounds["vless-us"]; outbound.TLS == nil || outbound.TLS.Reality == nil || outbound.TLS.Reality.ShortID != "0123456789abcdef" {
		t.Fatalf("unexpected VLESS Reality outbound: %#v", outbound)
	}
	if outbound := outbounds["Main"]; len(outbound.Outbounds) != 4 || outbound.Outbounds[3] != "reject" {
		t.Fatalf("REJECT group member was not preserved: %#v", outbound)
	}
	if outbound := outbounds["reject"]; outbound.Type != singbox.SingBoxOutboundBlock {
		t.Fatalf("missing block outbound: %#v", outbound)
	}
}

func TestSingBoxRejectsUnsupportedVLESSEncryption(t *testing.T) {
	document := subscriptionconverter.Document{Nodes: []subscriptionconverter.Node{{
		Name: "encrypted-vless", Type: subscriptionconverter.ProtocolVLESS,
		Server: "example.com", Port: 443,
		VLESS: &subscriptionconverter.VLESSOptions{
			UUID: "00000000-0000-0000-0000-000000000001", Encryption: "mlkem768x25519plus.native.0rtt.server",
		},
	}}}
	_, warnings, err := (singbox.SingBoxCodec{}).Encode(document, subscriptionconverter.EncodeOptions{})
	if err == nil || len(warnings) != 1 || !strings.Contains(warnings[0], "VLESS encryption") {
		t.Fatalf("expected unsupported VLESS encryption to be reported, warnings=%v err=%v", warnings, err)
	}
}

func TestProxyGroupCompatibility(t *testing.T) {
	nodes := []subscriptionconverter.Node{
		{Name: "a", Type: subscriptionconverter.ProtocolShadowsocks, Server: "192.0.2.1", Port: 8388, Shadowsocks: &subscriptionconverter.ShadowsocksOptions{Method: "aes-128-gcm", Password: "secret"}},
		{Name: "b", Type: subscriptionconverter.ProtocolShadowsocks, Server: "192.0.2.2", Port: 8388, Shadowsocks: &subscriptionconverter.ShadowsocksOptions{Method: "aes-128-gcm", Password: "secret"}},
	}
	document := subscriptionconverter.Document{
		Nodes: nodes,
		Groups: []subscriptionconverter.Group{
			{Name: "Relay", Type: subscriptionconverter.GroupRelay, Members: []string{"a", "b"}},
			{Name: "Fallback", Type: subscriptionconverter.GroupFallback, Members: []string{"a", "b"}},
			{Name: "Balance", Type: subscriptionconverter.GroupLoadBalance, Members: []string{"a", "b"}, Strategy: "round-robin"},
		},
		Route: subscriptionconverter.RouteConfig{Final: "Relay"},
	}
	output, warnings, err := (singbox.SingBoxCodec{}).Encode(document, subscriptionconverter.EncodeOptions{})
	if err != nil || len(warnings) != 2 {
		t.Fatalf("unexpected group compatibility result: warnings=%v err=%v", warnings, err)
	}
	var config singbox.SingBoxConfig
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatal(err)
	}
	outbounds := make(map[string]singbox.SingBoxOutbound, len(config.Outbounds))
	for _, outbound := range config.Outbounds {
		outbounds[outbound.Tag] = outbound
	}
	if outbounds["Relay"].Detour != "Relay-hop-1" || outbounds["Fallback"].Type != singbox.SingBoxOutboundURLTest || outbounds["Balance"].Type != singbox.SingBoxOutboundSelector {
		t.Fatalf("unexpected group outbounds: %#v", outbounds)
	}
}

func TestClashDNSIsConvertedThroughDocument(t *testing.T) {
	document, warnings, err := (clash.ClashCodec{}).Decode(readFixture(t), subscriptionconverter.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(document.DNS.Servers) != 6 || document.DNS.Servers[0].Type != subscriptionconverter.DNSServerUDP {
		t.Fatalf("unexpected DNS servers: %#v", document.DNS.Servers)
	}
	if len(document.DNS.Rules) != 3 || document.DNS.Rules[0].Match.DomainSuffixes[0] != "example.org" {
		t.Fatalf("unexpected DNS rules: %#v", document.DNS.Rules)
	}
	output, encodeWarnings, err := (singbox.SingBoxCodec{}).Encode(*document, subscriptionconverter.EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(encodeWarnings) != 0 {
		t.Fatalf("unexpected encode warnings: %v", encodeWarnings)
	}
	var config struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
			Final   string           `json:"final"`
		} `json:"dns"`
		Experimental *singbox.SingBoxExperimentalConfig `json:"experimental"`
	}
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatal(err)
	}
	if config.DNS.Final != "dns-1" || len(config.DNS.Servers) != 6 || len(config.DNS.Rules) != 3 || config.Experimental == nil || config.Experimental.CacheFile == nil || !config.Experimental.CacheFile.StoreFakeIP {
		t.Fatalf("unexpected encoded DNS: %#v", config.DNS)
	}
}

func TestClashDNSFakeIPRuleModeAndFallbackResponse(t *testing.T) {
	input := []byte(`
proxies:
  - {name: ss, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: secret}
proxy-groups:
  - {name: Proxy, type: select, proxies: [ss]}
dns:
  enable: true
  nameserver: [223.5.5.5]
  fallback: [tls://1.1.1.1]
  fallback-filter:
    geoip: false
    domain: ["+.fallback.example"]
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - DOMAIN-SUFFIX,local.example,real-ip
    - MATCH,fake-ip
rules: ["MATCH,Proxy"]
`)
	document, warnings, err := (clash.ClashCodec{}).Decode(input, subscriptionconverter.DecodeOptions{})
	if err != nil || len(warnings) != 1 {
		t.Fatalf("unexpected DNS conversion: warnings=%v err=%v", warnings, err)
	}
	if len(document.DNS.Rules) != 2 || document.DNS.Rules[0].Server != "dns-1" || document.DNS.Rules[1].Server != "fakeip" {
		t.Fatalf("unexpected FakeIP rules: %#v", document.DNS.Rules)
	}
	output, warnings, err := (singbox.SingBoxCodec{}).Encode(*document, subscriptionconverter.EncodeOptions{})
	if err != nil || len(warnings) != 0 || !strings.Contains(string(output), `"type": "fakeip"`) {
		t.Fatalf("unexpected FakeIP output: warnings=%v err=%v\n%s", warnings, err, output)
	}
}

func TestDocumentUsesJSONTags(t *testing.T) {
	document, _, err := (clash.ClashCodec{}).Decode(readFixture(t), subscriptionconverter.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	nodes, ok := value["nodes"].([]any)
	if !ok || len(nodes) == 0 {
		t.Fatalf("missing nodes JSON field: %s", encoded)
	}
	vless := nodes[1].(map[string]any)
	if vless["type"] != "vless" || vless["vless"] == nil || vless["transport"] == nil {
		t.Fatalf("unexpected tagged node JSON: %#v", vless)
	}
	if _, exists := value["Nodes"]; exists {
		t.Fatalf("Go field name leaked into JSON: %s", encoded)
	}
}

func readFixture(t *testing.T) []byte {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("..", "testdata", "clash.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return input
}
