package subscriptionconverter_test

import (
	"encoding/json"
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
	"sigs.k8s.io/yaml"
)

func TestClashConfigStrongTypes(t *testing.T) {
	var config subscriptionconverter.ClashConfig
	if err := yaml.Unmarshal(readFixture(t), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Proxies) != 3 || len(config.ProxyGroups) != 2 {
		t.Fatalf("unexpected config sizes: %#v", config)
	}
	vless := config.Proxies[1]
	if vless.Type != subscriptionconverter.ClashProxyVLESS || vless.Port != 443 {
		t.Fatalf("unexpected typed proxy: %#v", vless)
	}
	if vless.WebSocket == nil || vless.WebSocket.Path != "/ws" {
		t.Fatalf("unexpected WebSocket options: %#v", vless.WebSocket)
	}
	if vless.WebSocket.Headers["Host"] != "example.com" {
		t.Fatalf("unexpected WebSocket headers: %#v", vless.WebSocket.Headers)
	}
	if config.ProxyGroups[0].Type != "url-test" {
		t.Fatalf("unexpected typed group: %#v", config.ProxyGroups[0])
	}
}

func TestClashDecodeBuildsStrongDocument(t *testing.T) {
	decoded, warnings, err := (subscriptionconverter.ClashCodec{}).Decode(
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
	if vless.Transport == nil || vless.Transport.Type != subscriptionconverter.TransportWebSocket || vless.Transport.Path != "/ws" {
		t.Fatalf("unexpected transport: %#v", vless.Transport)
	}
	if len(decoded.Route.Rules) != 3 || decoded.Route.Final != "Main" {
		t.Fatalf("unexpected route: %#v", decoded.Route)
	}
	if !decoded.TUN.Enabled || len(decoded.DNS.Servers) != 3 {
		t.Fatalf("expected typed TUN and DNS config: %#v %#v", decoded.TUN, decoded.DNS)
	}
}

func TestClashDNSIsConvertedThroughDocument(t *testing.T) {
	document, warnings, err := (subscriptionconverter.ClashCodec{}).Decode(readFixture(t), subscriptionconverter.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(document.DNS.Servers) != 3 || document.DNS.Servers[0].Type != subscriptionconverter.DNSServerUDP {
		t.Fatalf("unexpected DNS servers: %#v", document.DNS.Servers)
	}
	if len(document.DNS.Rules) != 1 || document.DNS.Rules[0].Match.DomainSuffixes[0] != "example.org" {
		t.Fatalf("unexpected DNS rules: %#v", document.DNS.Rules)
	}
	output, encodeWarnings, err := (subscriptionconverter.SingBoxCodec{}).Encode(*document, subscriptionconverter.EncodeOptions{})
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
	}
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatal(err)
	}
	if config.DNS.Final != "dns-1" || len(config.DNS.Servers) != 3 || len(config.DNS.Rules) != 1 {
		t.Fatalf("unexpected encoded DNS: %#v", config.DNS)
	}
}

func TestDocumentUsesJSONTags(t *testing.T) {
	document, _, err := (subscriptionconverter.ClashCodec{}).Decode(readFixture(t), subscriptionconverter.DecodeOptions{})
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
