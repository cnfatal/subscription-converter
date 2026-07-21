package singbox_test

import (
	"encoding/json"
	"github.com/cnfatal/subscription-converter/builtin"
	"github.com/cnfatal/subscription-converter/singbox"
	"net/netip"
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
)

func TestSingBoxConfigAsPatchRoundTripsThroughDocument(t *testing.T) {
	patch, err := builtin.New().DecodePatch([]byte(`
log:
  level: info
  timestamp: true
dns:
  servers:
    - type: local
      tag: local
inbounds:
  - type: tun
    tag: tun-in
    address: [172.19.0.1/30]
    auto_route: true
    strict_route: true
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    listen_port: 7890
    set_system_proxy: true
    users:
      - username: local
        password: secret
outbounds:
  - type: direct
    tag: direct
route:
  rule_set:
    - type: remote
      tag: geoip-cn
      format: binary
      url: https://example.com/geoip-cn.srs
      download_detour: proxy
    - type: inline
      tag: ai-domains
      rules:
        - domain_suffix: [openai.com, anthropic.com]
  rules:
    - rule_set: [geoip-cn]
      outbound: direct
    - rule_set: [ai-domains]
      action: route
      outbound: proxy
    - domain_suffix: [ads.example]
      action: reject
  final: direct
`), subscriptionconverter.PatchFormatSingBox)
	if err != nil {
		t.Fatal(err)
	}
	if patch.Inbounds == nil || len(*patch.Inbounds) != 2 || patch.Route == nil || len(patch.Route.RuleSets) != 2 || len(patch.Route.Rules) != 3 {
		t.Fatalf("unexpected patch: %#v", patch)
	}

	document := subscriptionconverter.Document{
		Nodes: []subscriptionconverter.Node{{
			Name: "node", Type: subscriptionconverter.ProtocolShadowsocks,
			Server: "127.0.0.1", Port: 8388,
			Shadowsocks: &subscriptionconverter.ShadowsocksOptions{Method: "aes-128-gcm", Password: "secret"},
		}},
		Route: subscriptionconverter.RouteConfig{Final: "proxy"},
	}
	if err := subscriptionconverter.ApplyPatch(&document, patch); err != nil {
		t.Fatal(err)
	}
	if len(document.Route.RuleSets) != 2 || document.Route.Final != "direct" {
		t.Fatalf("unexpected patched document: %#v", document.Route)
	}
	if len(document.Inbounds) != 2 || document.Inbounds[1].Type != subscriptionconverter.InboundMixed {
		t.Fatalf("unexpected patched inbounds: %#v", document.Inbounds)
	}

	encoded, err := builtin.New().Encode(document, "sing-box", subscriptionconverter.EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var config singbox.SingBoxConfig
	if err := json.Unmarshal(encoded.Content, &config); err != nil {
		t.Fatal(err)
	}
	if config.Route == nil || len(config.Route.RuleSets) != 2 || config.Route.RuleSets[0].Tag != "geoip-cn" {
		t.Fatalf("unexpected encoded route: %#v", config.Route)
	}
	if len(config.Inbounds) != 2 || config.Inbounds[1].Listen != "127.0.0.1" || config.Inbounds[1].ListenPort != 7890 || len(config.Inbounds[1].Users) != 1 || !config.Inbounds[1].SetSystemProxy {
		t.Fatalf("unexpected encoded inbounds: %#v", config.Inbounds)
	}
	if got := config.Route.Rules[len(config.Route.Rules)-3].RuleSets; len(got) != 1 || got[0] != "geoip-cn" {
		t.Fatalf("unexpected encoded route rules: %#v", config.Route.Rules)
	}
}

func TestSingBoxPatchCanReplaceOrDisableInbounds(t *testing.T) {
	engine := builtin.New()
	patch, err := engine.DecodePatch([]byte(`
inbounds:
  - type: mixed
    tag: lan-in
    listen: 0.0.0.0
    listen_port: 7890
    users:
      - username: proxy
        password: secret
`), subscriptionconverter.PatchFormatSingBox)
	if err != nil {
		t.Fatal(err)
	}
	document := subscriptionconverter.DefaultDocument()
	if err := subscriptionconverter.ApplyPatch(&document, patch); err != nil {
		t.Fatal(err)
	}
	if len(document.Inbounds) != 1 || document.Inbounds[0].Type != subscriptionconverter.InboundMixed || document.Inbounds[0].Listen != "0.0.0.0" {
		t.Fatalf("inbounds were not replaced: %#v", document.Inbounds)
	}

	empty, err := engine.DecodePatch([]byte("inbounds: []\n"), subscriptionconverter.PatchFormatSingBox)
	if err != nil {
		t.Fatal(err)
	}
	if err := subscriptionconverter.ApplyPatch(&document, empty); err != nil {
		t.Fatal(err)
	}
	if document.Inbounds == nil || len(document.Inbounds) != 0 {
		t.Fatalf("inbounds were not explicitly disabled: %#v", document.Inbounds)
	}
}

func TestInboundPatchValidation(t *testing.T) {
	tests := map[string]string{
		"duplicate tag": `
inbounds:
  - {type: mixed, tag: duplicate, listen: 127.0.0.1, listen_port: 7890}
  - {type: http, tag: duplicate, listen: 127.0.0.1, listen_port: 8080}
`,
		"invalid listen": `
inbounds:
  - {type: socks, tag: socks-in, listen: localhost, listen_port: 1080}
`,
		"missing port": `
inbounds:
  - {type: mixed, tag: mixed-in, listen: 127.0.0.1}
`,
		"unsupported type": `
inbounds:
  - {type: redirect, tag: redirect-in, listen: 127.0.0.1, listen_port: 7892}
`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			patch, err := builtin.New().DecodePatch([]byte(input), subscriptionconverter.PatchFormatSingBox)
			if err != nil {
				t.Fatal(err)
			}
			document := subscriptionconverter.DefaultDocument()
			if err := subscriptionconverter.ApplyPatch(&document, patch); err == nil {
				t.Fatal("expected inbound validation error")
			}
		})
	}
}

func TestSingBoxEncodeWarnsForUnauthenticatedNonLoopbackInbound(t *testing.T) {
	document := subscriptionconverter.DefaultDocument()
	document.Inbounds = []subscriptionconverter.Inbound{{
		Type: subscriptionconverter.InboundMixed, Tag: "lan-in", Listen: "0.0.0.0", ListenPort: 7890,
	}}
	document.Nodes = []subscriptionconverter.Node{{
		Name: "node", Type: subscriptionconverter.ProtocolShadowsocks,
		Server: "127.0.0.1", Port: 8388,
		Shadowsocks: &subscriptionconverter.ShadowsocksOptions{Method: "aes-128-gcm", Password: "secret"},
	}}
	encoded, warnings, err := (singbox.SingBoxCodec{}).Encode(document, subscriptionconverter.EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected unauthenticated listener warning, got %v", warnings)
	}
	var raw struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	if _, exists := raw.Inbounds[0]["set_system_proxy"]; exists {
		t.Fatalf("default set_system_proxy was unexpectedly emitted: %#v", raw.Inbounds[0])
	}

	document.Inbounds[0].TUN = &subscriptionconverter.TUNConfig{}
	if _, _, err := (singbox.SingBoxCodec{}).Encode(document, subscriptionconverter.EncodeOptions{}); err == nil {
		t.Fatal("expected invalid inbound to fail encoding")
	}
}

func TestSingBoxEncodeSupportsLegacyDocumentTUN(t *testing.T) {
	document := subscriptionconverter.Document{
		TUN: subscriptionconverter.TUNConfig{
			Enabled: true, Tag: "legacy-tun", Addresses: []netip.Prefix{netip.MustParsePrefix("172.20.0.1/30")}, AutoRoute: true,
		},
		Nodes: []subscriptionconverter.Node{{
			Name: "node", Type: subscriptionconverter.ProtocolShadowsocks,
			Server: "127.0.0.1", Port: 8388,
			Shadowsocks: &subscriptionconverter.ShadowsocksOptions{Method: "aes-128-gcm", Password: "secret"},
		}},
		Route: subscriptionconverter.RouteConfig{Final: "proxy"},
	}
	encoded, _, err := (singbox.SingBoxCodec{}).Encode(document, subscriptionconverter.EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var config singbox.SingBoxConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || config.Inbounds[0].Tag != "legacy-tun" || len(config.Inbounds[0].Address) != 1 {
		t.Fatalf("legacy TUN was not encoded: %#v", config.Inbounds)
	}
}

func TestSingBoxPatchValidatesRuleSets(t *testing.T) {
	document := subscriptionconverter.Document{
		Nodes: []subscriptionconverter.Node{{Name: "node"}},
		Route: subscriptionconverter.RouteConfig{Final: "proxy"},
	}
	unknown := subscriptionconverter.DocumentPatch{Route: &subscriptionconverter.RoutePatch{
		Rules: []subscriptionconverter.RouteRule{{
			Match:  subscriptionconverter.RouteMatch{RuleSets: []string{"missing"}},
			Action: subscriptionconverter.RouteAction{Type: subscriptionconverter.RouteActionRoute, Target: "proxy"},
		}},
	}}
	if err := subscriptionconverter.ApplyPatch(&document, unknown); err == nil {
		t.Fatal("expected unknown rule-set error")
	}

	duplicate := subscriptionconverter.DocumentPatch{Route: &subscriptionconverter.RoutePatch{
		RuleSets: []subscriptionconverter.RuleSet{
			{Type: subscriptionconverter.RuleSetRemote, Tag: "same", URL: "https://example.com/one.srs"},
			{Type: subscriptionconverter.RuleSetRemote, Tag: "same", URL: "https://example.com/two.srs"},
		},
	}}
	if err := subscriptionconverter.ApplyPatch(&document, duplicate); err == nil {
		t.Fatal("expected duplicate rule-set error")
	}
}

func TestRuleSetPatchOverridesByTag(t *testing.T) {
	document := subscriptionconverter.Document{Route: subscriptionconverter.RouteConfig{
		RuleSets: []subscriptionconverter.RuleSet{{
			Type: subscriptionconverter.RuleSetRemote, Tag: "shared", URL: "https://example.com/source.srs",
		}},
	}}
	patch := subscriptionconverter.DocumentPatch{Route: &subscriptionconverter.RoutePatch{
		RuleSets: []subscriptionconverter.RuleSet{{
			Type: subscriptionconverter.RuleSetRemote, Tag: "shared", URL: "https://example.com/patch.srs",
		}},
	}}
	if err := subscriptionconverter.ApplyPatch(&document, patch); err != nil {
		t.Fatal(err)
	}
	if len(document.Route.RuleSets) != 1 || document.Route.RuleSets[0].URL != "https://example.com/patch.srs" {
		t.Fatalf("rule-set was not overridden: %#v", document.Route.RuleSets)
	}
}
