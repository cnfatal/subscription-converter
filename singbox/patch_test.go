package singbox_test

import (
	"encoding/json"
	"github.com/cnfatal/subscription-converter/builtin"
	"github.com/cnfatal/subscription-converter/singbox"
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
	if patch.Route == nil || len(patch.Route.RuleSets) != 2 || len(patch.Route.Rules) != 3 {
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
	if got := config.Route.Rules[len(config.Route.Rules)-3].RuleSets; len(got) != 1 || got[0] != "geoip-cn" {
		t.Fatalf("unexpected encoded route rules: %#v", config.Route.Rules)
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
