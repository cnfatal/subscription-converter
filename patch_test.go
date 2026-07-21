package subscriptionconverter_test

import (
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
)

func TestDecodeClashRulesPatchByDefault(t *testing.T) {
	patch, err := subscriptionconverter.DecodePatch([]byte(`
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - GEOIP,CN,DIRECT
  - IP-CIDR,192.0.2.0/24,REJECT
  - MATCH,proxy
`), "")
	if err != nil {
		t.Fatal(err)
	}
	if patch.Route == nil || len(patch.Route.Rules) != 3 || patch.Route.Final == nil || *patch.Route.Final != "proxy" {
		t.Fatalf("unexpected patch: %#v", patch)
	}
	if len(patch.Route.Rules[0].Match.DomainSuffixes) != 1 {
		t.Fatalf("unexpected domain rule: %#v", patch.Route.Rules[0])
	}
	if got := patch.Route.Rules[1].Match.GeoIPCodes; len(got) != 1 || got[0] != "cn" {
		t.Fatalf("unexpected GEOIP rule: %#v", patch.Route.Rules[1])
	}
	if patch.Route.Rules[2].Action.Type != subscriptionconverter.RouteActionReject {
		t.Fatalf("unexpected reject rule: %#v", patch.Route.Rules[2])
	}
}

func TestDecodeDocumentPatch(t *testing.T) {
	patch, err := subscriptionconverter.DecodePatch([]byte(`
route:
  rules:
    - match:
        domain_suffixes: [example.org]
      action:
        type: route
        target: direct
  final: proxy
`), subscriptionconverter.PatchFormatDocument)
	if err != nil {
		t.Fatal(err)
	}
	if patch.Route == nil || len(patch.Route.Rules) != 1 || patch.Route.Rules[0].Action.Target != "direct" {
		t.Fatalf("unexpected document patch: %#v", patch)
	}
}

func TestApplyPatchPrependsAndValidatesPolicies(t *testing.T) {
	document := subscriptionconverter.Document{
		Nodes: []subscriptionconverter.Node{{Name: "node"}},
		Route: subscriptionconverter.RouteConfig{
			Rules: []subscriptionconverter.RouteRule{{Match: subscriptionconverter.RouteMatch{Domains: []string{"source.example"}}, Action: subscriptionconverter.RouteAction{Type: subscriptionconverter.RouteActionRoute, Target: "node"}}},
			Final: "proxy",
		},
	}
	global := subscriptionconverter.DocumentPatch{Route: &subscriptionconverter.RoutePatch{Rules: []subscriptionconverter.RouteRule{{Match: subscriptionconverter.RouteMatch{Domains: []string{"global.example"}}, Action: subscriptionconverter.RouteAction{Type: subscriptionconverter.RouteActionRoute, Target: "direct"}}}}}
	local := subscriptionconverter.DocumentPatch{Route: &subscriptionconverter.RoutePatch{Rules: []subscriptionconverter.RouteRule{{Match: subscriptionconverter.RouteMatch{Domains: []string{"local.example"}}, Action: subscriptionconverter.RouteAction{Type: subscriptionconverter.RouteActionRoute, Target: "direct"}}}}}
	if err := subscriptionconverter.ApplyPatch(&document, global); err != nil {
		t.Fatal(err)
	}
	if err := subscriptionconverter.ApplyPatch(&document, local); err != nil {
		t.Fatal(err)
	}
	got := []string{
		document.Route.Rules[0].Match.Domains[0],
		document.Route.Rules[1].Match.Domains[0],
		document.Route.Rules[2].Match.Domains[0],
	}
	want := []string{"local.example", "global.example", "source.example"}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("unexpected rule order: %v", got)
		}
	}
	bad := subscriptionconverter.DocumentPatch{Route: &subscriptionconverter.RoutePatch{Rules: []subscriptionconverter.RouteRule{{Action: subscriptionconverter.RouteAction{Type: subscriptionconverter.RouteActionRoute, Target: "missing"}}}}}
	if err := subscriptionconverter.ApplyPatch(&document, bad); err == nil {
		t.Fatal("expected unknown policy error")
	}
}

func TestClashRulesPatchIsStrict(t *testing.T) {
	tests := [][]byte{
		[]byte("rules:\n  - GEOSITE,cn,DIRECT\n"),
		[]byte("rules:\n  - MATCH,direct\n  - MATCH,proxy\n"),
	}
	for _, input := range tests {
		if _, err := subscriptionconverter.DecodePatch(input, subscriptionconverter.PatchFormatClashRules); err == nil {
			t.Fatalf("expected patch error for %s", input)
		}
	}
	_, err := subscriptionconverter.DecodePatch([]byte("rules: []\n"), "unknown")
	if err == nil {
		t.Fatalf("unexpected format error: %v", err)
	}
}
