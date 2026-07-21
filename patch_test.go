package subscriptionconverter_test

import (
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
)

func TestDecodeDocumentPatch(t *testing.T) {
	patch, err := subscriptionconverter.New().DecodePatch([]byte(`
inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    listen_port: 7890
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
	if patch.Inbounds == nil || len(*patch.Inbounds) != 1 || (*patch.Inbounds)[0].Type != subscriptionconverter.InboundMixed || patch.Route == nil || len(patch.Route.Rules) != 1 || patch.Route.Rules[0].Action.Target != "direct" {
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
