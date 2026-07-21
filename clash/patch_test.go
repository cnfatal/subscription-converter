package clash_test

import (
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
	"github.com/cnfatal/subscription-converter/builtin"
)

func TestDecodeClashRulesPatchByDefault(t *testing.T) {
	patch, err := builtin.New().DecodePatch([]byte(`
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

func TestClashRulesPatchIsStrict(t *testing.T) {
	tests := [][]byte{
		[]byte("rules:\n  - UNKNOWN,cn,DIRECT\n"),
		[]byte("rules:\n  - MATCH,direct\n  - MATCH,proxy\n"),
	}
	for _, input := range tests {
		if _, err := builtin.New().DecodePatch(input, subscriptionconverter.PatchFormatClashRules); err == nil {
			t.Fatalf("expected patch error for %s", input)
		}
	}
	_, err := builtin.New().DecodePatch([]byte("rules: []\n"), "unknown")
	if err == nil {
		t.Fatalf("unexpected format error: %v", err)
	}
}
