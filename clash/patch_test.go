package clash_test

import (
	"os"
	"path/filepath"
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
	"github.com/cnfatal/subscription-converter/builtin"
)

func TestDecodeClashPatchByDefault(t *testing.T) {
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

func TestFullClashConfigPatchMergesDocumentSections(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "testdata", "clash.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	patch, err := builtin.New().DecodePatch(input, subscriptionconverter.PatchFormatClash)
	if err != nil {
		t.Fatal(err)
	}
	if len(patch.Nodes) != 5 || len(patch.Groups) != 2 || patch.DNS == nil || patch.Route == nil || patch.Route.Final == nil || len(patch.Warnings) != 1 {
		t.Fatalf("incomplete Clash patch: %#v", patch)
	}
	document := subscriptionconverter.DefaultDocument()
	document.Nodes = []subscriptionconverter.Node{{
		Name: "ss-hk", Type: subscriptionconverter.ProtocolShadowsocks,
		Server: "203.0.113.1", Port: 8388,
		Shadowsocks: &subscriptionconverter.ShadowsocksOptions{Method: "aes-128-gcm", Password: "old"},
	}}
	if err := subscriptionconverter.ApplyPatch(&document, patch); err != nil {
		t.Fatal(err)
	}
	if len(document.Nodes) != 5 || document.Nodes[0].Server != "192.0.2.10" || len(document.Groups) != 2 || len(document.DNS.Servers) != 6 || document.Route.Final != "Main" {
		t.Fatalf("Clash config was not fully merged: %#v", document)
	}
}

func TestClashPatchResolvesRelativeProviders(t *testing.T) {
	directory := t.TempDir()
	providerPath := filepath.Join(directory, "provider.yaml")
	patchPath := filepath.Join(directory, "patch.yaml")
	if err := os.WriteFile(providerPath, []byte(`
proxies:
  - {name: provider-node, type: ss, server: 192.0.2.50, port: 8388, cipher: aes-128-gcm, password: secret}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patchPath, []byte(`
proxy-providers:
  local:
    type: file
    path: ./provider.yaml
proxy-groups:
  - {name: Patched, type: select, use: [local]}
rules:
  - MATCH,Patched
`), 0o600); err != nil {
		t.Fatal(err)
	}
	patch, err := builtin.New().LoadPatches(subscriptionconverter.NewLoader(nil), []subscriptionconverter.PatchSource{{
		Format: subscriptionconverter.PatchFormatClash,
		Source: subscriptionconverter.Source{Location: patchPath},
	}})
	if err != nil {
		t.Fatal(err)
	}
	document := subscriptionconverter.DefaultDocument()
	if err := subscriptionconverter.ApplyPatch(&document, patch); err != nil {
		t.Fatal(err)
	}
	if len(document.Nodes) != 1 || document.Nodes[0].Name != "provider-node" || len(document.Groups) != 1 || document.Route.Final != "Patched" {
		t.Fatalf("relative provider patch failed: %#v", document)
	}
}

func TestClashPatchIsStrict(t *testing.T) {
	tests := [][]byte{
		[]byte("rules:\n  - UNKNOWN,cn,DIRECT\n"),
		[]byte("rules:\n  - MATCH,direct\n  - MATCH,proxy\n"),
	}
	for _, input := range tests {
		if _, err := builtin.New().DecodePatch(input, subscriptionconverter.PatchFormatClash); err == nil {
			t.Fatalf("expected patch error for %s", input)
		}
	}
	_, err := builtin.New().DecodePatch([]byte("rules: []\n"), "unknown")
	if err == nil {
		t.Fatalf("unexpected format error: %v", err)
	}
	if _, err := builtin.New().DecodePatch([]byte("rules: []\n"), "clash-rules"); err == nil {
		t.Fatal("legacy clash-rules format must be rejected")
	}
}
