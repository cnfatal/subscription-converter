package subscriptionconverter_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
)

func TestClashToSingBox(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("testdata", "clash.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	output, warnings, err := subscriptionconverter.New().Convert(input, "clash", "sing-box")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one unsupported-rule warning, got %v", warnings)
	}
	var config map[string]any
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatalf("invalid output JSON: %v", err)
	}
	outbounds, ok := config["outbounds"].([]any)
	if !ok || len(outbounds) != 7 {
		t.Fatalf("unexpected outbounds: %#v", config["outbounds"])
	}
	route := config["route"].(map[string]any)
	if route["final"] != "Main" {
		t.Fatalf("unexpected final route: %#v", route["final"])
	}
}

func TestUnknownFormats(t *testing.T) {
	engine := subscriptionconverter.New()
	if _, _, err := engine.Convert(nil, "unknown", "sing-box"); err == nil {
		t.Fatal("expected unsupported input format error")
	}
}

func TestDecodeAuto(t *testing.T) {
	input := readFixture(t)
	result, err := subscriptionconverter.New().Decode(input, "", subscriptionconverter.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "clash" {
		t.Fatalf("unexpected format: %#v", result)
	}
	if result.Document == nil || len(result.Document.Nodes) != 3 {
		t.Fatalf("unexpected document: %#v", result.Document)
	}
}

func TestDecodeFormatForcesCodec(t *testing.T) {
	_, err := subscriptionconverter.New().Decode(readFixture(t), "sing-box", subscriptionconverter.DecodeOptions{})
	if !errors.Is(err, subscriptionconverter.ErrDecodeUnsupported) {
		t.Fatalf("expected sing-box decoder error, got %v", err)
	}
}

func TestEncodeOptions(t *testing.T) {
	engine := subscriptionconverter.New()
	decoded, err := engine.Decode(readFixture(t), "clash", subscriptionconverter.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := engine.Encode(*decoded.Document, "singbox", subscriptionconverter.EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if encoded.Format != "sing-box" || len(encoded.Content) == 0 {
		t.Fatalf("unexpected encode result: %#v", encoded)
	}
	_, err = engine.Encode(*decoded.Document, "", subscriptionconverter.EncodeOptions{})
	if !errors.Is(err, subscriptionconverter.ErrMissingFormat) {
		t.Fatalf("expected missing format error, got %v", err)
	}
}

func TestEncodeGeoIPAsRuleSet(t *testing.T) {
	document := subscriptionconverter.Document{
		Nodes: []subscriptionconverter.Node{{
			Name: "node", Type: subscriptionconverter.ProtocolShadowsocks,
			Server: "127.0.0.1", Port: 8388,
			Shadowsocks: &subscriptionconverter.ShadowsocksOptions{Method: "aes-128-gcm", Password: "secret"},
		}},
		Route: subscriptionconverter.RouteConfig{
			Rules: []subscriptionconverter.RouteRule{{
				Match:  subscriptionconverter.RouteMatch{GeoIPCodes: []string{"cn"}},
				Action: subscriptionconverter.RouteAction{Type: subscriptionconverter.RouteActionRoute, Target: "direct"},
			}},
			Final: "proxy",
		},
	}
	encoded, err := subscriptionconverter.New().Encode(document, "sing-box", subscriptionconverter.EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(encoded.Content, &config); err != nil {
		t.Fatal(err)
	}
	route := config["route"].(map[string]any)
	ruleSets := route["rule_set"].([]any)
	if len(ruleSets) != 1 || ruleSets[0].(map[string]any)["tag"] != "geoip-cn" {
		t.Fatalf("unexpected rule sets: %#v", ruleSets)
	}
	rules := route["rules"].([]any)
	geoIPRule := rules[len(rules)-1].(map[string]any)
	if got := geoIPRule["rule_set"].([]any); len(got) != 1 || got[0] != "geoip-cn" {
		t.Fatalf("unexpected GEOIP route rule: %#v", geoIPRule)
	}
}

func readFixture(t *testing.T) []byte {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("testdata", "clash.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return input
}
