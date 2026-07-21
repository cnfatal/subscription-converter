package subscriptionconverter_test

import (
	"encoding/json"
	"github.com/cnfatal/subscription-converter/builtin"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
)

func TestHandlerRoutesSubscriptionsByName(t *testing.T) {
	config := subscriptionconverter.Config{Subscriptions: []subscriptionconverter.SubscriptionConfig{
		{Name: "primary", Source: subscriptionconverter.Source{Location: "testdata/clash.yaml"}},
		{Name: "wrong-format", Source: subscriptionconverter.Source{Location: "testdata/clash.yaml"}, Format: "sing-box"},
	}}
	handler, err := subscriptionconverter.NewHandler(config, builtin.New(), nil)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/subscriptions/primary?format=sing-box", nil)
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.Code, response.Body.String())
	}
	var output map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatalf("invalid converted JSON: %v", err)
	}
	if _, exists := output["outbounds"]; !exists {
		t.Fatal("converted configuration has no outbounds")
	}

	missingFormat := httptest.NewRecorder()
	handler.Routes().ServeHTTP(missingFormat, httptest.NewRequest(http.MethodGet, "/subscriptions/primary", nil))
	if missingFormat.Code != http.StatusBadRequest {
		t.Fatalf("unexpected missing format status: %d", missingFormat.Code)
	}

	missing := httptest.NewRecorder()
	handler.Routes().ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/subscriptions/missing", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unexpected missing status: %d", missing.Code)
	}

	forced := httptest.NewRecorder()
	handler.Routes().ServeHTTP(forced, httptest.NewRequest(http.MethodGet, "/subscriptions/wrong-format?format=sing-box", nil))
	if forced.Code != http.StatusBadGateway {
		t.Fatalf("configured input format was not forced: %d", forced.Code)
	}
}

func TestHandlerVersion(t *testing.T) {
	config := subscriptionconverter.Config{Subscriptions: []subscriptionconverter.SubscriptionConfig{{
		Name: "primary", Source: subscriptionconverter.Source{Location: "testdata/clash.yaml"},
	}}}
	handler, err := subscriptionconverter.NewHandler(config, builtin.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/version", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.Code, response.Body.String())
	}
	var version subscriptionconverter.Version
	if err := json.Unmarshal(response.Body.Bytes(), &version); err != nil {
		t.Fatal(err)
	}
	if version.GitVersion == "" || version.GitCommit == "" || version.Platform == "" {
		t.Fatalf("incomplete version: %#v", version)
	}
}

func TestHandlerAppliesSubscriptionPatchBeforeGlobalAndSourceRules(t *testing.T) {
	directory := t.TempDir()
	globalPath := filepath.Join(directory, "global.yaml")
	localPath := filepath.Join(directory, "local.yaml")
	if err := os.WriteFile(globalPath, []byte("rules:\n  - DOMAIN,global.example,DIRECT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, []byte("rules:\n  - DOMAIN,local.example,DIRECT\n  - MATCH,DIRECT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := subscriptionconverter.Config{
		Patches: []subscriptionconverter.PatchSource{{Source: subscriptionconverter.Source{Location: globalPath}}},
		Subscriptions: []subscriptionconverter.SubscriptionConfig{{
			Name: "primary", Source: subscriptionconverter.Source{Location: "testdata/clash.yaml"}, Format: "clash",
			Patches: []subscriptionconverter.PatchSource{{Source: subscriptionconverter.Source{Location: localPath}, Format: "clash"}},
		}},
	}
	handler, err := subscriptionconverter.NewHandler(config, builtin.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/subscriptions/primary?format=sing-box", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.Code, response.Body.String())
	}
	var output struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.Route.Final != "direct" {
		t.Fatalf("local patch did not override final: %#v", output.Route)
	}
	if len(output.Route.Rules) < 6 {
		t.Fatalf("missing route rules: %#v", output.Route.Rules)
	}
	if firstString(output.Route.Rules[3]["domain"]) != "local.example" || firstString(output.Route.Rules[4]["domain"]) != "global.example" || firstString(output.Route.Rules[5]["domain_suffix"]) != "example.org" {
		t.Fatalf("unexpected patch priority: %#v", output.Route.Rules)
	}
}

func TestHandlerAppliesSubscriptionInboundPatchOverGlobalDefault(t *testing.T) {
	directory := t.TempDir()
	globalPath := filepath.Join(directory, "global-sing-box.yaml")
	localPath := filepath.Join(directory, "local-sing-box.yaml")
	if err := os.WriteFile(globalPath, []byte(`
inbounds:
  - {type: mixed, tag: local-in, listen: 127.0.0.1, listen_port: 7890}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, []byte(`
inbounds:
  - type: mixed
    tag: lan-in
    listen: 0.0.0.0
    listen_port: 7891
    users:
      - {username: proxy, password: secret}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := subscriptionconverter.Config{
		Patches: []subscriptionconverter.PatchSource{{
			Format: subscriptionconverter.PatchFormatSingBox,
			Source: subscriptionconverter.Source{Location: globalPath},
		}},
		Subscriptions: []subscriptionconverter.SubscriptionConfig{{
			Name: "primary", Format: "clash", Source: subscriptionconverter.Source{Location: "testdata/clash.yaml"},
			Patches: []subscriptionconverter.PatchSource{{
				Format: subscriptionconverter.PatchFormatSingBox,
				Source: subscriptionconverter.Source{Location: localPath},
			}},
		}},
	}
	handler, err := subscriptionconverter.NewHandler(config, builtin.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/subscriptions/primary?format=sing-box", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.Code, response.Body.String())
	}
	var output struct {
		Inbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Listen     string `json:"listen"`
			ListenPort uint16 `json:"listen_port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Inbounds) != 1 || output.Inbounds[0].Tag != "lan-in" || output.Inbounds[0].Listen != "0.0.0.0" || output.Inbounds[0].ListenPort != 7891 {
		t.Fatalf("subscription inbounds did not replace global inbounds: %#v", output.Inbounds)
	}
}

func firstString(value any) string {
	values, _ := value.([]any)
	if len(values) == 0 {
		return ""
	}
	result, _ := values[0].(string)
	return result
}

func TestHandlerIndexListsGeneratedURLsWithoutSources(t *testing.T) {
	config := subscriptionconverter.Config{Subscriptions: []subscriptionconverter.SubscriptionConfig{
		{Name: "justmysocks", Source: subscriptionconverter.Source{Location: "https://secret.example/subscription?token=secret"}, Format: "base64"},
		{Name: "clash", Source: subscriptionconverter.Source{Location: "testdata/clash.yaml"}, Format: "clash"},
	}}
	handler, err := subscriptionconverter.NewHandler(config, builtin.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9099/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.Code)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"http://127.0.0.1:9099/subscriptions/clash?format=sing-box",
		"http://127.0.0.1:9099/subscriptions/justmysocks?format=sing-box",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing URL %q: %s", expected, body)
		}
	}
	if strings.Contains(body, "secret.example") || strings.Contains(body, "token=secret") {
		t.Fatalf("upstream source leaked in index: %s", body)
	}
}
