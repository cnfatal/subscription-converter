package subscriptionconverter_test

import (
	"os"
	"path/filepath"
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
)

func TestLoadConfig(t *testing.T) {
	path := writeConfig(t, `
patches:
  - source: ~/.config/proxy-rules.yaml
    headers:
      Authorization: Bearer patch
    timeout: 5s
    cache: 1h

subscriptions:
  - name: primary
    source: testdata/clash.yaml
    patches:
      - source: local-rules.yaml
        format: patch
`)
	config, err := subscriptionconverter.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Server.Listen != "127.0.0.1:9099" {
		t.Fatalf("unexpected listen address %q", config.Server.Listen)
	}
	subscription := config.Subscriptions[0]
	if subscription.Format != "" {
		t.Fatalf("defaults not applied: %#v", subscription)
	}
	if !filepath.IsAbs(subscription.Location) {
		t.Fatalf("relative source was not resolved: %q", subscription.Location)
	}
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Patches) != 1 || config.Patches[0].Format != subscriptionconverter.PatchFormatClashRules || config.Patches[0].Location != filepath.Join(homeDirectory, ".config", "proxy-rules.yaml") {
		t.Fatalf("unexpected global patches: %#v", config.Patches)
	}
	if config.Patches[0].Headers["Authorization"][0] != "Bearer patch" || config.Patches[0].Timeout != "5s" || config.Patches[0].Cache != "1h" {
		t.Fatalf("unexpected patch source options: %#v", config.Patches[0])
	}
	if len(subscription.Patches) != 1 || subscription.Patches[0].Format != subscriptionconverter.PatchFormatDocument || !filepath.IsAbs(subscription.Patches[0].Location) {
		t.Fatalf("unexpected subscription patches: %#v", subscription.Patches)
	}
}

func TestLoadConfigRejectsInvalidSubscriptions(t *testing.T) {
	tests := map[string]string{
		"duplicate": `subscriptions:
  - {name: same, source: one}
  - {name: same, source: two}
`,
		"invalid name": `subscriptions:
  - {name: ../secret, source: one}
`,
		"unknown field": `subscriptions:
  - {name: main, source: one, typo: value}
`,
		"unknown patch format": `patches:
  - {source: rules.yaml, format: unknown}
subscriptions:
  - {name: main, source: one}
`,
		"invalid source timeout": `subscriptions:
  - {name: main, source: one, timeout: never}
`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := subscriptionconverter.LoadConfig(writeConfig(t, content))
			if err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}

func TestLoadConfigNormalizesSingBoxPatchFormat(t *testing.T) {
	config, err := subscriptionconverter.LoadConfig(writeConfig(t, `
patches:
  - {source: rules.json, format: singbox}
subscriptions:
  - {name: main, source: subscription.txt}
`))
	if err != nil {
		t.Fatal(err)
	}
	if config.Patches[0].Format != subscriptionconverter.PatchFormatSingBox {
		t.Fatalf("unexpected patch format: %q", config.Patches[0].Format)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
