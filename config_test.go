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
	if !filepath.IsAbs(subscription.Source) {
		t.Fatalf("relative source was not resolved: %q", subscription.Source)
	}
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Patches) != 1 || config.Patches[0].Format != subscriptionconverter.PatchFormatClashRules || config.Patches[0].Source != filepath.Join(homeDirectory, ".config", "proxy-rules.yaml") {
		t.Fatalf("unexpected global patches: %#v", config.Patches)
	}
	if len(subscription.Patches) != 1 || subscription.Patches[0].Format != subscriptionconverter.PatchFormatDocument || !filepath.IsAbs(subscription.Patches[0].Source) {
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
