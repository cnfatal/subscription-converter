package subscriptionconverter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSource(t *testing.T) {
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		source string
		base   string
		want   string
	}{
		{name: "empty", source: "", base: "/etc/subscription-converter", want: ""},
		{name: "HTTP URL", source: "http://example.com/sub", base: "/etc/subscription-converter", want: "http://example.com/sub"},
		{name: "HTTPS URL", source: "https://example.com/sub", base: "/etc/subscription-converter", want: "https://example.com/sub"},
		{name: "absolute path", source: "/var/lib/rules.yaml", base: "/etc/subscription-converter", want: "/var/lib/rules.yaml"},
		{name: "relative path", source: "../rules.yaml", base: "/etc/subscription-converter", want: "/etc/rules.yaml"},
		{name: "home", source: "~", base: "/etc/subscription-converter", want: homeDirectory},
		{name: "home relative", source: "~/.config/proxy-rules.yaml", base: "/etc/subscription-converter", want: filepath.Join(homeDirectory, ".config", "proxy-rules.yaml")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ResolveSource(test.source, test.base); got != test.want {
				t.Fatalf("ResolveSource(%q, %q) = %q, want %q", test.source, test.base, got, test.want)
			}
		})
	}
}
