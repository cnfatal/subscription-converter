package subscriptionconverter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"sigs.k8s.io/yaml"
)

const defaultListenAddress = "127.0.0.1:9099"

var subscriptionNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type Config struct {
	Server        ServerConfig         `json:"server"`
	Patches       []PatchSource        `json:"patches,omitempty"`
	Subscriptions []SubscriptionConfig `json:"subscriptions"`
}

type ServerConfig struct {
	Listen string `json:"listen"`
}

type SubscriptionConfig struct {
	Name    string        `json:"name"`
	Source  string        `json:"source"`
	Format  string        `json:"format,omitempty"`
	Patches []PatchSource `json:"patches,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var config Config
	if err := yaml.UnmarshalStrict(data, &config); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	config.setDefaults()
	config.resolveSources(filepath.Dir(path))
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c *Config) resolveSources(baseDirectory string) {
	resolvePatchSources(c.Patches, baseDirectory)
	for index := range c.Subscriptions {
		c.Subscriptions[index].Source = ResolveSource(c.Subscriptions[index].Source, baseDirectory)
		resolvePatchSources(c.Subscriptions[index].Patches, baseDirectory)
	}
}

func resolvePatchSources(sources []PatchSource, baseDirectory string) {
	for index := range sources {
		sources[index].Source = ResolveSource(sources[index].Source, baseDirectory)
	}
}

func (c *Config) setDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = defaultListenAddress
	}
	normalizePatchSources(c.Patches)
	for index := range c.Subscriptions {
		normalizePatchSources(c.Subscriptions[index].Patches)
	}
}

func normalizePatchSources(sources []PatchSource) {
	for index := range sources {
		sources[index].Format = normalizePatchFormat(sources[index].Format)
	}
}

func (c Config) Validate() error {
	if len(c.Subscriptions) == 0 {
		return errors.New("config requires at least one subscription")
	}
	seen := make(map[string]struct{}, len(c.Subscriptions))
	if err := validatePatchSources("patches", c.Patches); err != nil {
		return err
	}
	for index, subscription := range c.Subscriptions {
		field := fmt.Sprintf("subscriptions[%d]", index)
		if !subscriptionNamePattern.MatchString(subscription.Name) {
			return fmt.Errorf("%s.name must match %s", field, subscriptionNamePattern)
		}
		if _, exists := seen[subscription.Name]; exists {
			return fmt.Errorf("duplicate subscription name %q", subscription.Name)
		}
		seen[subscription.Name] = struct{}{}
		if subscription.Source == "" || subscription.Source == "-" {
			return fmt.Errorf("%s.source is required", field)
		}
		if subscription.Format != "" && decodeFormat(subscription.Format) == "" {
			return fmt.Errorf("%s.format must name a codec; omit it for automatic recognition", field)
		}
		if err := validatePatchSources(field+".patches", subscription.Patches); err != nil {
			return err
		}
	}
	return nil
}

func validatePatchSources(field string, sources []PatchSource) error {
	for index, source := range sources {
		item := fmt.Sprintf("%s[%d]", field, index)
		if source.Source == "" || source.Source == "-" {
			return fmt.Errorf("%s.source is required", item)
		}
		if _, err := patchDecoder(source.Format); err != nil {
			return fmt.Errorf("%s.format: %w", item, err)
		}
	}
	return nil
}
