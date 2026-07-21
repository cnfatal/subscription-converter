package clash

import (
	"fmt"

	. "github.com/cnfatal/subscription-converter"
	"sigs.k8s.io/yaml"
)

func (ClashCodec) PatchFormats() []PatchFormat {
	return []PatchFormat{PatchFormatClash}
}

func (ClashCodec) DecodePatch(data []byte, _ PatchFormat, options DecodeOptions) (DocumentPatch, error) {
	var input ClashConfig
	if err := yaml.Unmarshal(data, &input); err != nil {
		return DocumentPatch{}, fmt.Errorf("decode Clash configuration: %w", err)
	}
	if input.Proxies == nil && input.ProxyProviders == nil && input.ProxyGroups == nil && input.RuleProviders == nil && input.DNS == nil && input.Rules == nil {
		return DocumentPatch{}, fmt.Errorf("Clash patch contains no supported sections")
	}
	document, warnings, err := decodeClashConfig(input, options, false)
	if err != nil {
		return DocumentPatch{}, err
	}
	patch := DocumentPatch{Warnings: warnings}
	if input.Proxies != nil || input.ProxyProviders != nil {
		patch.Nodes = document.Nodes
	}
	if input.ProxyGroups != nil {
		patch.Groups = document.Groups
	}
	if input.DNS != nil && input.DNS.Enable {
		dns := document.DNS
		patch.DNS = &dns
	}
	if input.Rules == nil && input.RuleProviders == nil {
		return patch, nil
	}
	route := &RoutePatch{RuleSets: document.Route.RuleSets, Rules: document.Route.Rules}
	var final string
	finalCount := 0
	for index, line := range input.Rules {
		_, value, warning := decodeClashRule(line)
		if warning != "" {
			return DocumentPatch{}, fmt.Errorf("rule #%d: %s", index+1, warning)
		}
		if value != "" {
			final, finalCount = value, finalCount+1
		}
	}
	if finalCount > 1 {
		return DocumentPatch{}, fmt.Errorf("multiple MATCH or FINAL rules")
	}
	if finalCount == 1 {
		route.Final = &final
	}
	patch.Route = route
	return patch, nil
}
