package clash

import (
	"fmt"

	. "github.com/cnfatal/subscription-converter"
	"sigs.k8s.io/yaml"
)

type rulesPatch struct {
	Rules []string `json:"rules"`
}

func (ClashCodec) PatchFormats() []PatchFormat {
	return []PatchFormat{PatchFormatClashRules}
}

func (ClashCodec) DecodePatch(data []byte, _ PatchFormat) (DocumentPatch, error) {
	var input rulesPatch
	if err := yaml.UnmarshalStrict(data, &input); err != nil {
		return DocumentPatch{}, fmt.Errorf("decode Clash rules: %w", err)
	}
	if len(input.Rules) == 0 {
		return DocumentPatch{}, fmt.Errorf("Clash rules patch contains no rules")
	}
	route := &RoutePatch{}
	for index, line := range input.Rules {
		rule, final, warning := decodeClashRule(line)
		if warning != "" {
			return DocumentPatch{}, fmt.Errorf("rule #%d: %s", index+1, warning)
		}
		if final != "" {
			if route.Final != nil {
				return DocumentPatch{}, fmt.Errorf("rule #%d: multiple MATCH or FINAL rules", index+1)
			}
			value := final
			route.Final = &value
			continue
		}
		route.Rules = append(route.Rules, rule)
	}
	return DocumentPatch{Route: route}, nil
}
