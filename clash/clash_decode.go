package clash

import (
	"fmt"
	. "github.com/cnfatal/subscription-converter"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

func (ClashCodec) Decode(data []byte, options DecodeOptions) (*Document, []string, error) {
	var input ClashConfig
	if err := yaml.Unmarshal(data, &input); err != nil {
		return nil, nil, fmt.Errorf("decode Clash YAML: %w", err)
	}
	return decodeClashConfig(input, options, true)
}

func decodeClashConfig(input ClashConfig, options DecodeOptions, requireProxies bool) (*Document, []string, error) {
	if requireProxies && len(input.Proxies) == 0 && len(input.ProxyProviders) == 0 {
		return nil, nil, fmt.Errorf("Clash configuration contains no proxies")
	}

	doc := DefaultDocument()
	var warnings []string
	seen := map[string]struct{}{}
	appendProxy := func(proxy ClashProxy, location string) bool {
		if proxy.Name == "" || proxy.Type == "" || proxy.Server == "" || !proxy.hasPort() {
			warnings = append(warnings, fmt.Sprintf("%s skipped: name, type, server, and port are required", location))
			return false
		}
		if _, exists := seen[proxy.Name]; exists {
			warnings = append(warnings, fmt.Sprintf("duplicate proxy %q skipped", proxy.Name))
			return false
		}
		node, warning := proxy.node()
		if warning != "" {
			warnings = append(warnings, warning)
			return false
		}
		seen[proxy.Name] = struct{}{}
		doc.Nodes = append(doc.Nodes, node)
		return true
	}
	for index, proxy := range input.Proxies {
		appendProxy(proxy, fmt.Sprintf("proxy #%d", index+1))
	}

	providerProxies, err := resolveClashProxyProviders(input.ProxyProviders, options)
	if err != nil {
		return nil, warnings, err
	}
	providerMembers := make(map[string][]string, len(providerProxies))
	providerNames := make([]string, 0, len(providerProxies))
	for name := range providerProxies {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	for _, name := range providerNames {
		providerMembers[name] = nil
		for index, proxy := range providerProxies[name] {
			if appendProxy(proxy, fmt.Sprintf("proxy provider %q item #%d", name, index+1)) {
				providerMembers[name] = append(providerMembers[name], proxy.Name)
			}
		}
	}

	for index, group := range input.ProxyGroups {
		if group.Name == "" || group.Type == "" {
			warnings = append(warnings, fmt.Sprintf("proxy group #%d skipped: name and type are required", index+1))
			continue
		}
		groupType, ok := clashGroupType(group.Type)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("proxy group %q skipped: unsupported type %q", group.Name, group.Type))
			continue
		}
		members := append([]string(nil), group.Proxies...)
		groupURL := group.URL
		groupInterval := group.Interval
		groupLazy := group.Lazy
		for _, providerName := range group.Use {
			providerNodes, exists := providerMembers[providerName]
			if !exists {
				return nil, warnings, fmt.Errorf("proxy group %q: unknown provider %q", group.Name, providerName)
			}
			filtered, err := filterProviderMembers(providerNodes, group.Filter, group.ExcludeFilter)
			if err != nil {
				return nil, warnings, fmt.Errorf("proxy group %q: %w", group.Name, err)
			}
			members = append(members, filtered...)
			if healthCheck := input.ProxyProviders[providerName].HealthCheck; healthCheck != nil && healthCheck.Enable {
				if groupURL == "" {
					groupURL = healthCheck.URL
				}
				if groupInterval == 0 {
					groupInterval = healthCheck.Interval
				}
				groupLazy = groupLazy || healthCheck.Lazy
			}
		}
		doc.Groups = append(doc.Groups, Group{
			Name: group.Name, Type: groupType, Members: uniqueStrings(members),
			URL: groupURL, Interval: time.Duration(groupInterval) * time.Second,
			Tolerance: group.Tolerance, Lazy: groupLazy, Strategy: group.Strategy,
		})
	}

	if input.DNS != nil && input.DNS.Enable {
		dns, dnsWarnings := input.DNS.documentDNS()
		warnings = append(warnings, dnsWarnings...)
		if len(dns.Servers) > 0 {
			doc.DNS = dns
			doc.Route.DefaultDomainResolver = FirstNonEmpty(dns.ProxyResolver, dns.Final)
		}
	}

	ruleSets, err := resolveClashRuleProviders(input.RuleProviders, options)
	if err != nil {
		return nil, warnings, err
	}
	doc.Route.RuleSets = append(doc.Route.RuleSets, ruleSets...)

	for _, line := range input.Rules {
		rule, final, warning := decodeClashRule(line)
		if warning != "" {
			warnings = append(warnings, warning)
			continue
		}
		if final != "" {
			doc.Route.Final = final
		} else {
			doc.Route.Rules = append(doc.Route.Rules, rule)
		}
	}
	if err := validateDocumentRuleSetReferences(doc); err != nil {
		return nil, warnings, err
	}
	return &doc, warnings, nil
}

func validateDocumentRuleSetReferences(document Document) error {
	available := make(map[string]struct{}, len(document.Route.RuleSets))
	for _, ruleSet := range document.Route.RuleSets {
		available[ruleSet.Tag] = struct{}{}
	}
	validate := func(owner string, values []string) error {
		for _, value := range values {
			if strings.HasPrefix(value, "geoip-") || strings.HasPrefix(value, "geosite-") {
				continue
			}
			if _, exists := available[value]; !exists {
				return fmt.Errorf("%s references unknown rule-set %q", owner, value)
			}
		}
		return nil
	}
	for index, rule := range document.Route.Rules {
		if err := validate(fmt.Sprintf("route rule #%d", index+1), rule.Match.RuleSets); err != nil {
			return err
		}
	}
	for _, ruleSet := range document.Route.RuleSets {
		for index, match := range ruleSet.Rules {
			if err := validate(fmt.Sprintf("rule-set %q rule #%d", ruleSet.Tag, index+1), match.RuleSets); err != nil {
				return err
			}
		}
	}
	for index, rule := range document.DNS.Rules {
		if err := validate(fmt.Sprintf("DNS rule #%d", index+1), rule.Match.RuleSets); err != nil {
			return err
		}
	}
	return nil
}

func (p ClashProxy) hasPort() bool {
	return p.Port != 0 || (p.Type == ClashProxyHysteria2 && len(p.Ports) > 0)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
