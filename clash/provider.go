package clash

import (
	"fmt"
	. "github.com/cnfatal/subscription-converter"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"
)

type clashProxyProviderContent struct {
	Proxies []ClashProxy `json:"proxies"`
}

type clashRuleProviderContent struct {
	Payload []string `json:"payload"`
}

func resolveClashProxyProviders(providers map[string]ClashProxyProvider, options DecodeOptions) (map[string][]ClashProxy, error) {
	result := make(map[string][]ClashProxy, len(providers))
	loader := options.Loader
	if loader == nil {
		loader = NewLoader(nil)
	}
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		provider := providers[name]
		if provider.Proxy != "" && !strings.EqualFold(provider.Proxy, "DIRECT") {
			return nil, fmt.Errorf("proxy provider %q: download proxy %q cannot be used by the converter", name, provider.Proxy)
		}
		var proxies []ClashProxy
		switch strings.ToLower(strings.TrimSpace(provider.Type)) {
		case "inline":
			proxies = append(proxies, provider.Payload...)
		case "http":
			if provider.URL == "" {
				return nil, fmt.Errorf("proxy provider %q: url is required", name)
			}
			source := Source{Location: provider.URL, Headers: provider.Header}
			if provider.Interval > 0 {
				source.Cache = strconv.Itoa(provider.Interval) + "s"
			}
			data, err := loader.Load(source)
			if err != nil {
				return nil, fmt.Errorf("proxy provider %q: %w", name, err)
			}
			decoded, err := decodeClashProxyProviderContent(data)
			if err != nil {
				return nil, fmt.Errorf("proxy provider %q: %w", name, err)
			}
			proxies = decoded
		case "file":
			if provider.Path == "" {
				return nil, fmt.Errorf("proxy provider %q: path is required", name)
			}
			location := ResolveSource(provider.Path, options.BaseDirectory)
			data, err := loader.Load(Source{Location: location})
			if err != nil {
				return nil, fmt.Errorf("proxy provider %q: %w", name, err)
			}
			decoded, err := decodeClashProxyProviderContent(data)
			if err != nil {
				return nil, fmt.Errorf("proxy provider %q: %w", name, err)
			}
			proxies = decoded
		default:
			return nil, fmt.Errorf("proxy provider %q: unsupported type %q", name, provider.Type)
		}
		filtered, err := filterClashProviderProxies(proxies, provider)
		if err != nil {
			return nil, fmt.Errorf("proxy provider %q: %w", name, err)
		}
		result[name] = filtered
	}
	return result, nil
}

func decodeClashProxyProviderContent(data []byte) ([]ClashProxy, error) {
	var content clashProxyProviderContent
	if err := yaml.Unmarshal(data, &content); err != nil {
		return nil, fmt.Errorf("decode provider YAML: %w", err)
	}
	if len(content.Proxies) == 0 {
		return nil, fmt.Errorf("provider contains no proxies")
	}
	return content.Proxies, nil
}

func filterClashProviderProxies(proxies []ClashProxy, provider ClashProxyProvider) ([]ClashProxy, error) {
	include, err := compileProviderPattern(provider.Filter)
	if err != nil {
		return nil, fmt.Errorf("invalid filter: %w", err)
	}
	exclude, err := compileProviderPattern(provider.ExcludeFilter)
	if err != nil {
		return nil, fmt.Errorf("invalid exclude-filter: %w", err)
	}
	excludedTypes := map[string]struct{}{}
	for _, value := range strings.Split(provider.ExcludeType, "|") {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			excludedTypes[value] = struct{}{}
		}
	}
	result := make([]ClashProxy, 0, len(proxies))
	for _, proxy := range proxies {
		if include != nil && !include.MatchString(proxy.Name) {
			continue
		}
		if exclude != nil && exclude.MatchString(proxy.Name) {
			continue
		}
		if _, excluded := excludedTypes[strings.ToLower(string(proxy.Type))]; excluded {
			continue
		}
		if provider.Override != nil {
			proxy.Name = provider.Override.AdditionalPrefix + proxy.Name + provider.Override.AdditionalSuffix
			if provider.Override.SkipCertVerify != nil {
				proxy.SkipCertVerify = *provider.Override.SkipCertVerify
			}
		}
		result = append(result, proxy)
	}
	return result, nil
}

func filterProviderMembers(members []string, includeValue, excludeValue string) ([]string, error) {
	include, err := compileProviderPattern(includeValue)
	if err != nil {
		return nil, fmt.Errorf("invalid filter: %w", err)
	}
	exclude, err := compileProviderPattern(excludeValue)
	if err != nil {
		return nil, fmt.Errorf("invalid exclude-filter: %w", err)
	}
	result := make([]string, 0, len(members))
	for _, member := range members {
		if include != nil && !include.MatchString(member) {
			continue
		}
		if exclude != nil && exclude.MatchString(member) {
			continue
		}
		result = append(result, member)
	}
	return result, nil
}

func compileProviderPattern(value string) (*regexp.Regexp, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	return regexp.Compile(value)
}

func resolveClashRuleProviders(providers map[string]ClashRuleProvider, options DecodeOptions) ([]RuleSet, error) {
	loader := options.Loader
	if loader == nil {
		loader = NewLoader(nil)
	}
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]RuleSet, 0, len(names))
	for _, name := range names {
		provider := providers[name]
		payload, err := loadClashRuleProvider(loader, provider, options.BaseDirectory)
		if err != nil {
			return nil, fmt.Errorf("rule provider %q: %w", name, err)
		}
		rules, err := decodeClashRuleProviderPayload(payload, provider.Behavior)
		if err != nil {
			return nil, fmt.Errorf("rule provider %q: %w", name, err)
		}
		result = append(result, RuleSet{Type: RuleSetInline, Tag: name, Rules: rules})
	}
	return result, nil
}

func loadClashRuleProvider(loader Loader, provider ClashRuleProvider, baseDirectory string) ([]string, error) {
	if provider.Proxy != "" && !strings.EqualFold(provider.Proxy, "DIRECT") {
		return nil, fmt.Errorf("download proxy %q cannot be used by the converter", provider.Proxy)
	}
	providerType := strings.ToLower(strings.TrimSpace(provider.Type))
	if providerType == "inline" {
		if len(provider.Payload) == 0 {
			return nil, fmt.Errorf("inline provider contains no payload")
		}
		return provider.Payload, nil
	}
	var location string
	switch providerType {
	case "http":
		if provider.URL == "" {
			return nil, fmt.Errorf("url is required")
		}
		location = provider.URL
	case "file":
		if provider.Path == "" {
			return nil, fmt.Errorf("path is required")
		}
		location = ResolveSource(provider.Path, baseDirectory)
	default:
		return nil, fmt.Errorf("unsupported type %q", provider.Type)
	}
	format := strings.ToLower(strings.TrimSpace(provider.Format))
	if format == "" {
		format = "yaml"
	}
	if format == "mrs" {
		return nil, fmt.Errorf("MRS format is not supported")
	}
	if format != "yaml" && format != "text" {
		return nil, fmt.Errorf("unsupported format %q", provider.Format)
	}
	source := Source{Location: location, Headers: provider.Header}
	if provider.Interval > 0 {
		source.Cache = strconv.Itoa(provider.Interval) + "s"
	}
	data, err := loader.Load(source)
	if err != nil {
		return nil, err
	}
	if format == "text" {
		return nonCommentLines(data), nil
	}
	var content clashRuleProviderContent
	if err := yaml.Unmarshal(data, &content); err != nil {
		return nil, fmt.Errorf("decode provider YAML: %w", err)
	}
	if len(content.Payload) == 0 {
		return nil, fmt.Errorf("provider contains no payload")
	}
	return content.Payload, nil
}

func nonCommentLines(data []byte) []string {
	var result []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}
	return result
}

func decodeClashRuleProviderPayload(payload []string, behavior string) ([]RouteMatch, error) {
	behavior = strings.ToLower(strings.TrimSpace(behavior))
	result := make([]RouteMatch, 0, len(payload))
	for index, value := range payload {
		value = strings.TrimSpace(value)
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		var match RouteMatch
		switch behavior {
		case "domain":
			switch {
			case strings.HasPrefix(value, "+."):
				match.DomainSuffixes = []string{strings.TrimPrefix(value, "+.")}
			case strings.HasPrefix(value, "*."):
				match.DomainSuffixes = []string{strings.TrimPrefix(value, "*.")}
			case strings.HasPrefix(value, "."):
				match.DomainSuffixes = []string{strings.TrimPrefix(value, ".")}
			default:
				match.Domains = []string{value}
			}
		case "ipcidr":
			prefix, err := parseProviderPrefix(value)
			if err != nil {
				return nil, fmt.Errorf("payload #%d: %w", index+1, err)
			}
			match.IPCIDRs = []netip.Prefix{prefix}
		case "classical":
			parts := SplitRule(value)
			if len(parts) == 3 && strings.EqualFold(parts[2], "no-resolve") {
				parts = parts[:2]
			}
			if len(parts) != 2 {
				return nil, fmt.Errorf("payload #%d: invalid classical rule %q", index+1, value)
			}
			rule, final, warning := decodeClashRule(strings.Join(parts, ",") + ",DIRECT")
			if warning != "" || final != "" {
				return nil, fmt.Errorf("payload #%d: %s", index+1, FirstNonEmpty(warning, "final rules are not allowed"))
			}
			match = rule.Match
		default:
			return nil, fmt.Errorf("unsupported behavior %q", behavior)
		}
		result = append(result, match)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("provider contains no usable rules")
	}
	return result, nil
}

func parseProviderPrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP prefix %q", value)
	}
	return netip.PrefixFrom(address, address.BitLen()), nil
}
