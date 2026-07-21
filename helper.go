package subscriptionconverter

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ResolveSource resolves a local source against baseDirectory. HTTP(S) URLs and
// absolute paths are returned unchanged, while ~ is expanded to the user home.
func ResolveSource(source, baseDirectory string) string {
	if source == "~" || strings.HasPrefix(source, "~/") {
		if homeDirectory, err := os.UserHomeDir(); err == nil {
			if source == "~" {
				return homeDirectory
			}
			return filepath.Clean(filepath.Join(homeDirectory, strings.TrimPrefix(source, "~/")))
		}
	}
	if source == "" || filepath.IsAbs(source) || strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return source
	}
	return filepath.Clean(filepath.Join(baseDirectory, source))
}

// SplitRule splits and trims a comma-separated rule.
func SplitRule(value string) []string {
	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	return parts
}

// StringValue converts a scalar value to its string representation.
func StringValue(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

// IntValue converts a numeric or numeric string value to int, returning zero on failure.
func IntValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case uint64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		parsed, _ := strconv.Atoi(StringValue(value))
		return parsed
	}
}

// StringSlice converts []string or []any to []string.
func StringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			result = append(result, StringValue(item))
		}
		return result
	default:
		return nil
	}
}

// MapValue returns value as map[string]any or nil when it has another type.
func MapValue(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

// BoolValue converts a boolean or boolean string and reports whether conversion succeeded.
func BoolValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(typed)
		return parsed, err == nil
	default:
		return false, false
	}
}

// FirstString returns the first non-empty string value for keys.
func FirstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := StringValue(values[key]); value != "" {
			return value
		}
	}
	return ""
}

// FirstNonEmpty returns the first non-empty string.
func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// SetIntValue converts value to int and stores it when conversion succeeds.
func SetIntValue(target map[string]any, key string, value any) {
	if value == nil {
		return
	}
	parsed, err := strconv.Atoi(StringValue(value))
	if err == nil {
		target[key] = parsed
	}
}

// CopyMapValue copies one existing, non-nil map value to another map.
func CopyMapValue(target map[string]any, targetKey string, source map[string]any, sourceKey string) {
	if source != nil && source[sourceKey] != nil {
		target[targetKey] = source[sourceKey]
	}
}

// FlattenOptions formats a string map as a stable semicolon-separated option list.
func FlattenOptions(value any) string {
	items := MapValue(value)
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", key, items[key]))
	}
	return strings.Join(parts, ";")
}
