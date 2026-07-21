package subscriptionconverter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxInputSize         = 16 << 20
	defaultSourceTimeout = 30 * time.Second
)

// HTTPHeaders accepts a scalar or a list for each HTTP header.
type HTTPHeaders map[string][]string

func (h *HTTPHeaders) UnmarshalJSON(data []byte) error {
	var input map[string]json.RawMessage
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	result := make(HTTPHeaders, len(input))
	for name, raw := range input {
		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			result[name] = []string{value}
			continue
		}
		var values []string
		if err := json.Unmarshal(raw, &values); err != nil {
			return fmt.Errorf("header %q must be a string or list of strings", name)
		}
		result[name] = values
	}
	*h = result
	return nil
}

// Source describes one local or HTTP-backed input.
type Source struct {
	Location string      `json:"source"`
	Headers  HTTPHeaders `json:"headers,omitempty"`
	Timeout  string      `json:"timeout,omitempty"`
	Cache    string      `json:"cache,omitempty"`
}

func (s Source) validate(field string) error {
	if _, err := s.timeout(); err != nil {
		return fmt.Errorf("%s.timeout: %w", field, err)
	}
	if _, err := s.cacheDuration(); err != nil {
		return fmt.Errorf("%s.cache: %w", field, err)
	}
	for name := range s.Headers {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s.headers contains an empty name", field)
		}
	}
	return nil
}

func (s Source) timeout() (time.Duration, error) {
	if strings.TrimSpace(s.Timeout) == "" {
		return defaultSourceTimeout, nil
	}
	value, err := time.ParseDuration(s.Timeout)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("must be a positive duration")
	}
	return value, nil
}

func (s Source) cacheDuration() (time.Duration, error) {
	if strings.TrimSpace(s.Cache) == "" {
		return 0, nil
	}
	value, err := time.ParseDuration(s.Cache)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("must be a non-negative duration")
	}
	return value, nil
}

type sourceCacheEntry struct {
	data         []byte
	etag         string
	lastModified string
	expires      time.Time
}

type sourceCall struct {
	done chan struct{}
	data []byte
	err  error
}

// Loader loads one local or remote source. Implementations can be injected by
// callers that need custom storage, authentication, caching, or tests.
type Loader interface {
	Load(Source) ([]byte, error)
}

// sourceLoader is the default Loader implementation. It provides local/HTTP
// loading, conditional requests, caching, and concurrent request coalescing.
type sourceLoader struct {
	client   *http.Client
	mu       sync.Mutex
	cache    map[string]sourceCacheEntry
	inflight map[string]*sourceCall
}

var _ Loader = (*sourceLoader)(nil)

func NewLoader(client *http.Client) Loader {
	if client == nil {
		client = &http.Client{}
	}
	return &sourceLoader{client: client, cache: map[string]sourceCacheEntry{}, inflight: map[string]*sourceCall{}}
}

var defaultLoader = NewLoader(nil)

// Load retains the original simple loading API.
func Load(location string) ([]byte, error) {
	return defaultLoader.Load(Source{Location: location})
}

func (l *sourceLoader) Load(source Source) ([]byte, error) {
	switch {
	case source.Location == "" || source.Location == "-":
		return readLimited(os.Stdin)
	case strings.HasPrefix(source.Location, "http://") || strings.HasPrefix(source.Location, "https://"):
		return l.loadRemote(source)
	default:
		data, err := os.ReadFile(source.Location)
		if err != nil {
			return nil, fmt.Errorf("read input: %w", err)
		}
		if len(data) > maxInputSize {
			return nil, fmt.Errorf("input exceeds %d bytes", maxInputSize)
		}
		return data, nil
	}
}

func (l *sourceLoader) loadRemote(source Source) ([]byte, error) {
	parsed, err := url.Parse(source.Location)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid source URL")
	}
	timeout, err := source.timeout()
	if err != nil {
		return nil, fmt.Errorf("invalid source timeout: %w", err)
	}
	cacheDuration, err := source.cacheDuration()
	if err != nil {
		return nil, fmt.Errorf("invalid source cache: %w", err)
	}
	key := sourceCacheKey(source)
	now := time.Now()

	l.mu.Lock()
	entry, cached := l.cache[key]
	if cached && cacheDuration > 0 && now.Before(entry.expires) {
		data := append([]byte(nil), entry.data...)
		l.mu.Unlock()
		return data, nil
	}
	if call := l.inflight[key]; call != nil {
		l.mu.Unlock()
		<-call.done
		return append([]byte(nil), call.data...), call.err
	}
	call := &sourceCall{done: make(chan struct{})}
	l.inflight[key] = call
	l.mu.Unlock()

	var etag, lastModified string
	call.data, etag, lastModified, call.err = l.fetchRemote(source, timeout, cacheDuration, entry, cached)
	l.mu.Lock()
	delete(l.inflight, key)
	if call.err == nil && cacheDuration > 0 {
		entry.data = append([]byte(nil), call.data...)
		entry.etag = etag
		entry.lastModified = lastModified
		entry.expires = time.Now().Add(cacheDuration)
		l.cache[key] = entry
	}
	close(call.done)
	l.mu.Unlock()
	return append([]byte(nil), call.data...), call.err
}

func (l *sourceLoader) fetchRemote(source Source, timeout, cacheDuration time.Duration, entry sourceCacheEntry, cached bool) ([]byte, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.Location, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("create source request: %w", err)
	}
	request.Header.Set("User-Agent", "subscription-converter/0.1")
	for name, values := range source.Headers {
		request.Header.Del(name)
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	if cacheDuration > 0 && cached {
		if entry.etag != "" {
			request.Header.Set("If-None-Match", entry.etag)
		}
		if entry.lastModified != "" {
			request.Header.Set("If-Modified-Since", entry.lastModified)
		}
	}
	response, err := l.client.Do(request)
	if err != nil {
		return nil, "", "", fmt.Errorf("download source: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified && cached {
		return append([]byte(nil), entry.data...), entry.etag, entry.lastModified, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, "", "", fmt.Errorf("download source: HTTP %s", response.Status)
	}
	data, err := readLimited(response.Body)
	if err != nil {
		return nil, "", "", err
	}
	return data, response.Header.Get("ETag"), response.Header.Get("Last-Modified"), nil
}

func sourceCacheKey(source Source) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, source.Location)
	normalized := make(map[string][]string, len(source.Headers))
	for name, values := range source.Headers {
		name = strings.ToLower(name)
		normalized[name] = append(normalized[name], values...)
	}
	names := make([]string, 0, len(normalized))
	for name := range normalized {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		_, _ = io.WriteString(hash, "\x00"+name)
		for _, value := range normalized[name] {
			_, _ = io.WriteString(hash, "\x00"+value)
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func readLimited(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxInputSize+1))
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if len(data) > maxInputSize {
		return nil, fmt.Errorf("input exceeds %d bytes", maxInputSize)
	}
	return data, nil
}
