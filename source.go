package subscriptionconverter

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxInputSize = 16 << 20

func Load(location string) ([]byte, error) {
	switch {
	case location == "" || location == "-":
		return readLimited(os.Stdin)
	case strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://"):
		return loadRemote(location)
	default:
		data, err := os.ReadFile(location)
		if err != nil {
			return nil, fmt.Errorf("read input: %w", err)
		}
		if len(data) > maxInputSize {
			return nil, fmt.Errorf("input exceeds %d bytes", maxInputSize)
		}
		return data, nil
	}
}

func loadRemote(location string) ([]byte, error) {
	parsed, err := url.Parse(location)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid subscription URL")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	request, err := http.NewRequest(http.MethodGet, location, nil)
	if err != nil {
		return nil, fmt.Errorf("create subscription request: %w", err)
	}
	request.Header.Set("User-Agent", "subscription-converter/0.1")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download subscription: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("download subscription: HTTP %s", response.Status)
	}
	return readLimited(response.Body)
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
