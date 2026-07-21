package subscriptionconverter_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
)

func TestLoaderUsesHeadersAndCache(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("Authorization") != "Bearer test" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("ETag", `"one"`)
		_, _ = writer.Write([]byte("content"))
	}))
	defer server.Close()
	loader := subscriptionconverter.NewLoader(nil)
	source := subscriptionconverter.Source{
		Location: server.URL,
		Headers:  subscriptionconverter.HTTPHeaders{"Authorization": {"Bearer test"}},
		Timeout:  time.Second.String(), Cache: time.Hour.String(),
	}
	for range 2 {
		data, err := loader.Load(source)
		if err != nil || string(data) != "content" {
			t.Fatalf("unexpected load result: %q %v", data, err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("expected one upstream request, got %d", requests.Load())
	}
}

func TestLoaderRevalidatesExpiredCache(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("If-None-Match") == `"one"` {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("ETag", `"one"`)
		_, _ = writer.Write([]byte("cached"))
	}))
	defer server.Close()
	loader := subscriptionconverter.NewLoader(nil)
	source := subscriptionconverter.Source{Location: server.URL, Cache: "1ns"}
	for range 2 {
		data, err := loader.Load(source)
		if err != nil || string(data) != "cached" {
			t.Fatalf("unexpected revalidation result: %q %v", data, err)
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("expected conditional revalidation, got %d requests", requests.Load())
	}
}
