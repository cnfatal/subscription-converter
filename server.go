package subscriptionconverter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"time"
)

var indexTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>subscription-converter</title>
  <style>
    body { max-width: 860px; margin: 48px auto; padding: 0 20px; font: 16px/1.6 system-ui, sans-serif; color: #1f2328; }
    h1 { font-size: 28px; }
    ul { padding: 0; list-style: none; }
    li { margin: 16px 0; padding: 16px; border: 1px solid #d0d7de; border-radius: 8px; }
    strong { display: block; margin-bottom: 6px; }
    code { overflow-wrap: anywhere; }
    a { color: #0969da; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>subscription-converter</h1>
  <p>Available sing-box subscriptions:</p>
  <ul>
    {{range .}}
    <li><strong>{{.Name}}</strong><a href="{{.URL}}"><code>{{.URL}}</code></a></li>
    {{else}}
    <li>No subscriptions configured.</li>
    {{end}}
  </ul>
</body>
</html>
`))

type Handler struct {
	subscriptions map[string]SubscriptionConfig
	patches       []PatchSource
	Converter     *Converter
	Logger        *slog.Logger
	Loader        Loader
}

func NewHandler(config Config, converter *Converter, logger *slog.Logger) (*Handler, error) {
	config.setDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if converter == nil {
		return nil, fmt.Errorf("converter is required")
	}
	subscriptions := make(map[string]SubscriptionConfig, len(config.Subscriptions))
	for _, subscription := range config.Subscriptions {
		subscriptions[subscription.Name] = subscription
	}
	return &Handler{subscriptions: subscriptions, patches: config.Patches, Converter: converter, Logger: logger, Loader: NewLoader(nil)}, nil
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", h.index)
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /version", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(writer).Encode(GetVersion())
	})
	mux.HandleFunc("GET /subscriptions", h.list)
	mux.HandleFunc("GET /subscriptions/{name}", h.convert)
	return mux
}

func (h *Handler) index(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	type item struct {
		Name string
		URL  string
	}
	items := make([]item, 0, len(h.subscriptions))
	for name := range h.subscriptions {
		items = append(items, item{
			Name: name,
			URL:  "http://" + request.Host + "/subscriptions/" + name + "?format=sing-box",
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if err := indexTemplate.Execute(writer, items); err != nil {
		h.logger().Error("render index", "error", err)
	}
}

func (h *Handler) list(writer http.ResponseWriter, _ *http.Request) {
	type item struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		FormatQuery string `json:"format_query"`
	}
	items := make([]item, 0, len(h.subscriptions))
	for name := range h.subscriptions {
		items = append(items, item{Name: name, Path: "/subscriptions/" + name, FormatQuery: "required"})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(writer).Encode(items)
}

func (h *Handler) convert(writer http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	subscription, exists := h.subscriptions[name]
	if !exists {
		http.NotFound(writer, request)
		return
	}
	outputFormat := normalize(request.URL.Query().Get("format"))
	if outputFormat == "" || outputFormat == "auto" {
		http.Error(writer, "format query parameter is required", http.StatusBadRequest)
		return
	}
	if _, err := h.Converter.codec(outputFormat); err != nil {
		http.Error(writer, "unknown output format", http.StatusBadRequest)
		return
	}
	input, err := h.Loader.Load(subscription.Source)
	if err != nil {
		h.writeError(writer, name, err)
		return
	}
	decoded, err := h.Converter.Decode(input, subscription.Format, DecodeOptions{
		Loader: h.Loader, BaseDirectory: SourceBaseDirectory(subscription.Location),
	})
	if err != nil {
		h.writeError(writer, name, err)
		return
	}
	if decoded.Document == nil {
		h.writeError(writer, name, fmt.Errorf("decoder returned no document"))
		return
	}
	globalPatch, err := h.Converter.LoadPatches(h.Loader, h.patches)
	if err != nil {
		h.writeError(writer, name, err)
		return
	}
	if err := ApplyPatch(decoded.Document, globalPatch); err != nil {
		h.writeError(writer, name, err)
		return
	}
	localPatch, err := h.Converter.LoadPatches(h.Loader, subscription.Patches)
	if err != nil {
		h.writeError(writer, name, err)
		return
	}
	if err := ApplyPatch(decoded.Document, localPatch); err != nil {
		h.writeError(writer, name, err)
		return
	}
	encoded, err := h.Converter.Encode(*decoded.Document, outputFormat, EncodeOptions{})
	if err != nil {
		h.writeError(writer, name, err)
		return
	}
	warnings := append([]string(nil), decoded.Warnings...)
	warnings = append(warnings, globalPatch.Warnings...)
	warnings = append(warnings, localPatch.Warnings...)
	warnings = append(warnings, encoded.Warnings...)
	for _, warning := range warnings {
		h.logger().Warn("conversion warning", "subscription", name, "message", warning)
	}
	writer.Header().Set("Content-Type", outputContentType(encoded.Format))
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = writer.Write(encoded.Content)
}

func outputContentType(format string) string {
	switch normalize(format) {
	case "sing-box", "singbox":
		return "application/json; charset=utf-8"
	case "clash", "mihomo":
		return "application/yaml; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func (h *Handler) writeError(writer http.ResponseWriter, name string, err error) {
	h.logger().Error("conversion failed", "subscription", name, "error", err)
	http.Error(writer, "conversion failed", http.StatusBadGateway)
}

func (h *Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func Listen(address string, handler http.Handler) error {
	server := &http.Server{
		Addr: address, Handler: handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
