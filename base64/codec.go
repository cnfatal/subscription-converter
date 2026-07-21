package base64

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	. "github.com/cnfatal/subscription-converter"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// Base64Codec decodes the common Base64-wrapped proxy URI subscription format.
type Base64Codec struct{}

var _ Codec = Base64Codec{}

func (Base64Codec) Format() string { return "base64" }

func (Base64Codec) Recognize(data []byte) Recognition {
	decoded, err := decodeBase64(data)
	if err != nil {
		return RecognitionNone
	}
	lines := subscriptionLines(decoded)
	if len(lines) == 0 {
		return RecognitionNone
	}
	for _, line := range lines {
		if !supportedURI(line) {
			return RecognitionNone
		}
	}
	return RecognitionExact
}

func (Base64Codec) Decode(data []byte, _ DecodeOptions) (*Document, []string, error) {
	decoded, err := decodeBase64(data)
	if err != nil {
		return nil, nil, fmt.Errorf("decode Base64 subscription: %w", err)
	}
	document := DefaultDocument()
	var warnings []string
	usedNames := map[string]int{}
	for index, line := range subscriptionLines(decoded) {
		node, err := decodeProxyURI(line)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("URI #%d skipped: %v", index+1, err))
			continue
		}
		node.Name = uniqueNodeName(node.Name, node.Type, usedNames)
		document.Nodes = append(document.Nodes, node)
	}
	if len(document.Nodes) == 0 {
		return nil, warnings, fmt.Errorf("Base64 subscription contains no supported proxy URIs")
	}
	return &document, warnings, nil
}

func (Base64Codec) Encode(Document, EncodeOptions) ([]byte, []string, error) {
	return nil, nil, ErrEncodeUnsupported
}

func decodeBase64(data []byte) ([]byte, error) {
	value := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, string(data))
	if value == "" {
		return nil, fmt.Errorf("empty input")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid Base64 data")
}

func subscriptionLines(data []byte) []string {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func supportedURI(value string) bool {
	switch strings.ToLower(strings.SplitN(value, ":", 2)[0]) {
	case "ss", "vmess", "vless":
		return true
	default:
		return false
	}
}

func decodeProxyURI(value string) (Node, error) {
	switch {
	case strings.HasPrefix(strings.ToLower(value), "ss://"):
		return decodeShadowsocksURI(value)
	case strings.HasPrefix(strings.ToLower(value), "vmess://"):
		return decodeVMessURI(value)
	case strings.HasPrefix(strings.ToLower(value), "vless://"):
		return decodeVLESSURI(value)
	default:
		return Node{}, fmt.Errorf("unsupported URI scheme")
	}
}

func decodeShadowsocksURI(value string) (Node, error) {
	payload := value[len("ss://"):]
	fragment := ""
	if position := strings.IndexByte(payload, '#'); position >= 0 {
		fragment, _ = url.QueryUnescape(payload[position+1:])
		payload = payload[:position]
	}
	if position := strings.IndexByte(payload, '?'); position >= 0 {
		payload = payload[:position]
	}
	decoded := payload
	if !strings.Contains(decoded, "@") {
		bytes, err := decodeBase64([]byte(decoded))
		if err != nil {
			return Node{}, fmt.Errorf("invalid legacy Shadowsocks payload")
		}
		decoded = string(bytes)
	}
	credentials, endpoint, ok := strings.Cut(decoded, "@")
	if !ok {
		return Node{}, fmt.Errorf("Shadowsocks endpoint is missing")
	}
	if !strings.Contains(credentials, ":") {
		bytes, err := decodeBase64([]byte(credentials))
		if err != nil {
			return Node{}, fmt.Errorf("invalid Shadowsocks credentials")
		}
		credentials = string(bytes)
	}
	method, password, ok := strings.Cut(credentials, ":")
	if !ok || method == "" {
		return Node{}, fmt.Errorf("invalid Shadowsocks credentials")
	}
	host, port, err := parseEndpoint(endpoint)
	if err != nil {
		return Node{}, err
	}
	return Node{
		Name: fragment, Type: ProtocolShadowsocks, Server: host, Port: port,
		Shadowsocks: &ShadowsocksOptions{Method: method, Password: password},
	}, nil
}

type vmessURI struct {
	Name       string          `json:"ps"`
	Server     string          `json:"add"`
	Port       json.RawMessage `json:"port"`
	UUID       string          `json:"id"`
	AlterID    json.RawMessage `json:"aid"`
	Security   string          `json:"scy"`
	Network    string          `json:"net"`
	HeaderType string          `json:"type"`
	Host       string          `json:"host"`
	Path       string          `json:"path"`
	TLS        string          `json:"tls"`
	ServerName string          `json:"sni"`
}

func decodeVMessURI(value string) (Node, error) {
	decoded, err := decodeBase64([]byte(value[len("vmess://"):]))
	if err != nil {
		return Node{}, fmt.Errorf("invalid VMess payload")
	}
	var input vmessURI
	if err := json.Unmarshal(decoded, &input); err != nil {
		return Node{}, fmt.Errorf("invalid VMess JSON: %w", err)
	}
	port, err := rawUint16(input.Port)
	if err != nil || input.Server == "" || input.UUID == "" {
		return Node{}, fmt.Errorf("VMess server, port, and UUID are required")
	}
	alterID, _ := rawInt(input.AlterID)
	node := Node{
		Name: input.Name, Type: ProtocolVMess, Server: input.Server, Port: port,
		VMess: &VMessOptions{UUID: input.UUID, Security: FirstNonEmpty(input.Security, "auto"), AlterID: alterID},
	}
	if strings.EqualFold(input.TLS, "tls") {
		node.TLS = &TLSOptions{ServerName: FirstNonEmpty(input.ServerName, input.Host)}
	}
	node.Transport = uriTransport(input.Network, input.Host, input.Path, "")
	return node, nil
}

func decodeVLESSURI(value string) (Node, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return Node{}, fmt.Errorf("invalid VLESS URI: %w", err)
	}
	portValue, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || portValue == 0 || parsed.Hostname() == "" || parsed.User == nil || parsed.User.Username() == "" {
		return Node{}, fmt.Errorf("VLESS server, port, and UUID are required")
	}
	query := parsed.Query()
	node := Node{
		Name: unescapeFragment(parsed.Fragment), Type: ProtocolVLESS,
		Server: parsed.Hostname(), Port: uint16(portValue),
		VLESS: &VLESSOptions{UUID: parsed.User.Username(), Flow: query.Get("flow"), Encryption: query.Get("encryption")},
	}
	security := strings.ToLower(query.Get("security"))
	if security == "tls" || security == "reality" {
		node.TLS = &TLSOptions{
			ServerName: query.Get("sni"), Fingerprint: query.Get("fp"),
		}
		if security == "reality" {
			node.TLS.Reality = &RealityOptions{PublicKey: query.Get("pbk"), ShortID: query.Get("sid")}
			if node.TLS.Reality.PublicKey == "" {
				return Node{}, fmt.Errorf("VLESS REALITY public key is required")
			}
		}
	}
	node.Transport = uriTransport(query.Get("type"), query.Get("host"), query.Get("path"), query.Get("serviceName"))
	return node, nil
}

func uriTransport(network, host, path, serviceName string) *Transport {
	switch strings.ToLower(network) {
	case "", "tcp", "raw":
		return nil
	case "ws":
		transport := &Transport{Type: TransportWebSocket, Path: path}
		if host != "" {
			transport.Headers = map[string]string{"Host": host}
		}
		return transport
	case "grpc":
		return &Transport{Type: TransportGRPC, ServiceName: serviceName}
	case "http", "h2":
		return &Transport{Type: TransportHTTP, Hosts: splitNonEmpty(host), Path: path}
	case "httpupgrade":
		transport := &Transport{Type: TransportHTTPUpgrade, Path: path}
		if host != "" {
			transport.Headers = map[string]string{"Host": host}
		}
		return transport
	default:
		return nil
	}
}

func parseEndpoint(value string) (string, uint16, error) {
	host, portValue, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("invalid proxy endpoint")
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("invalid proxy port")
	}
	return host, uint16(port), nil
}

func rawUint16(value json.RawMessage) (uint16, error) {
	parsed, err := rawInt(value)
	if err != nil || parsed < 1 || parsed > 65535 {
		return 0, fmt.Errorf("invalid port")
	}
	return uint16(parsed), nil
}

func rawInt(value json.RawMessage) (int, error) {
	if len(value) == 0 || string(value) == "null" {
		return 0, nil
	}
	var number int
	if err := json.Unmarshal(value, &number); err == nil {
		return number, nil
	}
	var text string
	if err := json.Unmarshal(value, &text); err != nil {
		return 0, err
	}
	return strconv.Atoi(text)
}

func uniqueNodeName(name string, protocol Protocol, used map[string]int) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = string(protocol)
	}
	used[name]++
	if used[name] == 1 {
		return name
	}
	return fmt.Sprintf("%s-%d", name, used[name])
}

func unescapeFragment(value string) string {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func splitNonEmpty(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
