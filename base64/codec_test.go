package base64_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	subscriptionbase64 "github.com/cnfatal/subscription-converter/base64"
	"github.com/cnfatal/subscription-converter/builtin"
	"strings"
	"testing"

	subscriptionconverter "github.com/cnfatal/subscription-converter"
)

func TestBase64CodecDecodesURIProtocols(t *testing.T) {
	vmess, err := json.Marshal(map[string]any{
		"v": "2", "ps": "vmess-node", "add": "192.0.2.2", "port": "443",
		"id": "00000000-0000-0000-0000-000000000002", "aid": "0",
		"net": "tcp", "type": "none", "tls": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	ssPayload := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret@192.0.2.1:8388"))
	lines := []string{
		"ss://" + ssPayload + "#ss-node",
		"vmess://" + base64.RawStdEncoding.EncodeToString(vmess),
		"vless://00000000-0000-0000-0000-000000000003@192.0.2.3:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.com&fp=chrome&pbk=public-key&sid=01234567&type=tcp#vless-node",
	}
	input := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n"))))
	codec := subscriptionbase64.Base64Codec{}
	if recognition := codec.Recognize(input); recognition != subscriptionconverter.RecognitionExact {
		t.Fatalf("unexpected recognition: %v", recognition)
	}

	decoded, err := builtin.New().Decode(input, "", subscriptionconverter.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Format != "base64" || len(decoded.Document.Nodes) != 3 || len(decoded.Warnings) != 0 {
		t.Fatalf("unexpected decode result: %#v", decoded)
	}
	vless := decoded.Document.Nodes[2]
	if vless.Type != subscriptionconverter.ProtocolVLESS || vless.VLESS.Flow != "xtls-rprx-vision" {
		t.Fatalf("unexpected VLESS node: %#v", vless)
	}
	if vless.TLS == nil || vless.TLS.Reality == nil || vless.TLS.Reality.PublicKey != "public-key" {
		t.Fatalf("unexpected REALITY options: %#v", vless.TLS)
	}

	encoded, warnings, err := builtin.New().Convert(input, "base64", "sing-box")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 || !strings.Contains(string(encoded), `"reality"`) {
		t.Fatalf("unexpected sing-box result: warnings=%v\n%s", warnings, encoded)
	}
}

func TestBase64CodecRejectsOrdinaryBase64(t *testing.T) {
	input := []byte(base64.StdEncoding.EncodeToString([]byte(fmt.Sprintln("ordinary text"))))
	if recognition := (subscriptionbase64.Base64Codec{}).Recognize(input); recognition != subscriptionconverter.RecognitionNone {
		t.Fatalf("unexpected recognition: %v", recognition)
	}
}
