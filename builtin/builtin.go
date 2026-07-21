// Package builtin assembles the codecs shipped with subscription-converter.
package builtin

import (
	subscriptionconverter "github.com/cnfatal/subscription-converter"
	"github.com/cnfatal/subscription-converter/base64"
	"github.com/cnfatal/subscription-converter/clash"
	"github.com/cnfatal/subscription-converter/singbox"
)

func New() *subscriptionconverter.Converter {
	return subscriptionconverter.New(base64.Base64Codec{}, clash.ClashCodec{}, singbox.SingBoxCodec{})
}
