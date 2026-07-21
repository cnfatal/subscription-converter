package subscriptionconverter

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Converter struct {
	codecs     map[string]Codec
	registered []Codec
}

type ConvertOptions struct {
	From   string        `json:"from,omitempty"`
	To     string        `json:"to"`
	Decode DecodeOptions `json:"decode,omitempty"`
	Encode EncodeOptions `json:"encode,omitempty"`
}

type DecodedResult struct {
	Format   string    `json:"format"`
	Document *Document `json:"document,omitempty"`
	Warnings []string  `json:"warnings,omitempty"`
}

type FormattedResult struct {
	Format   string   `json:"format"`
	Content  []byte   `json:"content"`
	Warnings []string `json:"warnings,omitempty"`
}

type ConvertResult struct {
	SourceFormat string   `json:"source_format"`
	TargetFormat string   `json:"target_format"`
	Content      []byte   `json:"content"`
	Warnings     []string `json:"warnings,omitempty"`
}

func New() *Converter {
	converter := &Converter{codecs: map[string]Codec{}}
	converter.RegisterCodec(Base64Codec{})
	converter.RegisterCodec(ClashCodec{})
	converter.RegisterCodec(SingBoxCodec{})
	_ = converter.RegisterAlias("mihomo", "clash")
	_ = converter.RegisterAlias("singbox", "sing-box")
	return converter
}

func (c *Converter) RegisterCodec(codec Codec) {
	format := normalize(codec.Format())
	c.codecs[format] = codec
	c.registered = append(c.registered, codec)
}

func (c *Converter) RegisterAlias(alias, format string) error {
	codec, err := c.codec(normalize(format))
	if err != nil {
		return err
	}
	c.codecs[normalize(alias)] = codec
	return nil
}

// Decode selects one codec explicitly or detects it, then decodes exactly once.
func (c *Converter) Decode(data []byte, format string, options DecodeOptions) (DecodedResult, error) {
	var codec Codec
	var err error
	format = decodeFormat(format)
	if format == "" {
		codec, err = c.detect(data)
	} else {
		codec, err = c.codec(format)
	}
	if err != nil {
		return DecodedResult{}, err
	}
	document, warnings, err := codec.Decode(data, options)
	return DecodedResult{Format: codec.Format(), Document: document, Warnings: warnings}, err
}

func (c *Converter) detect(data []byte) (Codec, error) {
	var best Codec
	bestRecognition := RecognitionNone
	bestCount := 0
	for _, codec := range c.registered {
		recognition := codec.Recognize(data)
		if recognition > bestRecognition {
			best, bestRecognition, bestCount = codec, recognition, 1
		} else if recognition != RecognitionNone && recognition == bestRecognition {
			bestCount++
		}
	}
	if bestRecognition == RecognitionNone {
		return nil, ErrUnknownFormat
	}
	if bestCount > 1 {
		return nil, ErrAmbiguousFormat
	}
	return best, nil
}

func (c *Converter) Encode(document Document, format string, options EncodeOptions) (FormattedResult, error) {
	format = normalize(format)
	if format == "" || format == "auto" {
		return FormattedResult{}, ErrMissingFormat
	}
	codec, err := c.codec(format)
	if err != nil {
		return FormattedResult{}, err
	}
	content, warnings, err := codec.Encode(document, options)
	return FormattedResult{Format: codec.Format(), Content: content, Warnings: warnings}, err
}

func (c *Converter) Convert(data []byte, from, to string) ([]byte, []string, error) {
	result, err := c.ConvertWithOptions(data, ConvertOptions{From: from, To: to})
	return result.Content, result.Warnings, err
}

func (c *Converter) ConvertWithOptions(data []byte, options ConvertOptions) (ConvertResult, error) {
	decoded, err := c.Decode(data, options.From, options.Decode)
	if err != nil {
		return ConvertResult{SourceFormat: decoded.Format, Warnings: decoded.Warnings}, err
	}
	if decoded.Document == nil {
		return ConvertResult{SourceFormat: decoded.Format, Warnings: decoded.Warnings}, errors.New("decoder returned no document")
	}
	encoded, err := c.Encode(*decoded.Document, options.To, options.Encode)
	warnings := append(decoded.Warnings, encoded.Warnings...)
	return ConvertResult{
		SourceFormat: decoded.Format,
		TargetFormat: encoded.Format,
		Content:      encoded.Content,
		Warnings:     warnings,
	}, err
}

func (c *Converter) Formats() []string {
	result := make([]string, 0, len(c.codecs))
	for format := range c.codecs {
		result = append(result, format)
	}
	sort.Strings(result)
	return result
}

func normalize(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}

func decodeFormat(format string) string {
	format = normalize(format)
	if format == "auto" {
		return ""
	}
	return format
}

func (c *Converter) codec(format string) (Codec, error) {
	codec, exists := c.codecs[format]
	if !exists {
		return nil, fmt.Errorf("%w %q (available: %s)", ErrUnknownFormat, format, strings.Join(c.Formats(), ", "))
	}
	return codec, nil
}
