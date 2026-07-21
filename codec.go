package subscriptionconverter

import "errors"

var (
	ErrDecodeUnsupported = errors.New("codec does not support decoding")
	ErrEncodeUnsupported = errors.New("codec does not support encoding")
	ErrMissingFormat     = errors.New("format is required")
	ErrUnknownFormat     = errors.New("unknown format")
	ErrAmbiguousFormat   = errors.New("ambiguous format")
)

type Recognition uint8

const (
	RecognitionNone Recognition = iota
	RecognitionPossible
	RecognitionLikely
	RecognitionExact
)

type DecodeOptions struct{}

type EncodeOptions struct{}

// Codec converts between one external format and the shared intermediate document.
type Codec interface {
	Format() string
	Recognize([]byte) Recognition
	Decode([]byte, DecodeOptions) (*Document, []string, error)
	Encode(Document, EncodeOptions) ([]byte, []string, error)
}
