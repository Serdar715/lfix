package bypass

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// EncodingType represents the type of encoding to apply
type EncodingType string

const (
	// NoEncoding - No encoding applied
	NoEncoding EncodingType = "none"
	// URLEncoding - Standard URL encoding (%XX)
	URLEncoding EncodingType = "url"
	// DoubleURLEncoding - Double URL encoding (%%XX -> %)
	DoubleURLEncoding EncodingType = "double_url"
	// TripleURLEncoding - Triple URL encoding
	TripleURLEncoding EncodingType = "triple_url"
	// UnicodeEncoding - Unicode escape sequences (\uXXXX)
	UnicodeEncoding EncodingType = "unicode"
	// OverlongUTF8 - Overlong UTF-8 encoding (bypass UTF-8 filters)
	OverlongUTF8 EncodingType = "overlong_utf8"
	// UnicodeVerticalTab - Unicode vertical tab bypass
	UnicodeVerticalTab EncodingType = "unicode_vtab"
	// UTF8MultiByte - Multi-byte UTF-8 sequences
	UTF8MultiByte EncodingType = "utf8_multibyte"
	// NullByte - Null byte injection (%00)
	NullByte EncodingType = "null_byte"
	// NullByteAfter - Null byte after payload
	NullByteAfter EncodingType = "null_byte_after"
)

// Encoder is a function type that transforms a string
type Encoder func(string) string

// EncodingManager handles all encoding operations
type EncodingManager struct {
	encoders map[EncodingType]Encoder
}

// NewEncodingManager creates a new encoding manager with all encoders
func NewEncodingManager() *EncodingManager {
	em := &EncodingManager{
		encoders: make(map[EncodingType]Encoder),
	}
	em.registerEncoders()
	return em
}

// registerEncoders registers all available encoders
func (em *EncodingManager) registerEncoders() {
	em.encoders = map[EncodingType]Encoder{
		URLEncoding:        encodeURL,
		DoubleURLEncoding:  encodeDoubleURL,
		TripleURLEncoding:  encodeTripleURL,
		UnicodeEncoding:    encodeUnicode,
		OverlongUTF8:       encodeOverlongUTF8,
		UnicodeVerticalTab: encodeUnicodeVerticalTab,
		UTF8MultiByte:      encodeUTF8MultiByte,
		NullByte:           encodeNullByte,
		NullByteAfter:      encodeNullByteAfter,
	}
}

// Encode applies the specified encoding to the input string
func (em *EncodingManager) Encode(input string, encType EncodingType) string {
	if encType == NoEncoding {
		return input
	}
	if encoder, ok := em.encoders[encType]; ok {
		return encoder(input)
	}
	return input
}

// EncodeMultiple applies multiple encodings in sequence
func (em *EncodingManager) EncodeMultiple(input string, encTypes ...EncodingType) string {
	result := input
	for _, encType := range encTypes {
		result = em.Encode(result, encType)
	}
	return result
}

// GetAvailableEncodings returns all available encoding types
func (em *EncodingManager) GetAvailableEncodings() []EncodingType {
	types := make([]EncodingType, 0, len(em.encoders))
	for encType := range em.encoders {
		types = append(types, encType)
	}
	return types
}

// HasEncoding checks if an encoding type is available
func (em *EncodingManager) HasEncoding(encType EncodingType) bool {
	_, ok := em.encoders[encType]
	return ok
}

// =============================================================================
// Encoding Functions
// =============================================================================

// unsafeChars contains characters that should be URL encoded
var unsafeChars = map[rune]bool{
	'<':  true,
	'>':  true,
	'"':  true,
	' ':  true,
	'#':  true,
	'%':  true,
	'&':  true,
	'+':  true,
	'=':  true,
	'\n': true,
	'\r': true,
	'\t': true,
	'/':  true,
	'\\': true,
	'.':  true,
}

// encodeURL applies standard URL encoding
func encodeURL(input string) string {
	var result strings.Builder
	result.Grow(len(input) * 3)

	for _, r := range input {
		if unsafeChars[r] || r > 127 {
			result.WriteString(fmt.Sprintf("%%%02x", r))
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// encodeDoubleURL applies double URL encoding
func encodeDoubleURL(input string) string {
	// First encode: % -> %25
	first := encodeURL(input)
	// Second encode: % -> %25
	return encodeURL(first)
}

// encodeTripleURL applies triple URL encoding
func encodeTripleURL(input string) string {
	first := encodeURL(input)
	second := encodeURL(first)
	return encodeURL(second)
}

// encodeUnicode converts characters to Unicode escape sequences
func encodeUnicode(input string) string {
	var result strings.Builder
	result.Grow(len(input) * 6)

	for _, r := range input {
		if r > 127 {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// encodeOverlongUTF8 converts characters to overlong UTF-8 sequences
// This bypasses some UTF-8 validation filters
// Example: / becomes %c0%af
func encodeOverlongUTF8(input string) string {
	var result strings.Builder
	result.Grow(len(input) * 4)

	for _, r := range input {
		if r > 0x7F {
			// Convert to overlong UTF-8 representation
			// 2-byte overlong: 110xxxxx 10xxxxxx
			b1 := byte(0xC0 | (r >> 6))
			b2 := byte(0x80 | (r & 0x3F))
			result.WriteString(fmt.Sprintf("%%%02X%%%02X", b1, b2))
		} else if r == '.' {
			// Special case for . -> %c0%2e
			result.WriteString("%c0%2e")
		} else if r == '/' {
			// Special case for / -> %c0%af
			result.WriteString("%c0%af")
		} else if r == '\\' {
			// Special case for \ -> %c0%5c
			result.WriteString("%c0%5c")
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// encodeUnicodeVerticalTab uses Unicode vertical tab (0x0B) as bypass
func encodeUnicodeVerticalTab(input string) string {
	var result strings.Builder

	// Replace path separators with vertical tab encoded versions
	for _, r := range input {
		switch r {
		case '/':
			// Unicode vertical tab
			result.WriteString("\x0B")
		case '\\':
			// Backslash with vertical tab
			result.WriteString("\x0B")
		default:
			result.WriteRune(r)
		}
	}

	return result.String()
}

// encodeUTF8MultiByte uses multi-byte UTF-8 sequences
func encodeUTF8MultiByte(input string) string {
	var result strings.Builder

	for _, r := range input {
		if r > 0x7F {
			buf := make([]byte, utf8.UTFMax)
			n := utf8.EncodeRune(buf, r)
			for i := 0; i < n; i++ {
				result.WriteString(fmt.Sprintf("%%%02X", buf[i]))
			}
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// encodeNullByte prepends null byte to bypass extension checks
func encodeNullByte(input string) string {
	return "%00" + input
}

// encodeNullByteAfter appends null byte after the payload
func encodeNullByteAfter(input string) string {
	return input + "%00"
}

// =============================================================================
// Path Traversal Specific Encodings
// =============================================================================

// TraversalEncoding represents path traversal encoding types
type TraversalEncoding int

const (
	TraversalNone TraversalEncoding = iota
	TraversalDoubleDot
	TraversalTripleDot
	TraversalEncodedSlash
	TraversalDoubleEncodedSlash
	TraversalUnicodeSlash
	TraversalMixed
)

// EncodeTraversal applies traversal-specific encoding
func EncodeTraversal(path string, encoding TraversalEncoding) string {
	switch encoding {
	case TraversalDoubleDot:
		return encodeDoubleDots(path)
	case TraversalTripleDot:
		return encodeTripleDots(path)
	case TraversalEncodedSlash:
		return encodeWithEncodedSlash(path)
	case TraversalDoubleEncodedSlash:
		return encodeDoubleEncodedSlash(path)
	case TraversalUnicodeSlash:
		return encodeWithUnicodeSlash(path)
	case TraversalMixed:
		return encodeMixed(path)
	default:
		return path
	}
}

func encodeDoubleDots(path string) string {
	// Replace ../ with ....// to bypass filter that blocks ..
	result := strings.ReplaceAll(path, "../", "....//")
	result = strings.ReplaceAll(result, "..\\", "....//")
	return result
}

func encodeTripleDots(path string) string {
	// Replace ../ with ...../ to bypass filter that blocks ..
	result := strings.ReplaceAll(path, "../", "...../")
	result = strings.ReplaceAll(result, "..\\", "...../")
	return result
}

func encodeWithEncodedSlash(path string) string {
	// Replace .. with %2e and / with %2f
	result := strings.ReplaceAll(path, "..", "%2e")
	result = strings.ReplaceAll(result, "/", "%2f")
	result = strings.ReplaceAll(result, "\\", "%2f")
	return result
}

func encodeDoubleEncodedSlash(path string) string {
	// Replace .. with %252e and / with %252f
	result := strings.ReplaceAll(path, "..", "%252e")
	result = strings.ReplaceAll(result, "/", "%252f")
	result = strings.ReplaceAll(result, "\\", "%252f")
	return result
}

func encodeWithUnicodeSlash(path string) string {
	// Replace .. with %c0%af. and / with %c0%af
	result := strings.ReplaceAll(path, "..", "%c0%af.")
	result = strings.ReplaceAll(result, "/", "%c0%af")
	result = strings.ReplaceAll(result, "\\", "%c0%af")
	return result
}

func encodeMixed(path string) string {
	// Mix of techniques: replace .. with ....// and / with %2f
	result := strings.ReplaceAll(path, "..", "....//")
	result = strings.ReplaceAll(result, "/", "%2f")
	result = strings.ReplaceAll(result, "\\", "%2f")
	return result
}

// =============================================================================
// Chained Encoding
// =============================================================================

// Chain encodings together for advanced bypass
type EncodingChain struct {
	encodings []EncodingType
	manager   *EncodingManager
}

// NewEncodingChain creates a new encoding chain
func NewEncodingChain(encodings ...EncodingType) *EncodingChain {
	return &EncodingChain{
		encodings: encodings,
		manager:   NewEncodingManager(),
	}
}

// Execute runs all encodings in sequence
func (ec *EncodingChain) Execute(input string) string {
	return ec.manager.EncodeMultiple(input, ec.encodings...)
}

// Add adds another encoding to the chain
func (ec *EncodingChain) Add(encoding EncodingType) *EncodingChain {
	ec.encodings = append(ec.encodings, encoding)
	return ec
}

// GetEncodings returns the current encodings in the chain
func (ec *EncodingChain) GetEncodings() []EncodingType {
	return ec.encodings
}

// Common encoding chains for LFI bypass
var (
	// URLChain - Standard URL encoding chain
	URLChain = NewEncodingChain(URLEncoding)

	// DoubleURLChain - Double URL encoding chain
	DoubleURLChain = NewEncodingChain(URLEncoding, URLEncoding)

	// TripleURLChain - Triple URL encoding chain
	TripleURLChain = NewEncodingChain(URLEncoding, URLEncoding, URLEncoding)

	// OverlongChain - Overlong UTF-8 encoding
	OverlongChain = NewEncodingChain(OverlongUTF8)

	// MixedTraversalChain - Mix of traversal encodings
	MixedTraversalChain = NewEncodingChain(URLEncoding, DoubleURLEncoding)
)

// =============================================================================
// Utility Functions
// =============================================================================

// GetEncodingName returns a human-readable name for the encoding type
func GetEncodingName(encType EncodingType) string {
	names := map[EncodingType]string{
		NoEncoding:         "No Encoding",
		URLEncoding:        "URL Encoding",
		DoubleURLEncoding:  "Double URL Encoding",
		TripleURLEncoding:  "Triple URL Encoding",
		UnicodeEncoding:    "Unicode Escape",
		OverlongUTF8:       "Overlong UTF-8",
		UnicodeVerticalTab: "Unicode Vertical Tab",
		UTF8MultiByte:      "UTF-8 Multi-Byte",
		NullByte:           "Null Byte (Prepend)",
		NullByteAfter:      "Null Byte (Append)",
	}
	if name, ok := names[encType]; ok {
		return name
	}
	return string(encType)
}

// GetTraversalName returns a human-readable name for traversal encoding
func GetTraversalName(enc TraversalEncoding) string {
	names := map[TraversalEncoding]string{
		TraversalNone:               "None",
		TraversalDoubleDot:          "Double Dot (....)",
		TraversalTripleDot:          "Triple Dot (.....)",
		TraversalEncodedSlash:       "Encoded Slash (%2f)",
		TraversalDoubleEncodedSlash: "Double Encoded Slash (%252f)",
		TraversalUnicodeSlash:       "Unicode Slash (%c0%af)",
		TraversalMixed:              "Mixed",
	}
	if name, ok := names[enc]; ok {
		return name
	}
	return "Unknown"
}
