package bypass

import (
	"fmt"
	"strings"
	"testing"
)

func TestURLEncoding(t *testing.T) {
	manager := NewEncodingManager()

	// Test that URL encoding works - it should encode path separators
	result := manager.Encode("../", URLEncoding)

	// Should contain encoded versions of . and /
	if !strings.Contains(result, "%2e") && !strings.Contains(result, "%2f") {
		t.Errorf("URL encoding should encode path characters, got: %q", result)
	}

	// Test double encoding
	result = manager.Encode("../", DoubleURLEncoding)
	if !strings.Contains(result, "%25") {
		t.Errorf("Double URL encoding should contain percent25, got: %q", result)
	}
}

func TestDoubleURLEncoding(t *testing.T) {
	manager := NewEncodingManager()

	input := "../"
	result := manager.Encode(input, DoubleURLEncoding)

	// Should contain double-encoded characters
	if !strings.Contains(result, "%25") {
		t.Errorf("DoubleURLEncode should contain percent25, got: %q", result)
	}
}

func TestTripleURLEncoding(t *testing.T) {
	manager := NewEncodingManager()

	input := "../"
	result := manager.Encode(input, TripleURLEncoding)

	// Should contain triple-encoded characters
	if strings.Count(result, "%25") < 2 {
		t.Errorf("TripleURLEncode should contain multiple percent25, got: %q", result)
	}
}

func TestOverlongUTF8(t *testing.T) {
	manager := NewEncodingManager()

	tests := []string{"/", ".", "\\"}

	for _, input := range tests {
		result := manager.Encode(input, OverlongUTF8)
		// Overlong UTF-8 should contain %c0
		if !strings.Contains(result, "%c0") {
			t.Errorf("OverlongUTF8 should contain percentc0, got: %q", result)
		}
	}
}

func TestTraversalDoubleDot(t *testing.T) {
	result := EncodeTraversal("../../etc/passwd", TraversalDoubleDot)
	// Should have 4 dots
	if !strings.Contains(result, "....") {
		t.Errorf("TraversalDoubleDot should have 4 dots, got: %q", result)
	}
}

func TestTraversalTripleDot(t *testing.T) {
	result := EncodeTraversal("../../etc/passwd", TraversalTripleDot)
	// Should have 5 dots
	if !strings.Contains(result, ".....") {
		t.Errorf("TraversalTripleDot should have 5 dots, got: %q", result)
	}
}

func TestTraversalEncodedSlash(t *testing.T) {
	result := EncodeTraversal("../../etc/passwd", TraversalEncodedSlash)
	// Should contain encoded slashes
	if !strings.Contains(result, "%2e") && !strings.Contains(result, "%2f") {
		t.Errorf("TraversalEncodedSlash should contain encoded chars, got: %q", result)
	}
}

func TestTraversalDoubleEncodedSlash(t *testing.T) {
	result := EncodeTraversal("../../etc/passwd", TraversalDoubleEncodedSlash)
	// Should contain double-encoded slashes
	if !strings.Contains(result, "%252") {
		t.Errorf("TraversalDoubleEncodedSlash should contain percent252, got: %q", result)
	}
}

func TestTraversalUnicodeSlash(t *testing.T) {
	result := EncodeTraversal("../../etc/passwd", TraversalUnicodeSlash)
	// Should contain overlong encoded slashes
	if !strings.Contains(result, "%c0") {
		t.Errorf("TraversalUnicodeSlash should contain percentc0, got: %q", result)
	}
}

func TestTraversalMixed(t *testing.T) {
	result := EncodeTraversal("../../etc/passwd", TraversalMixed)
	// Should contain both dots and encoded slashes
	if !strings.Contains(result, "....") && !strings.Contains(result, "%2f") {
		t.Errorf("TraversalMixed should contain dots and encoded slashes, got: %q", result)
	}
}

func TestEncodingChain(t *testing.T) {
	chain := NewEncodingChain(URLEncoding, URLEncoding)
	input := "../"
	result := chain.Execute(input)

	// Chain should apply both encodings
	if !strings.Contains(result, "%25") {
		t.Errorf("Chain.Execute should contain percent25, got: %q", result)
	}
}

func TestEncodingChainAdd(t *testing.T) {
	chain := NewEncodingChain(URLEncoding).Add(URLEncoding).Add(URLEncoding)
	input := "test"
	result := chain.Execute(input)

	// Triple encoding should produce output
	if result == "" {
		t.Error("Chain with 3 encodings should produce output")
	}
}

func TestNullByte(t *testing.T) {
	manager := NewEncodingManager()

	input := "test"
	result := manager.Encode(input, NullByte)

	// Should start with %00
	if !strings.HasPrefix(result, "%00") {
		t.Errorf("NullByte should prepend percent00, got: %q", result)
	}
}

func TestNullByteAfter(t *testing.T) {
	manager := NewEncodingManager()

	input := "test"
	result := manager.Encode(input, NullByteAfter)

	// Should end with %00
	if !strings.HasSuffix(result, "%00") {
		t.Errorf("NullByteAfter should append percent00, got: %q", result)
	}
}

func TestGetEncodingName(t *testing.T) {
	// Should return non-empty strings
	names := []EncodingType{
		URLEncoding,
		DoubleURLEncoding,
		TripleURLEncoding,
		UnicodeEncoding,
		OverlongUTF8,
		NullByte,
		NoEncoding,
	}

	for _, enc := range names {
		name := GetEncodingName(enc)
		if name == "" {
			t.Errorf("GetEncodingName(%s) should not return empty string", enc)
		}
	}
}

func TestGetTraversalName(t *testing.T) {
	names := []TraversalEncoding{
		TraversalNone,
		TraversalDoubleDot,
		TraversalTripleDot,
		TraversalEncodedSlash,
		TraversalUnicodeSlash,
		TraversalMixed,
	}

	for _, enc := range names {
		name := GetTraversalName(enc)
		if name == "" {
			t.Errorf("GetTraversalName(%d) should not return empty string", enc)
		}
	}
}

func TestEncodingPreservesContent(t *testing.T) {
	manager := NewEncodingManager()

	original := "../../etc/passwd"

	// Verify that encoded content contains the original words
	encodings := []EncodingType{URLEncoding, DoubleURLEncoding, OverlongUTF8}

	for _, enc := range encodings {
		encoded := manager.Encode(original, enc)
		if !strings.Contains(encoded, "etc") {
			t.Errorf("Encoded string should contain etc, encoding: %s, result: %q", enc, encoded)
		}
	}
}

func TestAllEncodingsAvailable(t *testing.T) {
	manager := NewEncodingManager()
	encodings := manager.GetAvailableEncodings()

	if len(encodings) == 0 {
		t.Error("No encodings available")
	}

	// Test all encodings can be called without panic
	for _, enc := range encodings {
		result := manager.Encode("test", enc)
		if result == "" {
			t.Errorf("Encoding %s returned empty string", enc)
		}
	}
}

func TestHasEncoding(t *testing.T) {
	manager := NewEncodingManager()

	// These should exist
	if !manager.HasEncoding(URLEncoding) {
		t.Error("HasEncoding(URLEncoding) should return true")
	}
	if !manager.HasEncoding(OverlongUTF8) {
		t.Error("HasEncoding(OverlongUTF8) should return true")
	}

	// Invalid encoding should return false
	if manager.HasEncoding(EncodingType("invalid_encoding")) {
		t.Error("HasEncoding(invalid) should return false")
	}
}

func TestNoEncoding(t *testing.T) {
	manager := NewEncodingManager()

	input := "test"
	result := manager.Encode(input, NoEncoding)

	// NoEncoding should return original
	if result != input {
		t.Errorf("NoEncoding should return original, got: %q", result)
	}
}

// Benchmark tests
func BenchmarkURLEncoding(b *testing.B) {
	manager := NewEncodingManager()
	input := "../../etc/passwd"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Encode(input, URLEncoding)
	}
}

func BenchmarkDoubleURLEncoding(b *testing.B) {
	manager := NewEncodingManager()
	input := "../../etc/passwd"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Encode(input, DoubleURLEncoding)
	}
}

func BenchmarkOverlongUTF8(b *testing.B) {
	manager := NewEncodingManager()
	input := "../../etc/passwd"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Encode(input, OverlongUTF8)
	}
}

// Example tests
func ExampleEncodingManager_Encode() {
	manager := NewEncodingManager()

	// Test various encodings
	fmt.Println(manager.Encode("../", URLEncoding))
	fmt.Println(manager.Encode("../", DoubleURLEncoding))
	fmt.Println(manager.Encode("/etc/passwd", OverlongUTF8))

	// Output will vary but should produce encoded strings
}

func ExampleEncodeTraversal() {
	// Test traversal encodings
	fmt.Println(EncodeTraversal("../../etc/passwd", TraversalDoubleDot))
	fmt.Println(EncodeTraversal("../../etc/passwd", TraversalEncodedSlash))
	fmt.Println(EncodeTraversal("test", TraversalUnicodeSlash))

	// Output will vary but should produce transformed strings
}

func ExampleEncodingChain() {
	chain := NewEncodingChain(URLEncoding, URLEncoding)
	input := "../"
	result := chain.Execute(input)
	fmt.Println(result)

	// Output: %252e%252e%252f
}
