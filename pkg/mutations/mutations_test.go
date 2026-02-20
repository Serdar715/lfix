package mutations

import (
	"testing"
)

func TestGetMutations(t *testing.T) {
	payload := "../etc/passwd"
	mutations := GetMutations(payload)

	// Ensure expected count matches the current implementation.
	const expectedCount = 8
	if len(mutations) != expectedCount {
		t.Errorf("Expected %d mutations, but got %d", expectedCount, len(mutations))
	}

	// Index 0: raw payload
	if mutations[0] != payload {
		t.Errorf("Expected raw payload at index 0, got '%s'", mutations[0])
	}

	// Index 1: single URL encode  ../ → ..%2F
	expected1 := "..%2Fetc%2Fpasswd"
	if mutations[1] != expected1 {
		t.Errorf("Expected single-url-encoded at index 1 '%s', got '%s'", expected1, mutations[1])
	}

	// Index 3: null byte append
	expectedNullByte := payload + "%00"
	if mutations[3] != expectedNullByte {
		t.Errorf("Expected null-byte mutation at index 3 '%s', got '%s'", expectedNullByte, mutations[3])
	}

	// Index 4: path filter bypass (....// replaces ../)
	expectedPathBypass := "....//etc/passwd"
	if mutations[4] != expectedPathBypass {
		t.Errorf("Expected path-filter bypass at index 4 '%s', got '%s'", expectedPathBypass, mutations[4])
	}

	// Index 5: backslash bypass
	expectedBackslash := "..\\etc\\passwd"
	if mutations[5] != expectedBackslash {
		t.Errorf("Expected backslash bypass at index 5 '%s', got '%s'", expectedBackslash, mutations[5])
	}

	// Index 6: semicolon separator bypass
	expectedSemicolon := "..;/etc/passwd"
	if mutations[6] != expectedSemicolon {
		t.Errorf("Expected semicolon bypass at index 6 '%s', got '%s'", expectedSemicolon, mutations[6])
	}
}
