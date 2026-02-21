package mutations

import (
	"testing"
)

func TestGetMutations(t *testing.T) {
	payload := "../etc/passwd"
	mutations := GetMutations(payload, "")

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

	// Index 3: path filter bypass (....// replaces ../)
	expectedPathBypass := "....//etc/passwd"
	if mutations[3] != expectedPathBypass {
		t.Errorf("Expected path-filter bypass at index 3 '%s', got '%s'", expectedPathBypass, mutations[3])
	}

	// Index 4: backslash bypass
	expectedBackslash := "..\\etc\\passwd"
	if mutations[4] != expectedBackslash {
		t.Errorf("Expected backslash bypass at index 4 '%s', got '%s'", expectedBackslash, mutations[4])
	}

	// Index 5: semicolon separator bypass
	expectedSemicolon := "..;/etc/passwd"
	if mutations[5] != expectedSemicolon {
		t.Errorf("Expected semicolon bypass at index 5 '%s', got '%s'", expectedSemicolon, mutations[5])
	}

	// Index 6: unicode slash
	if mutations[6] != "..%ef%bc%8fetc%ef%bc%8fpasswd" {
		t.Errorf("Expected unicode slash at index 6, got '%s'", mutations[6])
	}

	// Index 7: null byte append
	expectedNullByte := payload + "%00"
	if mutations[7] != expectedNullByte {
		t.Errorf("Expected null-byte mutation at index 7 '%s', got '%s'", expectedNullByte, mutations[7])
	}
}
