package mutations

import (
	"testing"
)

func TestGetMutations(t *testing.T) {
	payload := "../etc/passwd"
	mutations := GetMutations(payload)

	if len(mutations) != 5 {
		t.Errorf("Expected 5 mutations, but got %d", len(mutations))
	}

	expectedFirst := payload
	if mutations[0] != expectedFirst {
		t.Errorf("Expected first mutation to be '%s', but got '%s'", expectedFirst, mutations[0])
	}

	expectedSecond := "..%2Fetc%2Fpasswd"
	if mutations[1] != expectedSecond {
		t.Errorf("Expected second mutation to be '%s', but got '%s'", expectedSecond, mutations[1])
	}

	expectedNullByte := payload + "%00"
	if mutations[3] != expectedNullByte {
		t.Errorf("Expected fourth mutation to be '%s', but got '%s'", expectedNullByte, mutations[3])
	}

	expectedPathFilterBypass := "....//etc/passwd"
	if mutations[4] != expectedPathFilterBypass {
		t.Errorf("Expected fifth mutation to be '%s', but got '%s'", expectedPathFilterBypass, mutations[4])
	}
}
