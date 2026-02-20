package signatures

import (
	"testing"
)

func TestSignaturesLoaded(t *testing.T) {
	if len(AllSignatures) == 0 {
		t.Fatal("AllSignatures slice is empty, expected it to be populated.")
	}

	for _, sig := range AllSignatures {
		if sig.Pattern == "" {
			t.Error("Found a signature with an empty pattern.")
		}
		if sig.Category == "" {
			t.Errorf("Signature for pattern '%s' has an empty category.", sig.Pattern)
		}
		if sig.Confidence < 1 || sig.Confidence > 10 {
			t.Errorf("Signature '%s' has an out-of-range confidence score: %d", sig.Pattern, sig.Confidence)
		}
	}
}

func TestSignatureConfidence(t *testing.T) {
	confidenceMap := make(map[string]int)
	for _, sig := range AllSignatures {
		confidenceMap[sig.Pattern] = sig.Confidence
	}

	if confidenceMap["root:x:0:0:"] != 10 {
		t.Errorf("Expected 'root:x:0:0:' to have confidence 10, but got %d", confidenceMap["root:x:0:0:"])
	}

	// Verify high-FP generic patterns have been removed from AllSignatures.
	removedPatterns := []string{"[drivers]", "[extensions]", "<configuration>", "apache_bundle"}
	for _, p := range removedPatterns {
		if _, exists := confidenceMap[p]; exists {
			t.Errorf("Pattern '%s' should have been removed (too generic / high FP risk)", p)
		}
	}

	// Verify specific IIS pattern kept.
	if confidenceMap["<system.webServer>"] != 9 {
		t.Errorf("Expected '<system.webServer>' to have confidence 9, but got %d", confidenceMap["<system.webServer>"])
	}
}
