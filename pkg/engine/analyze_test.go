package engine

import (
	"github.com/Serdar715/lfix/pkg/signatures"
	"strings"
	"testing"
)

func TestAnalyzeResponse(t *testing.T) {
	// Setup signatures for testing purposes
	originalSignatures := signatures.AllSignatures
	signatures.AllSignatures = []signatures.Signature{
		{Pattern: "root:x:0:0:", Confidence: 10},
		{Pattern: "daemon:x:1:1:", Confidence: 8},
		{Pattern: "[boot loader]", Confidence: 7},
		{Pattern: "for 16-bit app support", Confidence: 5},
	}
	// Restore original signatures after test
	defer func() { signatures.AllSignatures = originalSignatures }()

	task := Task{URL: "http://test.com"}

	// Test case 1: High confidence signature found
	t.Run("HighConfidenceFinding", func(t *testing.T) {
		body := "this is a test response with root:x:0:0: inside"
		finding := AnalyzeResponse(body, "", task)
		if finding == nil {
			t.Fatal("Expected a finding for high confidence signature, got nil")
		}
		if finding.Task.URL != task.URL {
			t.Errorf("Finding has wrong task URL")
		}
	})

	// Test case 2: No signature found
	t.Run("NoFinding", func(t *testing.T) {
		body := "this is a clean response"
		finding := AnalyzeResponse(body, "", task)
		if finding != nil {
			t.Fatalf("Expected no finding, but got one: %v", finding)
		}
	})

	// Test case 3: Low confidence signature found (below threshold)
	t.Run("LowConfidenceNoFinding", func(t *testing.T) {
		body := "this contains for 16-bit app support" // Confidence 5, Threshold 9
		finding := AnalyzeResponse(body, "", task)
		if finding != nil {
			t.Fatalf("Expected no finding for low confidence signature, but got one: %v", finding)
		}
	})

	// Test case 4: Combined confidence meets threshold
	t.Run("CombinedConfidenceFinding", func(t *testing.T) {
		body := "contains [boot loader] and also for 16-bit app support"
		// ConfidenceThreshold is 9. 7 + 5 = 12, which is >= 9
		finding := AnalyzeResponse(body, "", task)
		if finding == nil {
			t.Fatal("Expected a finding for combined confidence signatures, got nil")
		}
	})

	// Test case 5: Signature found in baseline (false positive)
	t.Run("BaselineFalsePositive", func(t *testing.T) {
		body := "this is a test response with root:x:0:0: inside"
		baseline := "the baseline also has root:x:0:0: so it should be ignored"
		finding := AnalyzeResponse(body, baseline, task)
		if finding != nil {
			t.Fatalf("Expected no finding due to baseline match, but got one: %v", finding)
		}
	})

	// Test case 6: Base64 encoded high confidence finding
	t.Run("Base64HighConfidenceFinding", func(t *testing.T) {
		// "root:x:0:0:" = cm9vdDp4OjA6MDop
		// To match the regex of 20+ chars, we'll add some dummy data
		body := "some text and then cm9vdDp4OjA6MDpyb290On nyingi"
		finding := AnalyzeResponse(body, "", task)
		if finding == nil {
			t.Fatal("Expected a finding for base64 high confidence signature, got nil")
		}
		if !strings.Contains(finding.MatchInfo, "b64:root:x:0:0:") {
			t.Errorf("Match info should indicate base64, but got: %s", finding.MatchInfo)
		}
	})
}
