package engine

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/Serdar715/lfix/pkg/signatures"
)

const (
	// ConfidenceThreshold is the minimum total confidence score to trigger a vulnerability finding.
	ConfidenceThreshold = 7
)

var base64Regex = regexp.MustCompile(`([A-Za-z0-9+/]{20,})={0,2}`)

// AnalyzeResponse checks a response body for signatures of LFI.
// It uses a confidence score system to reduce false positives.
func AnalyzeResponse(body string, baseline string, task Task) *Finding {
	totalConfidence := 0
	var matchedSignatures []string

	// 1. Plaintext Signature Check
	for _, sig := range signatures.AllSignatures {
		if strings.Contains(body, sig.Pattern) {
			// Auto-Calibration: Skip if the signature also exists in the baseline response.
			// Optimization: If a signature has maximum confidence (10), we can trust it even without calibration
			// to reduce false negatives caused by faulty baselines.
			if sig.Confidence < 10 && baseline != "" && strings.Contains(baseline, sig.Pattern) {
				continue // False positive, exists in normal page
			}
			totalConfidence += sig.Confidence
			matchedSignatures = append(matchedSignatures, sig.Pattern)
		}
	}

	// 2. Base64 Decode Check (only if plaintext confidence is not already high)
	if totalConfidence < ConfidenceThreshold {
		matches := base64Regex.FindAllString(body, -1)
		for _, b64string := range matches {
			// To prevent decoding parts of a valid base64 string, we add padding.
			// This is a simplified approach. A more robust solution might involve checking boundaries.
			if len(b64string)%4 != 0 {
				b64string += strings.Repeat("=", 4-len(b64string)%4)
			}

			decodedBytes, err := base64.StdEncoding.DecodeString(b64string)
			if err != nil {
				continue
			}
			decodedStr := string(decodedBytes)
			for _, sig := range signatures.AllSignatures {
				if strings.Contains(decodedStr, sig.Pattern) {
					// Also check decoded content against baseline
					if baseline != "" && strings.Contains(baseline, sig.Pattern) {
						continue
					}
					totalConfidence += sig.Confidence
					// Add a marker to show it was found in a base64 string
					matchedSignatures = append(matchedSignatures, "b64:"+sig.Pattern)
				}
			}
		}
	}

	// 3. Final Evaluation
	if totalConfidence >= ConfidenceThreshold {
		matchInfo := fmt.Sprintf("Score %d: %s", totalConfidence, strings.Join(matchedSignatures, ", "))
		return &Finding{
			Task:      task,
			MatchInfo: matchInfo,
		}
	}

	return nil // No finding
}
