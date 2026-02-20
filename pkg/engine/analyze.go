package engine

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/Serdar715/lfix/pkg/signatures"
)

const (
	// confidenceThreshold is the minimum total confidence score to trigger a vulnerability finding.
	confidenceThreshold = 7

	// base64MinLength is the minimum length for a base64 string to be considered for decoding.
	// Shorter strings produce too many false positives.
	base64MinLength = 20
)

// base64Regex matches base64-encoded strings of sufficient length.
var base64Regex = regexp.MustCompile(`[A-Za-z0-9+/]{` + fmt.Sprintf("%d", base64MinLength) + `,}={0,2}`)

// AnalyzeResponse checks a response body for LFI signatures using a confidence score system.
// The baseline parameter is the normal response for the same endpoint — any signature
// found in both the payload response and the baseline is discarded to eliminate false positives.
func AnalyzeResponse(body string, baseline string, task Task) *Finding {
	totalConfidence := 0
	var matchedSignatures []string

	// 1. Plaintext Signature Check
	for _, sig := range signatures.AllSignatures {
		if !strings.Contains(body, sig.Pattern) {
			continue
		}
		// Calibration: discard the match if the same pattern exists in the baseline response.
		// We apply this uniformly to ALL confidence levels — no exceptions.
		// If the baseline itself is unreliable (empty), we skip the comparison.
		if baseline != "" && strings.Contains(baseline, sig.Pattern) {
			continue
		}
		totalConfidence += sig.Confidence
		matchedSignatures = append(matchedSignatures, sig.Pattern)
	}

	// 2. Base64 Decode Check — only run if plaintext score is still below threshold.
	// This avoids unnecessary regex work when we already have a high-confidence match.
	if totalConfidence < confidenceThreshold {
		matches := base64Regex.FindAllString(body, -1)
		for _, b64str := range matches {
			decoded, err := decodeBase64Padded(b64str)
			if err != nil {
				continue
			}
			for _, sig := range signatures.AllSignatures {
				if !strings.Contains(decoded, sig.Pattern) {
					continue
				}
				// Also exclude base64-decoded matches found in baseline.
				if baseline != "" && strings.Contains(baseline, sig.Pattern) {
					continue
				}
				totalConfidence += sig.Confidence
				matchedSignatures = append(matchedSignatures, "b64:"+sig.Pattern)
			}
		}
	}

	// 3. Final Evaluation
	if totalConfidence >= confidenceThreshold {
		matchInfo := fmt.Sprintf("Score %d: %s", totalConfidence, strings.Join(matchedSignatures, ", "))
		return &Finding{
			Task:      task,
			MatchInfo: matchInfo,
		}
	}

	return nil
}

// decodeBase64Padded tries to decode a base64 string, adding padding if necessary.
func decodeBase64Padded(s string) (string, error) {
	remainder := len(s) % 4
	if remainder != 0 {
		s += strings.Repeat("=", 4-remainder)
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
