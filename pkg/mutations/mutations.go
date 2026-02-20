package mutations

import (
	"net/url"
	"strings"
)

// GetMutations generates a list of WAF bypass variations for a given payload.
func GetMutations(payload string) []string {
	// WAF Bypass Techniques
	return []string{
		payload,                  // Original
		url.QueryEscape(payload), // URL Encode
		url.QueryEscape(url.QueryEscape(payload)), // Double Encode
		payload + "%00", // Null Byte
		strings.ReplaceAll(payload, "../", "....//"), // Path Filter Bypass
	}
}
