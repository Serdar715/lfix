package options

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// TargetValidator validates scan targets
type TargetValidator struct {
	allowedSchemes []string
}

var (
	ErrUnsupportedScheme = errors.New("unsupported scheme")
	ErrNoHostSpecified   = errors.New("no host specified")
	ErrInvalidScheme     = errors.New("scheme must be http or https")
)

// NewTargetValidator creates a new TargetValidator
func NewTargetValidator() *TargetValidator {
	return &TargetValidator{
		allowedSchemes: []string{"http", "https"},
	}
}

// Validate checks if a target URL is valid
func (tv *TargetValidator) Validate(target string) error {
	if target == "" {
		return ErrEmptyTarget
	}

	// If it doesn't contain a scheme, add http://
	resolved, err := tv.ResolveTarget(target)
	if err != nil {
		return err
	}

	parsed, err := url.Parse(resolved)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	if !tv.isAllowedScheme(parsed.Scheme) {
		return fmt.Errorf("%w: %s", ErrInvalidScheme, parsed.Scheme)
	}

	if parsed.Host == "" {
		return ErrNoHostSpecified
	}

	return nil
}

func (tv *TargetValidator) isAllowedScheme(scheme string) bool {
	for _, allowed := range tv.allowedSchemes {
		if scheme == allowed {
			return true
		}
	}
	return false
}

// ResolveTarget resolves a target to its final form
func (tv *TargetValidator) ResolveTarget(target string) (string, error) {
	if target == "" {
		return "", ErrEmptyTarget
	}

	// If it doesn't contain a scheme, treat as potential host
	if !strings.Contains(target, "://") {
		// Check if it's an IP address
		if ip := net.ParseIP(target); ip != nil {
			return "http://" + target, nil
		}
		// Assume it's a domain
		return "http://" + target, nil
	}
	return target, nil
}

// isValidURL checks if a string is a valid URL with mandatory http/https scheme
func isValidURL(target string) bool {
	if target == "" {
		return false
	}

	// Must contain :// to have a valid scheme
	if !strings.Contains(target, "://") {
		return false
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}

	// Must have valid scheme and host
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	if parsed.Host == "" {
		return false
	}

	// Avoid hosts with spaces or other obviously invalid chars
	if strings.Contains(parsed.Host, " ") {
		return false
	}

	return true
}

// ValidateTargetLine validates a single line from target list
func ValidateTargetLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	// Skip comments
	if strings.HasPrefix(trimmed, "#") {
		return false
	}

	// Skip empty lines
	if len(trimmed) < 3 {
		return false
	}

	return true
}
