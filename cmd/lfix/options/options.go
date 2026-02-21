package options

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidConcurrency = errors.New("concurrency must be between 1 and 1000")
	ErrInvalidTimeout     = errors.New("timeout must be between 1 and 300 seconds")
	ErrInvalidURL         = errors.New("invalid URL format")
	ErrEmptyTarget        = errors.New("target cannot be empty")
)

// StringSliceFlag implements flag.Value for repeated flags
type StringSliceFlag []string

func (s *StringSliceFlag) String() string     { return strings.Join(*s, ", ") }
func (s *StringSliceFlag) Set(v string) error { *s = append(*s, v); return nil }

// CLIOptions holds all command-line options with validation
type CLIOptions struct {
	SingleURL             string
	ListFile              string
	PayloadFile           string
	OutputFile            string
	OutputFormat          string // "text" or "json"
	PostData              string
	Method                string
	TargetHeader          string
	Proxy                 string
	StaticHeaders         StringSliceFlag
	Concurrency           int
	Timeout               int
	Verbose               bool
	Debug                 bool
	UseMutation           bool
	Calibrate             bool
	TLSInsecureSkipVerify bool
	// Exploitation flags
	EnableRCE       bool
	EnableLogPoison bool
	ShellPayload    string
}

// Validate ensures all options are within acceptable ranges
func (o *CLIOptions) Validate() error {
	if err := o.validateConcurrency(); err != nil {
		return err
	}
	if err := o.validateTimeout(); err != nil {
		return err
	}
	if err := o.validateURLs(); err != nil {
		return err
	}
	return nil
}

func (o *CLIOptions) validateConcurrency() error {
	if o.Concurrency < 1 || o.Concurrency > 1000 {
		return fmt.Errorf("%w: got %d", ErrInvalidConcurrency, o.Concurrency)
	}
	return nil
}

func (o *CLIOptions) validateTimeout() error {
	if o.Timeout < 1 || o.Timeout > 300 {
		return fmt.Errorf("%w: got %d", ErrInvalidTimeout, o.Timeout)
	}
	return nil
}

func (o *CLIOptions) validateURLs() error {
	if o.SingleURL != "" && !isValidURL(o.SingleURL) {
		return fmt.Errorf("%w: %s", ErrInvalidURL, o.SingleURL)
	}
	return nil
}

// ApplyDefaults sets default values for unset options
func (o *CLIOptions) ApplyDefaults() {
	if o.Concurrency == 0 {
		o.Concurrency = 30
	}
	if o.Timeout == 0 {
		o.Timeout = 7
	}
	if o.Method == "" {
		o.Method = "GET"
	}
	if o.OutputFormat == "" {
		o.OutputFormat = "text"
	}
	if !o.UseMutation {
		o.UseMutation = true
	}
	if !o.Calibrate {
		o.Calibrate = true
	}
}

// ScannerOptions is the configuration for the scanner
type ScannerOptions struct {
	Concurrency           int
	Timeout               int
	Proxy                 string
	UseMutation           bool
	Calibrate             bool
	Debug                 bool
	TLSInsecureSkipVerify bool
}

// ToScannerOptions converts CLI options to scanner options
func (o *CLIOptions) ToScannerOptions() ScannerOptions {
	return ScannerOptions{
		Concurrency:           o.Concurrency,
		Timeout:               o.Timeout,
		Proxy:                 o.Proxy,
		UseMutation:           o.UseMutation,
		Calibrate:             o.Calibrate,
		Debug:                 o.Debug,
		TLSInsecureSkipVerify: o.TLSInsecureSkipVerify,
	}
}

// ParseTimeout converts timeout in seconds to duration
func ParseTimeout(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}

// StringToInt converts string to int with default
func StringToInt(value string, defaultVal int) int {
	if value == "" {
		return defaultVal
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultVal
	}
	return parsed
}
