package options

import (
	"testing"
)

// TestValidateConcurrency tests concurrency validation
func TestValidateConcurrency(t *testing.T) {
	tests := []struct {
		name        string
		concurrency int
		wantErr     bool
	}{
		{"valid low", 1, false},
		{"valid mid", 30, false},
		{"valid high", 1000, false},
		{"invalid zero", 0, true},
		{"invalid negative", -1, true},
		{"invalid too high", 1001, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &CLIOptions{Concurrency: tt.concurrency}
			err := o.validateConcurrency()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConcurrency() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateTimeout tests timeout validation
func TestValidateTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout int
		wantErr bool
	}{
		{"valid low", 1, false},
		{"valid mid", 30, false},
		{"valid high", 300, false},
		{"invalid zero", 0, true},
		{"invalid negative", -1, true},
		{"invalid too high", 301, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &CLIOptions{Timeout: tt.timeout}
			err := o.validateTimeout()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTimeout() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestApplyDefaults tests default value application
func TestApplyDefaults(t *testing.T) {
	o := &CLIOptions{}
	o.ApplyDefaults()

	if o.Concurrency != 30 {
		t.Errorf("Expected concurrency 30, got %d", o.Concurrency)
	}
	if o.Timeout != 7 {
		t.Errorf("Expected timeout 7, got %d", o.Timeout)
	}
	if o.Method != "GET" {
		t.Errorf("Expected method GET, got %s", o.Method)
	}
	if o.OutputFormat != "text" {
		t.Errorf("Expected output format text, got %s", o.OutputFormat)
	}
}

// TestValidateURLs tests URL validation
func TestValidateURLs(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid http", "http://example.com", false},
		{"valid https", "https://example.com", false},
		{"valid with path", "http://example.com/index.php?file=test", false},
		{"invalid no scheme", "example.com", true},
		{"invalid spaces", "http://example .com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &CLIOptions{SingleURL: tt.url}
			err := o.validateURLs()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateURLs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestStringSliceFlag tests custom flag type
func TestStringSliceFlag(t *testing.T) {
	var flag StringSliceFlag

	// Test Set
	flag.Set("header1:value1")
	flag.Set("header2:value2")

	if len(flag) != 2 {
		t.Errorf("Expected length 2, got %d", len(flag))
	}

	// Test String
	str := flag.String()
	if str != "header1:value1, header2:value2" {
		t.Errorf("String() = %s, want 'header1:value1, header2:value2'", str)
	}
}

// TestParseTimeout tests timeout parsing
func TestParseTimeout(t *testing.T) {
	result := ParseTimeout(5)
	if result.String() != "5s" {
		t.Errorf("ParseTimeout(5) = %v, want 5s", result)
	}
}

// TestStringToInt tests string to int conversion
func TestStringToInt(t *testing.T) {
	tests := []struct {
		input    string
		def      int
		expected int
	}{
		{"10", 5, 10},
		{"0", 5, 0},
		{"", 5, 5},
		{"invalid", 5, 5},
	}

	for _, tt := range tests {
		result := StringToInt(tt.input, tt.def)
		if result != tt.expected {
			t.Errorf("StringToInt(%q, %d) = %d, want %d", tt.input, tt.def, result, tt.expected)
		}
	}
}
