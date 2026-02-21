package core

import (
	"regexp"
	"strings"
	"time"
)

// Severity levels for vulnerabilities
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ResponseAnalyzer analyzes HTTP responses for LFI indicators
type ResponseAnalyzer struct {
	linuxKeywords   []string
	windowsKeywords []string
	errorPatterns   []*ErrorPattern
	baselineLength  int
	baselineHash    string
}

// ErrorPattern represents an error pattern to detect
type ErrorPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    Severity
	Description string
}

// AnalysisResult contains the analysis results
type AnalysisResult struct {
	IsVulnerable  bool
	Severity      Severity
	Confidence    float64
	DetectedFiles []string
	OS            string
	ErrorFound    bool
	ErrorMessage  string
	KeywordsFound []string
	LengthDiff    int
	ContentDiff   bool
	IsBlind       bool
	TimingDelta   time.Duration
}

// NewResponseAnalyzer creates a new response analyzer
func NewResponseAnalyzer() *ResponseAnalyzer {
	return &ResponseAnalyzer{
		linuxKeywords: []string{
			"root:",
			"/bin/bash",
			"/bin/sh",
			"daemon:",
			"www-data:",
			"nobody:",
			"mysql:",
			"postgres:",
		},
		windowsKeywords: []string{
			"[boot loader]",
			"Windows",
			"[extensions]",
			" operating system",
			"Microsoft Windows",
		},
		errorPatterns: []*ErrorPattern{
			{
				Name:        "PHP Include Error",
				Regex:       regexp.MustCompile(`(?i)(include|require|include_once|require_once)\s*\(\s*['"]([^'"]+)['"]\s*\)`),
				Severity:    SeverityMedium,
				Description: "PHP include/require error",
			},
			{
				Name:        "Failed to Open Stream",
				Regex:       regexp.MustCompile(`(?i)failed to open stream`),
				Severity:    SeverityMedium,
				Description: "File open failure",
			},
			{
				Name:        "No Such File",
				Regex:       regexp.MustCompile(`(?i)No such file or directory`),
				Severity:    SeverityMedium,
				Description: "File not found",
			},
			{
				Name:        "Permission Denied",
				Regex:       regexp.MustCompile(`(?i)Permission denied`),
				Severity:    SeverityMedium,
				Description: "Permission error",
			},
			{
				Name:        "Warning Include",
				Regex:       regexp.MustCompile(`(?i)Warning:\s+include`),
				Severity:    SeverityLow,
				Description: "PHP warning",
			},
		},
	}
}

// Analyze compares baseline and test response
func (ra *ResponseAnalyzer) Analyze(baseline, response *Response) *AnalysisResult {
	result := &AnalysisResult{
		IsVulnerable: false,
		Confidence:   0.0,
	}

	// Check length difference
	result.LengthDiff = response.Length - baseline.Length
	result.ContentDiff = response.Body != baseline.Body

	// Check for keywords (file content disclosure)
	result.KeywordsFound = ra.detectKeywords(response.Body)
	if len(result.KeywordsFound) > 0 {
		result.IsVulnerable = true
		result.Confidence = 0.9
		result.DetectedFiles = ra.identifyFiles(result.KeywordsFound)
	}

	// Detect OS
	result.OS = ra.detectOS(response.Body)

	// Check for errors
	errResult := ra.detectErrors(response.Body)
	if errResult != nil {
		result.ErrorFound = true
		result.ErrorMessage = errResult.Name
		// If we found file content AND errors, high confidence
		if result.IsVulnerable {
			result.Confidence = 1.0
		}
	}

	return result
}

// detectKeywords finds LFI-indicating keywords in response
func (ra *ResponseAnalyzer) detectKeywords(body string) []string {
	found := make([]string, 0)

	allKeywords := append(ra.linuxKeywords, ra.windowsKeywords...)
	for _, keyword := range allKeywords {
		if strings.Contains(body, keyword) {
			found = append(found, keyword)
		}
	}

	return found
}

// detectOS identifies the operating system from response
func (ra *ResponseAnalyzer) detectOS(body string) string {
	// Check Linux indicators
	for _, keyword := range ra.linuxKeywords {
		if strings.Contains(body, keyword) {
			return "linux"
		}
	}

	// Check Windows indicators
	for _, keyword := range ra.windowsKeywords {
		if strings.Contains(body, keyword) {
			return "windows"
		}
	}

	return "unknown"
}

// detectErrors finds error patterns in response
func (ra *ResponseAnalyzer) detectErrors(body string) *ErrorPattern {
	for _, pattern := range ra.errorPatterns {
		if pattern.Regex.MatchString(body) {
			return pattern
		}
	}
	return nil
}

// identifyFiles attempts to identify which files were read
func (ra *ResponseAnalyzer) identifyFiles(keywords []string) []string {
	files := make([]string, 0)

	for _, keyword := range keywords {
		switch keyword {
		case "root:", "daemon:", "www-data:", "nobody:", "mysql:", "postgres:":
			files = append(files, "/etc/passwd")
		case "/bin/bash", "/bin/sh":
			files = append(files, "/etc/passwd", "/etc/shell")
		case "[boot loader]", "Microsoft Windows":
			files = append(files, "C:\\boot.ini", "C:\\Windows\\System32\\config\\SYSTEM")
		case "[extensions]":
			files = append(files, "C:\\boot.ini")
		}
	}

	return files
}

// IsFileInclusion checks if response indicates file inclusion vs reflection
func (ra *ResponseAnalyzer) IsFileInclusion(payload string, response *Response) bool {
	// If payload appears exactly in response, it's likely reflection
	if strings.Contains(response.Body, payload) {
		return false
	}

	// Check for any known file content
	keywords := ra.detectKeywords(response.Body)
	return len(keywords) > 0
}

// SetBaseline sets the baseline response for comparison
func (ra *ResponseAnalyzer) SetBaseline(response *Response) {
	ra.baselineLength = response.Length
	ra.baselineHash = response.MD5
}

// DetectBlindLFI detects blind LFI using timing analysis
func (ra *ResponseAnalyzer) DetectBlindLFI(baselineTime, testTime time.Duration, response *Response) bool {
	// If response time is significantly longer, might be blind LFI
	timingThreshold := baselineTime * 3 // 3x baseline is suspicious

	// Also check for error patterns that indicate blind inclusion
	errResult := ra.detectErrors(response.Body)
	if errResult != nil && testTime > timingThreshold {
		return true
	}

	return false
}

// AnalyzeWithTiming analyzes response with timing information
func (ra *ResponseAnalyzer) AnalyzeWithTiming(baseline, response *Response, baselineTime, testTime time.Duration) *AnalysisResult {
	result := ra.Analyze(baseline, response)
	result.TimingDelta = testTime - baselineTime

	// Check for blind LFI
	if !result.IsVulnerable && result.TimingDelta > baselineTime*2 {
		result.IsBlind = ra.DetectBlindLFI(baselineTime, testTime, response)
		if result.IsBlind {
			result.Confidence = 0.6
			result.Severity = SeverityMedium
		}
	}

	return result
}

// ReduceFalsePositives reduces false positives using multiple checks
func (ra *ResponseAnalyzer) ReduceFalsePositives(payload string, baseline, response *Response) bool {
	// Check 1: If payload appears in response, it's likely reflection
	if strings.Contains(response.Body, payload) {
		return false
	}

	// Check 2: If response is identical to baseline, no change occurred
	if response.MD5 == baseline.MD5 {
		return false
	}

	// Check 3: Check for error patterns (might be false positive)
	errResult := ra.detectErrors(response.Body)
	if errResult != nil {
		// Error found - check if it's a real vulnerability
		// by looking for file content keywords
		keywords := ra.detectKeywords(response.Body)
		if len(keywords) == 0 {
			// Only error, no file content - likely false positive
			return false
		}
	}

	return true
}

// DetectPHPVersion attempts to detect PHP version from response
func (ra *ResponseAnalyzer) DetectPHPVersion(body string) string {
	// Common PHP version indicators
	patterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"php8", regexp.MustCompile(`PHP/8\.\d+`)},
		{"php7", regexp.MustCompile(`PHP/7\.\d+`)},
		{"php5", regexp.MustCompile(`PHP/5\.\d+`)},
	}

	for _, p := range patterns {
		if p.re.FindString(body) != "" {
			return p.name
		}
	}

	return "unknown"
}
