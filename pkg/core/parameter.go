package core

import (
	"net/url"
	"strings"
)

// ParameterType represents the type of HTTP parameter
type ParameterType int

const (
	GET ParameterType = iota
	POST
	COOKIE
)

// Parameter represents an HTTP parameter
type Parameter struct {
	Name     string
	Value    string
	Type     ParameterType
	Position int
}

// VulnerableParam represents a potentially vulnerable parameter
type VulnerableParam struct {
	Parameter          *Parameter
	Confidence         float64
	TestPayloads       []string
	SuccessfulBypasses []string
}

// ParameterDetector detects vulnerable LFI parameters
type ParameterDetector struct {
	httpClient *HTTPClient
	baseline   *Response
}

// NewParameterDetector creates a new parameter detector
func NewParameterDetector(client *HTTPClient) *ParameterDetector {
	return &ParameterDetector{
		httpClient: client,
	}
}

// ParseURL extracts all parameters from a URL
func (pd *ParameterDetector) ParseURL(targetURL string) ([]*Parameter, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	params := make([]*Parameter, 0)
	queryParams, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}

	pos := 0
	for name, values := range queryParams {
		for _, value := range values {
			params = append(params, &Parameter{
				Name:     name,
				Value:    value,
				Type:     GET,
				Position: pos,
			})
			pos++
		}
	}

	return params, nil
}

// ParseForm parses POST form data
func (pd *ParameterDetector) ParseForm(formData string) ([]*Parameter, error) {
	params := make([]*Parameter, 0)
	formParams, err := url.ParseQuery(formData)
	if err != nil {
		return nil, err
	}

	pos := 0
	for name, values := range formParams {
		for _, value := range values {
			params = append(params, &Parameter{
				Name:     name,
				Value:    value,
				Type:     POST,
				Position: pos,
			})
			pos++
		}
	}

	return params, nil
}

// GetBaseline fetches the baseline response
func (pd *ParameterDetector) GetBaseline(targetURL string) (*Response, error) {
	resp, err := pd.httpClient.Get(targetURL)
	if err != nil {
		return nil, err
	}
	pd.baseline = resp
	return resp, nil
}

// DetectVulnerableParam tests parameters for LFI vulnerabilities
func (pd *ParameterDetector) DetectVulnerableParam(targetURL string, params []*Parameter, testPayloads []string) []*VulnerableParam {
	vulnerable := make([]*VulnerableParam, 0)

	// Get baseline if not exists
	if pd.baseline == nil {
		pd.GetBaseline(targetURL)
	}

	for _, param := range params {
		vp := &VulnerableParam{
			Parameter:    param,
			Confidence:   0.0,
			TestPayloads: testPayloads,
		}

		successCount := 0
		for _, payload := range testPayloads {
			resp, err := pd.httpClient.SendParameter(targetURL, param.Name, payload, param.Type)
			if err != nil {
				continue
			}

			// Analyze response
			analyzer := NewResponseAnalyzer()
			result := analyzer.Analyze(pd.baseline, resp)

			if result.IsVulnerable {
				successCount++
				vp.SuccessfulBypasses = append(vp.SuccessfulBypasses, payload)
			}
		}

		// Calculate confidence
		if len(testPayloads) > 0 {
			vp.Confidence = float64(successCount) / float64(len(testPayloads))
		}

		// If any bypass worked, add to vulnerable list
		if vp.Confidence > 0 {
			vulnerable = append(vulnerable, vp)
		}
	}

	return vulnerable
}

// ExtractParameterName extracts parameter name from URL
func ExtractParameterName(paramString string) string {
	parts := strings.Split(paramString, "=")
	if len(parts) > 0 {
		return parts[0]
	}
	return paramString
}
