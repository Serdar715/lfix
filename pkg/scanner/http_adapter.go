package scanner

import (
	"io"
	"net/http"
)

// HTTPAdapter implements the exploit.HTTPClientInterface
type HTTPAdapter struct {
	client *http.Client
}

// NewHTTPAdapter creates a new HTTP adapter
func NewHTTPAdapter(client *http.Client) *HTTPAdapter {
	return &HTTPAdapter{client: client}
}

// GetWithHeader performs a GET request with custom header
func (a *HTTPAdapter) GetWithHeader(targetURL, headerName, headerValue string) (string, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", err
	}

	if headerName != "" && headerValue != "" {
		req.Header.Set(headerName, headerValue)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// PostWithHeader performs a POST request with custom header
func (a *HTTPAdapter) PostWithHeader(targetURL, data, headerName, headerValue string) (string, error) {
	req, err := http.NewRequest("POST", targetURL, nil)
	if err != nil {
		return "", err
	}

	if headerName != "" && headerValue != "" {
		req.Header.Set(headerName, headerValue)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
