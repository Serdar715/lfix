package core

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient wraps HTTP operations
type HTTPClient struct {
	client *http.Client
	Proxy  string
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       string
	Length     int
	MD5        string
	Time       time.Duration
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient() *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// NewHTTPClientWithProxy creates HTTP client with proxy support
func NewHTTPClientWithProxy(proxyURL string) *HTTPClient {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if proxyURL != "" {
		if proxy, err := url.Parse(proxyURL); err == nil {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxy)}
		}
	}

	return &HTTPClient{
		client: client,
		Proxy:  proxyURL,
	}
}

// Get performs a GET request
func (c *HTTPClient) Get(targetURL string) (*Response, error) {
	start := time.Now()
	resp, err := c.client.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(body),
		Length:     len(body),
		MD5:        fmt.Sprintf("%x", md5.Sum(body)),
		Time:       time.Since(start),
	}, nil
}

// SendParameter sends a parameter with a payload
func (c *HTTPClient) SendParameter(targetURL, paramName, payload string, paramType ParameterType) (*Response, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	if paramType == GET {
		query.Set(paramName, payload)
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	if paramType == POST {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = url.Values{
			paramName: []string{payload},
		}
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(body),
		Length:     len(body),
		MD5:        fmt.Sprintf("%x", md5.Sum(body)),
		Time:       time.Since(start),
	}, nil
}

// SendWithHeaders sends a request with custom headers
func (c *HTTPClient) SendWithHeaders(targetURL, paramName, payload string, headers map[string]string) (*Response, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	query.Set(paramName, payload)
	u.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(body),
		Length:     len(body),
		MD5:        fmt.Sprintf("%x", md5.Sum(body)),
		Time:       time.Since(start),
	}, nil
}

// PostData sends POST data
func (c *HTTPClient) PostData(targetURL, data string) (*Response, error) {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(body),
		Length:     len(body),
		MD5:        fmt.Sprintf("%x", md5.Sum(body)),
		Time:       time.Since(start),
	}, nil
}

// SendJSON sends JSON body data
func (c *HTTPClient) SendJSON(targetURL, jsonData string) (*Response, error) {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	acceptHeader := "application/json"
	req.Header.Set("Accept", acceptHeader)

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(body),
		Length:     len(body),
		MD5:        fmt.Sprintf("%x", md5.Sum(body)),
		Time:       time.Since(start),
	}, nil
}

// SendWithCookies sends request with cookies
func (c *HTTPClient) SendWithCookies(targetURL, paramName, payload string, cookies map[string]string) (*Response, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	query.Set(paramName, payload)
	u.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	// Set cookies
	for name, value := range cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(body),
		Length:     len(body),
		MD5:        fmt.Sprintf("%x", md5.Sum(body)),
		Time:       time.Since(start),
	}, nil
}

// SendWithJSONBody sends request with JSON body containing payload
func (c *HTTPClient) SendWithJSONBody(targetURL, paramName, payload string) (*Response, error) {
	// Create JSON body with payload
	jsonBody := map[string]string{
		paramName: payload,
	}
	jsonData, err := json.Marshal(jsonBody)
	if err != nil {
		return nil, err
	}

	return c.SendJSON(targetURL, string(jsonData))
}
