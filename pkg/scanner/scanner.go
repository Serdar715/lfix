package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Serdar715/lfix/pkg/engine"
)

const (
	// maxResponseBodySize limits memory usage per response to avoid OOM with large payloads.
	maxResponseBodySize = 2 * 1024 * 1024 // 2 MB
)

// Options holds the configuration for the scanner.
type Options struct {
	Concurrency int
	Timeout     int
	Proxy       string
	UseMutation bool
	Calibrate   bool
	Debug       bool
}

// Scanner is the main struct that orchestrates the scanning process.
type Scanner struct {
	client        *http.Client
	Options       Options
	baselineCache sync.Map
	userAgents    []string
}

// NewScanner creates a new scanner instance with the given options.
func NewScanner(opts Options) *Scanner {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		MaxIdleConnsPerHost: opts.Concurrency,
	}
	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects
		},
	}

	return &Scanner{
		client:  client,
		Options: opts,
		userAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
		},
	}
}

// Start initiates the scanning process.
func (s *Scanner) Start(targets []string, payloads []string, postData, method, targetHeader string, staticHeaders map[string]string) <-chan engine.Finding {
	tasks := make(chan engine.Task, s.Options.Concurrency*2)
	findings := make(chan engine.Finding)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.Options.Concurrency; i++ {
		wg.Add(1)
		go s.worker(tasks, findings, &wg)
	}

	// Dispatcher goroutine: generates tasks and sends them to the workers.
	go func() {
		for _, target := range targets {
			engine.GenerateTasks(target, payloads, postData, method, targetHeader, staticHeaders, s.Options.UseMutation, tasks)
		}
		close(tasks)
	}()

	// Closer goroutine: waits for all workers to finish, then closes the findings channel.
	go func() {
		wg.Wait()
		close(findings)
	}()

	return findings
}

func (s *Scanner) worker(tasks <-chan engine.Task, findings chan<- engine.Finding, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range tasks {
		var baselineBody string
		if s.Options.Calibrate {
			baselineBody = s.getBaseline(task)
		}

		// doRequest encapsulates the HTTP round-trip so defer is scoped correctly.
		body, err := s.doRequest(task.Method, task.URL, task.PostData, task.Headers)
		if err != nil {
			if s.Options.Debug {
				fmt.Printf("[DEBUG] request failed: %v\n", err)
			}
			continue
		}

		if finding := engine.AnalyzeResponse(body, baselineBody, task); finding != nil {
			findings <- *finding
		}
	}
}

// doRequest performs a single HTTP request and returns the response body as a string.
// Body is always closed before returning — safe to call in a loop.
func (s *Scanner) doRequest(method, targetURL, postData string, headers map[string]string) (string, error) {
	req, err := http.NewRequest(method, targetURL, strings.NewReader(postData))
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}

	// Randomize User-Agent to reduce WAF fingerprinting.
	if len(s.userAgents) > 0 {
		req.Header.Set("User-Agent", s.userAgents[rand.Intn(len(s.userAgents))])
	}
	// Set Content-Type for POST requests with form data (not JSON).
	if method == "POST" && postData != "" && !strings.HasPrefix(strings.TrimSpace(postData), "{") {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	// Limit body read to maxResponseBodySize to prevent OOM on large responses.
	limited := io.LimitReader(resp.Body, maxResponseBodySize)
	bodyBytes, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("reading body: %w", err)
	}

	return string(bodyBytes), nil
}

// getBaseline fetches the original response body for a URL to use in calibration.
func (s *Scanner) getBaseline(task engine.Task) string {
	// Strip FUZZ keyword from URL for a clean baseline request.
	cleanURL := strings.ReplaceAll(task.OriginalURL, "FUZZ", "")
	baseKey := cleanURL

	if cached, ok := s.baselineCache.Load(baseKey); ok {
		return cached.(string)
	}

	body, err := s.doRequest(task.Method, cleanURL, "", task.Headers)
	if err != nil {
		// Cache empty string so we don't retry on every task for this URL.
		s.baselineCache.Store(baseKey, "")
		return ""
	}

	s.baselineCache.Store(baseKey, body)
	return body
}
