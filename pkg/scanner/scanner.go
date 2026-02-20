package scanner

import (
	"crypto/tls"
	"github.com/Serdar715/lfix/pkg/engine"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Options holds the configuration for the scanner.
type Options struct {
	Concurrency int
	Timeout     int
	Proxy       string
	UseMutation bool
	Calibrate   bool
	Debug       bool
	// Note: Other options like targets, payloads, etc., will be passed directly to Start/GenerateTasks
}

// Scanner is the main struct that orchestrates the scanning process.
type Scanner struct {
	Client        *http.Client
	Options       Options
	BaselineCache sync.Map
	userAgents    []string
}

// NewScanner creates a new scanner instance with the given options.
func NewScanner(opts Options) *Scanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
		Client:  client,
		Options: opts,
		userAgents: []string{ // This could be externalized later
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			"Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
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

		req, err := http.NewRequest(task.Method, task.URL, strings.NewReader(task.PostData))
		if err != nil {
			continue
		}

		// Set a random User-Agent
		if len(s.userAgents) > 0 {
			req.Header.Set("User-Agent", s.userAgents[rand.Intn(len(s.userAgents))])
		}
		// Set Content-Type for POST requests if not a JSON-like body
		if task.Method == "POST" && !strings.Contains(task.PostData, "{") {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		// Add custom headers
		for k, v := range task.Headers {
			req.Header.Set(k, v)
		}

		resp, err := s.Client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		if finding := engine.AnalyzeResponse(string(body), baselineBody, task); finding != nil {
			findings <- *finding
		}
	}
}

// getBaseline fetches the original response for a URL to compare against for calibration.
func (s *Scanner) getBaseline(task engine.Task) string {
	u, err := url.Parse(task.URL)
	if err != nil {
		return ""
	}
	baseKey := u.Scheme + "://" + u.Host + u.Path

	if cached, ok := s.BaselineCache.Load(baseKey); ok {
		return cached.(string)
	}

	req, err := http.NewRequest(task.Method, baseKey, nil) // Use a clean request
	if err != nil {
		return ""
	}
	if len(s.userAgents) > 0 {
		req.Header.Set("User-Agent", s.userAgents[rand.Intn(len(s.userAgents))])
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		s.BaselineCache.Store(baseKey, "")
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.BaselineCache.Store(baseKey, "")
		return ""
	}

	baselineStr := string(body)
	s.BaselineCache.Store(baseKey, baselineStr)
	return baselineStr
}
