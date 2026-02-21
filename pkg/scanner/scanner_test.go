package scanner

import (
	"testing"
	"time"
)

// TestStatisticsIncrement tests thread-safe statistics incrementing
func TestStatisticsIncrement(t *testing.T) {
	stats := NewStatistics()

	// Test incrementing requests
	stats.IncrementRequests()
	stats.IncrementRequests()

	targets, payloads, requests, findings, errors, _ := stats.Get()
	if requests != 2 {
		t.Errorf("Expected 2 requests, got %d", requests)
	}

	// Test incrementing findings
	stats.IncrementFindings()
	_, _, _, findings, _, _ = stats.Get()
	if findings != 1 {
		t.Errorf("Expected 1 finding, got %d", findings)
	}

	// Test incrementing errors
	stats.IncrementErrors()
	_, _, _, _, errors, _ = stats.Get()
	if errors != 1 {
		t.Errorf("Expected 1 error, got %d", errors)
	}

	// Test setting targets
	stats.SetTargets(5, 100)
	targets, payloads, _, _, _, _ = stats.Get()
	if targets != 5 || payloads != 100 {
		t.Errorf("Expected targets=5, payloads=100, got targets=%d, payloads=%d", targets, payloads)
	}
}

// TestStatisticsConcurrent tests concurrent access to statistics
func TestStatisticsConcurrent(t *testing.T) {
	stats := NewStatistics()
	done := make(chan bool)

	// Run 100 goroutines incrementing concurrently
	for i := 0; i < 100; i++ {
		go func() {
			stats.IncrementRequests()
			stats.IncrementFindings()
			stats.IncrementErrors()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	_, _, requests, findings, errors, _ := stats.Get()
	if requests != 100 {
		t.Errorf("Expected 100 requests, got %d", requests)
	}
	if findings != 100 {
		t.Errorf("Expected 100 findings, got %d", findings)
	}
	if errors != 100 {
		t.Errorf("Expected 100 errors, got %d", errors)
	}
}

// TestStatisticsTime tests elapsed time calculation
func TestStatisticsTime(t *testing.T) {
	stats := NewStatistics()

	time.Sleep(10 * time.Millisecond)

	_, _, _, _, _, elapsed := stats.Get()
	if elapsed < 10*time.Millisecond {
		t.Errorf("Expected elapsed time >= 10ms, got %v", elapsed)
	}
}

// TestNewScannerDefaults tests default values for scanner
func TestNewScannerDefaults(t *testing.T) {
	opts := Options{
		Concurrency: 0, // Should be set to default
		Timeout:     5,
	}

	scanner := NewScanner(opts)

	if scanner.Options.Concurrency != 30 {
		t.Errorf("Expected default concurrency 30, got %d", scanner.Options.Concurrency)
	}
}

// TestNewScannerMaxWorkers tests max worker limit enforcement
func TestNewScannerMaxWorkers(t *testing.T) {
	opts := Options{
		Concurrency: 1000, // Should be capped to 100
		Timeout:     5,
	}

	scanner := NewScanner(opts)

	if scanner.Options.Concurrency != maxWorkers {
		t.Errorf("Expected max workers %d, got %d", maxWorkers, scanner.Options.Concurrency)
	}
}

// TestScannerUserAgentRotation tests thread-safe UA rotation
func TestScannerUserAgentRotation(t *testing.T) {
	opts := Options{
		Concurrency: 10,
		Timeout:     5,
	}

	scanner := NewScanner(opts)

	// Get multiple UAs concurrently
	results := make(chan string, 20)
	done := make(chan bool)

	for i := 0; i < 20; i++ {
		go func() {
			ua := scanner.getNextUserAgent()
			results <- ua
			done <- true
		}()
	}

	// Wait for all
	for i := 0; i < 20; i++ {
		<-done
	}
	close(results)

	// Collect results
	uaCount := make(map[string]int)
	for ua := range results {
		uaCount[ua]++
	}

	// All UAs should be valid
	if len(uaCount) == 0 {
		t.Error("No user agents returned")
	}
}
