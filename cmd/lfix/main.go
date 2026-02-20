package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

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
)

// stringSliceFlag implements flag.Value for repeated -header flags.
// Usage: -header "Key: Value" -header "Other: Value"
type stringSliceFlag []string

func (s *stringSliceFlag) String() string     { return strings.Join(*s, ", ") }
func (s *stringSliceFlag) Set(v string) error { *s = append(*s, v); return nil }

type cliOptions struct {
	SingleURL, ListFile, PayloadFile, OutputFile string
	PostData, Method, TargetHeader, Proxy        string
	StaticHeaders                                stringSliceFlag
	Concurrency, Timeout                         int
	Verbose, Debug, UseMutation, Calibrate       bool
}

func main() {
	printBanner()
	// Note: rand.Seed is intentionally omitted — Go 1.20+ seeds the global
	// source automatically with a random value at program startup.

	opts := parseFlags()

	var outFile *os.File
	if opts.OutputFile != "" {
		f, err := os.OpenFile(opts.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logError("File error: %v", err)
			return
		}
		defer f.Close()
		outFile = f
	}

	targets := loadTargets(opts.SingleURL, opts.ListFile)
	if len(targets) == 0 {
		logError("Please provide a target (-u, -l, or piped from STDIN)")
		os.Exit(1)
	}

	payloads := loadPayloads(opts.PayloadFile)

	fmt.Printf("%s[+] Method: %s | Workers: %d | Targets: %d | Payloads: %d%s\n\n",
		ColorCyan, opts.Method, opts.Concurrency, len(targets), len(payloads), ColorReset)

	scannerOpts := scanner.Options{
		Concurrency: opts.Concurrency,
		Timeout:     opts.Timeout,
		Proxy:       opts.Proxy,
		UseMutation: opts.UseMutation,
		Calibrate:   opts.Calibrate,
		Debug:       opts.Debug,
	}
	s := scanner.NewScanner(scannerOpts)

	staticHeaders := parseHeaderSlice(opts.StaticHeaders)
	findings := s.Start(targets, payloads, opts.PostData, opts.Method, opts.TargetHeader, staticHeaders)

	found := false
	for finding := range findings {
		found = true
		output := fmt.Sprintf("%s[VULN] [%s] Found: %s\n    URL: %s\n    Payload: %s%s",
			ColorRed, finding.Task.InjectionPoint, finding.MatchInfo, finding.Task.URL, finding.Task.Payload, ColorReset)
		fmt.Println("\n" + output)

		if outFile != nil {
			outFile.WriteString(fmt.Sprintf("[%s] TYPE: %s | URL: %s | PAYLOAD: %s | MATCH: %s\n",
				time.Now().Format(TimeFormat), finding.Task.InjectionPoint, finding.Task.URL, finding.Task.Payload, finding.MatchInfo))
		}
	}

	if !found {
		fmt.Println(ColorGreen + "[+] Scan complete. No vulnerabilities found." + ColorReset)
	} else {
		fmt.Println("\n" + ColorGreen + "[+] Scan complete." + ColorReset)
	}
}

func parseFlags() cliOptions {
	o := cliOptions{}
	flag.StringVar(&o.SingleURL, "u", "", "Target URL")
	flag.StringVar(&o.ListFile, "l", "", "Target list file")
	flag.StringVar(&o.PayloadFile, "p", "", "Payload file (default: built-in)")
	flag.StringVar(&o.OutputFile, "o", "", "Output file")
	flag.StringVar(&o.PostData, "data", "", "POST body data")
	flag.StringVar(&o.Method, "X", "GET", "HTTP method")
	flag.StringVar(&o.TargetHeader, "H", "", "Header to inject payload into (e.g. 'X-Path: FUZZ')")
	flag.StringVar(&o.Proxy, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	flag.IntVar(&o.Concurrency, "c", 30, "Number of concurrent workers")
	flag.IntVar(&o.Timeout, "t", 7, "HTTP timeout in seconds")
	flag.BoolVar(&o.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&o.Debug, "debug", false, "Debug output")
	flag.BoolVar(&o.UseMutation, "mutate", true, "Enable WAF bypass mutations")
	flag.BoolVar(&o.Calibrate, "calibrate", true, "Enable baseline calibration")
	// -header can be specified multiple times: -header "Key: Val" -header "Key2: Val2"
	flag.Var(&o.StaticHeaders, "header", "Static request header (repeatable: -header 'K: V')")
	flag.Parse()
	return o
}

func loadTargets(singleURL, listFile string) []string {
	var targets []string
	if singleURL != "" {
		return append(targets, singleURL)
	}

	var sc *bufio.Scanner
	if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			logError("Could not open target file: %v", err)
			return targets
		}
		defer f.Close()
		sc = bufio.NewScanner(f)
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			sc = bufio.NewScanner(os.Stdin)
		} else {
			return targets
		}
	}

	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t != "" {
			targets = append(targets, t)
		}
	}
	return targets
}

//go:embed payload.txt
var embeddedPayloads string

func loadPayloads(filename string) []string {
	var sc *bufio.Scanner

	if filename != "" {
		f, err := os.Open(filename)
		if err != nil {
			logError("Could not open payload file, using built-in: %v", err)
			sc = bufio.NewScanner(strings.NewReader(embeddedPayloads))
		} else {
			defer f.Close()
			sc = bufio.NewScanner(f)
		}
	} else {
		sc = bufio.NewScanner(strings.NewReader(embeddedPayloads))
	}

	var payloads []string
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t != "" {
			payloads = append(payloads, t)
		}
	}
	return payloads
}

// parseHeaderSlice converts repeated -header "Key: Value" flags into a map.
func parseHeaderSlice(headers stringSliceFlag) map[string]string {
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
