package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"github.com/Serdar715/lfix/pkg/scanner"
	"math/rand"
	"os"
	"strings"
	"time"
)

const (
	AppName    = "lfix"
	Version    = "2.0.0"
	TimeFormat = "15:04:05"
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorCyan   = "\033[36m"
)

type cliOptions struct {
	SingleURL, ListFile, PayloadFile, OutputFile, PostData, Method, TargetHeader, StaticHeader, Proxy string
	Concurrency, Timeout int
	Verbose, Debug, UseMutation, Calibrate bool
}

func main() {
	printBanner()
	rand.Seed(time.Now().UnixNano())

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

	staticHeaders := parseHeaderString(opts.StaticHeader)
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
	flag.StringVar(&o.PayloadFile, "p", "", "Payload file")
	flag.StringVar(&o.OutputFile, "o", "", "Output file")
	flag.StringVar(&o.PostData, "data", "", "POST Body")
	flag.StringVar(&o.Method, "X", "GET", "HTTP Method")
	flag.StringVar(&o.TargetHeader, "H", "", "Header to attack")
	flag.StringVar(&o.StaticHeader, "header", "", "Static header")
	flag.StringVar(&o.Proxy, "proxy", "", "Proxy URL")
	flag.IntVar(&o.Concurrency, "c", 30, "Concurrency")
	flag.IntVar(&o.Timeout, "t", 7, "Timeout")
	flag.BoolVar(&o.Verbose, "v", false, "Verbose")
	flag.BoolVar(&o.Debug, "debug", false, "Debug")
	flag.BoolVar(&o.UseMutation, "mutate", true, "Enable/disable mutation")
	flag.BoolVar(&o.Calibrate, "calibrate", true, "Enable/disable calibration")
	flag.Parse()
	return o
}

func loadTargets(singleURL, listFile string) []string {
	var targets []string
	if singleURL != "" {
		targets = append(targets, singleURL)
	} else {
		var s *bufio.Scanner
		if listFile != "" {
			f, err := os.Open(listFile)
			if err != nil {
				logError("Could not open target file: %v", err)
				return targets
			}
			defer f.Close()
			s = bufio.NewScanner(f)
		} else {
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				s = bufio.NewScanner(os.Stdin)
			} else {
				return targets
			}
		}
		for s.Scan() {
			t := strings.TrimSpace(s.Text())
			if t != "" {
				targets = append(targets, t)
			}
		}
	}
	return targets
}

//go:embed payload.txt
var embeddedPayloads string

func loadPayloads(filename string) []string {
	var payloads []string
	var s *bufio.Scanner

	if filename != "" {
		f, err := os.Open(filename)
		if err != nil {
			logError("Could not open payload file: %v", err)
			s = bufio.NewScanner(strings.NewReader(embeddedPayloads))
		} else {
			defer f.Close()
			s = bufio.NewScanner(f)
		}
	} else {
		s = bufio.NewScanner(strings.NewReader(embeddedPayloads))
	}

	for s.Scan() {
		t := strings.TrimSpace(s.Text())
		if t != "" {
			payloads = append(payloads, t)
		}
	}
	return payloads
}

func parseHeaderString(h string) map[string]string {
	m := make(map[string]string)
	if h != "" {
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
	banner := fmt.Sprintf("%s LFix v%s - Refactored LFI Scanner %s", ColorCyan, Version, ColorReset)
	fmt.Println(banner)
}