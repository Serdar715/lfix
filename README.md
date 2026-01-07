<p align="center">
  <img src="https://img.shields.io/badge/Go-1.18+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20|%20macOS-blue?style=for-the-badge" alt="Platform"/>
  <img src="https://img.shields.io/badge/Version-1.0.0-red?style=for-the-badge" alt="Version"/>
</p>

<h1 align="center">🔥 LFix - Advanced LFI Vulnerability Scanner</h1>

<p align="center">
  <b>A blazing-fast, concurrent Local File Inclusion (LFI) vulnerability scanner with WAF bypass capabilities</b>
</p>

---

## 🎯 Overview

**LFix** is a powerful command-line security tool designed to detect Local File Inclusion (LFI) vulnerabilities in web applications. Built with Go for maximum performance, it features concurrent scanning, intelligent payload mutation for WAF bypass, and comprehensive signature-based detection.

### ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🚀 **High Performance** | Concurrent scanning with configurable worker threads |
| 🛡️ **WAF Bypass** | Intelligent payload mutation techniques (URL encoding, double encoding, null byte injection) |
| 🎯 **Multi-Vector Injection** | URL parameters, POST data, and HTTP headers |
| 🔍 **Smart Detection** | Signature-based analysis including Base64-encoded responses |
| 🌐 **Proxy Support** | Route traffic through HTTP/SOCKS proxies |
| 📝 **Flexible Input** | Single URL, file list, or stdin piping |
| 🎭 **Stealth Mode** | Random User-Agent rotation with 30+ agents |
| 📊 **Detailed Output** | Verbose logging and file export options |

---

## 📥 Installation

### Requirements

- **Go 1.18+** must be installed on your system

### Step 1: Install Go (if not installed)

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install golang-go -y

# Fedora
sudo dnf install golang -y

# Arch Linux
sudo pacman -S go --noconfirm
```

### Step 2: Clone and Build

```bash
git clone https://github.com/Serdar715/lfix.git && cd lfix && go build -o lfix lfix.go && chmod +x lfix
```

### Step 3: Add to PATH (Optional but Recommended)

```bash
sudo mv lfix /usr/local/bin/
```

### Step 4: Verify Installation

```bash
lfix -h
```

---

## 🚀 Quick Start

### Basic Usage

```bash
# Scan a single URL
lfix -u "http://target.com/page.php?file=test"

# Scan multiple URLs from file
lfix -l urls.txt

# Pipe URLs from stdin
cat urls.txt | lfix

# Using with custom payloads
lfix -u "http://target.com/page.php?file=test" -p payloads.txt
```

### Advanced Examples

```bash
# POST request with data injection
lfix -u "http://target.com/api" -X POST -data "filename=FUZZ"

# Header injection testing
lfix -u "http://target.com/" -H "X-File: FUZZ"

# Multiple workers with proxy
lfix -l urls.txt -c 50 -proxy "http://127.0.0.1:8080"

# Save results to file
lfix -u "http://target.com/page.php?file=test" -o results.txt

# Verbose mode with debugging
lfix -u "http://target.com/page.php?file=test" -v -debug
```

---

## 📖 Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Single target URL | - |
| `-l` | File containing list of URLs | - |
| `-p` | Custom payload file | Built-in payloads |
| `-o` | Output file for results | - |
| `-X` | HTTP method (GET/POST) | `GET` |
| `-data` | POST request body | - |
| `-H` | Target header for injection | - |
| `-header` | Static header to include | - |
| `-proxy` | Proxy URL (HTTP/SOCKS) | - |
| `-c` | Number of concurrent workers | `30` |
| `-t` | Request timeout (seconds) | `7` |
| `-v` | Verbose output | `false` |
| `-debug` | Debug mode | `false` |
| `-mutate` | Enable payload mutations | `true` |

### Using FUZZ Keyword

```bash
# URL parameter fuzzing
lfix -u "http://target.com/page.php?file=FUZZ"

# POST body fuzzing
lfix -u "http://target.com/api" -X POST -data "path=FUZZ&action=read"

# Header value fuzzing
lfix -u "http://target.com/" -H "X-Include-File: FUZZ"
```

---

## 🔍 Detection Capabilities

### Signature Categories

#### 🐧 Linux/Unix Signatures
- `/etc/passwd` content patterns (`root:x:0:0`, `daemon:x:`, `www-data:x:`)
- Shell path references (`/bin/bash`, `/bin/sh`)
- SSH key patterns (`ssh-rsa`)

#### 💻 Windows Signatures
- `win.ini` content patterns (`[boot loader]`, `[fonts]`)
- System file references

#### ⚠️ Application Error Patterns
- PHP errors (`Warning: include(`, `failed to open stream`)
- Java exceptions (`java.io.FileNotFoundException`)
- Source code leakage (`<?php`)

#### 🔐 Base64-Encoded Responses
Automatically detects and decodes Base64 content in responses.

---

## 🛡️ WAF Bypass Techniques

| Technique | Example |
|-----------|---------|
| Original | `../../../etc/passwd` |
| URL Encoding | `..%2F..%2F..%2Fetc%2Fpasswd` |
| Double Encoding | `..%252F..%252F..%252Fetc%252Fpasswd` |
| Null Byte Injection | `../../../etc/passwd%00` |
| Path Filter Bypass | `....//....//....//etc/passwd` |

---

## 🤝 Integration Examples

```bash
# Combine with waybackurls
waybackurls target.com | grep "=" | lfix

# Combine with gau
gau target.com | grep "file=" | lfix

# Combine with httpx
cat domains.txt | httpx -paths /page.php?file=test | lfix

# Use with Burp Suite proxy
lfix -u "http://target.com/page.php?file=test" -proxy "http://127.0.0.1:8080"
```

---

## 📊 Sample Output

```
  ██╗     ███████╗██╗██╗  ██╗
  ██║     ██╔════╝██║╚██╗██╔╝
  ██║     █████╗  ██║ ╚███╔╝
  ██║     ██╔══╝  ██║ ██╔██╗
  ███████╗██║     ██║██╔╝ ██╗
  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝
  lfix v1.0.0 - Advanced LFI Scanner

[+] Mod: GET | Workers: 30 | Targets: 1 | Payloads: 5

[VULN] [URL_file] Found: root:x:0:0
    URL: http://target.com/page.php?file=../../../../etc/passwd
    Payload: ../../../../etc/passwd

[+] Tarama Tamamlandı.
```

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. 

- ✅ Only use on systems you have explicit permission to test
- ✅ Follow responsible disclosure practices
- ❌ Do not use for malicious purposes
- ❌ Do not test systems without proper authorization

The developers assume no liability for misuse of this software.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

---

<p align="center">
  <b>Made with ❤️ for the Security Community</b>
</p>

<p align="center">
  <a href="https://github.com/Serdar715/lfix/issues">Report Bug</a>
  ·
  <a href="https://github.com/Serdar715/lfix/issues">Request Feature</a>
</p>
