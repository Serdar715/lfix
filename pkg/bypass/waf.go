package bypass

import (
	"fmt"
	"math/rand"
	"time"
)

// =============================================================================
// WAF BYPASS - 3 FARKLI YAKLAŞIM
// =============================================================================

// WAFBypassMode defines the bypass strategy
type WAFBypassMode string

const (
	ModeSimple       WAFBypassMode = "simple"
	ModePerformant   WAFBypassMode = "performant"
	ModeMaintainable WAFBypassMode = "maintainable"
)

// =============================================================================
// APPROACH 1: BASIT (Quick Fix - Mutations Only)
// =============================================================================

type SimpleWAFBypass struct{}

func NewSimpleWAFBypass() *SimpleWAFBypass {
	return &SimpleWAFBypass{}
}

func (s *SimpleWAFBypass) GetPayloads(basePayload string) []string {
	return []string{
		basePayload,
		urlEncode(basePayload),
		urlEncode(urlEncode(basePayload)),
		basePayload + "%00",
	}
}

// =============================================================================
// APPROACH 2: PERFORMANT (Adaptive Timing + WAF Detection)
// =============================================================================

type PerformantWAFBypass struct {
	baseDelay   time.Duration
	jitterRange time.Duration
}

func NewPerformantWAFBypass() *PerformantWAFBypass {
	return &PerformantWAFBypass{
		baseDelay:   100 * time.Millisecond,
		jitterRange: 200 * time.Millisecond,
	}
}

func (p *PerformantWAFBypass) GetNextDelay() time.Duration {
	jitter := time.Duration(rand.Int63n(int64(p.jitterRange)))
	return p.baseDelay + jitter
}

func (p *PerformantWAFBypass) DetectWAFStatus(code int, body string) bool {
	blocked := []int{403, 429, 503, 405}
	for _, c := range blocked {
		if code == c {
			return true
		}
	}
	return false
}

func (p *PerformantWAFBypass) GetBackoffDelay(attempt int) time.Duration {
	delay := p.baseDelay * time.Duration(1<<attempt)
	if delay > 5*time.Second {
		delay = 5 * time.Second
	}
	return delay + time.Duration(rand.Int63n(int64(p.jitterRange)))
}

func (p *PerformantWAFBypass) GetPayloads(basePayload string) []string {
	return []string{
		basePayload,
		urlEncode(basePayload),
		doubleEncode(basePayload),
		basePayload + "%00",
		encodeOverlong(basePayload),
	}
}

// =============================================================================
// APPROACH 3: MAINTAINABLE (Full Feature - WAF Detection + Rotation)
// =============================================================================

type MaintainableWAFBypass struct {
	encoder     *EncodingManager
	userAgents  []string
	currentUA   int
	wafDetected bool
	wafType     string
}

func NewMaintainableWAFBypass() *MaintainableWAFBypass {
	return &MaintainableWAFBypass{
		encoder: NewEncodingManager(),
		userAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Mozilla/5.0 (compatible; Googlebot/2.1)",
			"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0",
			"curl/7.88.1",
			"wget/1.21.3",
		},
	}
}

func (m *MaintainableWAFBypass) GetNextUserAgent() string {
	agent := m.userAgents[m.currentUA]
	m.currentUA = (m.currentUA + 1) % len(m.userAgents)
	return agent
}

func (m *MaintainableWAFBypass) DetectWAF(headers, body string) (bool, string) {
	signatures := map[string][]string{
		"cloudflare": {"cf-ray", "cf-cache-status"},
		"akamai":     {"akamai", "incapsula"},
		"aws":        {"x-amz-cf-id"},
		"imperva":    {"incapsula", "visid_incap"},
		"modsec":     {"mod_security", "modsecurity"},
	}

	combined := headers + body
	for name, sigs := range signatures {
		for _, sig := range sigs {
			if contains(combined, sig) {
				m.wafDetected = true
				m.wafType = name
				return true, name
			}
		}
	}
	return false, ""
}

func (m *MaintainableWAFBypass) IsBlocked(code int, body string) bool {
	if code == 403 || code == 405 || code == 429 || code == 503 {
		return true
	}
	patterns := []string{"blocked", "forbidden", "security", "waf", "firewall"}
	for _, p := range patterns {
		if contains(body, p) {
			return true
		}
	}
	return false
}

func (m *MaintainableWAFBypass) GetPayloads(basePayload string) []string {
	encodings := []EncodingType{
		NoEncoding,
		URLEncoding,
		DoubleURLEncoding,
		NullByte,
		OverlongUTF8,
	}

	result := []string{basePayload}
	for _, enc := range encodings {
		if enc != NoEncoding {
			result = append(result, m.encoder.Encode(basePayload, enc))
		}
	}
	return result
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func urlEncode(s string) string {
	result := ""
	for _, c := range s {
		if c == '.' || c == '/' || c == '\\' || c == ':' {
			result += fmt.Sprintf("%%%02x", c)
		} else {
			result += string(c)
		}
	}
	return result
}

func doubleEncode(s string) string {
	return urlEncode(urlEncode(s))
}

func encodeOverlong(s string) string {
	result := ""
	for _, c := range s {
		if c == '/' {
			result += "%c0%af"
		} else if c == '.' {
			result += "%c0%2e"
		} else if c == '\\' {
			result += "%c0%5c"
		} else {
			result += string(c)
		}
	}
	return result
}

func contains(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// FACTORY
// =============================================================================

type WAFBypasser interface {
	GetPayloads(string) []string
}

func NewWAFBypass(mode WAFBypassMode) WAFBypasser {
	switch mode {
	case ModeSimple:
		return NewSimpleWAFBypass()
	case ModePerformant:
		return NewPerformantWAFBypass()
	case ModeMaintainable:
		return NewMaintainableWAFBypass()
	default:
		return NewSimpleWAFBypass()
	}
}

func GetModeByName(name string) WAFBypassMode {
	switch name {
	case "simple":
		return ModeSimple
	case "performant":
		return ModePerformant
	case "maintainable":
		return ModeMaintainable
	default:
		return ModeSimple
	}
}
