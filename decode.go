package caddyguard

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// jsUnicodeRe matches \uXXXX (4 hex digits)
var jsUnicodeRe = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)

// jsUnicodeBraceRe matches \u{XXXXXX} (1-6 hex digits)
var jsUnicodeBraceRe = regexp.MustCompile(`\\u\{([0-9a-fA-F]{1,6})\}`)

// jsHexRe matches \xHH (2 hex digits)
var jsHexRe = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// htmlHexEntityRe matches &#xHH; or &#xHHH; (2-4 hex digits)
var htmlHexEntityRe = regexp.MustCompile(`&#x([0-9a-fA-F]{2,4});`)

// htmlDecEntityRe matches &#DDD; (2-3 decimal digits)
var htmlDecEntityRe = regexp.MustCompile(`&#(\d{2,3});`)

// hasEncodeMarkers checks if the string contains any encoding markers.
// This is the fast path: normal traffic (no % \u \x &#) costs zero decode overhead.
// Corresponds to Lua's has_encode_markers function.
func hasEncodeMarkers(s string) bool {
	if s == "" {
		return false
	}
	return strings.Contains(s, "%") ||
		strings.Contains(s, "\\u") ||
		strings.Contains(s, "\\x") ||
		strings.Contains(s, "&#")
}

// fullDecode performs recursive URL-decode + JS unicode/entity decode in one pass.
// This corresponds to Lua's full_decode function in access.lua.
//
// Step 1: recursive URL-decode (only if '%' present, up to 8 iterations)
// Step 2: JS unicode/hex/entity decode (only if markers present)
//
// Returns: decoded string, true if any decoding happened
func fullDecode(s string) (string, bool) {
	if s == "" {
		return s, false
	}

	changed := false

	// Step 1: recursive URL-decode (only if '%' present)
	if strings.Contains(s, "%") {
		prev := s
		for i := 0; i < 8; i++ {
			decoded, err := url.QueryUnescape(prev)
			if err != nil || decoded == prev {
				break
			}
			prev = decoded
			changed = true
		}
		s = prev
	}

	// Step 2: JS unicode/hex/entity decode (only if markers present)
	hasJS := strings.Contains(s, "\\u") ||
		strings.Contains(s, "\\x") ||
		strings.Contains(s, "&#")

	if hasJS {
		before := s

		// \u{XXXXXX} → char
		s = jsUnicodeBraceRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := jsUnicodeBraceRe.FindStringSubmatch(m)
			if len(sub) < 2 {
				return m
			}
			code, err := strconv.ParseInt(sub[1], 16, 32)
			if err != nil || code < 32 || code > 126 {
				return m
			}
			return string(rune(code))
		})

		// \uXXXX → char
		s = jsUnicodeRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := jsUnicodeRe.FindStringSubmatch(m)
			if len(sub) < 2 {
				return m
			}
			code, err := strconv.ParseInt(sub[1], 16, 32)
			if err != nil || code < 32 || code > 126 {
				return m
			}
			return string(rune(code))
		})

		// \xHH → char
		s = jsHexRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := jsHexRe.FindStringSubmatch(m)
			if len(sub) < 2 {
				return m
			}
			code, err := strconv.ParseInt(sub[1], 16, 32)
			if err != nil || code < 32 || code > 126 {
				return m
			}
			return string(rune(code))
		})

		// &#xHH; → char (case insensitive)
		s = htmlHexEntityRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := htmlHexEntityRe.FindStringSubmatch(m)
			if len(sub) < 2 {
				return m
			}
			code, err := strconv.ParseInt(sub[1], 16, 32)
			if err != nil || code < 32 || code > 126 {
				return m
			}
			return string(rune(code))
		})

		// &#DDD; → char
		s = htmlDecEntityRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := htmlDecEntityRe.FindStringSubmatch(m)
			if len(sub) < 2 {
				return m
			}
			code, err := strconv.Atoi(sub[1])
			if err != nil || code < 32 || code > 126 {
				return m
			}
			return string(rune(code))
		})

		if s != before {
			changed = true
		}
	}

	return s, changed
}
