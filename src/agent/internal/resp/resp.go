// Package resp parses the leading bytes of a captured Redis RESP request into the
// command verb and the first key/channel — and nothing more.
//
// The parser is the privacy boundary of the agent. A Redis command such as
// `SET key value` carries the business payload in arg2+, so this package reads AT
// MOST the first two arguments (the verb and the first key) and never looks at any
// later argument. The captured kernel buffer is a bounded prefix that may contain
// value bytes from the same TCP segment, but those bytes never leave this package:
// only (verb, firstKey) are returned, and only metadata derived from them reaches
// the EventEnvelope.
package resp

import (
	"bytes"
	"strconv"
	"strings"
)

var crlf = []byte("\r\n")

// Parse extracts the command verb (arg0, upper-cased) and the first key/channel
// argument (arg1) from a captured prefix of a RESP request buffer.
//
// It reads at most the first two arguments and never returns any value. firstKey
// is "" for commands with no key (e.g. PING). ok is false only when not even the
// verb can be recovered (empty or malformed buffer).
func Parse(b []byte) (verb string, firstKey string, ok bool) {
	if len(b) == 0 {
		return "", "", false
	}
	if b[0] == '*' {
		return parseArray(b)
	}
	return parseInline(b)
}

// ParseError extracts the error code and message line from a captured RESP simple-error
// reply ("-CODE message\r\n"). It is the recv-side counterpart to Parse and the privacy
// boundary for the receive path: it only ever runs on a buffer the kernel already gated on a
// leading '-', and a RESP error string is protocol-level diagnostic text (the broker's own
// message), NOT a business payload — so capturing it is allowed, exactly like an exception
// message. A non-error reply (success values, bulk strings, integers, arrays) yields ok=false,
// so a reply that carries a value can never surface through this package.
//
//	code    = the first whitespace-delimited token after '-' (e.g. "WRONGTYPE", "ERR")
//	message = the full error line after '-', up to the CRLF (or end-of-prefix if truncated)
//
// ok is false if b does not start with '-' or carries no error content.
func ParseError(b []byte) (code string, message string, ok bool) {
	if len(b) == 0 || b[0] != '-' {
		return "", "", false
	}
	// The error line is everything after '-' up to the first CRLF. The 256B capture may
	// truncate it (no CRLF), which is fine — take what's present and never read past it.
	line := b[1:]
	if i := bytes.Index(line, crlf); i >= 0 {
		line = line[:i]
	} else if i := bytes.IndexByte(line, '\r'); i >= 0 {
		line = line[:i] // tolerate a lone CR at the truncation boundary
	}
	message = strings.TrimSpace(string(line))
	if message == "" {
		return "", "", false
	}
	code = message
	if sp := strings.IndexByte(message, ' '); sp >= 0 {
		code = message[:sp]
	}
	return code, message, true
}

// parseArray handles the RESP array form a real client sends:
//
//	*<N>\r\n $<len>\r\n<arg0>\r\n $<len>\r\n<arg1>\r\n ...
func parseArray(b []byte) (verb, firstKey string, ok bool) {
	countLine, rest, ok := readLine(b[1:]) // skip '*'
	if !ok {
		return "", "", false
	}
	n, err := strconv.Atoi(string(countLine))
	if err != nil || n < 1 {
		return "", "", false
	}

	// arg0 — the verb. Require it complete; a truncated verb is not trustworthy.
	v, rest, ok := readBulk(rest, true /*requireComplete*/)
	if !ok || v == "" {
		return "", "", false
	}
	verb = strings.ToUpper(v)
	if n < 2 {
		return verb, "", true // keyless command (PING, INFO, ...)
	}

	// arg1 — the first key/channel. Best-effort: the 256B capture may truncate a
	// long key, which is fine (the mapper prefix-truncates anyway). We STOP here;
	// arg2+ (where values live) are never parsed.
	k, _, ok := readBulk(rest, false /*requireComplete*/)
	if !ok {
		return verb, "", true // valid verb, key unrecoverable → render as "keys:*"
	}
	return verb, k, true
}

// parseInline is a defensive fallback for the telnet-style inline form
// (`SET key value\r\n`). It scans only as far as the first two whitespace tokens,
// so the value is never even examined.
func parseInline(b []byte) (verb, firstKey string, ok bool) {
	t0, t1 := firstTwoTokens(b)
	if t0 == "" {
		return "", "", false
	}
	return strings.ToUpper(t0), t1, true
}

// readLine returns the bytes up to the next CRLF, the remainder after the CRLF,
// and whether a CRLF was found.
func readLine(b []byte) (line, rest []byte, ok bool) {
	i := bytes.Index(b, crlf)
	if i < 0 {
		return nil, nil, false
	}
	return b[:i], b[i+2:], true
}

// readBulk parses a RESP bulk string ($<len>\r\n<bytes>\r\n) at the head of b.
// When requireComplete is false, a content region shorter than the declared length
// is accepted (the kernel capture is a bounded prefix and may truncate the key).
func readBulk(b []byte, requireComplete bool) (s string, rest []byte, ok bool) {
	if len(b) == 0 || b[0] != '$' {
		return "", b, false
	}
	lenLine, afterHdr, ok := readLine(b[1:]) // skip '$'
	if !ok {
		return "", b, false
	}
	n, err := strconv.Atoi(string(lenLine))
	if err != nil || n < 0 { // n < 0 is a null bulk — not valid in a client command
		return "", b, false
	}
	if len(afterHdr) < n {
		if requireComplete {
			return "", b, false
		}
		return string(afterHdr), nil, true // truncated tail — take what's present
	}
	content := afterHdr[:n]
	rest = afterHdr[n:]
	if len(rest) >= 2 && rest[0] == '\r' && rest[1] == '\n' {
		rest = rest[2:] // skip the trailing CRLF
	}
	return string(content), rest, true
}

// firstTwoTokens returns the first two whitespace-delimited tokens of b, scanning
// no further than needed — the rest of the buffer (which may hold a value) is
// never examined.
func firstTwoTokens(b []byte) (t0, t1 string) {
	i := 0
	skipSpace := func() {
		for i < len(b) && isSpace(b[i]) {
			i++
		}
	}
	take := func() string {
		start := i
		for i < len(b) && !isSpace(b[i]) {
			i++
		}
		return string(b[start:i])
	}
	skipSpace()
	t0 = take()
	skipSpace()
	t1 = take()
	return t0, t1
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
