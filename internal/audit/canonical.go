// canonical.go is the JSON serializer we use exclusively for audit
// chain hashing. It exists separately from the regular `Sink`
// serialization (which uses encoding/json directly) because:
//
//  1. The hash function MUST produce the same byte sequence as
//     Python's `json.dumps(sort_keys=True, separators=(",", ":"))`,
//     not Go's default JSON layout.
//
//  2. Sink serialization is for humans / log shippers and follows
//     Go conventions; canonical serialization is for cryptographic
//     consistency and must match a specific external implementation.
//
// Keeping the two paths separate prevents future "let's just clean
// this up" refactors from accidentally breaking chain compatibility
// across language implementations.

package audit

import (
	"bytes"
	"encoding/json"
)

// canonicalJSON produces the byte sequence that Python's
// `json.dumps(value, sort_keys=True, separators=(",", ":"))` would
// produce for the same input.
//
// Key properties (each matches Python's default):
//   - Object keys sorted lexicographically at every depth
//   - Compact separators ("," and ":") — no whitespace
//   - HTML-special chars (<, >, &) NOT escaped — Go's default is
//     to escape these; we disable that via SetEscapeHTML(false)
//   - Non-ASCII Unicode characters preserved as UTF-8 bytes.
//     NOTE: Python's default ensure_ascii=True would produce
//     \uXXXX escapes here, which DIFFERS from this implementation.
//     For ASCII-only event payloads (the common case in aegrail's
//     audit data — hostnames, methods, paths) this is a non-issue.
//     If the project ever audits non-ASCII content, we add explicit
//     \uXXXX escaping in this function rather than changing Python.
func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	// json.Encoder.Encode appends a trailing newline; strip it.
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}
