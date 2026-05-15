// Package policy is the egress-allowlist enforcement layer of the
// aegrail engine. A Policy holds an immutable list of host patterns;
// callers ask Policy.Allows(host) to decide whether a request to
// `host` should be forwarded or denied.
//
// Pattern semantics intentionally match the aegrail Python library's
// fnmatch-based egress allowlist. Only `/` is treated as a separator
// by the underlying matcher; the dot character is just a literal,
// which gives the following behavior:
//
//   "api.openai.com"    matches only the exact host
//   "*.openai.com"      matches any host that ends in ".openai.com" —
//                       e.g. api.openai.com, api.v2.openai.com,
//                       alpha.beta.gamma.openai.com. The "*" is
//                       greedy across dots. Does NOT match
//                       "openai.com" (no leading dot to consume).
//   "*"                 matches any host (use only intentionally)
//   "?"                 matches any single character
//
// If you need strict single-level subdomain matching ("api.openai.com"
// but not "api.v2.openai.com"), spell out the patterns explicitly —
// there's no curated cross-dot-vs-single-dot syntax. This matches
// what Python's fnmatch does in the aegrail library; the two
// implementations are interchangeable for log analysis.
//
// An empty allowlist (zero patterns) denies everything: callers
// should pass an explicit list of allowed hosts. A nil Policy
// pointer also denies everything (fail secure).
package policy

import (
	"fmt"
	"path"
)

// Policy is the immutable allowlist used by the engine to decide
// whether to forward or deny an outbound request.
type Policy struct {
	patterns []string
}

// New constructs a Policy from a list of host patterns. The
// patterns are validated against path.Match's grammar; an invalid
// pattern returns an error so misconfiguration fails loudly at
// startup rather than at runtime.
func New(patterns []string) (*Policy, error) {
	// Validate each pattern up-front by running it against a
	// dummy string. path.Match returns ErrBadPattern for syntax
	// errors; we surface those immediately.
	for _, p := range patterns {
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("policy: invalid host pattern %q: %w", p, err)
		}
	}
	return &Policy{patterns: append([]string(nil), patterns...)}, nil
}

// Allows reports whether `host` matches any pattern in the policy.
// A nil Policy denies everything (fail secure).
func (p *Policy) Allows(host string) bool {
	if p == nil {
		return false
	}
	for _, pat := range p.patterns {
		// path.Match returns (false, nil) for non-matches, (true, nil)
		// for matches, and only returns ErrBadPattern for malformed
		// patterns — which we caught at New() time. We can ignore the
		// error here safely.
		ok, _ := path.Match(pat, host)
		if ok {
			return true
		}
	}
	return false
}

// Patterns returns a copy of the policy's patterns for inspection
// (e.g. emitting them into an `engine_start` audit event). The
// returned slice is safe for the caller to retain.
func (p *Policy) Patterns() []string {
	if p == nil {
		return nil
	}
	out := make([]string, len(p.patterns))
	copy(out, p.patterns)
	return out
}
