package policy

import (
	"strings"
	"testing"
)

func TestPolicy_Allows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		patterns []string
		host     string
		want     bool
	}{
		// Exact host matches
		{"exact match", []string{"api.openai.com"}, "api.openai.com", true},
		{"exact no match", []string{"api.openai.com"}, "api.anthropic.com", false},

		// fnmatch semantics: `*` is greedy and matches across dots
		// (only `/` is treated as a separator). Same behavior as the
		// Python aegrail library's egress allowlist.
		{"wildcard subdomain match", []string{"*.openai.com"}, "api.openai.com", true},
		{"wildcard no match — naked domain", []string{"*.openai.com"}, "openai.com", false},
		{"wildcard matches multi-level subdomain (fnmatch greedy)",
			[]string{"*.openai.com"}, "api.v2.openai.com", true},
		{"wildcard no match — different domain",
			[]string{"*.openai.com"}, "api.evil.com", false},

		// Multiple patterns
		{"multi-pattern first match",
			[]string{"api.openai.com", "*.anthropic.com"}, "api.openai.com", true},
		{"multi-pattern second match",
			[]string{"api.openai.com", "*.anthropic.com"}, "api.anthropic.com", true},
		{"multi-pattern no match",
			[]string{"api.openai.com", "*.anthropic.com"}, "evil.example.com", false},

		// Empty allowlist denies everything
		{"empty allowlist denies", []string{}, "api.openai.com", false},

		// IP-like hosts work fine (no special handling for dotted
		// numerics — the matcher is pattern-string-vs-host-string)
		{"ipv4 exact match", []string{"127.0.0.1"}, "127.0.0.1", true},
		{"ipv4 no match", []string{"127.0.0.1"}, "127.0.0.2", false},

		// Single-char wildcard
		{"single-char wildcard match", []string{"a?i.openai.com"}, "api.openai.com", true},
		{"single-char wildcard no match", []string{"a?i.openai.com"}, "abxi.openai.com", false},

		// Empty host
		{"empty host with empty allowlist", []string{}, "", false},
		{"empty host with universal wildcard", []string{"*"}, "", true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := New(tc.patterns)
			if err != nil {
				t.Fatalf("New(%v) returned unexpected error: %v", tc.patterns, err)
			}
			if got := p.Allows(tc.host); got != tc.want {
				t.Errorf("Allows(%q) with patterns %v = %v, want %v",
					tc.host, tc.patterns, got, tc.want)
			}
		})
	}
}

func TestPolicy_NilDeniesEverything(t *testing.T) {
	t.Parallel()
	var p *Policy
	if p.Allows("anything") {
		t.Error("nil Policy must deny every host (fail secure), got allow")
	}
}

func TestPolicy_New_InvalidPatternErrors(t *testing.T) {
	t.Parallel()
	// path.Match returns ErrBadPattern for unmatched '['
	_, err := New([]string{"api.[unmatched.openai.com"})
	if err == nil {
		t.Fatal("expected error for invalid pattern, got nil")
	}
	if !strings.Contains(err.Error(), "invalid host pattern") {
		t.Errorf("error message should mention 'invalid host pattern', got: %v", err)
	}
}

func TestPolicy_Patterns_ReturnsCopy(t *testing.T) {
	t.Parallel()
	original := []string{"api.openai.com", "*.anthropic.com"}
	p, err := New(original)
	if err != nil {
		t.Fatal(err)
	}
	got := p.Patterns()
	if len(got) != len(original) {
		t.Fatalf("want %d patterns, got %d", len(original), len(got))
	}
	// Mutating the returned slice must not change the policy's
	// internal state.
	got[0] = "MUTATED"
	if p.Allows("api.openai.com") != true {
		t.Error("mutating returned slice changed policy behavior — copy is not defensive")
	}
}

func TestPolicy_Patterns_NilSafe(t *testing.T) {
	t.Parallel()
	var p *Policy
	if got := p.Patterns(); got != nil {
		t.Errorf("nil Policy.Patterns() should return nil, got %v", got)
	}
}
