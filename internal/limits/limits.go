// Package limits is the network-layer rate and request-count
// enforcement for the engine. It exists so an agent that never
// imported the aegrail SDK still gets cost-bounded behavior — the
// engine sees every outbound call and can cap rate / total count
// without inspecting bodies or knowing what model is being called.
//
// Two primitives:
//
//   RequestCounter — atomic counter, denies once `max` requests
//                    have been served by this engine process.
//   RateLimiter    — simple token bucket. Refills continuously;
//                    denies when no token is available.
//
// Both are no-ops when their max is 0/empty — the operator opts in
// per limit.

package limits

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RequestCounter caps the total number of allowed requests over the
// engine process's lifetime. Useful for tight cost guarantees on
// short-lived agent pods or for canarying a new policy.
//
// Construct with NewRequestCounter; pass max=0 for "unlimited."
// Safe for concurrent use.
type RequestCounter struct {
	max int64
	n   atomic.Int64
}

// NewRequestCounter builds a counter with the given hard cap. A
// max of 0 (or negative) means "unlimited" — every Allow returns
// true.
func NewRequestCounter(max int64) *RequestCounter {
	return &RequestCounter{max: max}
}

// Allow increments the counter and reports whether the request is
// permitted. Returns (allowed, totalSoFar). When max is 0, allowed
// is always true.
func (c *RequestCounter) Allow() (bool, int64) {
	next := c.n.Add(1)
	if c.max <= 0 {
		return true, next
	}
	return next <= c.max, next
}

// Max returns the configured ceiling (0 means unlimited).
func (c *RequestCounter) Max() int64 { return c.max }

// TokenBudget caps the total token count over the engine process's
// lifetime, accumulated from parsed LLM responses (v0.3.0+).
// Construct with NewTokenBudget; pass max=0 for "unlimited."
// Safe for concurrent use.
type TokenBudget struct {
	max  int64
	used atomic.Int64
}

// NewTokenBudget builds a token budget with the given hard cap.
// max=0 (or negative) means "unlimited" — Add reports allowed
// regardless of usage.
func NewTokenBudget(max int64) *TokenBudget {
	return &TokenBudget{max: max}
}

// Add records `n` tokens consumed by an LLM response. Returns
// (allowedNextCall, totalSoFar): allowedNextCall is true unless
// the *next* request would push the running total beyond max
// (i.e., the budget is exhausted). The current call always
// records — we never lose accounting for already-consumed work.
func (t *TokenBudget) Add(n int64) (bool, int64) {
	total := t.used.Add(n)
	if t.max <= 0 {
		return true, total
	}
	return total < t.max, total
}

// Used reports the current cumulative token count.
func (t *TokenBudget) Used() int64 { return t.used.Load() }

// Max returns the configured ceiling (0 means unlimited).
func (t *TokenBudget) Max() int64 { return t.max }

// OverBudget reports whether the running total has crossed the cap.
// Useful as a pre-flight check before initiating an LLM call so the
// engine refuses traffic the moment the budget is gone.
func (t *TokenBudget) OverBudget() bool {
	if t.max <= 0 {
		return false
	}
	return t.used.Load() >= t.max
}

// RateLimiter is a single-bucket token-bucket limiter. Bucket holds
// up to `burst` tokens; refills at `rate` tokens per second. Each
// Allow attempts to take one token.
//
// Construct via ParseRateSpec("10/sec") or directly via NewRateLimiter.
// A nil RateLimiter Allow()s everything (the "unlimited" sentinel).
type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	burst    float64
	rate     float64
	lastTime time.Time
}

// NewRateLimiter constructs a limiter that refills `tokensPerSecond`
// tokens per second up to a maximum of `burst` tokens. Bucket starts
// full.
func NewRateLimiter(tokensPerSecond float64, burst float64) *RateLimiter {
	if tokensPerSecond <= 0 || burst <= 0 {
		return nil
	}
	return &RateLimiter{
		tokens:   burst,
		burst:    burst,
		rate:     tokensPerSecond,
		lastTime: time.Now(),
	}
}

// Allow returns true if a token is available; false otherwise. A
// nil RateLimiter always allows (treated as "no limit configured").
func (r *RateLimiter) Allow() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(r.lastTime).Seconds()
	r.tokens = math.Min(r.burst, r.tokens+elapsed*r.rate)
	r.lastTime = now
	if r.tokens >= 1.0 {
		r.tokens -= 1.0
		return true
	}
	return false
}

// Rate returns the configured refill rate in tokens per second
// (0 means unlimited / nil receiver).
func (r *RateLimiter) Rate() float64 {
	if r == nil {
		return 0
	}
	return r.rate
}

// Burst returns the maximum bucket size.
func (r *RateLimiter) Burst() float64 {
	if r == nil {
		return 0
	}
	return r.burst
}

// ParseRateSpec turns a string like "10/sec", "100/min", "5/s" into
// a configured RateLimiter. The integer is both the per-period rate
// and the burst (single-bucket; suitable for the rough enforcement
// the engine wants — not for highly bursty traffic shaping).
//
// Returns (nil, nil) for empty input — operator opted out.
// Returns (nil, err) for malformed input — surface loudly so we
// don't silently allow everything on a config typo.
func ParseRateSpec(spec string) (*RateLimiter, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("limits: rate spec %q must be in the form <n>/<unit>, e.g. 10/sec", spec)
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("limits: rate spec %q has invalid count", spec)
	}
	unit := strings.ToLower(strings.TrimSpace(parts[1]))
	var perSecond float64
	switch unit {
	case "s", "sec", "second", "seconds":
		perSecond = n
	case "m", "min", "minute", "minutes":
		perSecond = n / 60.0
	case "h", "hr", "hour", "hours":
		perSecond = n / 3600.0
	default:
		return nil, fmt.Errorf("limits: rate spec %q has unknown unit %q (use sec, min, or hour)", spec, unit)
	}
	if perSecond == 0 {
		return nil, errors.New("limits: rate spec resolves to zero per-second")
	}
	return NewRateLimiter(perSecond, n), nil
}
