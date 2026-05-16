package limits

import (
	"testing"
	"time"
)

// -- RequestCounter ----------------------------------------------

func TestRequestCounter_Unlimited(t *testing.T) {
	t.Parallel()
	c := NewRequestCounter(0)
	for i := 0; i < 100; i++ {
		ok, n := c.Allow()
		if !ok {
			t.Fatalf("call %d denied; max=0 should be unlimited", i)
		}
		if n != int64(i+1) {
			t.Errorf("call %d: total=%d, want %d", i, n, i+1)
		}
	}
}

func TestRequestCounter_HardCap(t *testing.T) {
	t.Parallel()
	c := NewRequestCounter(3)

	for i := 0; i < 3; i++ {
		ok, n := c.Allow()
		if !ok {
			t.Errorf("call %d denied within cap; total=%d", i, n)
		}
	}
	ok, n := c.Allow()
	if ok {
		t.Errorf("call 4 should be denied; total=%d, max=3", n)
	}
	if n != 4 {
		t.Errorf("counter should still increment: got %d, want 4", n)
	}
}

// -- RateLimiter -------------------------------------------------

func TestRateLimiter_NilAllowsAll(t *testing.T) {
	t.Parallel()
	var r *RateLimiter
	for i := 0; i < 50; i++ {
		if !r.Allow() {
			t.Fatalf("nil RateLimiter denied call %d", i)
		}
	}
}

func TestRateLimiter_BurstThenDeny(t *testing.T) {
	t.Parallel()
	// 5/sec, burst 5 → first 5 calls instantly allowed, 6th denied
	r := NewRateLimiter(5.0, 5.0)
	for i := 0; i < 5; i++ {
		if !r.Allow() {
			t.Errorf("call %d should fit in initial burst", i)
		}
	}
	if r.Allow() {
		t.Error("call 6 should be denied (bucket empty)")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	t.Parallel()
	r := NewRateLimiter(100.0, 1.0) // 100/sec, burst 1
	if !r.Allow() {
		t.Fatal("first call should be allowed")
	}
	if r.Allow() {
		t.Error("immediately-following call should be denied")
	}
	// 20 ms at 100/sec = 2 tokens; bucket clamps to burst=1
	time.Sleep(20 * time.Millisecond)
	if !r.Allow() {
		t.Error("call after refill window should be allowed")
	}
}

// -- ParseRateSpec ----------------------------------------------

func TestParseRateSpec(t *testing.T) {
	t.Parallel()
	cases := []struct {
		spec    string
		want    float64
		wantErr bool
		empty   bool // expect nil RateLimiter, no error
	}{
		{"", 0, false, true},
		{"10/sec", 10, false, false},
		{"10/s", 10, false, false},
		{"10/seconds", 10, false, false},
		{"60/min", 1, false, false},
		{"60/minutes", 1, false, false},
		{"3600/hour", 1, false, false},
		{"3600/h", 1, false, false},
		{"  100 / sec  ", 100, false, false},
		{"abc/sec", 0, true, false},
		{"10/century", 0, true, false},
		{"-5/sec", 0, true, false},
		{"10", 0, true, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.spec, func(t *testing.T) {
			r, err := ParseRateSpec(c.spec)
			if c.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got rate=%v", c.spec, r)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", c.spec, err)
			}
			if c.empty {
				if r != nil {
					t.Errorf("expected nil RateLimiter for %q, got %v", c.spec, r)
				}
				return
			}
			if r == nil {
				t.Fatalf("nil RateLimiter for %q (expected configured)", c.spec)
			}
			if r.Rate() != c.want {
				t.Errorf("%q: rate=%v, want %v", c.spec, r.Rate(), c.want)
			}
		})
	}
}
