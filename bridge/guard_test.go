package bridge

import (
	"sync"
	"testing"
	"time"
)

func TestAllowlist(t *testing.T) {
	al, err := NewAllowlist([]string{"Owner@Gmail.com", " boss@corp.io "})
	if err != nil {
		t.Fatal(err)
	}
	if !al.Allows("owner@gmail.com") {
		t.Fatal("case-insensitive allow failed")
	}
	if !al.Allows("  BOSS@CORP.IO ") {
		t.Fatal("trim/case allow failed")
	}
	if al.Allows("stranger@gmail.com") {
		t.Fatal("stranger must be denied")
	}
	if al.Allows("owner@gmail.com\n") {
		t.Fatal("control char must not match")
	}
}

func TestAllowlistEmptyDeniesAll(t *testing.T) {
	al, err := NewAllowlist(nil)
	if err != nil {
		t.Fatal(err)
	}
	if al.Allows("anyone@gmail.com") {
		t.Fatal("empty allowlist must deny all")
	}
	var nilAL *Allowlist
	if nilAL.Allows("x@y.com") {
		t.Fatal("nil allowlist must deny all")
	}
}

func TestAllowlistRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "no-at", "a@b", "@domain.com", "local@", "two@@x.com", "x@y.com\n"} {
		if _, err := NewAllowlist([]string{bad}); err == nil {
			t.Fatalf("expected rejection of %q", bad)
		}
	}
}

func TestRateLimiterPerSender(t *testing.T) {
	rl := NewRateLimiter(RateConfig{PerSenderPerHour: 3600, PerSenderBurst: 2})
	now := time.Unix(0, 0)
	rl.now = func() time.Time { return now }

	if !rl.Allow("a@x.com") || !rl.Allow("a@x.com") {
		t.Fatal("burst of 2 must pass")
	}
	if rl.Allow("a@x.com") {
		t.Fatal("3rd immediate call must be limited")
	}
	// A different sender has its own bucket.
	if !rl.Allow("b@x.com") {
		t.Fatal("independent sender must pass")
	}
	// 1/sec refill: after 1s, one token back.
	now = now.Add(time.Second)
	if !rl.Allow("a@x.com") {
		t.Fatal("token must refill after 1s")
	}
	if rl.Allow("a@x.com") {
		t.Fatal("only one token should have refilled")
	}
}

func TestRateLimiterGlobalCap(t *testing.T) {
	rl := NewRateLimiter(RateConfig{GlobalPerHour: 3600, GlobalBurst: 2})
	now := time.Unix(0, 0)
	rl.now = func() time.Time { return now }
	if !rl.Allow("a@x.com") || !rl.Allow("b@x.com") {
		t.Fatal("global burst 2 across senders must pass")
	}
	if rl.Allow("c@x.com") {
		t.Fatal("global cap must block a third distinct sender")
	}
}

func TestRateLimiterNoPartialSpend(t *testing.T) {
	// Per-key exhausted but global available: the failed call must not spend
	// a global token.
	rl := NewRateLimiter(RateConfig{PerSenderPerHour: 3600, PerSenderBurst: 1, GlobalPerHour: 3600, GlobalBurst: 10})
	now := time.Unix(0, 0)
	rl.now = func() time.Time { return now }
	if !rl.Allow("a@x.com") {
		t.Fatal("first must pass")
	}
	if rl.Allow("a@x.com") {
		t.Fatal("per-key exhausted must block")
	}
	// Global should still have 9 tokens: 9 distinct senders pass.
	for i := 0; i < 9; i++ {
		if !rl.Allow(string(rune('b'+i)) + "@x.com") {
			t.Fatalf("global token %d wrongly consumed by blocked call", i)
		}
	}
}

func TestRateLimiterUnlimited(t *testing.T) {
	rl := NewRateLimiter(RateConfig{}) // both zero => unlimited
	for i := 0; i < 1000; i++ {
		if !rl.Allow("a@x.com") {
			t.Fatal("unlimited limiter must always pass")
		}
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	rl := NewRateLimiter(RateConfig{GlobalPerHour: 3600, GlobalBurst: 100})
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow("a@x.com") {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if passed != 100 {
		t.Fatalf("expected exactly 100 passes under contention, got %d", passed)
	}
}
