// Package bridge implements the Web2<->Web3 mail bridge for fractal-demail
// (Phase 2, see docs phase2-bridge-design). This file provides the two abuse
// defenses that every inbound/outbound path shares: a sender allowlist and a
// token-bucket rate limiter. Both are pure and dependency-free so the relayer
// and outbound watcher can be built and tested behind mocks before any real
// provider is wired in.
package bridge

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Allowlist is a case-insensitive set of permitted email addresses.
// An empty allowlist denies everyone — the same deny-all-by-default posture
// as the on-chain sender allowlist, and the primary gas-drain defense.
type Allowlist struct {
	allowed map[string]struct{}
}

// NewAllowlist builds an allowlist from email addresses. Entries are
// lowercased and trimmed; blank entries are rejected.
func NewAllowlist(addrs []string) (*Allowlist, error) {
	m := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		norm := normalizeEmail(a)
		if norm == "" {
			return nil, fmt.Errorf("allowlist: invalid email %q", a)
		}
		m[norm] = struct{}{}
	}
	return &Allowlist{allowed: m}, nil
}

// Allows reports whether addr is permitted. Empty allowlist => false.
func (a *Allowlist) Allows(addr string) bool {
	if a == nil {
		return false
	}
	_, ok := a.allowed[normalizeEmail(addr)]
	return ok
}

// normalizeEmail lowercases and trims; returns "" if not a plausible address
// (must contain a single @ with non-empty local and domain parts and no
// control characters). This is a gate, not full RFC 5322 validation.
func normalizeEmail(s string) string {
	// Reject any control character (incl. CR/LF/TAB) before trimming, so a
	// trailing newline cannot be silently stripped into a valid-looking
	// address. Ordinary surrounding spaces are still trimmed.
	if strings.IndexFunc(s, isControl) >= 0 {
		return ""
	}
	s = strings.ToLower(strings.TrimSpace(s))
	at := strings.IndexByte(s, '@')
	if at <= 0 || at != strings.LastIndexByte(s, '@') || at == len(s)-1 {
		return ""
	}
	if !strings.Contains(s[at+1:], ".") {
		return ""
	}
	return s
}

// isControl covers C0, DEL, and the C1 range so no control rune can be
// trimmed into a valid-looking address.
func isControl(r rune) bool { return unicode.IsControl(r) }

// RateLimiter is a token-bucket limiter with a global bucket and per-key
// buckets (key = sender email). It defends against a compromised allowlisted
// account draining the gas pool. Safe for concurrent use.
type RateLimiter struct {
	mu         sync.Mutex
	perKey     map[string]*bucket
	global     *bucket
	perKeyRate rate
	globalRate rate
	now        func() time.Time
}

type rate struct {
	capacity float64
	perSec   float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

// RateConfig configures a RateLimiter. A zero capacity on either scope means
// that scope is unlimited.
type RateConfig struct {
	PerSenderPerHour int
	PerSenderBurst   int
	GlobalPerHour    int
	GlobalBurst      int
}

// NewRateLimiter builds a limiter from an hourly config.
func NewRateLimiter(cfg RateConfig) *RateLimiter {
	mk := func(perHour, burst int) rate {
		if perHour <= 0 {
			return rate{} // unlimited
		}
		cap := float64(burst)
		if cap <= 0 {
			cap = float64(perHour)
		}
		return rate{capacity: cap, perSec: float64(perHour) / 3600.0}
	}
	return &RateLimiter{
		perKey:     make(map[string]*bucket),
		global:     &bucket{},
		perKeyRate: mk(cfg.PerSenderPerHour, cfg.PerSenderBurst),
		globalRate: mk(cfg.GlobalPerHour, cfg.GlobalBurst),
		now:        time.Now,
	}
}

// Allow consumes one token for key from both the per-key and global buckets.
// It returns true only if BOTH scopes have a token; on failure it consumes
// from neither (no partial spend). Unlimited scopes always pass.
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()

	gOK := r.globalRate.capacity == 0 || r.peek(r.global, r.globalRate, now) >= 1
	kb := r.keyBucket(key)
	kOK := r.perKeyRate.capacity == 0 || r.peek(kb, r.perKeyRate, now) >= 1
	if !gOK || !kOK {
		return false
	}
	if r.globalRate.capacity != 0 {
		r.global.tokens = r.peek(r.global, r.globalRate, now) - 1
		r.global.last = now
	}
	if r.perKeyRate.capacity != 0 {
		kb.tokens = r.peek(kb, r.perKeyRate, now) - 1
		kb.last = now
	}
	return true
}

// peek returns the refilled token count without committing last.
func (r *RateLimiter) peek(b *bucket, rt rate, now time.Time) float64 {
	if b.last.IsZero() {
		return rt.capacity
	}
	elapsed := now.Sub(b.last).Seconds()
	tokens := b.tokens + elapsed*rt.perSec
	if tokens > rt.capacity {
		tokens = rt.capacity
	}
	return tokens
}

func (r *RateLimiter) keyBucket(key string) *bucket {
	b, ok := r.perKey[key]
	if !ok {
		b = &bucket{}
		r.perKey[key] = b
	}
	return b
}
