package bridge

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/fractalmind-ai/fractal-demail/client-go/schema"
)

type mockSMTP struct {
	calls             int
	to, subject, body string
	err               error
}

func (m *mockSMTP) Send(_ context.Context, to, subject, body string) error {
	m.calls++
	m.to, m.subject, m.body = to, subject, body
	return m.err
}

func newWatcher(t *testing.T, smtp *mockSMTP, opts func(*OutboundConfig)) *OutboundWatcher {
	t.Helper()
	al, _ := NewAllowlist([]string{"owner@gmail.com"})
	cfg := OutboundConfig{Allowlist: al, Limiter: NewRateLimiter(RateConfig{})}
	if opts != nil {
		opts(&cfg)
	}
	w, err := NewOutboundWatcher(cfg, smtp)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func reply(web2To, body string) *schema.Plaintext {
	return &schema.Plaintext{
		Type:   schema.TypeReply,
		From:   agentAddr,
		To:     bridgeAddr,
		Body:   body,
		Web2To: web2To,
	}
}

func TestOutboundHappyPathDelivers(t *testing.T) {
	s := &mockSMTP{}
	w := newWatcher(t, s, nil)
	m := reply("Owner@gmail.com", "the result is 42")
	m.Subject = "re: your job"
	res, err := w.Handle(context.Background(), m)
	if err != nil || !res.Delivered {
		t.Fatalf("expected delivery, got %+v err=%v", res, err)
	}
	if s.calls != 1 || s.to != "owner@gmail.com" || s.body != "the result is 42" || s.subject != "re: your job" {
		t.Fatalf("smtp got %+v", *s)
	}
}

func TestOutboundNoWeb2ToDropped(t *testing.T) {
	s := &mockSMTP{}
	w := newWatcher(t, s, nil)
	res, _ := w.Handle(context.Background(), reply("", "x"))
	if res.Drop != DropNoWeb2To || s.calls != 0 {
		t.Fatalf("expected no_web2_to, got %+v", res)
	}
}

func TestOutboundOffAllowlistWithoutSpendingToken(t *testing.T) {
	s := &mockSMTP{}
	var lim *RateLimiter
	w := newWatcher(t, s, func(c *OutboundConfig) {
		lim = NewRateLimiter(RateConfig{GlobalPerHour: 3600, GlobalBurst: 1})
		c.Limiter = lim
	})
	res, _ := w.Handle(context.Background(), reply("stranger@evil.com", "x"))
	if res.Drop != DropNotAllowed || s.calls != 0 {
		t.Fatalf("expected not_allowed, got %+v", res)
	}
	if !lim.Allow("owner@gmail.com") {
		t.Fatal("off-allowlist recipient wrongly consumed an outbound token")
	}
}

func TestOutboundRateLimited(t *testing.T) {
	s := &mockSMTP{}
	w := newWatcher(t, s, func(c *OutboundConfig) {
		c.Limiter = NewRateLimiter(RateConfig{PerSenderPerHour: 3600, PerSenderBurst: 1})
	})
	if res, _ := w.Handle(context.Background(), reply("owner@gmail.com", "a")); !res.Delivered {
		t.Fatalf("first must deliver, got %+v", res)
	}
	res, _ := w.Handle(context.Background(), reply("owner@gmail.com", "b"))
	if res.Drop != DropRateLimited || s.calls != 1 {
		t.Fatalf("second must be rate_limited, got %+v calls=%d", res, s.calls)
	}
}

func TestOutboundEmptyBodyDropped(t *testing.T) {
	s := &mockSMTP{}
	w := newWatcher(t, s, nil)
	res, err := w.Handle(context.Background(), reply("owner@gmail.com", "   "))
	if res.Drop != DropMalformed || err == nil || s.calls != 0 {
		t.Fatalf("empty body must drop, got %+v err=%v", res, err)
	}
}

func TestOutboundDeliverFailureSurfaced(t *testing.T) {
	s := &mockSMTP{err: errors.New("smtp 500")}
	w := newWatcher(t, s, nil)
	res, err := w.Handle(context.Background(), reply("owner@gmail.com", "x"))
	if res.Drop != DropDeliverFailed || err == nil {
		t.Fatalf("expected deliver_failed, got %+v err=%v", res, err)
	}
}

func TestOutboundNilMessage(t *testing.T) {
	s := &mockSMTP{}
	w := newWatcher(t, s, nil)
	res, err := w.Handle(context.Background(), nil)
	if res.Drop != DropMalformed || err == nil || s.calls != 0 {
		t.Fatalf("nil message must drop, got %+v err=%v", res, err)
	}
}

func TestNewOutboundWatcherRequiresSMTP(t *testing.T) {
	if _, err := NewOutboundWatcher(OutboundConfig{}, nil); err == nil {
		t.Fatal("expected nil smtp rejection")
	}
}

func TestOutboundSubjectStripsHeaderInjection(t *testing.T) {
	s := &mockSMTP{}
	w := newWatcher(t, s, nil)
	m := reply("owner@gmail.com", "body")
	// schema.Parse would keep the bare LF in Subject; the watcher must strip it.
	m.Subject = "hi\r\nBcc: victim@x.com\nX-Injected: 1\ttab"
	res, err := w.Handle(context.Background(), m)
	if err != nil || !res.Delivered {
		t.Fatalf("expected delivery, got %+v err=%v", res, err)
	}
	if strings.ContainsAny(s.subject, "\r\n\t") {
		t.Fatalf("subject retained control chars (header injection): %q", s.subject)
	}
	if s.subject != "hiBcc: victim@x.comX-Injected: 1tab" {
		t.Fatalf("unexpected sanitized subject: %q", s.subject)
	}
}
