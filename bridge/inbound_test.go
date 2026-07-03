package bridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/fractalmind-ai/fractal-demail/client-go/envelope"
	"github.com/fractalmind-ai/fractal-demail/client-go/schema"
)

const (
	bridgeAddr = "0xeedfe046af0c10613356dea725fbe22af969a58077f27622936a6c4d9ec2fce3"
	agentAddr  = "0xf4fafecc95c2e7c984f8d26db9b692cf58da977ee0119be38b84904b394e82e2"
)

type mockVerifier struct {
	email *InboundEmail
	err   error
}

func (m mockVerifier) Verify(map[string]string, []byte) (*InboundEmail, error) {
	return m.email, m.err
}

type mockSender struct {
	calls   int
	lastTo  string
	lastPay []byte
	err     error
}

func (m *mockSender) Send(_ context.Context, to string, payload []byte) (string, error) {
	m.calls++
	m.lastTo = to
	m.lastPay = payload
	if m.err != nil {
		return "", m.err
	}
	return "0xDIGEST", nil
}

func newRelayer(t *testing.T, email *InboundEmail, verr error, sender *mockSender, opts func(*InboundConfig)) (*InboundRelayer, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	al, _ := NewAllowlist([]string{"owner@gmail.com"})
	cfg := InboundConfig{
		BridgeAddress: bridgeAddr,
		Agents:        map[string]Agent{"agent": {SuiAddress: agentAddr, PubKey: pub}},
		Allowlist:     al,
		Limiter:       NewRateLimiter(RateConfig{}),
		Now:           func() time.Time { return time.UnixMilli(1783000000000) },
	}
	if opts != nil {
		opts(&cfg)
	}
	r, err := NewInboundRelayer(cfg, mockVerifier{email: email, err: verr}, sender)
	if err != nil {
		t.Fatal(err)
	}
	return r, priv
}

func TestInboundHappyPathSealsAndSends(t *testing.T) {
	email := &InboundEmail{From: "Owner@gmail.com", To: "agent@mail.example.com", Subject: "hi", Body: "run the job"}
	s := &mockSender{}
	r, agentPriv := newRelayer(t, email, nil, s, nil)

	res, err := r.Handle(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !res.Delivered || res.TxDigest != "0xDIGEST" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if s.calls != 1 || s.lastTo != agentAddr {
		t.Fatalf("sender got calls=%d to=%s", s.calls, s.lastTo)
	}
	// The payload must decrypt with the agent key and preserve provenance.
	wire, err := base64.StdEncoding.DecodeString(string(s.lastPay))
	if err != nil {
		t.Fatalf("payload not base64: %v", err)
	}
	env, err := envelope.Unmarshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	bRaw, _ := hexAddress(bridgeAddr)
	aRaw, _ := hexAddress(agentAddr)
	pt, err := envelope.Open(agentPriv, bRaw, aRaw, env)
	if err != nil {
		t.Fatalf("agent cannot open: %v", err)
	}
	msg, err := schema.Parse(pt, bridgeAddr, agentAddr)
	if err != nil {
		t.Fatalf("schema.Parse: %v", err)
	}
	if msg.Body != "run the job" || msg.Web2From != "owner@gmail.com" || msg.From != bridgeAddr {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestInboundRejectsUnverified(t *testing.T) {
	s := &mockSender{}
	r, _ := newRelayer(t, nil, errors.New("bad sig"), s, nil)
	res, err := r.Handle(context.Background(), nil, nil)
	if err == nil || res.Drop != DropUnverified || s.calls != 0 {
		t.Fatalf("expected unverified drop, got %+v err=%v", res, err)
	}
}

func TestInboundRejectsOffAllowlistWithoutSpendingToken(t *testing.T) {
	email := &InboundEmail{From: "stranger@evil.com", To: "agent@mail.example.com", Body: "x"}
	s := &mockSender{}
	var lim *RateLimiter
	r, _ := newRelayer(t, email, nil, s, func(c *InboundConfig) {
		lim = NewRateLimiter(RateConfig{GlobalPerHour: 3600, GlobalBurst: 1})
		c.Limiter = lim
	})
	res, _ := r.Handle(context.Background(), nil, nil)
	if res.Drop != DropNotAllowed || s.calls != 0 {
		t.Fatalf("expected not_allowed, got %+v", res)
	}
	// The off-list sender must not have consumed the single global token.
	if !lim.Allow("owner@gmail.com") {
		t.Fatal("off-allowlist sender wrongly consumed a rate-limit token")
	}
}

func TestInboundUnknownRecipientDropped(t *testing.T) {
	email := &InboundEmail{From: "owner@gmail.com", To: "nobody@mail.example.com", Body: "x"}
	s := &mockSender{}
	r, _ := newRelayer(t, email, nil, s, nil)
	res, _ := r.Handle(context.Background(), nil, nil)
	if res.Drop != DropNoRecipient || s.calls != 0 {
		t.Fatalf("expected no_recipient, got %+v", res)
	}
}

func TestInboundRateLimited(t *testing.T) {
	email := &InboundEmail{From: "owner@gmail.com", To: "agent@mail.example.com", Body: "x"}
	s := &mockSender{}
	r, _ := newRelayer(t, email, nil, s, func(c *InboundConfig) {
		c.Limiter = NewRateLimiter(RateConfig{PerSenderPerHour: 3600, PerSenderBurst: 1})
	})
	if res, _ := r.Handle(context.Background(), nil, nil); !res.Delivered {
		t.Fatalf("first must deliver, got %+v", res)
	}
	res, _ := r.Handle(context.Background(), nil, nil)
	if res.Drop != DropRateLimited || s.calls != 1 {
		t.Fatalf("second must be rate_limited, got %+v calls=%d", res, s.calls)
	}
}

func TestInboundSendFailureSurfaced(t *testing.T) {
	email := &InboundEmail{From: "owner@gmail.com", To: "agent@mail.example.com", Body: "x"}
	s := &mockSender{err: errors.New("rpc down")}
	r, _ := newRelayer(t, email, nil, s, nil)
	res, err := r.Handle(context.Background(), nil, nil)
	if res.Drop != DropSendFailed || err == nil {
		t.Fatalf("expected send_failed, got %+v err=%v", res, err)
	}
}

func TestNewInboundRelayerValidation(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	base := InboundConfig{BridgeAddress: bridgeAddr, Agents: map[string]Agent{"a": {SuiAddress: agentAddr, PubKey: pub}}}
	if _, err := NewInboundRelayer(InboundConfig{BridgeAddress: "bad"}, mockVerifier{}, &mockSender{}); err == nil {
		t.Fatal("expected bad bridge address rejection")
	}
	if _, err := NewInboundRelayer(base, nil, &mockSender{}); err == nil {
		t.Fatal("expected nil verifier rejection")
	}
	bad := InboundConfig{BridgeAddress: bridgeAddr, Agents: map[string]Agent{"a": {SuiAddress: agentAddr, PubKey: []byte{1, 2}}}}
	if _, err := NewInboundRelayer(bad, mockVerifier{}, &mockSender{}); err == nil {
		t.Fatal("expected bad pubkey rejection")
	}
}

func TestInboundEmptyBodyRejectedBeforeMint(t *testing.T) {
	email := &InboundEmail{From: "owner@gmail.com", To: "agent@mail.example.com", Body: "   "}
	s := &mockSender{}
	r, _ := newRelayer(t, email, nil, s, nil)
	res, err := r.Handle(context.Background(), nil, nil)
	if res.Drop != DropMalformed || err == nil || s.calls != 0 {
		t.Fatalf("empty body must drop before mint, got %+v err=%v calls=%d", res, err, s.calls)
	}
}
