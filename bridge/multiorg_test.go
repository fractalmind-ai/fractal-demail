package bridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/fractalmind-ai/fractal-demail/client-go/envelope"
	"github.com/fractalmind-ai/fractal-demail/client-go/schema"
)

// orgAddr returns a distinct 32-byte hex Sui address for org index i.
func orgAddr(i byte) string {
	b := make([]byte, 32)
	for j := range b {
		b[j] = i
	}
	return "0x" + hexEncode(b)
}

func hexEncode(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0xf]
	}
	return string(out)
}

func buildOrg(t *testing.T, bridge string, sender *mockSender, allowed []string) (*InboundRelayer, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	al, _ := NewAllowlist(allowed)
	r, err := NewInboundRelayer(InboundConfig{
		BridgeAddress: bridge,
		Agents:        map[string]Agent{"agent": {SuiAddress: orgAddr(0xA0), PubKey: pub}},
		Allowlist:     al,
		Now:           func() time.Time { return time.UnixMilli(1783000000000) },
	}, mockVerifier{}, sender)
	if err != nil {
		t.Fatal(err)
	}
	return r, priv
}

func TestMultiOrgRoutesByDomain(t *testing.T) {
	s := &mockSender{}
	bridgeA := orgAddr(0x11)
	bridgeB := orgAddr(0x22)
	orgA, keyA := buildOrg(t, bridgeA, s, []string{"owner@a.com"})
	orgB, keyB := buildOrg(t, bridgeB, s, []string{"owner@b.com"})

	// Org A only allows owner@a.com; org B only owner@b.com. This proves the
	// per-org allowlists apply to the routed org, not globally.
	emailToA := &InboundEmail{From: "owner@a.com", To: "agent@mail.orga.io", Body: "hi A"}
	emailToB := &InboundEmail{From: "owner@b.com", To: "agent@mail.orgb.io", Body: "hi B"}

	m, err := NewMultiOrgRelayer(mockVerifier{email: emailToA}, map[string]*InboundRelayer{
		"mail.orga.io": orgA,
		"MAIL.ORGB.IO": orgB, // mixed case key must normalize
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := m.Handle(context.Background(), nil, nil)
	if err != nil || !res.Delivered {
		t.Fatalf("org A delivery failed: %+v err=%v", res, err)
	}
	// The message routed to org A must be sealed with org A's bridge identity
	// and open with org A's agent key.
	assertSealedFromBridge(t, keyA, bridgeA, orgAddr(0xA0), s.lastPay, "hi A", "owner@a.com")

	// Now route to org B via a verifier returning the B email.
	m.verifier = mockVerifier{email: emailToB}
	res, err = m.Handle(context.Background(), nil, nil)
	if err != nil || !res.Delivered {
		t.Fatalf("org B delivery failed: %+v err=%v", res, err)
	}
	assertSealedFromBridge(t, keyB, bridgeB, orgAddr(0xA0), s.lastPay, "hi B", "owner@b.com")
}

func assertSealedFromBridge(t *testing.T, agentKey ed25519.PrivateKey, bridge, agent string, payload []byte, wantBody, wantFrom string) {
	t.Helper()
	wire, err := base64.StdEncoding.DecodeString(string(payload))
	if err != nil {
		t.Fatal(err)
	}
	env, err := envelope.Unmarshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	bRaw, _ := hexAddress(bridge)
	aRaw, _ := hexAddress(agent)
	pt, err := envelope.Open(agentKey, bRaw, aRaw, env)
	if err != nil {
		t.Fatalf("agent key cannot open org-routed message: %v", err)
	}
	msg, err := schema.Parse(pt, bridge, agent)
	if err != nil {
		t.Fatalf("schema.Parse: %v", err)
	}
	if msg.Body != wantBody || msg.Web2From != wantFrom || msg.From != bridge {
		t.Fatalf("wrong routed message: %+v", msg)
	}
}

func TestMultiOrgUnknownDomainDropped(t *testing.T) {
	s := &mockSender{}
	orgA, _ := buildOrg(t, orgAddr(0x11), s, []string{"owner@a.com"})
	m, _ := NewMultiOrgRelayer(mockVerifier{email: &InboundEmail{
		From: "owner@a.com", To: "agent@unknown.example", Body: "x",
	}}, map[string]*InboundRelayer{"mail.orga.io": orgA})
	res, _ := m.Handle(context.Background(), nil, nil)
	if res.Drop != DropNoOrg || s.calls != 0 {
		t.Fatalf("unknown domain must drop as no_org without minting, got %+v calls=%d", res, s.calls)
	}
}

func TestMultiOrgCrossTenantSenderIsolation(t *testing.T) {
	// owner@a.com is allowed in org A but NOT in org B. A message from
	// owner@a.com to org B's domain must be dropped by org B's allowlist.
	s := &mockSender{}
	orgB, _ := buildOrg(t, orgAddr(0x22), s, []string{"owner@b.com"})
	m, _ := NewMultiOrgRelayer(mockVerifier{email: &InboundEmail{
		From: "owner@a.com", To: "agent@mail.orgb.io", Body: "x",
	}}, map[string]*InboundRelayer{"mail.orgb.io": orgB})
	res, _ := m.Handle(context.Background(), nil, nil)
	if res.Drop != DropNotAllowed || s.calls != 0 {
		t.Fatalf("cross-tenant sender must be denied by org B allowlist, got %+v", res)
	}
}

func TestMultiOrgRejectsUnverified(t *testing.T) {
	s := &mockSender{}
	orgA, _ := buildOrg(t, orgAddr(0x11), s, []string{"owner@a.com"})
	m, _ := NewMultiOrgRelayer(mockVerifier{err: errTest}, map[string]*InboundRelayer{"mail.orga.io": orgA})
	res, err := m.Handle(context.Background(), nil, nil)
	if res.Drop != DropUnverified || err == nil || s.calls != 0 {
		t.Fatalf("expected unverified drop, got %+v err=%v", res, err)
	}
}

func TestNewMultiOrgRelayerValidation(t *testing.T) {
	s := &mockSender{}
	orgA, _ := buildOrg(t, orgAddr(0x11), s, []string{"owner@a.com"})
	if _, err := NewMultiOrgRelayer(nil, map[string]*InboundRelayer{"mail.orga.io": orgA}); err == nil {
		t.Fatal("nil verifier must be rejected")
	}
	if _, err := NewMultiOrgRelayer(mockVerifier{}, map[string]*InboundRelayer{"bad domain": orgA}); err == nil {
		t.Fatal("invalid domain must be rejected")
	}
	if _, err := NewMultiOrgRelayer(mockVerifier{}, map[string]*InboundRelayer{"mail.orga.io": nil}); err == nil {
		t.Fatal("nil org relayer must be rejected")
	}
}

var errTest = errTestType("verify failed")

type errTestType string

func (e errTestType) Error() string { return string(e) }
