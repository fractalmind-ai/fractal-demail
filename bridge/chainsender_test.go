package bridge

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	csPkg     = "0x65c96400535e97f9a5c444c284dfb531590f2119f5de4a1253f15f1a99b72e82"
	csSender  = "0xeedfe046af0c10613356dea725fbe22af969a58077f27622936a6c4d9ec2fce3"
	csSponsor = "0xdec6927c11163e81881f24e8f8c07e22bc04f7406dee0f1f0235c2ee99b0cddf"
	csGasCoin = "0xaefda11d73d84d396efc835f68f4d0b243109c3ceede1f64528f1358a9cac902"
	csRecip   = "0xf4fafecc95c2e7c984f8d26db9b692cf58da977ee0119be38b84904b394e82e2"
)

// scriptedExec returns canned CLI outputs and records the calls.
type scriptedExec struct {
	calls [][]string
}

func (s *scriptedExec) run(_ context.Context, name string, args ...string) ([]byte, error) {
	s.calls = append(s.calls, append([]string{name}, args...))
	switch {
	case len(args) >= 2 && args[0] == "client" && args[1] == "ptb":
		return []byte("banner\nTXBYTES_B64"), nil
	case len(args) >= 3 && args[0] == "keytool" && args[1] == "sign":
		return []byte(`{"suiSignature":"SIG_` + args[3] + `"}`), nil
	case len(args) >= 2 && args[0] == "client" && args[1] == "execute-signed-tx":
		return []byte(`{"digest":"0xDIGEST"}`), nil
	}
	return nil, errors.New("unexpected exec: " + strings.Join(args, " "))
}

func newCS(t *testing.T, sponsor string, ex func(context.Context, string, ...string) ([]byte, error)) *CLIChainSender {
	t.Helper()
	c, err := NewCLIChainSender(CLIChainSenderConfig{
		PackageID: csPkg, Sender: csSender, Sponsor: sponsor, GasCoin: csGasCoin,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.execFn = ex
	return c
}

func TestCLIChainSenderDistinctSponsorDualSign(t *testing.T) {
	ex := &scriptedExec{}
	c := newCS(t, csSponsor, ex.run)
	digest, err := c.Send(context.Background(), csRecip, []byte("PAYLOAD_B64"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if digest != "0xDIGEST" {
		t.Fatalf("digest = %q", digest)
	}
	// Expect: ptb serialize, sign(sender), sign(sponsor), execute with 2 sigs.
	signs := 0
	var execArgs []string
	for _, call := range ex.calls {
		if len(call) >= 3 && call[1] == "keytool" && call[2] == "sign" {
			signs++
		}
		if len(call) >= 3 && call[1] == "client" && call[2] == "execute-signed-tx" {
			execArgs = call
		}
	}
	if signs != 2 {
		t.Fatalf("distinct sponsor must sign twice, got %d", signs)
	}
	if n := strings.Count(strings.Join(execArgs, " "), "--signatures"); n != 2 {
		t.Fatalf("execute must carry 2 signatures, got %d", n)
	}
	// The ptb call must place recipient, payload (quoted), sponsor, gas-coin.
	joined := strings.Join(ex.calls[0], " ")
	for _, want := range []string{"send_inline", "@" + csRecip, `"PAYLOAD_B64"`, "--gas-sponsor @" + csSponsor, "--gas-coin @" + csGasCoin} {
		if !strings.Contains(joined, want) {
			t.Fatalf("ptb args missing %q in: %s", want, joined)
		}
	}
}

func TestCLIChainSenderSelfSponsoredSingleSign(t *testing.T) {
	ex := &scriptedExec{}
	c := newCS(t, csSender, ex.run) // sponsor == sender
	if _, err := c.Send(context.Background(), csRecip, []byte("PAYLOAD_B64")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	signs := 0
	var execArgs []string
	for _, call := range ex.calls {
		if len(call) >= 3 && call[1] == "keytool" && call[2] == "sign" {
			signs++
		}
		if len(call) >= 3 && call[1] == "client" && call[2] == "execute-signed-tx" {
			execArgs = call
		}
	}
	if signs != 1 {
		t.Fatalf("self-sponsored must sign once, got %d", signs)
	}
	if n := strings.Count(strings.Join(execArgs, " "), "--signatures"); n != 1 {
		t.Fatalf("self-sponsored execute must carry 1 signature, got %d", n)
	}
}

func TestCLIChainSenderRejectsUnsafePayload(t *testing.T) {
	c := newCS(t, csSender, (&scriptedExec{}).run)
	for _, bad := range []string{"has space", "has\"quote", "-flaglike", "line\nbreak"} {
		if _, err := c.Send(context.Background(), csRecip, []byte(bad)); err == nil {
			t.Fatalf("payload %q must be rejected as unsafe", bad)
		}
	}
}

func TestCLIChainSenderRejectsBadRecipient(t *testing.T) {
	c := newCS(t, csSender, (&scriptedExec{}).run)
	if _, err := c.Send(context.Background(), "0xbad", []byte("PAYLOAD_B64")); err == nil {
		t.Fatal("bad recipient must be rejected")
	}
}

func TestCLIChainSenderSurfacesExecError(t *testing.T) {
	failPtb := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		return nil, errors.New("sui not found")
	}
	c := newCS(t, csSender, failPtb)
	if _, err := c.Send(context.Background(), csRecip, []byte("PAYLOAD_B64")); err == nil {
		t.Fatal("exec failure must surface")
	}
}

func TestNewCLIChainSenderValidation(t *testing.T) {
	base := CLIChainSenderConfig{PackageID: csPkg, Sender: csSender, GasCoin: csGasCoin}
	bad := base
	bad.PackageID = "0xnope"
	if _, err := NewCLIChainSender(bad); err == nil {
		t.Fatal("bad package must be rejected")
	}
	bad = base
	bad.GasCoin = ""
	if _, err := NewCLIChainSender(bad); err == nil {
		t.Fatal("missing gas coin must be rejected")
	}
	// Sponsor defaults to sender.
	c, err := NewCLIChainSender(base)
	if err != nil {
		t.Fatal(err)
	}
	if c.sponsor != csSender {
		t.Fatalf("sponsor should default to sender, got %q", c.sponsor)
	}
}
