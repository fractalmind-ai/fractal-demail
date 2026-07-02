package gasstation

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	testSender     = "0xf4fafecc95c2e7c984f8d26db9b692cf58da977ee0119be38b84904b394e82e2"
	testGasSponsor = "0xeedfe046af0c10613356dea725fbe22af969a58077f27622936a6c4d9ec2fce3"
)

func TestRouteCLIArgs(t *testing.T) {
	args, err := (Route{Sender: strings.ToUpper(testSender), GasSponsor: "  " + strings.ToUpper(testGasSponsor) + "  "}).CLIArgs()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--sender", testSender, "--gas-sponsor", testGasSponsor}
	if len(args) != len(want) {
		t.Fatalf("len(args) = %d, want %d", len(args), len(want))
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestSponsorBuildsDualSignatureEnvelope(t *testing.T) {
	relay, err := New(Route{Sender: testSender, GasSponsor: testGasSponsor}, nil)
	if err != nil {
		t.Fatal(err)
	}

	senderCalls := 0
	sponsorCalls := 0
	req, err := relay.Sponsor(context.Background(), []byte("unsigned"), func(context.Context, []byte) ([]byte, error) {
		senderCalls++
		return []byte("sender-sig"), nil
	}, func(context.Context, []byte) ([]byte, error) {
		sponsorCalls++
		return []byte("sponsor-sig"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if senderCalls != 1 || sponsorCalls != 1 {
		t.Fatalf("signer calls = %d/%d, want 1/1", senderCalls, sponsorCalls)
	}
	if !bytes.Equal(req.UnsignedTx, []byte("unsigned")) {
		t.Fatalf("unsigned tx = %q", req.UnsignedTx)
	}
	if !bytes.Equal(req.SenderSignature, []byte("sender-sig")) {
		t.Fatalf("sender sig = %q", req.SenderSignature)
	}
	if !bytes.Equal(req.SponsorSignature, []byte("sponsor-sig")) {
		t.Fatalf("sponsor sig = %q", req.SponsorSignature)
	}
	if req.Route.Sender != testSender || req.Route.GasSponsor != testGasSponsor {
		t.Fatalf("route = %+v", req.Route)
	}
}

func TestSponsorRequiresBothSigners(t *testing.T) {
	relay, err := New(Route{Sender: testSender, GasSponsor: testGasSponsor}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.Sponsor(context.Background(), []byte("unsigned"), nil, nil); err == nil {
		t.Fatal("expected error for missing signers")
	}
}

func TestRelayDelegatesToTransport(t *testing.T) {
	var got RelayRequest
	relay, err := New(Route{Sender: testSender, GasSponsor: testGasSponsor}, TransportFunc(func(_ context.Context, req RelayRequest) error {
		got = req
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	// A request without its own route must be rejected, not silently stamped.
	if err := relay.Relay(context.Background(), RelayRequest{
		UnsignedTx:       []byte("tx"),
		SenderSignature:  []byte("s1"),
		SponsorSignature: []byte("s2"),
	}); err == nil {
		t.Fatal("expected rejection of request without route")
	}
	req := RelayRequest{
		Route:            Route{Sender: testSender, GasSponsor: testGasSponsor},
		UnsignedTx:       []byte("tx"),
		SenderSignature:  []byte("s1"),
		SponsorSignature: []byte("s2"),
	}
	if err := relay.Relay(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.UnsignedTx, []byte("tx")) || !bytes.Equal(got.SenderSignature, []byte("s1")) || !bytes.Equal(got.SponsorSignature, []byte("s2")) {
		t.Fatalf("transport got %+v", got)
	}
	if got.Route.Sender != testSender || got.Route.GasSponsor != testGasSponsor {
		t.Fatalf("transport route = %+v", got.Route)
	}
}

func TestRelayAcceptsEquivalentCanonicalRoute(t *testing.T) {
	relay, err := New(Route{Sender: testSender, GasSponsor: testGasSponsor}, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := RelayRequest{
		Route:            Route{Sender: strings.ToUpper(testSender), GasSponsor: strings.ToUpper(testGasSponsor)},
		UnsignedTx:       []byte("tx"),
		SenderSignature:  []byte("s1"),
		SponsorSignature: []byte("s2"),
	}
	if err := relay.Relay(context.Background(), req); err != nil {
		t.Fatalf("equivalent route rejected: %v", err)
	}
}

func TestRelayRejectsBadEnvelope(t *testing.T) {
	relay, err := New(Route{Sender: testSender, GasSponsor: testGasSponsor}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.Relay(context.Background(), RelayRequest{}); err == nil {
		t.Fatal("expected error for missing envelope fields")
	}
}

func TestNewRejectsMalformedAddress(t *testing.T) {
	if _, err := New(Route{Sender: "0x123", GasSponsor: testGasSponsor}, nil); err == nil {
		t.Fatal("expected malformed sender address rejection")
	}
}

type TransportFunc func(context.Context, RelayRequest) error

func (f TransportFunc) Relay(ctx context.Context, req RelayRequest) error { return f(ctx, req) }

func TestSponsorPropagatesSignerError(t *testing.T) {
	relay, err := New(Route{Sender: testSender, GasSponsor: testGasSponsor}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("boom")
	_, err = relay.Sponsor(context.Background(), []byte("unsigned"), func(context.Context, []byte) ([]byte, error) {
		return nil, want
	}, func(context.Context, []byte) ([]byte, error) {
		return []byte("sponsor"), nil
	})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}
