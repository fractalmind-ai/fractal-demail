// Package gasstation codes the outbound sponsored-transaction relay used by
// fractalbot in Phase 1.
//
// The package is intentionally small: it validates the verified dual-sign
// route (`--sender` + `--gas-sponsor`), collects both signatures over the same
// unsigned transaction bytes, and hands the sealed request to a transport.
//
// It does not talk to a real sponsor provider yet; the transport is an
// interface so a Testnet pool / provider client can be wired in later without
// changing the Phase 1 contract.
package gasstation

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Signer signs the same unsigned transaction bytes that will be sponsored.
type Signer func(context.Context, []byte) ([]byte, error)

// Transport submits the dual-signed request to a sponsor pool or provider.
type Transport interface {
	Relay(context.Context, RelayRequest) error
}

// Route identifies the verified dual-sign path.
type Route struct {
	Sender     string
	GasSponsor string
}

// Validate rejects empty or malformed Sui addresses.
func (r Route) Validate() error {
	if _, err := normalizeAddress(r.Sender); err != nil {
		return fmt.Errorf("sender: %w", err)
	}
	if _, err := normalizeAddress(r.GasSponsor); err != nil {
		return fmt.Errorf("gas sponsor: %w", err)
	}
	return nil
}

// CLIArgs returns the minimal verified flag set used by the dual-sign flow.
func (r Route) CLIArgs() ([]string, error) {
	sender, err := canonicalAddress(r.Sender)
	if err != nil {
		return nil, fmt.Errorf("sender: %w", err)
	}
	sponsor, err := canonicalAddress(r.GasSponsor)
	if err != nil {
		return nil, fmt.Errorf("gas sponsor: %w", err)
	}
	return []string{"--sender", sender, "--gas-sponsor", sponsor}, nil
}

// RelayRequest is the sealed outbound sponsorship envelope.
type RelayRequest struct {
	Route            Route
	UnsignedTx       []byte
	SenderSignature  []byte
	SponsorSignature []byte
}

// Relay wires the route to the submission transport.
type Relay struct {
	Route     Route
	Transport Transport
}

// New validates the route and returns a ready relay.
func New(route Route, transport Transport) (*Relay, error) {
	if err := route.Validate(); err != nil {
		return nil, err
	}
	return &Relay{Route: route, Transport: transport}, nil
}

// Sponsor collects both signatures over the same transaction bytes.
func (r *Relay) Sponsor(ctx context.Context, unsignedTx []byte, senderSigner, sponsorSigner Signer) (RelayRequest, error) {
	if r == nil {
		return RelayRequest{}, errors.New("relay is nil")
	}
	if len(unsignedTx) == 0 {
		return RelayRequest{}, errors.New("unsigned tx is required")
	}
	if senderSigner == nil || sponsorSigner == nil {
		return RelayRequest{}, errors.New("both senderSigner and sponsorSigner are required")
	}
	if err := r.Route.Validate(); err != nil {
		return RelayRequest{}, err
	}

	senderSig, err := senderSigner(ctx, unsignedTx)
	if err != nil {
		return RelayRequest{}, fmt.Errorf("sender sign: %w", err)
	}
	sponsorSig, err := sponsorSigner(ctx, unsignedTx)
	if err != nil {
		return RelayRequest{}, fmt.Errorf("gas sponsor sign: %w", err)
	}
	return RelayRequest{
		Route:            r.Route,
		UnsignedTx:       append([]byte(nil), unsignedTx...),
		SenderSignature:  append([]byte(nil), senderSig...),
		SponsorSignature: append([]byte(nil), sponsorSig...),
	}, nil
}

// Relay submits the sealed request if a transport exists.
func (r *Relay) Relay(ctx context.Context, req RelayRequest) error {
	if r == nil {
		return errors.New("relay is nil")
	}
	canonicalRoute, err := normalizeRoute(r.Route)
	if err != nil {
		return err
	}
	if req.Route != (Route{}) {
		canonicalReqRoute, err := normalizeRoute(req.Route)
		if err != nil {
			return err
		}
		if canonicalReqRoute != canonicalRoute {
			return fmt.Errorf("request route %q/%q does not match relay route %q/%q",
				req.Route.Sender, req.Route.GasSponsor, r.Route.Sender, r.Route.GasSponsor)
		}
	}
	req.Route = canonicalRoute
	if len(req.UnsignedTx) == 0 {
		return errors.New("unsigned tx is required")
	}
	if len(req.SenderSignature) == 0 {
		return errors.New("sender signature is required")
	}
	if len(req.SponsorSignature) == 0 {
		return errors.New("gas sponsor signature is required")
	}
	if r.Transport == nil {
		return nil
	}
	return r.Transport.Relay(ctx, req)
}

func normalizeRoute(r Route) (Route, error) {
	sender, err := canonicalAddress(r.Sender)
	if err != nil {
		return Route{}, fmt.Errorf("sender: %w", err)
	}
	sponsor, err := canonicalAddress(r.GasSponsor)
	if err != nil {
		return Route{}, fmt.Errorf("gas sponsor: %w", err)
	}
	return Route{Sender: sender, GasSponsor: sponsor}, nil
}

func canonicalAddress(s string) (string, error) {
	_, err := normalizeAddress(s)
	if err != nil {
		return "", err
	}
	return "0x" + strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"), nil
}

func normalizeAddress(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if len(s) != 64 {
		return nil, fmt.Errorf("address must be 32 bytes, got %d hex chars", len(s))
	}
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return out, nil
}
