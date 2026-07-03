// Package gasstation codes the outbound sponsored-transaction relay used by
// fractalbot in Phase 1.
//
// The package is intentionally small: it validates the verified dual-sign
// route (`--sender` + `--gas-sponsor`), collects both signatures over the same
// unsigned transaction bytes, and hands the sealed request to a transport.
//
// Self-sponsored routes (sender == gas sponsor) are a single-signature
// special case: Sui expects exactly one signature when the sender pays its
// own gas, so Sponsor collects only the sender signature and Relay enforces
// that the sponsor signature stays empty. Transports must submit only the
// non-empty signatures on a request.
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

// SelfSponsored reports whether the canonical sender and canonical gas
// sponsor are the same address, i.e. the sender pays its own gas. A route
// that fails canonicalization is never self-sponsored.
func (r Route) SelfSponsored() bool {
	canonical, err := normalizeRoute(r)
	if err != nil {
		return false
	}
	return canonical.Sender == canonical.GasSponsor
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
//
// SenderSignature is always present. SponsorSignature is present exactly
// when the route is NOT self-sponsored: on a self-sponsored route
// (Route.SelfSponsored() == true) Sui expects a single signature, so
// SponsorSignature is nil/empty. Transports must submit only the non-empty
// signatures and can use SponsorSignature emptiness (or Route.SelfSponsored)
// to distinguish the two modes.
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

// Sponsor collects the signatures over the same transaction bytes.
//
// On a distinct-address route it collects both signatures and both signers
// are required. On a self-sponsored route Sui expects exactly one signature,
// so only senderSigner is called and the sponsorSigner may be nil; the
// returned request carries an empty SponsorSignature.
func (r *Relay) Sponsor(ctx context.Context, unsignedTx []byte, senderSigner, sponsorSigner Signer) (RelayRequest, error) {
	if r == nil {
		return RelayRequest{}, errors.New("relay is nil")
	}
	if len(unsignedTx) == 0 {
		return RelayRequest{}, errors.New("unsigned tx is required")
	}
	if err := r.Route.Validate(); err != nil {
		return RelayRequest{}, err
	}
	selfSponsored := r.Route.SelfSponsored()
	if senderSigner == nil {
		return RelayRequest{}, errors.New("senderSigner is required")
	}
	if sponsorSigner == nil && !selfSponsored {
		return RelayRequest{}, errors.New("sponsorSigner is required for a distinct gas sponsor")
	}

	// Copy before signing so neither signer (nor the caller, concurrently)
	// can mutate the bytes between the two signatures — both signatures must
	// cover the identical transaction.
	tx := append([]byte(nil), unsignedTx...)
	senderSig, err := senderSigner(ctx, tx)
	if err != nil {
		return RelayRequest{}, fmt.Errorf("sender sign: %w", err)
	}
	if selfSponsored {
		// Single-signature mode: the sender signature is the only signature
		// Sui accepts, so sponsorSigner is never called even when non-nil.
		return RelayRequest{
			Route:           r.Route,
			UnsignedTx:      tx,
			SenderSignature: append([]byte(nil), senderSig...),
		}, nil
	}
	sponsorSig, err := sponsorSigner(ctx, tx)
	if err != nil {
		return RelayRequest{}, fmt.Errorf("gas sponsor sign: %w", err)
	}
	return RelayRequest{
		Route:            r.Route,
		UnsignedTx:       tx,
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
	// The request must carry its own route and it must match this relay —
	// silently stamping an empty route would hide caller wiring bugs.
	canonicalReqRoute, err := normalizeRoute(req.Route)
	if err != nil {
		return fmt.Errorf("request route: %w", err)
	}
	if canonicalReqRoute != canonicalRoute {
		return fmt.Errorf("request route %q/%q does not match relay route %q/%q",
			req.Route.Sender, req.Route.GasSponsor, r.Route.Sender, r.Route.GasSponsor)
	}
	req.Route = canonicalRoute
	if len(req.UnsignedTx) == 0 {
		return errors.New("unsigned tx is required")
	}
	if len(req.SenderSignature) == 0 {
		return errors.New("sender signature is required")
	}
	if canonicalRoute.Sender == canonicalRoute.GasSponsor {
		// Self-sponsored: Sui expects exactly one signature. A sponsor
		// signature here is ambiguous — fail loudly instead of letting a
		// transport submit two signatures and get rejected on-chain.
		if len(req.SponsorSignature) != 0 {
			return errors.New("gas sponsor signature must be empty on a self-sponsored route")
		}
	} else if len(req.SponsorSignature) == 0 {
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
