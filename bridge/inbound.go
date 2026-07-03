package bridge

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fractalmind-ai/fractal-demail/client-go/envelope"
	"github.com/fractalmind-ai/fractal-demail/client-go/schema"
)

// InboundEmail is a Web2 message extracted from a verified provider webhook.
type InboundEmail struct {
	From    string // Web2 sender address
	To      string // Web2 recipient, e.g. agent@mail.example.com
	Subject string
	Body    string
}

// WebhookVerifier authenticates a provider webhook (signature/HMAC) and
// returns the parsed email. Provider-specific; mocked in tests. It MUST reject
// unsigned or tampered requests.
type WebhookVerifier interface {
	Verify(headers map[string]string, body []byte) (*InboundEmail, error)
}

// ChainSender mints a Message on-chain to recipient. Implemented over the sui
// CLI / gas-station-adapter in production; mocked in tests. payload is the
// canonical inline bytes (base64 text of the envelope JSON).
type ChainSender interface {
	Send(ctx context.Context, recipient string, payload []byte) (txDigest string, err error)
}

// Agent is a bridge-reachable node: its Sui address and Ed25519 public key
// (needed to seal the envelope — a Sui address cannot be reversed to a key).
type Agent struct {
	SuiAddress string
	PubKey     ed25519.PublicKey
}

// InboundConfig configures the inbound relayer.
type InboundConfig struct {
	// BridgeAddress is the bridge's own Sui identity; it is the on-chain
	// `from` of every relayed message (added to each agent's allowedSenders).
	BridgeAddress string
	// Agents maps the recipient localpart (before @) to the target agent.
	Agents map[string]Agent
	// Allowlist gates Web2 senders (deny-all when empty) — primary gas-drain
	// defense.
	Allowlist *Allowlist
	// Limiter throttles per-sender and global mint rate.
	Limiter *RateLimiter
	// Now is injectable for tests.
	Now func() time.Time
}

// InboundRelayer turns verified Web2 email into sponsored on-chain Messages.
type InboundRelayer struct {
	cfg      InboundConfig
	verifier WebhookVerifier
	sender   ChainSender
}

// NewInboundRelayer validates config and returns a relayer.
func NewInboundRelayer(cfg InboundConfig, verifier WebhookVerifier, sender ChainSender) (*InboundRelayer, error) {
	if _, err := hexAddress(cfg.BridgeAddress); err != nil {
		return nil, fmt.Errorf("bridge address: %w", err)
	}
	if verifier == nil || sender == nil {
		return nil, fmt.Errorf("verifier and sender are required")
	}
	if cfg.Allowlist == nil {
		cfg.Allowlist = &Allowlist{} // deny-all
	}
	if cfg.Limiter == nil {
		cfg.Limiter = NewRateLimiter(RateConfig{}) // unlimited unless configured
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// Recipient localparts are matched case-insensitively (lowercased), so
	// normalize the map keys here — a mixed-case config key would otherwise
	// silently 404 every message.
	agents := make(map[string]Agent, len(cfg.Agents))
	for lp, ag := range cfg.Agents {
		if _, err := hexAddress(ag.SuiAddress); err != nil {
			return nil, fmt.Errorf("agent %q address: %w", lp, err)
		}
		if len(ag.PubKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("agent %q pubkey must be %d bytes", lp, ed25519.PublicKeySize)
		}
		key := strings.ToLower(strings.TrimSpace(lp))
		if key == "" {
			return nil, fmt.Errorf("agent localpart must not be blank")
		}
		if _, dup := agents[key]; dup {
			return nil, fmt.Errorf("agent localpart %q duplicated after normalization", key)
		}
		agents[key] = ag
	}
	cfg.Agents = agents
	return &InboundRelayer{cfg: cfg, verifier: verifier, sender: sender}, nil
}

// DropReason categorizes why an inbound message was not relayed. It lets the
// HTTP layer map outcomes to status codes without leaking internals.
type DropReason string

const (
	DropUnverified  DropReason = "unverified"   // bad/absent signature
	DropNotAllowed  DropReason = "not_allowed"  // sender off allowlist
	DropRateLimited DropReason = "rate_limited" // over per-sender/global cap
	DropNoRecipient DropReason = "no_recipient" // unknown localpart
	DropMalformed   DropReason = "malformed"    // unparseable email fields
	DropSendFailed  DropReason = "send_failed"  // chain mint failed
	DropNoOrg       DropReason = "no_org"       // recipient domain has no org
)

// RelayResult is the outcome of one webhook.
type RelayResult struct {
	Delivered bool
	TxDigest  string
	Drop      DropReason
}

// Handle processes one provider webhook end to end.
func (r *InboundRelayer) Handle(ctx context.Context, headers map[string]string, body []byte) (RelayResult, error) {
	email, err := r.verifier.Verify(headers, body)
	if err != nil {
		return RelayResult{Drop: DropUnverified}, fmt.Errorf("verify: %w", err)
	}
	return r.deliver(ctx, email)
}

// deliver runs the post-verification pipeline for an already-authenticated
// email. Shared with the multi-org router, which verifies once and then
// dispatches to the org owning the recipient domain.
func (r *InboundRelayer) deliver(ctx context.Context, email *InboundEmail) (RelayResult, error) {
	from := normalizeEmail(email.From)
	if from == "" {
		return RelayResult{Drop: DropMalformed}, fmt.Errorf("malformed sender %q", email.From)
	}
	// Allowlist BEFORE rate limit: an off-list sender must never consume a
	// token (else a flood of unknown senders exhausts the global bucket and
	// denies real ones).
	if !r.cfg.Allowlist.Allows(from) {
		return RelayResult{Drop: DropNotAllowed}, nil
	}
	// An empty body would seal and mint, then be dropped as poison at the
	// agent (schema.Parse requires body) — reject before spending gas.
	if strings.TrimSpace(email.Body) == "" {
		return RelayResult{Drop: DropMalformed}, fmt.Errorf("empty body")
	}
	localpart := recipientLocalpart(email.To)
	agent, ok := r.cfg.Agents[localpart]
	if !ok {
		return RelayResult{Drop: DropNoRecipient}, nil
	}
	if !r.cfg.Limiter.Allow(from) {
		return RelayResult{Drop: DropRateLimited}, nil
	}

	payload, err := r.sealForAgent(from, agent, email)
	if err != nil {
		return RelayResult{Drop: DropMalformed}, err
	}
	digest, err := r.sender.Send(ctx, agent.SuiAddress, payload)
	if err != nil {
		return RelayResult{Drop: DropSendFailed}, fmt.Errorf("chain send: %w", err)
	}
	return RelayResult{Delivered: true, TxDigest: digest}, nil
}

func (r *InboundRelayer) sealForAgent(from string, agent Agent, email *InboundEmail) ([]byte, error) {
	bridgeRaw, err := hexAddress(r.cfg.BridgeAddress)
	if err != nil {
		return nil, err
	}
	agentRaw, err := hexAddress(agent.SuiAddress)
	if err != nil {
		return nil, err
	}
	// On-chain route is bridge -> agent; the real Web2 sender rides in
	// web2_from so provenance survives without breaking route enforcement.
	pt := schema.Plaintext{
		Type:     schema.TypeTask,
		From:     r.cfg.BridgeAddress,
		To:       agent.SuiAddress,
		Subject:  email.Subject,
		Body:     email.Body,
		TS:       r.cfg.Now().UnixMilli(),
		Web2From: from,
	}
	plaintext, err := json.Marshal(pt)
	if err != nil {
		return nil, fmt.Errorf("marshal plaintext: %w", err)
	}
	env, err := envelope.Seal(agent.PubKey, bridgeRaw, agentRaw, plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	wire, err := env.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	// Canonical inline encoding: base64 text of the envelope JSON.
	enc := base64.StdEncoding.EncodeToString(wire)
	return []byte(enc), nil
}

// recipientLocalpart returns the lowercased localpart of an email address.
func recipientLocalpart(addr string) string {
	addr = normalizeEmail(addr)
	if addr == "" {
		return ""
	}
	return addr[:strings.IndexByte(addr, '@')]
}

// emailDomain returns the lowercased domain of an email address, or "" if the
// address is malformed.
func emailDomain(addr string) string {
	addr = normalizeEmail(addr)
	if addr == "" {
		return ""
	}
	return addr[strings.IndexByte(addr, '@')+1:]
}

// hexAddress validates and decodes a 0x Sui address to 32 raw bytes.
func hexAddress(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if len(s) != 64 {
		return nil, fmt.Errorf("address must be 32 bytes, got %d hex chars", len(s))
	}
	return hex.DecodeString(s)
}
