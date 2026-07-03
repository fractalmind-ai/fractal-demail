package bridge

import (
	"context"
	"fmt"
	"strings"

	"github.com/fractalmind-ai/fractal-demail/client-go/schema"
)

// SMTPClient delivers a plaintext email out to Web2. Implemented over a real
// provider (Resend/Postmark/SMTP) in production; mocked in tests.
type SMTPClient interface {
	Send(ctx context.Context, to, subject, body string) error
}

// OutboundConfig configures the outbound watcher.
type OutboundConfig struct {
	// Allowlist gates Web2 recipients (deny-all when empty) so the bridge
	// cannot be turned into a spam cannon.
	Allowlist *Allowlist
	// Limiter throttles per-recipient and global outbound send rate.
	Limiter *RateLimiter
}

// OutboundWatcher turns decrypted on-chain replies (addressed to the bridge)
// into Web2 emails. It consumes messages already decrypted+validated by a
// listener keyed to the bridge address; this core owns the Web2-side policy
// (recipient resolution, allowlist, rate limit) and delivery.
type OutboundWatcher struct {
	cfg  OutboundConfig
	smtp SMTPClient
}

// NewOutboundWatcher validates config and returns a watcher.
func NewOutboundWatcher(cfg OutboundConfig, smtp SMTPClient) (*OutboundWatcher, error) {
	if smtp == nil {
		return nil, fmt.Errorf("smtp client is required")
	}
	if cfg.Allowlist == nil {
		cfg.Allowlist = &Allowlist{} // deny-all
	}
	if cfg.Limiter == nil {
		cfg.Limiter = NewRateLimiter(RateConfig{})
	}
	return &OutboundWatcher{cfg: cfg, smtp: smtp}, nil
}

// OutboundResult is the outcome of one on-chain reply.
type OutboundResult struct {
	Delivered bool
	Drop      DropReason
}

// Additional drop reasons for the outbound path.
const (
	// DropNoWeb2To is a reply with no web2_to (not intended for the bridge).
	DropNoWeb2To DropReason = "no_web2_to"
	// DropDeliverFailed is an SMTP delivery failure.
	DropDeliverFailed DropReason = "deliver_failed"
)

// Handle delivers one decrypted reply out to Web2. The message must carry a
// web2_to; the recipient is gated by allowlist then rate limit (allowlist
// first so an off-list flood cannot drain the outbound token bucket).
func (w *OutboundWatcher) Handle(ctx context.Context, msg *schema.Plaintext) (OutboundResult, error) {
	if msg == nil {
		return OutboundResult{Drop: DropMalformed}, fmt.Errorf("nil message")
	}
	to := normalizeEmail(msg.Web2To)
	if to == "" {
		// No/invalid Web2 recipient: this reply was not meant for the bridge.
		return OutboundResult{Drop: DropNoWeb2To}, nil
	}
	if strings.TrimSpace(msg.Body) == "" {
		return OutboundResult{Drop: DropMalformed}, fmt.Errorf("empty body")
	}
	if !w.cfg.Allowlist.Allows(to) {
		return OutboundResult{Drop: DropNotAllowed}, nil
	}
	if !w.cfg.Limiter.Allow(to) {
		return OutboundResult{Drop: DropRateLimited}, nil
	}
	// schema.Parse already stripped control chars from Web2To (CRLF header
	// injection) and Body; deliver as plaintext.
	if err := w.smtp.Send(ctx, to, msg.Subject, msg.Body); err != nil {
		return OutboundResult{Drop: DropDeliverFailed}, fmt.Errorf("smtp send: %w", err)
	}
	return OutboundResult{Delivered: true}, nil
}
