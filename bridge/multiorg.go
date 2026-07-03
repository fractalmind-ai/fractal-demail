package bridge

import (
	"context"
	"fmt"
	"strings"
)

// MultiOrgRelayer is a multi-tenant inbound relayer: each organization owns an
// email domain and its own config (bridge Sui identity, agents, allowlist,
// rate limits). One provider account/webhook is shared, so the webhook is
// verified ONCE at this layer and then dispatched to the org that owns the
// recipient's domain. This satisfies "每个组织配置自己的邮件域名".
type MultiOrgRelayer struct {
	verifier WebhookVerifier
	// orgs is keyed by lowercased email domain (e.g. "mail.algonius.ai").
	orgs map[string]*InboundRelayer
}

// NewMultiOrgRelayer builds a router. Each org value is a fully-configured
// single-org InboundRelayer (built with the same shared verifier+sender);
// the router calls their post-verify pipeline, never their Handle, so the
// webhook is verified exactly once. Domain keys are normalized to lowercase;
// an unknown recipient domain is dropped as DropNoOrg (no token spent).
func NewMultiOrgRelayer(verifier WebhookVerifier, orgs map[string]*InboundRelayer) (*MultiOrgRelayer, error) {
	if verifier == nil {
		return nil, fmt.Errorf("verifier is required")
	}
	norm := make(map[string]*InboundRelayer, len(orgs))
	for domain, r := range orgs {
		d := emailDomain("x@" + strings.TrimSpace(domain))
		if d == "" {
			return nil, fmt.Errorf("invalid org domain %q", domain)
		}
		if r == nil {
			return nil, fmt.Errorf("org %q relayer is nil", domain)
		}
		if _, dup := norm[d]; dup {
			return nil, fmt.Errorf("org domain %q duplicated after normalization", d)
		}
		norm[d] = r
	}
	return &MultiOrgRelayer{verifier: verifier, orgs: norm}, nil
}

// Handle verifies the webhook once, resolves the org by the recipient's
// domain, and runs that org's delivery pipeline.
func (m *MultiOrgRelayer) Handle(ctx context.Context, headers map[string]string, body []byte) (RelayResult, error) {
	email, err := m.verifier.Verify(headers, body)
	if err != nil {
		return RelayResult{Drop: DropUnverified}, fmt.Errorf("verify: %w", err)
	}
	domain := emailDomain(email.To)
	if domain == "" {
		return RelayResult{Drop: DropMalformed}, fmt.Errorf("malformed recipient %q", email.To)
	}
	org, ok := m.orgs[domain]
	if !ok {
		// Unknown tenant domain: drop before any token/gas spend.
		return RelayResult{Drop: DropNoOrg}, nil
	}
	return org.deliver(ctx, email)
}
