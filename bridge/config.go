package bridge

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// RelayerConfig is the deploy-time configuration for the inbound bridge
// service. Secrets (the webhook signing secret) are read from the environment,
// not this file, so the file itself carries no credentials.
type RelayerConfig struct {
	// Bind is the HTTP listen address, e.g. ":8080".
	Bind string `json:"bind"`
	// PackageID is the fractal-demail Move package.
	PackageID string `json:"packageId"`
	// Orgs is the per-tenant configuration keyed by email domain.
	Orgs []OrgJSON `json:"orgs"`
	// MaxBodyBytes caps the inbound webhook body (default 1 MiB).
	MaxBodyBytes int64 `json:"maxBodyBytes,omitempty"`
}

// OrgJSON is one tenant.
type OrgJSON struct {
	Domain         string      `json:"domain"`
	BridgeAddress  string      `json:"bridgeAddress"`
	SponsorAddress string      `json:"sponsorAddress,omitempty"` // defaults to bridge
	GasCoin        string      `json:"gasCoin"`
	AllowedSenders []string    `json:"allowedSenders"`
	Agents         []AgentJSON `json:"agents"`
	// Rate limits (0 = unlimited).
	PerSenderPerHour int `json:"perSenderPerHour,omitempty"`
	PerSenderBurst   int `json:"perSenderBurst,omitempty"`
	GlobalPerHour    int `json:"globalPerHour,omitempty"`
	GlobalBurst      int `json:"globalBurst,omitempty"`
}

// AgentJSON maps a recipient localpart to an agent's Sui address + base64
// Ed25519 public key.
type AgentJSON struct {
	Localpart  string `json:"localpart"`
	SuiAddress string `json:"suiAddress"`
	PubKey     string `json:"pubKey"`
}

// LoadRelayerConfig reads and parses a JSON config file.
func LoadRelayerConfig(path string) (*RelayerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg RelayerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// BuildServer assembles the full inbound service from config. webhookSecret is
// the shared Resend/Svix signing secret (from the environment). It returns the
// HTTP server ready to Handler()+ListenAndServe.
func (cfg *RelayerConfig) BuildServer(webhookSecret string) (*WebhookServer, error) {
	verifier, err := NewResendInboundVerifier(webhookSecret)
	if err != nil {
		return nil, err
	}
	if len(cfg.Orgs) == 0 {
		return nil, fmt.Errorf("at least one org is required")
	}
	orgs := make(map[string]*InboundRelayer, len(cfg.Orgs))
	for _, o := range cfg.Orgs {
		agents := make(map[string]Agent, len(o.Agents))
		for _, a := range o.Agents {
			pub, err := base64.StdEncoding.DecodeString(a.PubKey)
			if err != nil || len(pub) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("org %q agent %q: invalid base64 ed25519 pubkey", o.Domain, a.Localpart)
			}
			agents[a.Localpart] = Agent{SuiAddress: a.SuiAddress, PubKey: ed25519.PublicKey(pub)}
		}
		al, err := NewAllowlist(o.AllowedSenders)
		if err != nil {
			return nil, fmt.Errorf("org %q allowlist: %w", o.Domain, err)
		}
		sender, err := NewCLIChainSender(CLIChainSenderConfig{
			PackageID: cfg.PackageID,
			Sender:    o.BridgeAddress,
			Sponsor:   o.SponsorAddress,
			GasCoin:   o.GasCoin,
		})
		if err != nil {
			return nil, fmt.Errorf("org %q chain sender: %w", o.Domain, err)
		}
		relayer, err := NewInboundRelayer(InboundConfig{
			BridgeAddress: o.BridgeAddress,
			Agents:        agents,
			Allowlist:     al,
			Limiter: NewRateLimiter(RateConfig{
				PerSenderPerHour: o.PerSenderPerHour,
				PerSenderBurst:   o.PerSenderBurst,
				GlobalPerHour:    o.GlobalPerHour,
				GlobalBurst:      o.GlobalBurst,
			}),
			Now: time.Now,
		}, verifier, sender)
		if err != nil {
			return nil, fmt.Errorf("org %q relayer: %w", o.Domain, err)
		}
		orgs[o.Domain] = relayer
	}
	multi, err := NewMultiOrgRelayer(verifier, orgs)
	if err != nil {
		return nil, err
	}
	return NewWebhookServer(multi, cfg.MaxBodyBytes, nil), nil
}
