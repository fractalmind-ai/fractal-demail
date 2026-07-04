package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	gasstation "github.com/fractalmind-ai/fractal-demail/gas-station-adapter"
)

// CLIChainSender is the production ChainSender: it mints a demail Message via
// the sui CLI using the sponsored dual/single-sign flow, routed through the
// gas-station-adapter so the route/signature invariants apply. The bridge's
// Sui identity is the sender; a sponsor (possibly the same address —
// self-sponsored single-sig) pays gas. exec is injected for tests.
type CLIChainSender struct {
	packageID string
	sender    string // bridge Sui address (on-chain `from`)
	sponsor   string // gas sponsor address (== sender for self-sponsored)
	gasCoin   string // sponsor-owned gas coin object id
	gasBudget string
	execFn    func(ctx context.Context, name string, args ...string) ([]byte, error)
}

const (
	demailClockObjectID = "0x6"
	defaultGasBudget    = "10000000"
)

// CLIChainSenderConfig configures the sender. Sponsor defaults to Sender
// (self-sponsored). GasCoin is required for outbound mints.
type CLIChainSenderConfig struct {
	PackageID string
	Sender    string
	Sponsor   string
	GasCoin   string
	GasBudget string
}

// NewCLIChainSender validates config and returns a sender.
func NewCLIChainSender(cfg CLIChainSenderConfig) (*CLIChainSender, error) {
	if _, err := hexAddress(cfg.PackageID); err != nil {
		return nil, fmt.Errorf("packageId: %w", err)
	}
	if _, err := hexAddress(cfg.Sender); err != nil {
		return nil, fmt.Errorf("sender: %w", err)
	}
	sponsor := strings.TrimSpace(cfg.Sponsor)
	if sponsor == "" {
		sponsor = cfg.Sender
	}
	if _, err := hexAddress(sponsor); err != nil {
		return nil, fmt.Errorf("sponsor: %w", err)
	}
	if _, err := hexAddress(cfg.GasCoin); err != nil {
		return nil, fmt.Errorf("gasCoin: %w", err)
	}
	budget := strings.TrimSpace(cfg.GasBudget)
	if budget == "" {
		budget = defaultGasBudget
	}
	return &CLIChainSender{
		packageID: cfg.PackageID,
		sender:    cfg.Sender,
		sponsor:   sponsor,
		gasCoin:   cfg.GasCoin,
		gasBudget: budget,
		execFn: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			if err != nil {
				tail := lastNonEmptyLine(string(out))
				if len(tail) > 300 {
					tail = tail[:300]
				}
				return out, fmt.Errorf("%w: %s", err, tail)
			}
			return out, nil
		},
	}, nil
}

// Send mints `payload` (canonical inline bytes) to recipient and returns the
// tx digest. payload must already be a CLI-safe base64 string; recipient must
// be a valid Sui address.
func (c *CLIChainSender) Send(ctx context.Context, recipient string, payload []byte) (string, error) {
	if _, err := hexAddress(recipient); err != nil {
		return "", fmt.Errorf("recipient: %w", err)
	}
	// Guard against argv-injection: the payload is placed next to CLI flags.
	payloadStr := string(payload)
	if strings.ContainsAny(payloadStr, " \t\r\n\"'") || strings.HasPrefix(payloadStr, "-") {
		return "", fmt.Errorf("payload is not a bare CLI-safe token")
	}

	txBytes, err := c.serializeUnsignedTx(ctx, recipient, payloadStr)
	if err != nil {
		return "", err
	}

	transport := &cliChainTransport{execFn: c.execFn}
	route := gasstation.Route{Sender: c.sender, GasSponsor: c.sponsor}
	relay, err := gasstation.New(route, transport)
	if err != nil {
		return "", fmt.Errorf("relay init: %w", err)
	}
	var sponsorSigner gasstation.Signer
	if !route.SelfSponsored() {
		sponsorSigner = c.suiSigner(c.sponsor)
	}
	req, err := relay.Sponsor(ctx, []byte(txBytes), c.suiSigner(c.sender), sponsorSigner)
	if err != nil {
		return "", fmt.Errorf("sponsor signing: %w", err)
	}
	if err := relay.Relay(ctx, req); err != nil {
		return "", fmt.Errorf("relay: %w", err)
	}
	return transport.digest, nil
}

func (c *CLIChainSender) serializeUnsignedTx(ctx context.Context, recipient, payload string) (string, error) {
	args := []string{
		"client", "ptb",
		"--sender", "@" + c.sender,
		"--move-call", c.packageID + "::demail::send_inline",
		"@" + recipient,
		`"` + payload + `"`,
		"@" + demailClockObjectID,
		"--gas-sponsor", "@" + c.sponsor,
		"--gas-coin", "@" + c.gasCoin,
		"--gas-budget", c.gasBudget,
		"--serialize-unsigned-transaction",
	}
	out, err := c.execFn(ctx, "sui", args...)
	if err != nil {
		return "", fmt.Errorf("tx serialization: %w", err)
	}
	tx := lastNonEmptyLine(string(out))
	if tx == "" {
		return "", fmt.Errorf("tx serialization returned no bytes")
	}
	return tx, nil
}

// suiSigner signs base64 tx bytes with the sui keytool for the given address.
func (c *CLIChainSender) suiSigner(address string) gasstation.Signer {
	return func(ctx context.Context, txBytes []byte) ([]byte, error) {
		out, err := c.execFn(ctx, "sui", "keytool", "sign", "--address", address, "--data", string(txBytes), "--json")
		if err != nil {
			return nil, fmt.Errorf("keytool sign %s: %w", address, err)
		}
		var res struct {
			SuiSignature string `json:"suiSignature"`
		}
		if err := unmarshalLastJSON(out, &res); err != nil {
			return nil, fmt.Errorf("keytool sign json: %w", err)
		}
		sig := strings.TrimSpace(res.SuiSignature)
		if sig == "" {
			return nil, fmt.Errorf("keytool sign %s: empty signature", address)
		}
		return []byte(sig), nil
	}
}

// cliChainTransport executes the dual/single-signed tx via the sui CLI,
// submitting only non-empty signatures (self-sponsored → one).
type cliChainTransport struct {
	execFn func(ctx context.Context, name string, args ...string) ([]byte, error)
	digest string
}

func (t *cliChainTransport) Relay(ctx context.Context, req gasstation.RelayRequest) error {
	args := []string{"client", "execute-signed-tx", "--tx-bytes", string(req.UnsignedTx)}
	for _, sig := range [][]byte{req.SenderSignature, req.SponsorSignature} {
		if len(sig) > 0 {
			args = append(args, "--signatures", string(sig))
		}
	}
	args = append(args, "--json")
	out, err := t.execFn(ctx, "sui", args...)
	if err != nil {
		return fmt.Errorf("execute-signed-tx: %w", err)
	}
	var res struct {
		Digest string `json:"digest"`
	}
	if err := unmarshalLastJSON(out, &res); err != nil {
		return fmt.Errorf("execute-signed-tx json: %w", err)
	}
	if strings.TrimSpace(res.Digest) == "" {
		return fmt.Errorf("execute-signed-tx returned no digest")
	}
	t.digest = strings.TrimSpace(res.Digest)
	return nil
}

// unmarshalLastJSON finds the first '{' and decodes from there, tolerating
// CLI banner lines before the JSON document.
func unmarshalLastJSON(out []byte, v any) error {
	i := strings.IndexByte(string(out), '{')
	if i < 0 {
		return fmt.Errorf("no json document in output")
	}
	return json.Unmarshal(out[i:], v)
}

func lastNonEmptyLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}
