// Package listener polls Sui JSON-RPC for fractal-demail MessageSent events
// addressed to this node, fetches the Message object payload, decrypts the
// envelope, and hands sanitized plaintext to a handler — the inbound half of
// the fractalbot gateway integration.
package listener

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fractalmind-ai/fractal-demail/client-go/envelope"
	"github.com/fractalmind-ai/fractal-demail/client-go/schema"
)

// Handler receives each successfully decrypted and validated message.
// messageID is the on-chain Message object id.
type Handler func(messageID string, msg *schema.Plaintext)

// Config for a Listener.
type Config struct {
	RPCURL    string
	PackageID string
	// Recipient is this node's Sui address; events routed elsewhere are ignored.
	Recipient string
	// IdentityKey decrypts envelopes (the node's Ed25519 key).
	IdentityKey ed25519.PrivateKey
	// PollInterval defaults to 2s.
	PollInterval time.Duration
	// HTTPClient defaults to a client with a 15s timeout.
	HTTPClient *http.Client
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// CursorFile persists the poll cursor across restarts. Without it the
	// cursor is memory-only and a restart would replay all history through
	// the handler; with it, only messages since the last processed event
	// are (re)delivered. On the very first run (no file, no cursor) the
	// listener initializes from the newest existing event and does NOT
	// replay history.
	CursorFile string
}

// Listener polls suix_queryEvents with a cursor and processes new events.
type Listener struct {
	cfg       Config
	handler   Handler
	cursor    json.RawMessage
	needsInit bool
}

func New(cfg Config, handler Handler) (*Listener, error) {
	if cfg.RPCURL == "" || cfg.PackageID == "" || cfg.Recipient == "" {
		return nil, fmt.Errorf("RPCURL, PackageID and Recipient are required")
	}
	if _, err := decodeAddress(cfg.Recipient); err != nil {
		return nil, fmt.Errorf("invalid Recipient: %w", err)
	}
	if len(cfg.IdentityKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("IdentityKey must be a %d-byte ed25519 private key", ed25519.PrivateKeySize)
	}
	if handler == nil {
		return nil, fmt.Errorf("handler is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.HTTPClient == nil {
		// A hung connection must not stall the poll loop forever.
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	l := &Listener{cfg: cfg, handler: handler}
	if cfg.CursorFile != "" {
		data, err := os.ReadFile(cfg.CursorFile)
		switch {
		case err == nil && json.Valid(data) && string(data) != "null":
			l.cursor = json.RawMessage(data)
		case err == nil:
			// Corrupt/empty checkpoint: safer to skip history than replay it.
			l.needsInit = true
		case os.IsNotExist(err):
			// Fresh deployment: position at the newest event, do not replay
			// history through the handler.
			l.needsInit = true
		default:
			return nil, fmt.Errorf("read cursor file: %w", err)
		}
	}
	return l, nil
}

// setCursor advances the cursor and best-effort persists it. Persistence
// failures are logged, not fatal: losing a checkpoint means re-delivery,
// which downstream must tolerate anyway.
func (l *Listener) setCursor(cursor json.RawMessage) {
	if cursor == nil || string(cursor) == "null" {
		return
	}
	l.cursor = cursor
	if l.cfg.CursorFile == "" {
		return
	}
	tmp := l.cfg.CursorFile + ".tmp"
	if err := os.WriteFile(tmp, cursor, 0o600); err != nil {
		l.cfg.Logger.Warn("demail: persist cursor", "err", err)
		return
	}
	if err := os.Rename(tmp, l.cfg.CursorFile); err != nil {
		l.cfg.Logger.Warn("demail: persist cursor", "err", err)
	}
}

// initCursorFromLatest positions a brand-new listener at the newest existing
// event so history is not replayed through the handler.
func (l *Listener) initCursorFromLatest(ctx context.Context) error {
	filter := map[string]any{
		"MoveEventType": l.cfg.PackageID + "::demail::MessageSent",
	}
	var res queryEventsResult
	// descending_order=true: first page starts at the newest event.
	if err := l.call(ctx, "suix_queryEvents", []any{filter, nil, 1, true}, &res); err != nil {
		return err
	}
	if len(res.Data) > 0 {
		l.setCursor(res.Data[0].ID)
	}
	l.needsInit = false
	return nil
}

// Run polls until ctx is cancelled. Poll errors are logged and retried on the
// next tick; they never stop the loop.
func (l *Listener) Run(ctx context.Context) error {
	ticker := time.NewTicker(l.cfg.PollInterval)
	defer ticker.Stop()
	for {
		if err := l.PollOnce(ctx); err != nil {
			l.cfg.Logger.Warn("demail poll failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (l *Listener) call(ctx context.Context, method string, params []any, out any) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.cfg.RPCURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: http %d", method, resp.StatusCode)
	}
	var rpc rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpc); err != nil {
		return fmt.Errorf("%s: decode: %w", method, err)
	}
	if rpc.Error != nil {
		return fmt.Errorf("%s: rpc error %d: %s", method, rpc.Error.Code, rpc.Error.Message)
	}
	return json.Unmarshal(rpc.Result, out)
}

type messageSentEvent struct {
	MessageID   string          `json:"message_id"`
	Sender      string          `json:"sender"`
	Recipient   string          `json:"recipient"`
	PayloadKind json.RawMessage `json:"payload_kind"`
	CreatedAtMs string          `json:"created_at_ms"`
}

type queryEventsResult struct {
	Data []struct {
		ID         json.RawMessage `json:"id"`
		ParsedJSON json.RawMessage `json:"parsedJson"`
	} `json:"data"`
	NextCursor  json.RawMessage `json:"nextCursor"`
	HasNextPage bool            `json:"hasNextPage"`
}

// PollOnce fetches and processes one page of new events.
func (l *Listener) PollOnce(ctx context.Context) error {
	if l.needsInit {
		if err := l.initCursorFromLatest(ctx); err != nil {
			return fmt.Errorf("init cursor from latest: %w", err)
		}
		return nil
	}
	filter := map[string]any{
		"MoveEventType": l.cfg.PackageID + "::demail::MessageSent",
	}
	var cursor any
	if l.cursor != nil {
		cursor = json.RawMessage(l.cursor)
	}
	var res queryEventsResult
	if err := l.call(ctx, "suix_queryEvents", []any{filter, cursor, 50, false}, &res); err != nil {
		return err
	}
	for _, ev := range res.Data {
		var parsed messageSentEvent
		if err := json.Unmarshal(ev.ParsedJSON, &parsed); err != nil {
			l.cfg.Logger.Warn("demail: bad event json", "err", err)
			l.setCursor(ev.ID)
			continue
		}
		if !strings.EqualFold(parsed.Recipient, l.cfg.Recipient) {
			l.setCursor(ev.ID)
			continue
		}
		if err := l.process(ctx, &parsed); err != nil {
			// Transient transport failures (RPC/network) must NOT advance the
			// cursor: the message is valid and will be retried next poll.
			// Only genuine poison (bad envelope/key/schema) is skipped.
			var te *transientError
			if errors.As(err, &te) {
				return fmt.Errorf("transient failure at message %s, will retry: %w", parsed.MessageID, err)
			}
			l.cfg.Logger.Warn("demail: message dropped", "message_id", parsed.MessageID, "err", err)
		}
		l.setCursor(ev.ID)
	}
	l.setCursor(res.NextCursor)
	return nil
}

// transientError marks failures where the message itself is fine but the
// fetch could not complete; these must be retried, never skipped.
type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

func (l *Listener) process(ctx context.Context, ev *messageSentEvent) error {
	kind, err := decodeVectorU8(ev.PayloadKind)
	if err != nil {
		return fmt.Errorf("bad payload_kind encoding: %w", err)
	}
	payload, err := l.fetchPayload(ctx, ev.MessageID)
	if err != nil {
		return err
	}
	var envBytes []byte
	switch string(kind) {
	case "inline":
		envBytes, err = decodeInlinePayload(payload)
		if err != nil {
			return err
		}
	case "walrus":
		return fmt.Errorf("walrus payloads not supported yet")
	default:
		return fmt.Errorf("unknown payload kind %q", kind)
	}
	env, err := envelope.Unmarshal(envBytes)
	if err != nil {
		return fmt.Errorf("bad envelope: %w", err)
	}
	senderAddr, err := decodeAddress(ev.Sender)
	if err != nil {
		return fmt.Errorf("bad sender address: %w", err)
	}
	recipientAddr, err := decodeAddress(ev.Recipient)
	if err != nil {
		return fmt.Errorf("bad recipient address: %w", err)
	}
	plaintext, err := envelope.Open(l.cfg.IdentityKey, senderAddr, recipientAddr, env)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	msg, err := schema.Parse(plaintext, strings.ToLower(ev.Sender), strings.ToLower(ev.Recipient))
	if err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	l.handler(ev.MessageID, msg)
	return nil
}

type getObjectResult struct {
	Data struct {
		Content struct {
			Fields struct {
				Payload json.RawMessage `json:"payload"`
			} `json:"fields"`
		} `json:"content"`
	} `json:"data"`
}

func (l *Listener) fetchPayload(ctx context.Context, messageID string) ([]byte, error) {
	var res getObjectResult
	params := []any{messageID, map[string]any{"showContent": true}}
	if err := l.call(ctx, "sui_getObject", params, &res); err != nil {
		// RPC/network failure: the message may be perfectly valid.
		return nil, &transientError{err}
	}
	if res.Data.Content.Fields.Payload == nil {
		return nil, fmt.Errorf("message object %s has no payload (deleted?)", messageID)
	}
	return decodeVectorU8(res.Data.Content.Fields.Payload)
}

// decodeInlinePayload returns the envelope JSON bytes for an inline payload.
// Canonical on-chain encoding (docs/payload-envelope.md §0/§1) is the
// pinned-variant base64 text of the envelope JSON — standard alphabet,
// padded, no interior whitespace — CLI-safe for PTB string arguments. Raw
// envelope JSON (leading '{', outside the base64 alphabet) is accepted for
// compatibility with early senders. Leading/trailing ASCII whitespace is
// stripped first (CLI tools append a newline); anything else non-conformant
// is a poison message and is rejected with an error, never handed through.
func decodeInlinePayload(payload []byte) ([]byte, error) {
	if len(payload) > 0 && payload[0] == '{' {
		return payload, nil
	}
	decoded, err := envelope.DecodeBase64(strings.TrimSpace(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("inline payload is neither raw envelope JSON nor pinned-variant base64: %w", err)
	}
	return decoded, nil
}

// decodeVectorU8 accepts the two renderings Sui RPC uses for vector<u8>:
// a base64 string or a JSON array of numbers.
func decodeVectorU8(raw json.RawMessage) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return base64.StdEncoding.DecodeString(s)
	}
	var nums []json.Number
	if err := json.Unmarshal(raw, &nums); err == nil {
		out := make([]byte, len(nums))
		for i, n := range nums {
			v, err := strconv.Atoi(n.String())
			if err != nil || v < 0 || v > 255 {
				return nil, fmt.Errorf("invalid byte at %d: %s", i, n)
			}
			out[i] = byte(v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unrecognized vector<u8> encoding")
}

// decodeAddress converts a 0x-prefixed Sui address to raw 32 bytes.
func decodeAddress(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if len(s) != 64 {
		return nil, fmt.Errorf("address must be 32 bytes, got %d hex chars", len(s))
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}
