package bridge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Resend is the concrete provider adapter: a WebhookVerifier for inbound email
// (Svix-signed webhooks) and an SMTPClient for outbound send (Resend API).
// HTTP is injected so the adapter is fully unit-tested without live calls.

// ResendInboundVerifier verifies a Resend/Svix inbound-email webhook and
// parses it into an InboundEmail. Svix signs `${id}.${timestamp}.${body}` with
// HMAC-SHA256 under a base64 secret (the part after the `whsec_` prefix), and
// sends the signature(s) in `svix-signature` as space-separated `v1,<b64>`.
type ResendInboundVerifier struct {
	// Secret is the endpoint signing secret. The `whsec_` prefix is optional.
	secret []byte
	// Tolerance rejects timestamps outside +/- this window (replay defense).
	tolerance time.Duration
	now       func() time.Time
}

// NewResendInboundVerifier builds a verifier from the endpoint signing secret.
func NewResendInboundVerifier(secret string) (*ResendInboundVerifier, error) {
	s := strings.TrimSpace(secret)
	s = strings.TrimPrefix(s, "whsec_")
	if s == "" {
		return nil, fmt.Errorf("resend webhook secret is required")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("resend webhook secret must be base64: %w", err)
	}
	return &ResendInboundVerifier{secret: raw, tolerance: 5 * time.Minute, now: time.Now}, nil
}

// resendInboundPayload is the subset of the Resend inbound webhook we use.
type resendInboundPayload struct {
	Type string `json:"type"`
	Data struct {
		From    string   `json:"from"`
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		Text    string   `json:"text"`
	} `json:"data"`
}

// Verify authenticates the webhook and returns the parsed email. It rejects a
// missing/short-length signature, a stale timestamp (replay), and a bad MAC.
func (v *ResendInboundVerifier) Verify(headers map[string]string, body []byte) (*InboundEmail, error) {
	id := header(headers, "svix-id")
	ts := header(headers, "svix-timestamp")
	sigHeader := header(headers, "svix-signature")
	if id == "" || ts == "" || sigHeader == "" {
		return nil, fmt.Errorf("missing svix headers")
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad svix-timestamp")
	}
	skew := v.now().Sub(time.Unix(tsInt, 0))
	if skew < -v.tolerance || skew > v.tolerance {
		return nil, fmt.Errorf("svix-timestamp outside tolerance")
	}

	signed := id + "." + ts + "."
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(signed))
	mac.Write(body)
	want := mac.Sum(nil)

	// The header carries one or more space-separated `v1,<base64>` sigs; accept
	// if any matches (constant-time).
	ok := false
	for _, part := range strings.Fields(sigHeader) {
		_, b64, found := strings.Cut(part, ",")
		if !found {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(got, want) == 1 {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("no valid svix signature")
	}

	var p resendInboundPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("bad webhook json: %w", err)
	}
	if len(p.Data.To) == 0 {
		return nil, fmt.Errorf("webhook has no recipient")
	}
	return &InboundEmail{
		From:    p.Data.From,
		To:      p.Data.To[0],
		Subject: p.Data.Subject,
		Body:    p.Data.Text,
	}, nil
}

func header(h map[string]string, key string) string {
	if v, ok := h[key]; ok {
		return v
	}
	// Case-insensitive fallback.
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// ResendSMTPClient sends outbound email via the Resend REST API.
type ResendSMTPClient struct {
	apiKey  string
	from    string // verified sender, e.g. agent@mail.example.com
	baseURL string
	http    *http.Client
}

// NewResendSMTPClient builds an outbound client. from must be a domain Resend
// has verified for this account.
func NewResendSMTPClient(apiKey, from string, httpClient *http.Client) (*ResendSMTPClient, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("resend api key is required")
	}
	if normalizeEmail(from) == "" {
		return nil, fmt.Errorf("resend from address is invalid")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &ResendSMTPClient{apiKey: apiKey, from: from, baseURL: "https://api.resend.com", http: httpClient}, nil
}

// Send delivers a plaintext email. to/subject/body are already sanitized by
// the OutboundWatcher (recipient re-gated, subject control-stripped).
func (c *ResendSMTPClient) Send(ctx context.Context, to, subject, body string) error {
	payload := map[string]any{
		"from":    c.from,
		"to":      []string{to},
		"subject": subject,
		"text":    body,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/emails", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("resend send: http %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}
