// Package schema defines the sanitized plaintext JSON exchanged between
// gateways, per docs/payload-envelope.md §3.
package schema

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// MaxPlaintextSize is the cap gateways enforce before routing.
const MaxPlaintextSize = 64 * 1024

// Valid message types.
const (
	TypeTask    = "task"
	TypeReply   = "reply"
	TypeReceipt = "receipt"
	TypeNotice  = "notice"
)

// Plaintext is the decrypted, sanitized message handed to downstream
// routing (agent-manager-skill).
type Plaintext struct {
	Type    string `json:"type"`
	From    string `json:"from"`
	To      string `json:"to"`
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body"`
	ReplyTo string `json:"reply_to,omitempty"`
	TS      int64  `json:"ts"`
}

var validTypes = map[string]bool{
	TypeTask: true, TypeReply: true, TypeReceipt: true, TypeNotice: true,
}

func isSuiAddress(s string) bool {
	if !strings.HasPrefix(s, "0x") || len(s) != 66 {
		return false
	}
	for _, r := range s[2:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// stripControl removes control characters other than newline and tab.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// Parse validates and sanitizes plaintext bytes. onChainSender and
// onChainRecipient are the addresses from the MessageSent event; the
// embedded from/to MUST match or the message is dropped.
func Parse(data []byte, onChainSender, onChainRecipient string) (*Plaintext, error) {
	if len(data) > MaxPlaintextSize {
		return nil, fmt.Errorf("plaintext exceeds %d bytes", MaxPlaintextSize)
	}
	var p Plaintext
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid plaintext json: %w", err)
	}
	if !validTypes[p.Type] {
		return nil, fmt.Errorf("invalid type %q", p.Type)
	}
	if !isSuiAddress(p.From) || !isSuiAddress(p.To) {
		return nil, fmt.Errorf("invalid from/to address")
	}
	if p.From != onChainSender {
		return nil, fmt.Errorf("from %s does not match on-chain sender %s", p.From, onChainSender)
	}
	if p.To != onChainRecipient {
		return nil, fmt.Errorf("to %s does not match on-chain recipient %s", p.To, onChainRecipient)
	}
	if p.Body == "" {
		return nil, fmt.Errorf("body is required")
	}
	if p.TS <= 0 {
		return nil, fmt.Errorf("ts is required")
	}
	p.Subject = stripControl(p.Subject)
	p.Body = stripControl(p.Body)
	return &p, nil
}
