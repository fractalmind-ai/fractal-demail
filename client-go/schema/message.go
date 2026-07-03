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
	// Web2From carries the originating Web2 email address when a message was
	// relayed in by the bridge (on-chain From is the bridge's Sui identity, so
	// this preserves provenance). Optional; empty for pure on-chain mail.
	Web2From string `json:"web2_from,omitempty"`
	// Web2To names the Web2 email recipient for a message the agent wants the
	// bridge to deliver out over SMTP (on-chain To is the bridge address).
	// Optional; empty for pure on-chain mail.
	Web2To string `json:"web2_to,omitempty"`
}

var validTypes = map[string]bool{
	TypeTask: true, TypeReply: true, TypeReceipt: true, TypeNotice: true,
}

// normalizeSuiAddress lowercases a 0x-prefixed address so comparisons are
// case-insensitive; returns "" if it is not a well-formed 32-byte address.
func normalizeSuiAddress(s string) string {
	s = strings.ToLower(s)
	if !strings.HasPrefix(s, "0x") || len(s) != 66 {
		return ""
	}
	for _, r := range s[2:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ""
		}
	}
	return s
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
	p.From = normalizeSuiAddress(p.From)
	p.To = normalizeSuiAddress(p.To)
	if p.From == "" || p.To == "" {
		return nil, fmt.Errorf("invalid from/to address")
	}
	if p.From != normalizeSuiAddress(onChainSender) {
		return nil, fmt.Errorf("from %s does not match on-chain sender %s", p.From, onChainSender)
	}
	if p.To != normalizeSuiAddress(onChainRecipient) {
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
	// Bridge provenance fields are email addresses from an untrusted source.
	// Strip ALL control characters including CR/LF/TAB — unlike Subject/Body,
	// these may reach an SMTP client, where CR/LF is the header-injection
	// vector. Length-cap to the RFC 5321 maximum.
	p.Web2From = capString(stripEmailControl(p.Web2From), maxWeb2AddrLen)
	p.Web2To = capString(stripEmailControl(p.Web2To), maxWeb2AddrLen)
	return &p, nil
}

const maxWeb2AddrLen = 320 // RFC 5321 max email address length

// stripEmailControl removes every control character (no newline/tab exception)
// so a value cannot inject SMTP headers downstream.
func stripEmailControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func capString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	// Cap by bytes but never split a multibyte rune.
	r := []rune(s)
	for len(string(r)) > max {
		r = r[:len(r)-1]
	}
	return string(r)
}
