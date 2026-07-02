package schema

import (
	"strings"
	"testing"
)

const (
	sender    = "0xf4fafecc95c2e7c984f8d26db9b692cf58da977ee0119be38b84904b394e82e2"
	recipient = "0xeedfe046af0c10613356dea725fbe22af969a58077f27622936a6c4d9ec2fce3"
)

func valid() string {
	return `{"type":"task","from":"` + sender + `","to":"` + recipient + `","body":"do the thing","ts":1783011086750}`
}

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(valid()), sender, recipient)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Type != TypeTask || p.Body != "do the thing" {
		t.Fatalf("unexpected parse result: %+v", p)
	}
}

func TestParseRejectsRouteMismatch(t *testing.T) {
	if _, err := Parse([]byte(valid()), recipient, sender); err == nil {
		t.Fatal("expected route mismatch rejection")
	}
}

func TestParseRejectsBadType(t *testing.T) {
	bad := strings.Replace(valid(), `"task"`, `"exec"`, 1)
	if _, err := Parse([]byte(bad), sender, recipient); err == nil {
		t.Fatal("expected type rejection")
	}
}

func TestParseStripsControlChars(t *testing.T) {
	// JSON \u0007 (BEL) and \u001b (ESC) unmarshal to control runes;
	// sanitization must strip them but keep newline and tab.
	withCtl := strings.Replace(valid(), "do the thing", `do the\u0007 thing\u001b\nok\tend`, 1)
	p, err := Parse([]byte(withCtl), sender, recipient)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if strings.ContainsAny(p.Body, "\x07\x1b") {
		t.Fatalf("control chars not stripped: %q", p.Body)
	}
	if p.Body != "do the thing\nok\tend" {
		t.Fatalf("unexpected sanitized body: %q", p.Body)
	}
}

func TestParseRejectsOversize(t *testing.T) {
	big := strings.Replace(valid(), "do the thing", strings.Repeat("a", MaxPlaintextSize), 1)
	if _, err := Parse([]byte(big), sender, recipient); err == nil {
		t.Fatal("expected oversize rejection")
	}
}
