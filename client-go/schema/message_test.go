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

func TestParseNormalizesAddressCase(t *testing.T) {
	mixed := strings.Replace(valid(), sender, "0x"+strings.ToUpper(sender[2:]), 1)
	p, err := Parse([]byte(mixed), sender, recipient)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.From != sender {
		t.Fatalf("address not normalized: %q", p.From)
	}
}

func TestParseRejectsOversize(t *testing.T) {
	big := strings.Replace(valid(), "do the thing", strings.Repeat("a", MaxPlaintextSize), 1)
	if _, err := Parse([]byte(big), sender, recipient); err == nil {
		t.Fatal("expected oversize rejection")
	}
}

func TestParseWeb2FieldsSanitizedAndCapped(t *testing.T) {
	// web2_from/web2_to must survive Parse but be stripped of ALL control
	// chars (CRLF header-injection defense) and length-capped.
	body := `{"type":"notice","from":"` + sender + `","to":"` + recipient +
		`","body":"x","ts":1,"web2_from":"attacker@evil.com\r\nBcc: victim@x.com","web2_to":"boss@corp.io"}`
	p, err := Parse([]byte(body), sender, recipient)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if strings.ContainsAny(p.Web2From, "\r\n\t") {
		t.Fatalf("web2_from not stripped of CRLF: %q", p.Web2From)
	}
	if p.Web2From != "attacker@evil.comBcc: victim@x.com" {
		t.Fatalf("unexpected web2_from: %q", p.Web2From)
	}
	if p.Web2To != "boss@corp.io" {
		t.Fatalf("unexpected web2_to: %q", p.Web2To)
	}
}

func TestParseWeb2FieldsAbsentByDefault(t *testing.T) {
	p, err := Parse([]byte(valid()), sender, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if p.Web2From != "" || p.Web2To != "" {
		t.Fatalf("web2 fields must be empty for pure on-chain mail: %+v", p)
	}
}
