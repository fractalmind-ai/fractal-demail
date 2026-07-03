package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func addr(b byte) []byte {
	a := make([]byte, 32)
	for i := range a {
		a[i] = b
	}
	return a
}

func TestSealOpenRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sender, recipient := addr(0xAA), addr(0xBB)
	plaintext := []byte(`{"type":"task","body":"hello"}`)

	env, err := Seal(pub, sender, recipient, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	wire, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Unmarshal(wire)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got, err := Open(priv, sender, recipient, parsed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plaintext)
	}
}

func TestOpenRejectsWrongRoute(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(pub, addr(0xAA), addr(0xBB), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(priv, addr(0xCC), addr(0xBB), env); err == nil {
		t.Fatal("expected AAD failure for wrong sender address")
	}
}

func TestOpenRejectsWrongRecipientKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(pub, addr(0xAA), addr(0xBB), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(otherPriv, addr(0xAA), addr(0xBB), env); err == nil {
		t.Fatal("expected decryption failure with wrong recipient key")
	}
}

func TestOpenRejectsMalformedNonceAndCT(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(pub, addr(0xAA), addr(0xBB), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Wrong-length nonces must return an error, never panic: the AEAD
	// panics on bad nonce length and Open is the untrusted inbound path.
	for _, nonce := range []string{"", "AAAA", "AAAAAAAAAAAAAAAA"} {
		bad := *env
		bad.Nonce = nonce
		if _, err := Open(priv, addr(0xAA), addr(0xBB), &bad); err == nil {
			t.Fatalf("expected error for malformed nonce %q", nonce)
		}
	}
	// Ciphertext shorter than the Poly1305 tag must be rejected early.
	bad := *env
	bad.CT = "AAAA"
	if _, err := Open(priv, addr(0xAA), addr(0xBB), &bad); err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestDecodeBase64PinnedVariant(t *testing.T) {
	// Accepts exactly the pinned variant: std alphabet, padded, canonical
	// trailing bits, no whitespace (docs/payload-envelope.md §0).
	raw := []byte{0xfb, 0xff, 0x00, 0x68, 0x69} // encodes with both '+' and '/'
	canonical := base64.StdEncoding.EncodeToString(raw)
	got, err := DecodeBase64(canonical)
	if err != nil {
		t.Fatalf("canonical form rejected: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("roundtrip mismatch: %x != %x", got, raw)
	}

	rejects := map[string]string{
		"empty":                       "",
		"url-safe alphabet":           base64.URLEncoding.EncodeToString(raw),
		"unpadded":                    base64.RawStdEncoding.EncodeToString([]byte("hi")),
		"interior newline":            "aGVs\nbG8=",
		"interior crlf":               "aGVs\r\nbG8=",
		"leading space":               " aGk=",
		"trailing newline":            "aGk=\n",
		"non-canonical trailing bits": "ZE==", // lenient decoders read 'd', Strict must reject
		"padding in the middle":       "aG==aG==",
		"length not a multiple of 4":  "aGk",
		"character outside alphabet":  "aG!k",
	}
	for name, in := range rejects {
		if _, err := DecodeBase64(in); err == nil {
			t.Errorf("%s (%q) must be rejected", name, in)
		}
	}
}

func TestOpenRejectsNonPinnedBase64Fields(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(pub, addr(0xAA), addr(0xBB), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the untouched envelope opens.
	if _, err := Open(priv, addr(0xAA), addr(0xBB), env); err != nil {
		t.Fatalf("baseline Open failed: %v", err)
	}

	toURLSafe := func(s string) string {
		return strings.NewReplacer("+", "-", "/", "_").Replace(s)
	}
	insertCRLF := func(s string) string { return s[:4] + "\r\n" + s[4:] }
	unpad := func(s string) string { return strings.TrimRight(s, "=") }

	// The same bytes re-encoded in a non-pinned variant must not open:
	// with the variant pinned, an envelope has exactly one conformant
	// text form (no re-encoding malleability past filters/dedup).
	mutations := map[string]func(*Envelope){
		"epk url-safe":      func(e *Envelope) { e.EPK = toURLSafe(e.EPK) },
		"epk interior crlf": func(e *Envelope) { e.EPK = insertCRLF(e.EPK) },
		"nonce interior lf": func(e *Envelope) { e.Nonce = e.Nonce[:4] + "\n" + e.Nonce[4:] },
		"ct unpadded":       func(e *Envelope) { e.CT = unpad(e.CT) },
		"ct url-safe":       func(e *Envelope) { e.CT = toURLSafe(e.CT) },
		"ct interior crlf":  func(e *Envelope) { e.CT = insertCRLF(e.CT) },
	}
	for name, mutate := range mutations {
		bad := *env
		mutate(&bad)
		if bad == *env {
			// Mutation was a no-op (e.g. no +/ in this random encoding):
			// the case proves nothing this run, but must not false-fail.
			continue
		}
		if _, err := Open(priv, addr(0xAA), addr(0xBB), &bad); err == nil {
			t.Errorf("%s: non-pinned field encoding must be rejected", name)
		}
	}
}

func TestOpenRejectsUnknownVersionAndAlg(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(pub, addr(0xAA), addr(0xBB), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	bad := *env
	bad.V = 2
	if _, err := Open(priv, addr(0xAA), addr(0xBB), &bad); err == nil {
		t.Fatal("expected rejection of unknown version")
	}
	bad = *env
	bad.Alg = "rot13"
	if _, err := Open(priv, addr(0xAA), addr(0xBB), &bad); err == nil {
		t.Fatal("expected rejection of unknown alg")
	}
}
