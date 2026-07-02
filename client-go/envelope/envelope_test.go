package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
