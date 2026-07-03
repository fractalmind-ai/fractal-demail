// Package envelope implements the Phase 1 payload envelope defined in
// docs/payload-envelope.md: X25519 (derived from Ed25519 identity keys) +
// XChaCha20-Poly1305, with AAD binding the ciphertext to the on-chain
// sender/recipient route.
package envelope

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// Version is the only envelope version accepted in Phase 1.
	Version = 1
	// Alg is the only algorithm accepted in Phase 1.
	Alg = "x25519-xchacha20poly1305"

	hkdfInfo = "fractal-demail:v1"
)

// Envelope is the JSON wire format carried in Message.payload (kind
// "inline") or stored in Walrus (kind "walrus").
type Envelope struct {
	V     int    `json:"v"`
	Alg   string `json:"alg"`
	EPK   string `json:"epk"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// DecodeBase64 decodes s enforcing the pinned base64 variant from
// docs/payload-envelope.md §0: RFC 4648 §4 standard alphabet, '=' padding,
// canonical trailing bits, no whitespace. Go's StdEncoding is looser than
// the spec — it silently skips \r/\n and accepts non-canonical trailing
// padding bits — so alphabet membership is checked explicitly and decoding
// uses Strict mode.
func DecodeBase64(s string) ([]byte, error) {
	if s == "" || len(s)%4 != 0 {
		return nil, fmt.Errorf("base64 length %d is not a positive multiple of 4", len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/', c == '=':
		default:
			return nil, fmt.Errorf("byte %q at offset %d is outside the pinned base64 alphabet", c, i)
		}
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}

// Ed25519PublicToX25519 converts an Ed25519 public key to its X25519
// counterpart (RFC 7748 birational map).
func Ed25519PublicToX25519(pub ed25519.PublicKey) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("invalid ed25519 public key: %w", err)
	}
	return p.BytesMontgomery(), nil
}

// Ed25519PrivateToX25519 converts an Ed25519 private key to its X25519
// counterpart (SHA-512 of the seed, clamped — same construction libsodium
// uses).
func Ed25519PrivateToX25519(priv ed25519.PrivateKey) []byte {
	h := sha512.Sum512(priv.Seed())
	scalar := h[:32]
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	return scalar
}

func deriveKey(shared, epk, recipientXPub []byte) ([]byte, error) {
	salt := append(append([]byte{}, epk...), recipientXPub...)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte(hkdfInfo)), key); err != nil {
		return nil, err
	}
	return key, nil
}

// aad binds the ciphertext to the on-chain route: raw sender address bytes
// followed by raw recipient address bytes.
func aad(senderAddr, recipientAddr []byte) []byte {
	return append(append([]byte{}, senderAddr...), recipientAddr...)
}

// Seal encrypts plaintext to the recipient's Ed25519 identity key.
// senderAddr and recipientAddr are the raw 32-byte Sui addresses used as
// associated data.
func Seal(recipientEdPub ed25519.PublicKey, senderAddr, recipientAddr, plaintext []byte) (*Envelope, error) {
	recipientXPub, err := Ed25519PublicToX25519(recipientEdPub)
	if err != nil {
		return nil, err
	}
	curve := ecdh.X25519()
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	recipientKey, err := curve.NewPublicKey(recipientXPub)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(recipientKey)
	if err != nil {
		return nil, err
	}
	epk := ephemeral.PublicKey().Bytes()
	key, err := deriveKey(shared, epk, recipientXPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad(senderAddr, recipientAddr))
	return &Envelope{
		V:     Version,
		Alg:   Alg,
		EPK:   base64.StdEncoding.EncodeToString(epk),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Open decrypts an envelope with the recipient's Ed25519 identity key,
// verifying the sender/recipient route via AAD.
func Open(recipientEdPriv ed25519.PrivateKey, senderAddr, recipientAddr []byte, env *Envelope) ([]byte, error) {
	if env.V != Version {
		return nil, fmt.Errorf("unsupported envelope version %d", env.V)
	}
	if env.Alg != Alg {
		return nil, fmt.Errorf("unsupported envelope alg %q", env.Alg)
	}
	// Field encodings are validated against the pinned base64 variant
	// (docs/payload-envelope.md §0) so an envelope has exactly one
	// conformant text form — no re-encoding malleability.
	epk, err := DecodeBase64(env.EPK)
	if err != nil {
		return nil, errors.New("invalid epk encoding")
	}
	nonce, err := DecodeBase64(env.Nonce)
	if err != nil {
		return nil, errors.New("invalid nonce encoding")
	}
	// chacha20poly1305.Open panics (rather than erroring) on a wrong-length
	// nonce, and this is the untrusted inbound boundary — reject early.
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("invalid nonce length %d", len(nonce))
	}
	ct, err := DecodeBase64(env.CT)
	if err != nil {
		return nil, errors.New("invalid ct encoding")
	}
	if len(ct) < chacha20poly1305.Overhead {
		return nil, fmt.Errorf("ciphertext too short: %d", len(ct))
	}
	curve := ecdh.X25519()
	recipientKey, err := curve.NewPrivateKey(Ed25519PrivateToX25519(recipientEdPriv))
	if err != nil {
		return nil, err
	}
	ephemeralKey, err := curve.NewPublicKey(epk)
	if err != nil {
		return nil, err
	}
	shared, err := recipientKey.ECDH(ephemeralKey)
	if err != nil {
		return nil, err
	}
	recipientXPub := recipientKey.PublicKey().Bytes()
	key, err := deriveKey(shared, epk, recipientXPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, aad(senderAddr, recipientAddr))
}

// Marshal renders the envelope as canonical UTF-8 JSON bytes.
func (e *Envelope) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// Unmarshal parses envelope JSON bytes.
func Unmarshal(data []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}
