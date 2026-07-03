# Payload Envelope Specification (Phase 1)

Status: frozen for Phase 1 (2026-07-03). Governs the bytes carried in `Message.payload` and the plaintext schema gateways exchange. Phase 2 hardening (2026-07-03) pinned the base64 variant (§0) — a clarification of what conformant encoders already emitted, not a wire change.

## 0. Base64 variant (pinned)

Every `base64` in this document means exactly one variant — **RFC 4648 §4 standard alphabet (`A–Z a–z 0–9 + /`), with `=` padding, canonical trailing bits, and no whitespace or line breaks**:

- Encoders MUST emit this form and nothing else. URL-safe alphabet (`-`, `_`), unpadded output, MIME/PEM line wrapping, and non-canonical trailing padding bits are all non-conformant.
- Decoders MAY strip *leading/trailing* ASCII whitespace before validation (tolerates the trailing newline that CLI tools such as `base64(1)` append). After that, any input that is not the pinned form — wrong alphabet, missing padding, interior whitespace, non-canonical trailing bits — MUST be rejected as a poison message (log + drop, advance past it; never block the stream, never route).

This closes an encoding-malleability seam: with variants pinned, a given byte string has exactly one conformant text encoding, so filtering/dedup/audit layers cannot be bypassed by re-encoding the same envelope differently.

## 1. Payload kinds

`Message.payload_kind` selects how `Message.payload` is interpreted:

| kind | `payload` contents | Use when |
|------|--------------------|----------|
| `inline` | The **base64 text** (§0) of the encrypted envelope JSON (§2) — CLI/PTB-safe. Readers MUST also accept raw envelope JSON (leading `{`, which is outside the base64 alphabet, so the two forms are unambiguous) for compatibility with early senders | envelope ≤ 16 KiB (soft limit; hard cap is Sui object size) |
| `walrus` | UTF-8 Walrus blob id of the stored envelope, `:` , lowercase-hex SHA-256 of the envelope bytes | larger payloads; blob integrity is checked against the hash after fetch |

Unknown kinds MUST be rejected by gateways (log + drop; never route).

## 2. Encryption envelope

End-to-end encryption between agent nodes. Sui accounts are Ed25519; each side derives an X25519 key from its Ed25519 identity key (RFC 7748 birational map, as in libsodium `crypto_sign_ed25519_pk_to_curve25519`).

Envelope is a JSON object, UTF-8 encoded:

```json
{
  "v": 1,
  "alg": "x25519-xchacha20poly1305",
  "epk": "<base64 (§0) 32-byte ephemeral X25519 public key>",
  "nonce": "<base64 (§0) 24-byte XChaCha20 nonce>",
  "ct": "<base64 (§0) ciphertext||poly1305 tag>"
}
```

`epk`, `nonce` and `ct` use the pinned base64 variant (§0); decoders reject non-conformant field encodings the same way they reject a malformed envelope. (JSON string escaping is a JSON-layer concern and does not relax this: after JSON parsing, the field value must be pinned-form base64.)

- Sender generates an ephemeral X25519 keypair per message; shared secret = X25519(ephemeral_sk, recipient_x25519_pk), key = HKDF-SHA256(shared, info="fractal-demail:v1", salt=epk||recipient_pk).
- AEAD: XChaCha20-Poly1305. Associated data (AAD) = `sender_address || recipient_address` (raw 32-byte Sui addresses, sender first) — binds the ciphertext to the on-chain route so an envelope replayed under a different sender/recipient fails authentication.
- `v` MUST be `1`; gateways reject unknown versions.

## 3. Plaintext schema (decrypted, sanitized JSON)

What `client-go` hands to downstream routing (agent-manager-skill):

```json
{
  "type": "task | reply | receipt | notice",
  "from": "0x<sender sui address>",
  "to": "0x<recipient sui address>",
  "subject": "optional short string",
  "body": "free-form string (instruction, result, or message text)",
  "reply_to": "optional message_id (0x object id) this responds to",
  "ts": 1783011086750
}
```

- `type`, `from`, `to`, `body`, `ts` are required. `from`/`to` MUST equal the on-chain `MessageSent` sender/recipient or the gateway drops the message.
- Gateways sanitize before routing: strip control characters, enforce a size cap (64 KiB plaintext), and treat `body` as data — never shell-interpret it.

## 4. Versioning

Envelope evolution bumps `v` (breaking) or adds optional JSON fields (non-breaking). `payload_kind` evolution adds new kinds; existing kinds are never repurposed. Contract changes are not required for either axis — this is the reason payload interpretation lives entirely off-chain.
