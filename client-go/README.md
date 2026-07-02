# client-go

Go client for fractal-demail, consumed by [fractalbot](https://github.com/fractalmind-ai/fractalbot).

Implemented:

- `envelope` — the Phase 1 payload envelope ([spec](../docs/payload-envelope.md)): X25519 keys derived from Ed25519 identities, XChaCha20-Poly1305 AEAD, AAD binding to the on-chain sender/recipient route. `Seal`/`Open` + JSON wire codec.
- `schema` — sanitized plaintext message (`type/from/to/subject/body/reply_to/ts`): validation against the on-chain `MessageSent` route, control-character stripping, size caps.

Upcoming (KR4):

- `listener` — `MessageSent` event subscription over Sui RPC, payload fetch (inline/walrus), decrypt + sanitize into `schema.Plaintext` for downstream routing (agent-manager-skill).

```bash
go test ./...
```
