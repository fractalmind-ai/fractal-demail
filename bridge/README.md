# bridge

Web2↔Web3 mail bridge for fractal-demail (Phase 2). Design: `docs/ops/fractal-demail/phase2-bridge-design.md` (workspace) / tracker [#6](https://github.com/fractalmind-ai/fractal-demail/issues/6).

The bridge is the only semi-trusted component in the system (Web2 email is plaintext at the SMTP boundary). It must be run by the node owner and defends two abuse surfaces:

- **gas-drain** (inbound minting) — sender `Allowlist` (deny-all when empty) + token-bucket `RateLimiter` (per-sender and global).
- **relay-abuse** (outbound SMTP) — same primitives applied to Web2 recipients.

This package currently provides those dependency-free primitives (`guard.go`), built and tested behind mocks ahead of the relayer/watcher cores (steps 2–3) and the gated real-provider wiring (steps 4–5, need owner approval for paid signup + domain/DNS).

```bash
go test ./...
```
