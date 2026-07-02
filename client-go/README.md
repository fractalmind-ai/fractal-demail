# client-go

Go client for fractal-demail, consumed by [fractalbot](https://github.com/fractalmind-ai/fractalbot):

- subscribe to `MessageSent` events on the Sui RPC event stream
- fetch and decrypt payloads (inline or off-chain reference)
- sanitize into structured JSON for downstream routing (agent-manager-skill)

Phase 1 milestone KR4 — implementation starts after the contracts are validated on Testnet (KR3).
