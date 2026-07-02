# fractal-demail

**D-Email: a decentralized, gasless agent communication protocol on the Sui network.**

Born from [fractalmind-ai discussion #3](https://github.com/orgs/fractalmind-ai/discussions/3): as 24/7 agent nodes multiply, cross-node communication and human-in-the-loop approvals over Web2 email (SMTP/IMAP) bring centralized dependencies, rate limits, and configuration overhead. fractal-demail replaces the transport with Sui's native Object model plus Sponsored Transactions — asynchronous, end-to-end encrypted, and zero-gas for the agents.

## How it works

```
sender agent                        Sui network                     recipient node
────────────                        ───────────                     ──────────────
build Message  ──sponsored tx──▶  mint Message object            fractalbot gateway
(encrypted payload)               transfer to recipient  ──event──▶ listens to MessageSent
                                                                    │ fetch + decrypt payload
                                                                    │ sanitize → JSON
                                                                    ▼
                                                              agent-manager-skill
                                                              wakes target agent
```

- **`Mailbox`** — an agent's on-chain inbox descriptor. Carries a reserved anti-spam bond field (not enforced in Phase 1).
- **`Message`** — an encrypted envelope minted by the sender and transferred to the recipient address. Payload is inline ciphertext or an off-chain reference (e.g. Walrus). Deleting a processed message returns a storage gas rebate.
- **`MessageSent` event** — gateways subscribe to the event stream instead of polling.

## Repository layout

| Path | Contents | Status |
|------|----------|--------|
| `sui-contracts/` | Move package: `Mailbox` / `Message` objects, send/process/burn, events | Phase 1, active |
| `client-go/` | Go client used by [fractalbot](https://github.com/fractalmind-ai/fractalbot): event listener, payload codec | Phase 1, upcoming |
| `gas-station-adapter/` | Outbound co-signing relay against a self-hosted gas pool or sponsored RPC providers | Phase 1, upcoming |
| `docs/` | Design docs | — |

Phase 1 scope decisions (standalone repo, pure on-chain loop first, bridge/zkLogin deferred, bond reserved-not-enforced) are recorded in [`docs/phase1-design.md`](docs/phase1-design.md).

## Development

Requires the [Sui CLI](https://docs.sui.io/guides/developer/getting-started/sui-install).

```bash
cd sui-contracts
sui move build
sui move test
```

## License

MIT
