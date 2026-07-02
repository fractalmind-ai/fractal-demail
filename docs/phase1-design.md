# fractal-demail Phase 1 Design One-Pager (2026-07-03)

Source: https://github.com/orgs/fractalmind-ai/discussions/3 (proposal + Web2↔Web3 bridge add-on comment)
OKR: `OKR.md` — fractal-demail Phase 1 (activated 2026-07-03 by Elliot Slack assignment)

## Decisions (KR1 freeze)

### D1. Repository structure — standalone repo `fractalmind-ai/fractal-demail`
- Keeps the protocol modular and independently open-sourceable; fractalbot only takes a lightweight client dependency (listener + decrypt/sanitize module) via a normal integration PR.
- Avoids coupling fractalbot's release cadence to Move contract iteration.
- Layout: `sui-contracts/` (Move workspace), `client-go/` (event listener + payload codec used by fractalbot), `gas-station-adapter/` (outbound co-sign relay skeleton), `docs/`.

### D2. Phase 1 scope — pure SUI on-chain closed loop + fractalbot integration; bridge & zklogin deferred to Phase 2
Phase 1 IN:
1. `Mailbox` / `Message` Move objects with `mint` / `transfer` / `delete` (gas rebate) logic.
2. Sponsored-transaction flow proven on Testnet: a zero-balance agent address can receive and reply.
3. fractalbot integration: SUI RPC event subscription → payload fetch/decrypt → sanitized JSON → agent-manager-skill wake-up; outbound reply routed through gas-station-adapter (Testnet pool).

Phase 1 OUT (→ Phase 2):
- Web2 ↔ Web3 bridge relayer (Resend/Postmark webhook inbound, SMTP outbound). Rationale: it introduces a semi-centralized trust node, plaintext handling, gas-sponsorship-drain attack surface, and third-party paid services — all orthogonal to validating the core on-chain loop. The add-on comment's own trade-off analysis points the same way.
- `zklogin-client` HITL web component. Rationale: human approval can ride existing Slack flows in Phase 1; zkLogin adds frontend + auth scope better done once the message model is frozen.
- Off-chain payload store: Phase 1 uses Walrus Testnet if straightforward, else inline encrypted payload up to object size limits, with the storage interface abstracted so Walrus/IPFS can swap in without contract changes.

### D3. Spam prevention — reserve, don't enforce
- Contract carries an optional `bond` field / config hook on `Mailbox` (postage-stamp micro-staking per the proposal), default 0 in Phase 1.
- Actual spam control in Phase 1 lives at the fractalbot gateway: sender allowlist + rate limiting.
- Enforcement economics (0.05 SUI bond, slashing/refund rules) get decided in Phase 2 with real traffic data.

## Verification plan
- `sui move test` + `sui move build` PASS in CI.
- Testnet deploy: package id + full send → receive → delete tx digests recorded in tracker issue.
- Sponsored flow proof: zero-balance address receives a `Message` and emits a reply via sponsored tx.
- Integration PR to fractalbot: CI green + QA agent PASS + merged; end-to-end demo readback (on-chain Message → agent wake → on-chain receipt) recorded.

## Boundary
- Autonomous: design docs, discussion replies, repo creation under org (explicitly assigned), Move/Go code + tests, Testnet deploys/writes, integration PR (merge gated on CI + QA PASS).
- Approval-gated: mainnet or real funds, funding a real gas pool, paid third-party services (Shinami/Resend/Postmark), domain/DNS changes, public announcements.
