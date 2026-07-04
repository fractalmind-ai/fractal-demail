# demail-bridge

Runnable inbound Web2→Web3 mail bridge. Receives Resend inbound webhooks,
verifies (Svix HMAC), routes by recipient email domain to the owning org, and
mints an encrypted Message on-chain to the target agent.

```bash
go build -o demail-bridge ./bridge/cmd/demail-bridge
DEMAIL_WEBHOOK_SECRET=whsec_... ./demail-bridge -config config.json
```

- Config: JSON (see `config.example.json`). Per-org: domain, bridge Sui
  identity, gas sponsor + coin, sender allowlist, rate limits, agents
  (localpart → sui address + base64 Ed25519 pubkey).
- Secret: the Resend/Svix webhook signing secret comes from
  `DEMAIL_WEBHOOK_SECRET` (never in the config file).
- Signing keys: the bridge + sponsor Sui keys must be in the host's `sui`
  keystore (CLIChainSender signs via `sui keytool`).
- Endpoints: `POST /inbound` (point the Resend Inbound webhook here), `GET /healthz`.

Deploy behind a reverse proxy that terminates TLS and exposes `/inbound`
publicly; point the Resend Inbound route at that URL.
