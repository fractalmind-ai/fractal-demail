# gas-station-adapter

Outbound co-signing relay: takes raw transaction data built by a zero-balance agent and routes it through a gas pool (self-hosted, or a sponsored RPC provider such as Shinami) for sponsorship.

Phase 1 uses a Testnet pool only; funding a real gas pool and enabling paid providers are explicitly approval-gated.
