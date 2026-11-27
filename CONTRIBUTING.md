# Contributing to Hyphae (`hyp`)

Thanks for contributing to Hyphae! Please read [AGENTS.md](AGENTS.md) for engineering invariants and our McKeeman differential testing philosophy.

## Workspace Layout

Hyphae uses a pure-Rust workspace (Rust 1.87+, `edition = "2024"`).

- `crates/hyp-proto` — CloudEvents v1.0, RFC 8785 JCS, address/channel/filter AST, scopes, manifests, RFC 9457 Problem Details, JSON-RPC 2.0.
- `crates/hyp-crypto` — Zeroized Ed25519 & RFC 7748 X25519 (`ring`), RFC 9180 HPKE Base Mode, E2EE DMs/`#channels`/KV, streaming AEAD `tar.gz` (`flate2`), `hp2p1_`/`am2_`/v1 compat, `SecretStore`.
- `crates/hyp-store` — Single WAL `node.sqlite` (`rusqlite` bundled), atomic migrations, `EventStore`, `MessageStore`, `ChannelStore`, `KvStore`, `TransferStore`, `LocalStateStore` (`gate_audit` immutability triggers), `PeerStore`, exact `next_deadline_ms()` scheduler.
- `crates/hyp-node` — `UnifiedNode` engine, `hyper 1` HTTP/SSE Peer Server & `PeerLink`, `SecurityGatePipeline` + 6 filter plugins, `DeliveryEngine` (delivery policy, burst protection, token-budget hybrid packer, paginated inbox), compiled-in webhook adapters & deduplicated `github-public` ETag poller.
- `crates/hyp-pairing-client` — Outbound P2P and Admin-CA handshakes, signed manifest fetching, and guest and delegated enrollment over the node HTTP and SSH transports.
- `crates/hyp-harness` — Compatibility re-exports and cross-harness integration tests. New consumers can depend directly on the package they use.
  - `ipc/` (`hyp-harness-ipc`) owns local socket framing, wire fields, session identifiers, loopback KV authentication, and the shared test-environment switch.
  - `client/` (`hyp-harness-client`) implements synchronous hooks, MCP stdio, and wait/watch on top of IPC.
  - `transport/` (`hyp-harness-transport`) delivers metadata-only wakeups to external harnesses. It shares identity hints with clients through IPC.
  - `daemon/` (`hyp-daemon`) runs the socket server, verifies callers, and coordinates delivery through the node and transports.
  - `plugins/` (`hyp-harness-plugins`) reads plugin configuration, supervises subprocesses, and connects bridge delivery to the daemon.
- `crates/hyp-mycelium` — Braille frame renderer for the onboarding intro, animation preview, and menu banner.
- `crates/hyp-cli` — Single self-contained `hyp` binary (static musl on Linux x86_64, native glibc on Linux arm64).
- `plugins/` — Optional external self-contained chat & webhook bridge scripts (Node/Python) supervised over JSON-RPC 2.0 / fd-3 NDJSON (never required for the core Rust binary).
- `workers/drop-relay/` — Zero-dependency Cloudflare Workers kit for the Blind Drop Relay.

## Building from Source

Requires Rust 1.87 or newer:

```sh
git clone https://github.com/hyphae-to/hyp && cd hyp
cargo install --path crates/hyp-cli
```

## Verification Checklist

Every PR must pass all checks with zero warnings and strict test isolation (`HYPHAE_SECRET_BACKEND=file`, `TempDir`, `127.0.0.1:0`, zero live user config or Keychain mutations):

```sh
cargo clippy --workspace --all-targets -- -D warnings
HYPHAE_SECRET_BACKEND=file cargo test --workspace
cargo build --release -p hyp-cli
bash scripts/test-installer.sh
```

## Testing & Architecture Docs

- [Testing Strategy (McKeeman Differential Testing)](docs/internals/testing.md)
- [Architecture Overview](docs/internals/architecture.md)
- [Delivery Engine](docs/internals/delivery.md)
- [Threat Model](docs/security/threat-model.md)

## Security Conventions

- Fail closed on authentication, signature checks, scope checks, E2EE policy, and filesystem permissions (`0700`/`0600`).
- Never accept or print secrets or pairing tokens (`hp2p1_`, `am2_`, `t3mp1_`) via CLI argv flags, logs, or plaintext `node.json`.
- Treat all inbound network data, webhooks, `#channels`, bridged messages, and escalation notes as untrusted external data.
