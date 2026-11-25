# Architecture Documentation Has Moved

The unified `Node` architecture documentation now lives under `docs/internals/` and `docs/reference/`:

- **[Architecture Overview](internals/architecture.md)** — Unified Rust `Node`, SQLite WAL schema v5, adapters, live hot-reload IPC, and standards wire layer.
- **[Delivery Engine](internals/delivery.md)** — Delivery tiers (`interrupt` / `queue` / `notify` / `mute`), Focus Mode, burst protection, and batch packing.
- **[Scopes & Capabilities](reference/scopes.md)** — Scope grammar, presets, and active vs. reserved/planned endpoints.
- **[Testing Strategy](internals/testing.md)** — McKeeman differential testing suites across all 6 crates.
