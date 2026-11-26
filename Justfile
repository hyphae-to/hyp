# Hyphae (`hyp`) — Developer & CI Task Runner

set shell := ["bash", "-euo", "pipefail", "-c"]

hyp_bin := env_var_or_default("HYP_BIN", justfile_directory() / "target/debug/hyp")

# Default recipe: list available commands
default:
    @just --list

# Tier 0: Rust clippy lint check (zero warnings)
check:
    cargo clippy --workspace --all-targets -- -D warnings

# Tier 0: Full Rust workspace test suite (isolated file SecretStore)
test:
    HYPHAE_SECRET_BACKEND=file cargo test --workspace

# Build debug `hyp` binary for local black-box integration tests
build:
    cargo build --bin hyp

# Populate version-pinned isolated harness cache under ~/.cache/hyphae-itest/
itest-provision *args:
    node itest/scripts/provision.mjs {{args}}

# Inspect host harness binaries vs itest/versions.lock.json
itest-provision-host:
    node itest/scripts/provision.mjs --use-host-bins

# Tier 1: Core black-box PR gate (zero Docker; OpenClaw, Claude, Codex, Herdr, Bridges, SaaS Sources, Onboarding)
itest-core: build
    HYP_BIN="{{hyp_bin}}" HYPHAE_ITEST_USE_HOST_BINS=1 HYPHAE_NO_SERVICE=1 HYPHAE_SECRET_BACKEND=file npm --prefix itest run itest:core

# Tier 2: Full black-box matrix (all 15 suites across Phases 1-4)
itest-full: build
    HYP_BIN="{{hyp_bin}}" HYPHAE_ITEST_USE_HOST_BINS=1 HYPHAE_NO_SERVICE=1 HYPHAE_SECRET_BACKEND=file npm --prefix itest run itest:all

# Phase 1: llm-shim unit + OpenClaw + Claude Code
itest-phase1: build
    HYP_BIN="{{hyp_bin}}" HYPHAE_ITEST_USE_HOST_BINS=1 HYPHAE_NO_SERVICE=1 HYPHAE_SECRET_BACKEND=file npm --prefix itest run itest:phase1

# Phase 2: Codex + Herdr + OpenCode + Gemini + P1-P8 Differential Parity Matrix
itest-phase2: build
    HYP_BIN="{{hyp_bin}}" HYPHAE_ITEST_USE_HOST_BINS=1 HYPHAE_NO_SERVICE=1 HYPHAE_SECRET_BACKEND=file npm --prefix itest run itest:phase2

# Phase 3: Chat Bridges + Compiled-In/SaaS Sources + Onboarding Trees
itest-phase3: build
    HYP_BIN="{{hyp_bin}}" HYPHAE_ITEST_USE_HOST_BINS=1 HYPHAE_NO_SERVICE=1 HYPHAE_SECRET_BACKEND=file npm --prefix itest run itest:phase3

# Phase 4: T3 Code + Cursor/Antigravity Replay + Multi-Node E2EE Topology + Schema Compat
itest-phase4: build
    HYP_BIN="{{hyp_bin}}" HYPHAE_ITEST_USE_HOST_BINS=1 HYPHAE_NO_SERVICE=1 HYPHAE_SECRET_BACKEND=file npm --prefix itest run itest:phase4
