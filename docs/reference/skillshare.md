# Skillshare ownership during setup

When `skillshare` is executable on PATH, `hyp setup`, deterministic onboarding,
join auto-setup, skill refresh, and guided onboarding skill installation use it
for generated `hyp-mesh` and `hyp-setup` skills. Without the executable, the
existing direct installation remains available. A failed Skillshare operation
reports an error and does not switch to a direct installation.

An uninitialized manager is initialized noninteractively without importing other
skills or adding unrelated targets. Hyphae installs local generated skills into
stable per-destination collections, then synchronizes them. Existing target
naming, filters, and merge/copy modes remain in force. Full-directory symlink
mode cannot isolate harness-specific variants, so setup preserves it and reports
that merge or copy mode is required. Consequently, the exposed folder
can be `hyphae-<id>__hyp-mesh` under flat naming, while standard naming keeps
`hyp-mesh`. Onboarding reports the actual exposed path. Copy-mode updates retain Skillshare's normal ownership policy. Customized skills marked
`<!-- hyphae:unmanaged -->` are preserved, including edits through manager links.

Supported MCP registrations retain the `hyphae` name. Recognized existing direct
entries are normalized and adopted by Skillshare; native-only settings, other
servers, and tool approval namespaces remain in place. Skillshare refuses
conflicts rather than overwriting another registration.

| Integration | MCP ownership with Skillshare present |
| --- | --- |
| Claude Code, default profile | Skillshare |
| Cursor, OpenCode JSON, Gemini | Skillshare |
| Claude Desktop | Skillshare when its `--ephemeral` launch is compatible with the source definition |
| Codex CLI/Desktop | Direct; Skillshare cannot express Codex-only optional environment forwarding in one shared server definition |
| Antigravity plugin | Direct; Skillshare's native MCP target writes a different global configuration file |
| OpenClaw, Herdr, T3 | Existing direct/native integration; no matching Skillshare MCP target |
| Custom Claude accounts or OpenCode JSONC | Explicit mapping/migration required; existing configuration is preserved |

Codex still forwards `CODEX_HOME` and `HYPHAE_SOCKET` dynamically. They are absent
from Codex's default MCP child environment. Skillshare represents forwarding as
portable environment references shared by every receiving client; it rejects
`options.codex.env_vars`. Removing forwarding or replacing it with setup-time
literal values would change working configurations, so setup reports this
ownership limitation explicitly.

Channel mode remains an explicit `--claude-channel` choice. Skillshare also cannot
represent differing per-client command arguments under one `hyphae` definition.
If an existing channel, socket, or Desktop ephemeral launch conflicts with the
shared source, setup reports the conflict and preserves existing registrations.
Customized portable MCP fields require explicit migration rather than silently
propagating one client's environment or credentials to every other client.

## Backend selection from MCP initialization

Generated registrations use `hyp mcp` without `--backend`. The first MCP
`initialize` request can supply an exact transport hint from `clientInfo.name`:

| Verified client version | Name |
| --- | --- |
| [Codex 0.172.0](https://github.com/openai/codex/blob/rust-v0.172.0/codex-rs/codex-mcp/src/rmcp_client.rs#L1396-L1400) | `codex-mcp-client` |
| [OpenCode 2.3.2](https://github.com/anomalyco/opencode/blob/v2.3.2/packages/server/src/routes.ts#L165-L168) | `opencode` |
| [OpenClaw 2026.11.10](https://github.com/openclaw/openclaw/blob/v2026.11.10/src/agents/agent-bundle-mcp-runtime.ts#L343-L354) | `openclaw-bundle-mcp` |
| Claude Code 2.1.332, installed client constructor | `claude-code` |
| Claude Desktop 7.37095.0, installed local server manager | `local-agent-mode-hyphae` |

The hint is latched before instructions or the normal daemon connection are sent.
An existing explicit `--backend` wins. Unknown names and malformed metadata do not
select a backend. No hint enables channel or ephemeral mode. Caller identity and
authority still require existing hook/session/call-token verification. Explicit
scratch mode retains its existing default Claude identity and rejects asserted
but unverifiable caller proof even when client metadata is unknown.

Verification used version-matched upstream source, installed constructors, and
isolated real-daemon differential tests. Older clients with different names keep
their existing explicit override; their handshake identities have not been
verified.

## Contract tests

The manager integration was exercised with Skillshare v0.33.0 and isolated homes:

```sh
cargo test -p hyp-cli --test skillshare_e2e -- --include-ignored --test-threads=1
```

The real-manager cases are opt-in because they require the external CLI. Ordinary
CI also exercises unavailable and failing manager paths without external tools.
