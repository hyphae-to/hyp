// Hyphae v2 official OpenClaw plugin (`~/.openclaw/extensions/hyphae/index.js`).
//
// Zero external npm dependencies (native Node.js ESM only):
//   - Registers scoped `before_tool_call` + `after_tool_call` hooks (matching ONLY Hyphae MCP
//     tools, never `exec` or unrelated tools) so every Hyphae tool call is cryptographically bound
//     to the exact OpenClaw `(agentId, sessionKey)` via single-use `_meshCall` tokens — ZERO
//     `--ephemeral` split-brain UUIDs and ZERO cross-session mailbox leaks!
//   - Registers native `hyphae-wake` Gateway service (`api.registerService`) using OpenClaw's
//     `api.runtime.system.captureSessionEventTarget` + `enqueueSessionEvent(..., { expectedTarget })`
//     (strictly WITHOUT `createIfMissing: true`!) so inbound Hyphae messages wake ONLY the exact
//     existing registered OpenClaw session — zero webhook token required, zero isolated cron
//     `Job ID` spawns, and clean rejection if the target session no longer exists!
//   - Registers `before_prompt_build` (respecting `promptInjection` + OpenClaw host gates) and
//     observational `agent_end` / `run_stopped` hooks for exact-session turn-start drain and
//     immediate end-of-turn Queue flush.
//   - Invokes `hyp hook openclaw <event>` strictly via `execFile` argv arrays (ZERO shell
//     interpolation), with a 5s timeout, 256 KiB output cap, and fail-safe fallbacks so an offline
//     daemon or bad JSON NEVER breaks or hangs an OpenClaw turn.

import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const DEFAULT_HYP_BIN = process.env.HYPHAE_BIN || "hyp";
const DEFAULT_HYP_SOCKET = process.env.HYPHAE_SOCKET || "";

const HOOK_TIMEOUT_MS = 5_000;
const MAX_BUFFER_BYTES = 256_000;
const MAX_SOCKET_LINE_BYTES = 64 * 1024;
const MAX_SESSION_KEY_BYTES = 256;
const MAX_AGENT_ID_BYTES = 128;
const RECONNECT_INITIAL_MS = 1_000;
const RECONNECT_MAX_MS = 5_000;

/**
 * Exact canonical OpenClaw tool matcher scoped strictly to Hyphae MCP tools.
 * Never uses a wildcard (`*`) and never matches `exec` or unrelated host tools.
 */
export const HYPHAE_TOOL_MATCHER = Object.freeze([
  "hyp_send",
  "hyp_inbox",
  "hyp_mesh",
  "hyp_stream",
  "hyp_bridge",
  "hyp_kv",
  "hyphae__hyp_send",
  "hyphae__hyp_inbox",
  "hyphae__hyp_mesh",
  "hyphae__hyp_stream",
  "hyphae__hyp_bridge",
  "hyphae__hyp_kv",
]);

const KNOWN_HYPHAE_TOOL_RE =
  /(?:^|__|[./:_])(hyp_(?:send|inbox|mesh|stream|bridge|kv|session|channel))$/;
const VALID_SESSION_ID_RE = /^[a-z0-9][A-Za-z0-9._:-]{1,255}$/;

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value) {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function hasControlOrSpace(str) {
  for (let i = 0; i < str.length; i += 1) {
    const code = str.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

export function isHyphaeToolName(rawName) {
  if (typeof rawName !== "string") return false;
  const trimmed = rawName.trim();
  if (!trimmed || trimmed.length > 128) return false;
  return KNOWN_HYPHAE_TOOL_RE.test(trimmed);
}

/**
 * Strictly validates an OpenClaw `sessionKey` (e.g. `agent:main:main` or
 * `agent:main:explicit:thread-2`), failing closed (`undefined`) on empty strings,
 * excessive length (>256 UTF-8 bytes), whitespace, or ASCII control characters.
 */
export function validateOpenClawSessionKey(raw) {
  if (typeof raw !== "string") return undefined;
  if (raw.length === 0 || Buffer.byteLength(raw, "utf8") > MAX_SESSION_KEY_BYTES) {
    return undefined;
  }
  if (hasControlOrSpace(raw)) {
    return undefined;
  }
  return raw;
}

/**
 * Extracts `<agentId>` from a canonical OpenClaw sessionKey (`agent:<agentId>:<rest>`).
 */
export function parseOpenClawAgentIdFromSessionKey(sessionKey) {
  if (typeof sessionKey !== "string" || !sessionKey.startsWith("agent:")) {
    return undefined;
  }
  const rest = sessionKey.slice("agent:".length);
  const sep = rest.indexOf(":");
  if (sep <= 0 || sep === rest.length - 1) {
    return undefined;
  }
  const agentId = rest.slice(0, sep);
  if (
    Buffer.byteLength(agentId, "utf8") > MAX_AGENT_ID_BYTES ||
    hasControlOrSpace(agentId)
  ) {
    return undefined;
  }
  return agentId;
}

/**
 * Deterministically maps a validated OpenClaw `sessionKey` (or fallback ID) to its canonical
 * Hyphae session ID (`openclaw:<key>`, or `openclaw:sk_<sha256[0..32]>` when `<key>` contains
 * characters outside `[A-Za-z0-9._:-]` or exceeds 256 bytes with prefix).
 *
 * Matches `canonical_openclaw_session_id()` in `crates/hyp-harness/ipc/src/hints.rs`
 * bit-for-bit.
 */
export function canonicalOpenClawSessionId(rawKey) {
  if (typeof rawKey !== "string") return undefined;
  const stripped = rawKey.startsWith("openclaw:")
    ? rawKey.slice("openclaw:".length)
    : rawKey;
  const key = validateOpenClawSessionKey(stripped);
  if (!key) return undefined;
  const direct = `openclaw:${key}`;
  if (VALID_SESSION_ID_RE.test(direct)) {
    return direct;
  }
  const digest = crypto.createHash("sha256").update(key, "utf8").digest("hex");
  return `openclaw:sk_${digest.slice(0, 32)}`;
}

export function resolvePluginConfig(rawConfig) {
  const cfg = isPlainObject(rawConfig) ? rawConfig : {};
  const hypBin =
    nonEmptyString(cfg.hypBin) ||
    nonEmptyString(process.env.HYPHAE_BIN) ||
    DEFAULT_HYP_BIN;
  const socket =
    nonEmptyString(cfg.socket) ||
    nonEmptyString(process.env.HYPHAE_SOCKET) ||
    DEFAULT_HYP_SOCKET;
  const deliveryMode = cfg.deliveryMode === "inbox" ? "inbox" : "gateway";
  const promptInjection = cfg.promptInjection !== false;
  return { hypBin, socket, deliveryMode, promptInjection };
}

export function resolveDefaultDaemonSocket(cfg = {}) {
  const resolved = resolvePluginConfig(cfg);
  if (resolved.socket) {
    return resolved.socket;
  }
  const filename =
    process.platform === "win32" ? "connector.addr" : "connector.sock";
  const envDir = nonEmptyString(process.env.HYPHAE_CONFIG_DIR);
  if (envDir) {
    return path.join(envDir, filename);
  }
  const xdg = nonEmptyString(process.env.XDG_CONFIG_HOME);
  if (xdg) {
    return path.join(xdg, "hyphae", filename);
  }
  if (process.platform === "win32") {
    const appData = nonEmptyString(process.env.APPDATA);
    if (appData) {
      return path.join(appData, "hyphae", filename);
    }
  }
  return path.join(os.homedir(), ".config", "hyphae", filename);
}

/**
 * Extracts exact OpenClaw session routing metadata from a trusted OpenClaw hook context.
 *
 * Precedence: `sessionKey` FIRST (stable canonical session routing key across turns,
 * `/new`, `/reset`, and live wakeups), then `sessionId`, then `agentId`.
 * Fails closed (returns `{}` without `session_id`) when no valid session identifier exists.
 */
export function extractOpenClawSessionPayload(ctx) {
  const c = isPlainObject(ctx) ? ctx : {};
  const rawSessionKey = nonEmptyString(c.sessionKey);
  const sessionKey = rawSessionKey
    ? validateOpenClawSessionKey(
        rawSessionKey.startsWith("openclaw:")
          ? rawSessionKey.slice("openclaw:".length)
          : rawSessionKey,
      )
    : undefined;
  const rawSessionId = nonEmptyString(c.sessionId);
  const sessionId =
    rawSessionId &&
    Buffer.byteLength(rawSessionId, "utf8") <= 200 &&
    !hasControlOrSpace(rawSessionId)
      ? rawSessionId
      : undefined;
  const rawAgentId = nonEmptyString(c.agentId);
  const agentId =
    (rawAgentId &&
    Buffer.byteLength(rawAgentId, "utf8") <= MAX_AGENT_ID_BYTES &&
    !hasControlOrSpace(rawAgentId)
      ? rawAgentId
      : undefined) ||
    (sessionKey ? parseOpenClawAgentIdFromSessionKey(sessionKey) : undefined);
  const cwd = nonEmptyString(c.workspaceDir) || nonEmptyString(c.cwd);

  const primary = sessionKey || sessionId || agentId;
  if (!primary) {
    return {};
  }

  const payload = { session_id: primary };
  if (sessionKey) payload.sessionKey = sessionKey;
  if (sessionId) payload.sessionId = sessionId;
  if (agentId) payload.agentId = agentId;
  if (cwd) payload.cwd = cwd;
  return payload;
}

export function runMeshHook(event, payload, config = {}) {
  const resolved = resolvePluginConfig(config);
  const hypBin = resolved.hypBin;
  const hypSocket = resolved.socket;

  return new Promise((resolve) => {
    const argv = ["hook", "openclaw", event];
    if (hypSocket) {
      argv.push("--socket", hypSocket);
    }

    let settled = false;
    const finish = (val) => {
      if (!settled) {
        settled = true;
        resolve(val);
      }
    };

    try {
      const runViaNode =
        process.platform === "win32" && /\.(?:mjs|cjs|js)$/i.test(hypBin);
      const child = execFile(
        runViaNode ? process.execPath : hypBin,
        runViaNode ? [hypBin, ...argv] : argv,
        {
          timeout: HOOK_TIMEOUT_MS,
          maxBuffer: MAX_BUFFER_BYTES,
          windowsHide: true,
        },
        (error, stdout) => {
          if (error || typeof stdout !== "string") {
            finish({});
            return;
          }
          const trimmed = stdout.trim();
          if (!trimmed) {
            finish({});
            return;
          }
          try {
            const parsed = JSON.parse(trimmed);
            finish(isPlainObject(parsed) ? parsed : {});
          } catch {
            finish({});
          }
        },
      );
      child.on("error", () => finish({}));
      child.stdin?.on("error", () => {});
      child.stdin?.end(JSON.stringify(payload));
    } catch {
      finish({});
    }
  });
}

function classifyWakeErrorReason(errorMessage) {
  const msg = String(errorMessage || "").toLowerCase();
  if (
    msg.includes("origin is missing") ||
    msg.includes("session is missing") ||
    msg.includes("not found") ||
    msg.includes("does not exist") ||
    msg.includes("deleted")
  ) {
    return "openclaw_session_missing";
  }
  return "openclaw_gateway_unavailable";
}

/**
 * Delivers a metadata-only Hyphae wake nudge into an EXACT existing OpenClaw session via
 * `runtimeSystem.captureSessionEventTarget` + `runtimeSystem.enqueueSessionEvent`.
 *
 * Security & correctness invariants:
 * - Fails closed on missing/invalid `sessionKey`, `agentId`, or empty `text`.
 * - NEVER passes `createIfMissing: true`, so closed/deleted sessions fail cleanly with
 *   `openclaw_session_missing` instead of spawning ghost sessions or isolated cron jobs.
 */
export async function handleOpenClawWakePacket(packet, runtimeSystem, logger) {
  if (!isPlainObject(packet)) {
    return { ok: false, reason: "openclaw_invalid_session_key" };
  }
  const sessionKey = validateOpenClawSessionKey(packet.sessionKey);
  if (!sessionKey) {
    return { ok: false, reason: "openclaw_invalid_session_key" };
  }
  const rawAgent = nonEmptyString(packet.agentId);
  const agentId =
    (rawAgent &&
    Buffer.byteLength(rawAgent, "utf8") <= MAX_AGENT_ID_BYTES &&
    !hasControlOrSpace(rawAgent)
      ? rawAgent
      : undefined) ||
    parseOpenClawAgentIdFromSessionKey(sessionKey) ||
    "main";
  const text = nonEmptyString(packet.text);
  if (!text) {
    return { ok: false, reason: "openclaw_request_rejected" };
  }
  const batchId = nonEmptyString(packet.batchId);

  if (
    !runtimeSystem ||
    typeof runtimeSystem.captureSessionEventTarget !== "function" ||
    typeof runtimeSystem.enqueueSessionEvent !== "function"
  ) {
    return { ok: false, reason: "openclaw_gateway_unavailable" };
  }

  try {
    const expectedTarget = await runtimeSystem.captureSessionEventTarget(
      agentId,
      sessionKey,
    );
    const options = {
      agentId,
      sessionKey,
      expectedTarget,
    };
    if (batchId) {
      options.contextKey = `hyphae:wake:${batchId}`;
    }
    const receipt = runtimeSystem.enqueueSessionEvent(text, options);
    if (receipt?.settled && typeof receipt.settled.then === "function") {
      receipt.settled.then(
        (outcome) => {
          if (outcome && outcome.status && outcome.status !== "completed") {
            logger?.warn?.(
              `hyphae-wake session event ${outcome.status} for ${sessionKey}`,
            );
          }
        },
        () => {},
      );
    }
    const accepted = await receipt?.accepted;
    if (accepted?.ok === true) {
      return { ok: true };
    }
    return {
      ok: false,
      reason: classifyWakeErrorReason(accepted?.error || "wake rejected"),
    };
  } catch (err) {
    return {
      ok: false,
      reason: classifyWakeErrorReason(err?.message || String(err)),
    };
  }
}

function connectDaemonSocket(socketPath) {
  // Windows loopback TCP `.addr` file support (strict loopback-only validation).
  if (socketPath.endsWith(".addr")) {
    const raw = fs.readFileSync(socketPath, "utf8").trim();
    const match = /^(127\.0\.0\.1|localhost|\[::1\]):(\d{1,5})$/i.exec(raw);
    if (!match) {
      throw new Error("Invalid loopback daemon address file");
    }
    const host = match[1] === "[::1]" ? "::1" : match[1];
    const port = Number(match[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error("Invalid loopback daemon port");
    }
    return net.createConnection({ host, port });
  }
  return net.createConnection(socketPath);
}

/**
 * Creates the native OpenClaw Gateway plugin service (`hyphae-wake`) that connects to
 * Hyphae's local `connector.sock` and delivers exact-session `enqueueSessionEvent` wakeups
 * with zero webhook tokens, zero polling, and bounded reconnect backoff.
 */
export function createOpenClawWakeService(api, cfg) {
  let stopped = true;
  let activeConn = null;
  let reconnectTimer = null;
  let backoffMs = RECONNECT_INITIAL_MS;

  const clearReconnectTimer = () => {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  };

  const closeActiveConn = () => {
    if (activeConn) {
      try {
        activeConn.removeAllListeners();
        activeConn.destroy();
      } catch {
        // ignore
      }
      activeConn = null;
    }
  };

  return {
    id: "hyphae-wake",
    start(serviceCtx) {
      const runtimeSystem = api?.runtime?.system;
      if (
        !runtimeSystem ||
        typeof runtimeSystem.captureSessionEventTarget !== "function" ||
        typeof runtimeSystem.enqueueSessionEvent !== "function"
      ) {
        return;
      }

      const logger = serviceCtx?.logger || api?.logger;
      const socketPath = resolveDefaultDaemonSocket(cfg);
      stopped = false;
      backoffMs = RECONNECT_INITIAL_MS;

      const scheduleReconnect = () => {
        if (stopped || reconnectTimer !== null) return;
        const delay = backoffMs;
        backoffMs = Math.min(backoffMs * 2, RECONNECT_MAX_MS);
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          connectOnce();
        }, delay);
        reconnectTimer.unref?.();
      };

      const connectOnce = () => {
        if (stopped) return;
        closeActiveConn();

        let conn;
        try {
          conn = connectDaemonSocket(socketPath);
        } catch {
          scheduleReconnect();
          return;
        }
        activeConn = conn;
        let buf = "";

        conn.on("connect", () => {
          if (stopped || activeConn !== conn) return;
          backoffMs = RECONNECT_INITIAL_MS;
          try {
            conn.write(
              `${JSON.stringify({ type: "openclaw.service.ready", version: 1 })}\n`,
            );
          } catch {
            conn.destroy();
          }
        });

        conn.on("data", (chunk) => {
          if (stopped || activeConn !== conn) return;
          buf += chunk.toString("utf8");
          if (Buffer.byteLength(buf, "utf8") > MAX_SOCKET_LINE_BYTES * 2) {
            buf = "";
            conn.destroy();
            return;
          }
          let nl;
          while ((nl = buf.indexOf("\n")) !== -1) {
            const line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line || Buffer.byteLength(line, "utf8") > MAX_SOCKET_LINE_BYTES) {
              continue;
            }
            let pkt;
            try {
              pkt = JSON.parse(line);
            } catch {
              continue;
            }
            if (pkt?.type === "openclaw.wake" && typeof pkt.delivery === "number") {
              const delivery = pkt.delivery;
              void handleOpenClawWakePacket(pkt, runtimeSystem, logger).then(
                (res) => {
                  if (stopped || activeConn !== conn || conn.destroyed) return;
                  const ack = {
                    type: "openclaw.wake.ack",
                    delivery,
                    ok: res.ok === true,
                  };
                  if (res.reason) {
                    ack.reason = res.reason;
                  }
                  try {
                    conn.write(`${JSON.stringify(ack)}\n`);
                  } catch {
                    // socket closing
                  }
                },
              );
            }
          }
        });

        const handleDisconnect = () => {
          if (activeConn === conn) {
            activeConn = null;
          }
          scheduleReconnect();
        };
        conn.on("error", handleDisconnect);
        conn.on("close", handleDisconnect);
      };

      connectOnce();
    },
    stop() {
      stopped = true;
      clearReconnectTimer();
      closeActiveConn();
    },
  };
}

export function createHyphaePlugin() {
  return {
    id: "hyphae",
    name: "Hyphae Mesh",
    description:
      "Hyphae E2EE agent mesh exact-session caller binding, native wake service, and turn-start inbox delivery plugin for OpenClaw.",
    register(api) {
      const cfg = resolvePluginConfig(api?.pluginConfig);

      if (typeof api?.on === "function") {
        // 1. Scoped PreToolUse verification: binds every Hyphae MCP tool call to this exact
        //    OpenClaw `(agentId, sessionKey)` via a single-use cryptographic `_meshCall` token.
        //    Never matches `exec` or unrelated tools, and never throws (fail-safe when daemon offline).
        api.on(
          "before_tool_call",
          async (event, ctx) => {
            try {
              const toolName =
                nonEmptyString(event?.toolName) || nonEmptyString(ctx?.toolName);
              if (!toolName || !isHyphaeToolName(toolName)) {
                return undefined;
              }
              const payload = extractOpenClawSessionPayload(ctx);
              if (!payload.session_id) {
                return undefined;
              }
              payload.toolName = toolName;
              const toolCallId =
                nonEmptyString(event?.toolCallId) ||
                nonEmptyString(ctx?.toolCallId);
              if (toolCallId) {
                payload.toolCallId = toolCallId;
              }
              const origParams = isPlainObject(event?.params) ? event.params : {};
              payload.params = origParams;

              const res = await runMeshHook("before-tool-call", payload, cfg);
              const callToken = nonEmptyString(res?.callToken);
              if (callToken) {
                return { params: { ...origParams, _meshCall: callToken } };
              }
              return undefined;
            } catch {
              return undefined;
            }
          },
          { matcher: HYPHAE_TOOL_MATCHER },
        );

        // 2. Scoped PostToolUse cleanup: releases any unconsumed `callId` in daemon CallRegistry.
        //    Never drains mailbox (OpenClaw ignores `after_tool_call` return values).
        api.on(
          "after_tool_call",
          async (event, ctx) => {
            try {
              const toolName =
                nonEmptyString(event?.toolName) || nonEmptyString(ctx?.toolName);
              if (!toolName || !isHyphaeToolName(toolName)) {
                return undefined;
              }
              const payload = extractOpenClawSessionPayload(ctx);
              if (!payload.session_id) {
                return undefined;
              }
              payload.toolName = toolName;
              const toolCallId =
                nonEmptyString(event?.toolCallId) ||
                nonEmptyString(ctx?.toolCallId);
              if (toolCallId) {
                payload.toolCallId = toolCallId;
              }
              await runMeshHook("after-tool-call", payload, cfg);
            } catch {
              // fail-safe
            }
            return undefined;
          },
          { matcher: HYPHAE_TOOL_MATCHER },
        );

        // 3. TurnStart inbox drain (`before_prompt_build`): defense-in-depth toggle in addition to
        //    OpenClaw's host-enforced `allowPromptModification` + `allowConversationAccess`.
        api.on("before_prompt_build", async (_event, ctx) => {
          if (!cfg.promptInjection) {
            return undefined;
          }
          const payload = extractOpenClawSessionPayload(ctx);
          if (!payload.session_id) {
            return undefined;
          }
          const res = await runMeshHook("before-prompt-build", payload, cfg);
          if (
            typeof res.prependContext === "string" &&
            res.prependContext.length > 0
          ) {
            return { prependContext: res.prependContext };
          }
          return undefined;
        });

        // 4. Observational TurnEnd hooks (`agent_end` + `run_stopped`): notify LocalDaemon
        //    immediately that the turn ended (flips Active -> Idle so deferred Queue wakeups flush
        //    with zero lease delay). `run_stopped` runs even when `allowConversationAccess=false`.
        api.on("agent_end", async (_event, ctx) => {
          const payload = extractOpenClawSessionPayload(ctx);
          if (!payload.session_id) {
            return undefined;
          }
          await runMeshHook("agent-end", payload, cfg);
          return undefined;
        });

        api.on("run_stopped", async (event, ctx) => {
          const sessions = Array.isArray(event?.sessions) && event.sessions.length > 0
            ? event.sessions
            : [ctx];
          for (const sess of sessions) {
            const payload = extractOpenClawSessionPayload(sess);
            if (payload.session_id) {
              await runMeshHook("agent-end", payload, cfg);
            }
          }
          return undefined;
        });
      }

      // 5. Native exact-session Gateway wake service (enabled unless deliveryMode === "inbox").
      if (
        cfg.deliveryMode !== "inbox" &&
        typeof api?.registerService === "function"
      ) {
        api.registerService(createOpenClawWakeService(api, cfg));
      }
    },
  };
}

export default createHyphaePlugin();
