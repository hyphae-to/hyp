// Hyphae v2 official OpenClaw plugin (`~/.openclaw/extensions/hyphae/index.js`).
//
// Zero external npm dependencies (native Node.js ESM only):
//   - Registers `before_prompt_build` via OpenClaw's typed `api.on(...)` hook surface.
//   - Invokes `hyp hook openclaw before-prompt-build` using strict `execFile` argv arrays
//     (ZERO shell interpolation), a 5s timeout, 256 KiB output cap, and fail-safe fallbacks
//     so an offline daemon or bad JSON NEVER breaks or hangs an OpenClaw turn.
//   - Defense-in-depth toggle: respects `api.pluginConfig.promptInjection !== false` in addition
//     to OpenClaw's host-enforced `plugins.entries.hyphae.hooks.allowPromptModification` and
//     `allowConversationAccess` gates. When disabled, does NOT drain or mutate prompts — unread
//     Hyphae messages remain intact for Gateway wake nudges and `hyp_inbox`.

import { execFile } from "node:child_process";

const DEFAULT_HYP_BIN = process.env.HYPHAE_BIN || "hyp";
const DEFAULT_HYP_SOCKET = process.env.HYPHAE_SOCKET || "";

const HOOK_TIMEOUT_MS = 5_000;
const MAX_BUFFER_BYTES = 256_000;

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value) {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function resolvePluginConfig(rawConfig) {
  const cfg = isPlainObject(rawConfig) ? rawConfig : {};
  const hypBin = nonEmptyString(cfg.hypBin) || nonEmptyString(process.env.HYPHAE_BIN) || DEFAULT_HYP_BIN;
  const socket = nonEmptyString(cfg.socket) || nonEmptyString(process.env.HYPHAE_SOCKET) || DEFAULT_HYP_SOCKET;
  const deliveryMode = cfg.deliveryMode === "inbox" ? "inbox" : "gateway";
  const promptInjection = cfg.promptInjection !== false;
  return { hypBin, socket, deliveryMode, promptInjection };
}

export function extractOpenClawSessionPayload(ctx) {
  const c = isPlainObject(ctx) ? ctx : {};
  const sessionId = nonEmptyString(c.sessionId);
  const sessionKey = nonEmptyString(c.sessionKey);
  const agentId = nonEmptyString(c.agentId);
  const cwd = nonEmptyString(c.workspaceDir) || nonEmptyString(c.cwd);

  const primarySessionId = sessionId || sessionKey || agentId || "main";
  const payload = { session_id: primarySessionId };
  if (sessionId) payload.sessionId = sessionId;
  if (sessionKey) payload.sessionKey = sessionKey;
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

export function createHyphaePlugin() {
  return {
    id: "hyphae",
    name: "Hyphae Mesh",
    description: "Hyphae E2EE agent mesh turn-start inbox delivery plugin for OpenClaw.",
    register(api) {
      const cfg = resolvePluginConfig(api?.pluginConfig);

      if (typeof api?.on !== "function") {
        return;
      }

      api.on("before_prompt_build", async (_event, ctx) => {
        if (!cfg.promptInjection) {
          return undefined;
        }
        const payload = extractOpenClawSessionPayload(ctx);
        const res = await runMeshHook("before-prompt-build", payload, cfg);
        if (
          typeof res.prependContext === "string" &&
          res.prependContext.length > 0
        ) {
          return { prependContext: res.prependContext };
        }
        return undefined;
      });
    },
  };
}

export default createHyphaePlugin();
