// Hyphae v2 real lifecycle hook plugin for OpenCode (`~/.config/opencode/plugins/hyphae.ts`).
//
// Wires OpenCode's native plugin lifecycle hooks to `hyp hook opencode <event>` over stdin/stdout
// using strict `execFile` argv arrays (never shell interpolation), a 5s timeout, and fail-safe `{}`
// fallbacks so an offline daemon never breaks OpenCode tool execution:
//   - `tool.execute.before`: registers verified per-session caller (`opencode:<sessionID>`) and
//     injects `_meshCall` (and any `updatedInput` fields) into `output.args`.
//   - `tool.execute.after`: drains incoming Hyphae messages and appends `additionalContext` cleanly
//     without breaking non-string tool outputs.
//   - `event` (`session.idle`): drains unread messages / arms idle waiter via `client.session.prompt`.

import { execFile } from "node:child_process";

const HYP_BIN: string = process.env.HYPHAE_BIN || "hyp";
const HYP_SOCKET: string = process.env.HYPHAE_SOCKET || "";

const HOOK_TIMEOUT_MS = 5_000;
const MAX_BUFFER_BYTES = 256_000;
const HYPHAE_TOOL_RE = /^(?:(?:mcp__?)?hyphae(?:__|[_./:])[a-z0-9_]+|hyp_[a-z_]+)$/;
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

interface ToolHookInput {
  tool?: string;
  sessionID?: string;
  callID?: string;
}

interface ToolBeforeOutput {
  args?: Record<string, unknown>;
}

interface ToolAfterOutput {
  title?: string;
  output?: unknown;
  metadata?: unknown;
}

interface OpenCodeEvent {
  type?: string;
  sessionID?: string;
  properties?: {
    sessionID?: string;
    sessionId?: string;
  };
  data?: {
    sessionID?: string;
    sessionId?: string;
  };
}

interface OpenCodePluginContext {
  directory?: string;
  worktree?: string;
  client?: {
    session?: {
      prompt?: (input: {
        path: { id: string };
        body: { parts: Array<{ type: "text"; text: string }> };
      }) => unknown;
    };
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function runMeshHook(
  event: string,
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const argv = ["hook", "opencode", event];
    if (HYP_SOCKET) {
      argv.push("--socket", HYP_SOCKET);
    }

    let settled = false;
    const finish = (val: Record<string, unknown>) => {
      if (!settled) {
        settled = true;
        resolve(val);
      }
    };

    try {
      const child = execFile(
        HYP_BIN,
        argv,
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
            const parsed: unknown = JSON.parse(trimmed);
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

function appendAdditionalContext(
  output: ToolAfterOutput | undefined,
  context: string,
): void {
  if (!isPlainObject(output) || !context) return;

  if (typeof output.output === "string") {
    output.output =
      output.output.length > 0 ? `${output.output}\n\n${context}` : context;
    return;
  }

  if (output.output === undefined || output.output === null) {
    output.output = context;
    return;
  }

  if (
    Array.isArray(output.output) &&
    (output.output.length === 0 ||
      output.output.every(
        (part) => isPlainObject(part) && typeof part.type === "string",
      ))
  ) {
    output.output.push({ type: "text", text: context });
    return;
  }

  // Preserve non-string / structured tool outputs intact; attach to metadata if present.
  if (isPlainObject(output.metadata)) {
    output.metadata.hyphaeAdditionalContext = context;
  }
}

function extractIdleSessionId(event: OpenCodeEvent | undefined): string | undefined {
  if (!isPlainObject(event) || event.type !== "session.idle") {
    return undefined;
  }
  const candidate =
    event.properties?.sessionID ??
    event.properties?.sessionId ??
    event.data?.sessionID ??
    event.data?.sessionId ??
    event.sessionID;
  return typeof candidate === "string" && candidate.length > 0
    ? candidate
    : undefined;
}

export const HyphaePlugin = async (ctx: OpenCodePluginContext = {}) => {
  const cwd =
    typeof ctx?.directory === "string" && ctx.directory
      ? ctx.directory
      : typeof ctx?.worktree === "string" && ctx.worktree
        ? ctx.worktree
        : undefined;
  const idleReminderSent = new Set<string>();

  return {
    "tool.execute.before": async (
      input: ToolHookInput,
      output: ToolBeforeOutput,
    ) => {
      const sessionID =
        typeof input?.sessionID === "string" ? input.sessionID : "";
      if (!sessionID) return;
      idleReminderSent.delete(sessionID);

      const tool = typeof input?.tool === "string" ? input.tool : "";
      if (!tool || !HYPHAE_TOOL_RE.test(tool)) return;

      const rawArgs = isPlainObject(output?.args) ? output.args : undefined;
      const payload: Record<string, unknown> = {
        session_id: sessionID,
        sessionID,
        tool_name: tool,
        tool,
      };
      if (typeof input.callID === "string" && input.callID) {
        payload.call_id = input.callID;
        payload.callID = input.callID;
      }
      if (rawArgs) {
        payload.tool_input = rawArgs;
        payload.args = rawArgs;
      }
      if (cwd) {
        payload.cwd = cwd;
      }

      const res = await runMeshHook("pre-tool-use", payload);
      if (!isPlainObject(output)) return;

      const updatedInput = isPlainObject(res.updatedInput)
        ? res.updatedInput
        : undefined;
      const meshCall =
        typeof res._meshCall === "string" && res._meshCall
          ? res._meshCall
          : typeof res.callToken === "string" && res.callToken
            ? res.callToken
            : undefined;

      if (!updatedInput && !meshCall) return;
      if (!isPlainObject(output.args)) {
        output.args = {};
      }
      if (updatedInput) {
        for (const [key, val] of Object.entries(updatedInput)) {
          if (!UNSAFE_KEYS.has(key)) {
            output.args[key] = val;
          }
        }
      }
      if (meshCall) {
        output.args._meshCall = meshCall;
      }
    },

    "tool.execute.after": async (
      input: ToolHookInput,
      output: ToolAfterOutput,
    ) => {
      const sessionID =
        typeof input?.sessionID === "string" ? input.sessionID : "";
      if (!sessionID) return;
      idleReminderSent.delete(sessionID);

      const payload: Record<string, unknown> = {
        session_id: sessionID,
        sessionID,
      };
      if (typeof input.tool === "string" && input.tool) {
        payload.tool_name = input.tool;
        payload.tool = input.tool;
      }
      if (typeof input.callID === "string" && input.callID) {
        payload.call_id = input.callID;
        payload.callID = input.callID;
      }
      if (cwd) {
        payload.cwd = cwd;
      }

      const res = await runMeshHook("post-tool-use", payload);
      if (
        typeof res.additionalContext === "string" &&
        res.additionalContext.length > 0
      ) {
        appendAdditionalContext(output, res.additionalContext);
      }
    },

    event: async (arg: { event?: OpenCodeEvent }) => {
      const sessionID = extractIdleSessionId(arg?.event);
      if (!sessionID) return;

      const payload: Record<string, unknown> = {
        session_id: sessionID,
        sessionID,
        continuationActive: idleReminderSent.has(sessionID),
      };
      if (cwd) {
        payload.cwd = cwd;
      }

      const res = await runMeshHook("stop", payload);
      if (
        typeof res.followupMessage !== "string" ||
        res.followupMessage.length === 0
      ) {
        return;
      }

      const sessionApi = ctx?.client?.session;
      if (typeof sessionApi?.prompt !== "function") {
        return;
      }

      if (!res.followupMessage.startsWith("Incoming hyphae message(s):")) {
        idleReminderSent.add(sessionID);
      }

      try {
        await sessionApi.prompt({
          path: { id: sessionID },
          body: { parts: [{ type: "text", text: res.followupMessage }] },
        });
      } catch {
        // Fail-safe: never crash OpenCode if prompt delivery fails.
      }
    },
  };
};

export default HyphaePlugin;
