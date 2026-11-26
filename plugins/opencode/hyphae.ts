// Hyphae v2 real lifecycle hook plugin for OpenCode (`~/.config/opencode/plugins/hyphae.ts`).
//
// Supports BOTH:
//   - OpenCode v2 (`export default { id: "hyphae", async setup(api) { ... } }`):
//     * `api.tool.transform`: observes Code Mode (`options.codemode === true`) tool IDs so inner
//       Code Mode calls never swallow mid-turn Interrupt messages.
//     * `api.tool.hook("execute.before")`: strips untrusted `_meshCall`, registers verified
//       per-session caller (`opencode:<sessionID>`) via `hyp hook opencode pre-tool-use`, and
//       injects single-use `_meshCall` (plus safe `updatedInput`) into `ev.input` — works for
//       BOTH Code Mode (`tools.hyphae.hyp_*` inside `execute`) and direct tool calls.
//     * `api.tool.hook("execute.after")`: scrubs consumed `_meshCall`, skips inner Code Mode
//       calls (whose `result.content` is discarded by Code Mode), and drains mid-turn Interrupt
//       messages into outer `execute` / direct tool `ev.result.content`.
//     * `api.session.hook("prompt")`: drains pre-turn messages via `hyp hook opencode pre-invocation`
//       and appends `additionalContext` to `ev.prompt.text` (skipping plugin-originated prompts).
//     * `api.event.subscribe` (`session.execution.succeeded` / `session.idle`): runs
//       `hyp hook opencode stop` and delivers held Queue messages or a single-shot background
//       waiter reminder via `api.session.prompt({ sessionID, text })` with an anti-loop guard.
//   - OpenCode v1 (`export const HyphaePlugin = async (ctx) => ({ ... })`):
//     * Preserved named factory for v1 harnesses (`tool.execute.before`, `tool.execute.after`,
//       `event` -> `ctx.client.session.prompt`).
//
// Security invariants:
//   - Strict `execFile` argv arrays (never shell interpolation), 5s timeout, 256 KiB buffer cap,
//     and fail-safe `{}` fallbacks so an offline daemon never breaks OpenCode tool execution.
//   - Strips pre-existing/forged `_meshCall` before `pre-tool-use` and guards against prototype
//     pollution (`__proto__`, `constructor`, `prototype`).

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
  sessionId?: string;
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

interface OpenCodeV2ToolBeforeEvent {
  tool?: string;
  sessionID?: string;
  sessionId?: string;
  id?: string;
  callID?: string;
  callId?: string;
  input?: Record<string, unknown>;
}

interface OpenCodeV2ToolAfterEvent {
  tool?: string;
  sessionID?: string;
  sessionId?: string;
  id?: string;
  callID?: string;
  callId?: string;
  input?: Record<string, unknown>;
  status?: string;
  result?: {
    output?: unknown;
    content?: unknown[];
    metadata?: unknown;
  };
}

interface OpenCodeV2PromptHookEvent {
  sessionID?: string;
  sessionId?: string;
  messageID?: string;
  prompt?: {
    text?: string;
    files?: unknown[];
  };
  delivery?: string;
}

interface OpenCodeV2ToolDefinition {
  id?: string;
  name?: string;
  options?: {
    codemode?: boolean;
    namespace?: string;
  };
}

interface OpenCodeV2ToolRegistry {
  list?: () => OpenCodeV2ToolDefinition[];
}

interface OpenCodeV2PluginApi {
  location?: {
    directory?: string;
    project?: {
      directory?: string;
    };
  };
  tool?: {
    transform?: (
      cb: (registry: OpenCodeV2ToolRegistry) => void,
    ) => unknown;
    hook?: (
      name: string,
      handler: (ev: any) => unknown,
    ) => unknown;
  };
  session?: {
    hook?: (
      name: string,
      handler: (ev: any) => unknown,
      opts?: unknown,
    ) => unknown;
    prompt?: (input: { sessionID: string; text: string }) => unknown;
  };
  event?: {
    subscribe?: (opts?: { types?: string[] }) => unknown;
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] ===
      "function"
  );
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
      const runViaNode =
        process.platform === "win32" && /\.(?:mjs|cjs|js)$/i.test(HYP_BIN);
      const child = execFile(
        runViaNode ? process.execPath : HYP_BIN,
        runViaNode ? [HYP_BIN, ...argv] : argv,
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

function extractSessionId(rec: unknown): string {
  if (!isPlainObject(rec)) return "";
  const candidate = rec.sessionID ?? rec.sessionId;
  return typeof candidate === "string" && candidate.length > 0 ? candidate : "";
}

function extractCallId(rec: unknown): string {
  if (!isPlainObject(rec)) return "";
  const candidate = rec.callID ?? rec.callId ?? rec.id;
  return typeof candidate === "string" && candidate.length > 0 ? candidate : "";
}

function extractMeshCall(res: Record<string, unknown>): string | undefined {
  if (typeof res._meshCall === "string" && res._meshCall) {
    return res._meshCall;
  }
  if (typeof res.callToken === "string" && res.callToken) {
    return res.callToken;
  }
  return undefined;
}

function applyPreToolResult(
  targetArgs: Record<string, unknown>,
  updatedInput: Record<string, unknown> | undefined,
  meshCall: string | undefined,
): void {
  if (updatedInput) {
    for (const [key, val] of Object.entries(updatedInput)) {
      if (!UNSAFE_KEYS.has(key)) {
        targetArgs[key] = val;
      }
    }
  }
  if (meshCall) {
    targetArgs._meshCall = meshCall;
  }
}

function buildPreToolPayload(
  sessionID: string,
  tool: string,
  callID: string,
  rawArgs: Record<string, unknown> | undefined,
  cwd: string | undefined,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    session_id: sessionID,
    sessionID,
    tool_name: tool,
    tool,
  };
  if (callID) {
    payload.call_id = callID;
    payload.callID = callID;
  }
  if (rawArgs) {
    payload.tool_input = rawArgs;
    payload.args = rawArgs;
  }
  if (cwd) {
    payload.cwd = cwd;
  }
  return payload;
}

function buildPostToolPayload(
  sessionID: string,
  tool: string,
  callID: string,
  cwd: string | undefined,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    session_id: sessionID,
    sessionID,
  };
  if (tool) {
    payload.tool_name = tool;
    payload.tool = tool;
  }
  if (callID) {
    payload.call_id = callID;
    payload.callID = callID;
  }
  if (cwd) {
    payload.cwd = cwd;
  }
  return payload;
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

function appendV2ToolResultContext(
  result: OpenCodeV2ToolAfterEvent["result"],
  context: string,
): void {
  if (!isPlainObject(result) || !context) return;

  if (Array.isArray(result.content)) {
    result.content.push({ type: "text", text: context });
    return;
  }

  appendAdditionalContext(result as ToolAfterOutput, context);
}

function extractEventSessionId(event: OpenCodeEvent | undefined): string | undefined {
  if (!isPlainObject(event)) return undefined;
  const candidate =
    event.data?.sessionID ??
    event.data?.sessionId ??
    event.properties?.sessionID ??
    event.properties?.sessionId ??
    event.sessionID ??
    event.sessionId;
  return typeof candidate === "string" && candidate.length > 0
    ? candidate
    : undefined;
}

function extractIdleSessionId(event: OpenCodeEvent | undefined): string | undefined {
  if (
    !isPlainObject(event) ||
    (event.type !== "session.idle" && event.type !== "session.execution.succeeded")
  ) {
    return undefined;
  }
  return extractEventSessionId(event);
}

interface ExecuteTracker {
  ids: Set<string>;
  anonymousDepth: number;
}

function markExecuteStart(
  map: Map<string, ExecuteTracker>,
  sessionID: string,
  callID: string,
): void {
  let tracker = map.get(sessionID);
  if (!tracker) {
    tracker = { ids: new Set<string>(), anonymousDepth: 0 };
    map.set(sessionID, tracker);
  }
  if (callID) {
    tracker.ids.add(callID);
  } else {
    tracker.anonymousDepth += 1;
  }
}

function markExecuteEnd(
  map: Map<string, ExecuteTracker>,
  sessionID: string,
  callID: string,
): void {
  const tracker = map.get(sessionID);
  if (!tracker) return;
  if (callID && tracker.ids.has(callID)) {
    tracker.ids.delete(callID);
  } else if (tracker.anonymousDepth > 0) {
    tracker.anonymousDepth -= 1;
  } else if (tracker.ids.size > 0) {
    const first = tracker.ids.values().next().value;
    if (first !== undefined) tracker.ids.delete(first);
  }
  if (tracker.ids.size === 0 && tracker.anonymousDepth === 0) {
    map.delete(sessionID);
  }
}

function hasActiveExecute(
  map: Map<string, ExecuteTracker>,
  sessionID: string,
): boolean {
  const tracker = map.get(sessionID);
  return Boolean(tracker && (tracker.ids.size > 0 || tracker.anonymousDepth > 0));
}

interface PendingPluginPrompt {
  id: number;
  text: string;
}

let nextPluginPromptId = 1;

function enqueuePendingPluginPrompt(
  map: Map<string, PendingPluginPrompt[]>,
  sessionID: string,
  text: string,
): number {
  const id = nextPluginPromptId++;
  let list = map.get(sessionID);
  if (!list) {
    list = [];
    map.set(sessionID, list);
  }
  list.push({ id, text });
  return id;
}

function consumePendingPluginPrompt(
  map: Map<string, PendingPluginPrompt[]>,
  sessionID: string,
  text: string | undefined,
): boolean {
  if (typeof text !== "string" || !text) return false;
  const list = map.get(sessionID);
  if (!list || list.length === 0) return false;
  const idx = list.findIndex((item) => item.text === text);
  if (idx === -1) return false;
  list.splice(idx, 1);
  if (list.length === 0) map.delete(sessionID);
  return true;
}

function removePendingPluginPrompt(
  map: Map<string, PendingPluginPrompt[]>,
  sessionID: string,
  id: number,
): void {
  const list = map.get(sessionID);
  if (!list) return;
  const idx = list.findIndex((item) => item.id === id);
  if (idx !== -1) {
    list.splice(idx, 1);
  }
  if (list.length === 0) map.delete(sessionID);
}

function invokeDisposer(handle: unknown): void {
  try {
    if (typeof handle === "function") {
      (handle as () => unknown)();
    } else if (isPlainObject(handle) && typeof handle.dispose === "function") {
      (handle.dispose as () => unknown)();
    }
  } catch {
    // Fail-safe: never throw during plugin teardown.
  }
}

// ============================================================================
// OpenCode v1 Factory Export (preserved for v1 harnesses & backward compatibility)
// ============================================================================

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
      const sessionID = extractSessionId(input);
      if (!sessionID) return;
      idleReminderSent.delete(sessionID);

      const tool = typeof input?.tool === "string" ? input.tool : "";
      if (!tool || !HYPHAE_TOOL_RE.test(tool)) return;

      if (isPlainObject(output?.args) && "_meshCall" in output.args) {
        delete output.args._meshCall;
      }

      const rawArgs = isPlainObject(output?.args) ? { ...output.args } : undefined;
      const callID = extractCallId(input);
      const payload = buildPreToolPayload(sessionID, tool, callID, rawArgs, cwd);

      const res = await runMeshHook("pre-tool-use", payload);
      if (!isPlainObject(output)) return;

      const updatedInput = isPlainObject(res.updatedInput)
        ? res.updatedInput
        : undefined;
      const meshCall = extractMeshCall(res);

      if (!updatedInput && !meshCall) return;
      if (!isPlainObject(output.args)) {
        output.args = {};
      }
      applyPreToolResult(output.args, updatedInput, meshCall);
    },

    "tool.execute.after": async (
      input: ToolHookInput,
      output: ToolAfterOutput,
    ) => {
      const sessionID = extractSessionId(input);
      if (!sessionID) return;
      idleReminderSent.delete(sessionID);

      const tool = typeof input?.tool === "string" ? input.tool : "";
      const callID = extractCallId(input);
      const payload = buildPostToolPayload(sessionID, tool, callID, cwd);

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

// ============================================================================
// OpenCode v2 Plugin Definition Default Export (`{ id, setup(api) }`)
// ============================================================================

const HyphaeV2Plugin = {
  id: "hyphae",

  async setup(api: OpenCodeV2PluginApi) {
    const cwd =
      typeof api?.location?.directory === "string" && api.location.directory
        ? api.location.directory
        : typeof api?.location?.project?.directory === "string" &&
            api.location.project.directory
          ? api.location.project.directory
          : undefined;

    const idleReminderSent = new Set<string>();
    const inFlightIdle = new Set<string>();
    const codemodeToolIds = new Set<string>();
    const activeExecuteCalls = new Map<string, ExecuteTracker>();
    const pendingPluginPrompts = new Map<string, PendingPluginPrompt[]>();
    const disposers: unknown[] = [];
    let disposed = false;

    const registerDisposer = (handle: unknown) => {
      if (handle !== undefined && handle !== null) {
        disposers.push(handle);
      }
    };

    // 1. Track Code Mode tools (`options.codemode === true`) without mutating registry.
    if (typeof api?.tool?.transform === "function") {
      try {
        const dTransform = await api.tool.transform((reg) => {
          if (typeof reg?.list !== "function") return;
          const next = new Set<string>();
          for (const toolDef of reg.list()) {
            if (
              isPlainObject(toolDef) &&
              typeof toolDef.id === "string" &&
              isPlainObject(toolDef.options) &&
              toolDef.options.codemode === true
            ) {
              next.add(toolDef.id);
            }
          }
          codemodeToolIds.clear();
          for (const id of next) {
            codemodeToolIds.add(id);
          }
        });
        registerDisposer(dTransform);
      } catch {
        // Fail-safe: HYPHAE_TOOL_RE fallback still handles Code Mode Hyphae tools.
      }
    }

    // 2. Tool hooks: verified `_meshCall` injection on `execute.before` (both Code Mode
    //    `tools.hyphae.hyp_*` and direct calls) + mid-turn Interrupt drain on `execute.after`.
    if (typeof api?.tool?.hook === "function") {
      const dBefore = await api.tool.hook(
        "execute.before",
        async (ev: OpenCodeV2ToolBeforeEvent) => {
          const sessionID = extractSessionId(ev);
          if (!sessionID) return;
          idleReminderSent.delete(sessionID);

          const tool = typeof ev?.tool === "string" ? ev.tool : "";
          const callID = extractCallId(ev);
          if (tool === "execute") {
            markExecuteStart(activeExecuteCalls, sessionID, callID);
          }
          if (!tool || !HYPHAE_TOOL_RE.test(tool)) return;

          // Fail closed against untrusted/forged `_meshCall` passed inside Code Mode arguments.
          if (isPlainObject(ev.input) && "_meshCall" in ev.input) {
            delete ev.input._meshCall;
          }

          const rawArgs = isPlainObject(ev.input) ? { ...ev.input } : undefined;
          const payload = buildPreToolPayload(sessionID, tool, callID, rawArgs, cwd);
          const res = await runMeshHook("pre-tool-use", payload);

          const updatedInput = isPlainObject(res.updatedInput)
            ? res.updatedInput
            : undefined;
          const meshCall = extractMeshCall(res);
          if (!updatedInput && !meshCall) return;

          if (!isPlainObject(ev.input)) {
            ev.input = {};
          }
          applyPreToolResult(ev.input, updatedInput, meshCall);
        },
      );
      registerDisposer(dBefore);

      const dAfter = await api.tool.hook(
        "execute.after",
        async (ev: OpenCodeV2ToolAfterEvent) => {
          const sessionID = extractSessionId(ev);
          if (!sessionID) return;
          idleReminderSent.delete(sessionID);

          const tool = typeof ev?.tool === "string" ? ev.tool : "";
          const callID = extractCallId(ev);
          if (tool === "execute") {
            markExecuteEnd(activeExecuteCalls, sessionID, callID);
          }

          // Scrub single-use `_meshCall` from tool input after execution completes.
          if (
            tool &&
            HYPHAE_TOOL_RE.test(tool) &&
            isPlainObject(ev.input) &&
            "_meshCall" in ev.input
          ) {
            delete ev.input._meshCall;
          }

          // Code Mode discards `ev.result.content` of inner tools and forwards only parsed
          // `ev.result.output` to JS. Skip draining here so mid-turn Interrupt messages
          // drain into the enclosing `execute` call's `ev.result.content` instead.
          const isInnerCodeMode =
            tool !== "execute" &&
            hasActiveExecute(activeExecuteCalls, sessionID) &&
            (codemodeToolIds.has(tool) || HYPHAE_TOOL_RE.test(tool));
          if (isInnerCodeMode) {
            return;
          }

          const payload = buildPostToolPayload(sessionID, tool, callID, cwd);
          const res = await runMeshHook("post-tool-use", payload);
          if (
            typeof res.additionalContext === "string" &&
            res.additionalContext.length > 0
          ) {
            appendV2ToolResultContext(ev?.result, res.additionalContext);
          }
        },
      );
      registerDisposer(dAfter);
    }

    // 3. Pre-turn inbox drain (`api.session.hook("prompt")` -> `hyp hook opencode pre-invocation`).
    if (typeof api?.session?.hook === "function") {
      const dPrompt = await api.session.hook(
        "prompt",
        async (ev: OpenCodeV2PromptHookEvent) => {
          const sessionID = extractSessionId(ev);
          if (!sessionID) return;

          const promptObj = isPlainObject(ev?.prompt) ? ev.prompt : undefined;
          const promptText =
            typeof promptObj?.text === "string" ? promptObj.text : undefined;

          if (consumePendingPluginPrompt(pendingPluginPrompts, sessionID, promptText)) {
            return;
          }

          idleReminderSent.delete(sessionID);
          activeExecuteCalls.delete(sessionID);

          const payload: Record<string, unknown> = {
            session_id: sessionID,
            sessionID,
          };
          if (cwd) {
            payload.cwd = cwd;
          }

          const res = await runMeshHook("pre-invocation", payload);
          if (
            typeof res.additionalContext === "string" &&
            res.additionalContext.length > 0 &&
            promptObj
          ) {
            promptObj.text =
              typeof promptObj.text === "string" && promptObj.text.length > 0
                ? `${promptObj.text}\n\n${res.additionalContext}`
                : res.additionalContext;
          }
        },
      );
      registerDisposer(dPrompt);
    }

    // 4. Turn-boundary / idle delivery (`api.event.subscribe` -> `hyp hook opencode stop`
    //    -> `api.session.prompt({ sessionID, text })`) with anti-loop guard.
    if (typeof api?.event?.subscribe === "function") {
      let sub: unknown;
      try {
        sub = api.event.subscribe({
          types: [
            "session.execution.succeeded",
            "session.execution.failed",
            "session.execution.aborted",
            "session.idle",
          ],
        });
      } catch {
        sub = undefined;
      }

      const handleEvent = async (ev: unknown) => {
        if (!isPlainObject(ev)) return;
        const evType = typeof ev.type === "string" ? ev.type : "";
        const sessionID = extractEventSessionId(ev as OpenCodeEvent);
        if (!sessionID) return;

        if (
          evType === "session.execution.failed" ||
          evType === "session.execution.aborted"
        ) {
          activeExecuteCalls.delete(sessionID);
          return;
        }
        if (evType !== "session.execution.succeeded" && evType !== "session.idle") {
          return;
        }

        activeExecuteCalls.delete(sessionID);
        if (inFlightIdle.has(sessionID)) return;
        inFlightIdle.add(sessionID);
        try {
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

          const sessionApi = api?.session;
          if (typeof sessionApi?.prompt !== "function") {
            return;
          }

          if (!res.followupMessage.startsWith("Incoming hyphae message(s):")) {
            idleReminderSent.add(sessionID);
          }

          const token = enqueuePendingPluginPrompt(
            pendingPluginPrompts,
            sessionID,
            res.followupMessage,
          );
          try {
            await sessionApi.prompt({
              sessionID,
              text: res.followupMessage,
            });
          } catch {
            // Fail-safe: never crash OpenCode if prompt delivery fails.
          } finally {
            removePendingPluginPrompt(pendingPluginPrompts, sessionID, token);
          }
        } finally {
          inFlightIdle.delete(sessionID);
        }
      };

      if (isAsyncIterable(sub)) {
        const iterator = sub[Symbol.asyncIterator]();
        registerDisposer(() => {
          try {
            void iterator.return?.();
          } catch {
            // ignore shutdown iterator errors
          }
        });
        void (async () => {
          try {
            while (!disposed) {
              const step = await iterator.next();
              if (step.done || disposed) break;
              await handleEvent(step.value);
            }
          } catch {
            // Fail-safe: ignore event stream shutdown errors.
          }
        })();
      }
    }

    return () => {
      disposed = true;
      for (const handle of disposers) {
        invokeDisposer(handle);
      }
      disposers.length = 0;
    };
  },
};

export default HyphaeV2Plugin;
