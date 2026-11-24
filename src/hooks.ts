import { createConnection } from "node:net";
import { normalizeMeshToolName, object, type HarnessKind } from "./protocol.ts";

export type HookEvent = "pre-tool-use" | "post-tool-use" | "pre-invocation" | "stop";

interface DaemonRpcResult {
  ok: boolean;
  result?: Record<string, unknown>;
}

/** Fast single-shot local Unix socket RPC for synchronous hooks (fails open when daemon is offline). */
export function daemonRpc(socketPath: string, packet: Record<string, unknown>, timeoutMs = 2_000): Promise<DaemonRpcResult> {
  return new Promise((resolve) => {
    const socket = createConnection(socketPath);
    let settled = false;
    let buffer = "";
    const done = (value: DaemonRpcResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(value);
    };
    const timer = setTimeout(() => done({ ok: false }), timeoutMs).unref();
    socket.on("error", () => done({ ok: false }));
    socket.on("end", () => done({ ok: false }));
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(JSON.stringify(packet) + "\n"));
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      const newline = buffer.indexOf("\n");
      if (newline < 0) return;
      try {
        const parsed: unknown = JSON.parse(buffer.slice(0, newline));
        if (object(parsed) && parsed.ok === true && object(parsed.result)) {
          done({ ok: true, result: parsed.result });
          return;
        }
      } catch {}
      done({ ok: false });
    });
  });
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", () => resolve(""));
  });
}

function extractSessionId(harness: HarnessKind, payload: Record<string, unknown>): string | null {
  if (harness === "antigravity") {
    const id = payload.conversationId;
    return typeof id === "string" && id.length > 0 ? `antigravity:${id}` : null;
  }
  if (harness === "cursor") {
    const id = payload.conversation_id ?? payload.conversationId ?? payload.session_id ?? payload.sessionId;
    return typeof id === "string" && id.length > 0 ? `cursor:${id}` : null;
  }
  const id = payload.session_id ?? payload.sessionId ?? payload.thread_id ?? payload.threadId;
  return typeof id === "string" && id.length > 0 ? `${harness}:${id}` : null;
}

function extractToolInfo(
  harness: HarnessKind,
  payload: Record<string, unknown>,
): { toolName?: string; callId?: string; wrappedMcpArgs?: Record<string, unknown> } {
  if (harness === "antigravity") {
    const call = object(payload.toolCall) ? payload.toolCall : undefined;
    const rawName = typeof call?.name === "string" ? call.name : undefined;
    const callId = typeof call?.id === "string" ? call.id : undefined;
    // Antigravity invokes lazy MCP tools through the built-in `call_mcp_tool` wrapper:
    // { ServerName, ToolName, Arguments: { ... } }.
    if (rawName === "call_mcp_tool" && object(call?.args) && typeof call.args.ToolName === "string") {
      const innerArgs = object(call.args.Arguments) ? { ...call.args.Arguments } : {};
      return { toolName: call.args.ToolName, callId, wrappedMcpArgs: innerArgs };
    }
    return { toolName: rawName, callId };
  }
  const toolName = typeof payload.tool_name === "string" ? payload.tool_name : typeof payload.toolName === "string" ? payload.toolName : undefined;
  const rawCallId = payload.tool_use_id ?? payload.call_id ?? payload.callId ?? payload.toolUseId;
  return {
    toolName,
    callId: typeof rawCallId === "string" && rawCallId.length > 0 ? rawCallId : undefined,
  };
}

function formatDrainedMessages(items: Array<{ text?: unknown }>): string {
  return items
    .map((item) => (typeof item.text === "string" ? item.text : ""))
    .filter((text) => text.length > 0)
    .join("\n\n---\n\n");
}

function waiterArmPrompt(harness: HarnessKind, sessionId: string, cliCommand: string, socketPath: string): string {
  const socketFlag = socketPath ? ` --socket ${JSON.stringify(socketPath)}` : "";
  if (harness === "antigravity") {
    return [
      "hyphae: This conversation is enrolled on the mesh, but no background waiter is running yet.",
      `Run \`${cliCommand} wait --session ${sessionId}${socketFlag}\` in the background (WaitMsBeforeAsync: 500, IsDaemon: false) so incoming mesh messages wake this conversation automatically without polling, then end your turn.`,
    ].join(" ");
  }
  if (harness === "cursor" || harness === "gemini" || harness === "opencode" || harness === "openclaw") {
    return [
      "hyphae: This session is enrolled on the mesh, but no background waiter is running yet.",
      `Run \`${cliCommand} wait --session ${sessionId}${socketFlag}\` as a background shell command so incoming mesh messages wake this session automatically without polling, then end your turn.`,
    ].join(" ");
  }
  return [
    "hyphae: This session is enrolled on the mesh, but no background watcher is running yet.",
    `Start \`${cliCommand} watch --session ${sessionId}${socketFlag}\` with the Monitor tool (or \`${cliCommand} wait --session ${sessionId}${socketFlag}\` via Bash with run_in_background=true) so incoming mesh messages wake this session automatically without polling, then end your turn.`,
  ].join(" ");
}

export interface HandleHookOptions {
  readonly harness: HarnessKind;
  readonly event: HookEvent;
  readonly socketPath: string;
  readonly cliPath?: string;
  readonly explicitSocket?: string;
  readonly rpc?: (socketPath: string, packet: Record<string, unknown>, timeoutMs?: number) => Promise<DaemonRpcResult>;
}

/** Pure hook decision logic (easily unit-tested without spawning subprocesses). */
export async function handleHookPayload(
  payload: Record<string, unknown>,
  options: HandleHookOptions,
): Promise<Record<string, unknown>> {
  const rpc = options.rpc ?? daemonRpc;
  const sessionId = extractSessionId(options.harness, payload);
  const allowAntigravity = options.harness === "antigravity" && options.event === "pre-tool-use";
  const allowCursor = options.harness === "cursor" && options.event === "pre-tool-use";
  const allowGemini = options.harness === "gemini" && options.event === "pre-tool-use";
  const defaultPreResponse = () =>
    allowAntigravity ? { decision: "allow" } : allowCursor ? { permission: "allow" } : allowGemini ? { decision: "allow" } : {};
  if (!sessionId) return defaultPreResponse();

  if (options.event === "pre-tool-use") {
    const { toolName, callId, wrappedMcpArgs } = extractToolInfo(options.harness, payload);
    const normalized = toolName ? normalizeMeshToolName(toolName) : null;
    if (!normalized) return defaultPreResponse();
    const res = await rpc(options.socketPath, {
      type: "call.start",
      harness: options.harness,
      sessionId,
      tool: normalized,
      ...(callId ? { callId } : {}),
    });
    const token = res.ok && typeof res.result?.callToken === "string" ? res.result.callToken : undefined;
    if (options.harness === "antigravity") {
      if (!token) return { decision: "allow" };
      return wrappedMcpArgs
        ? { decision: "allow", overwrite: { Arguments: { ...wrappedMcpArgs, _meshCall: token } } }
        : { decision: "allow", overwrite: { _meshCall: token } };
    }
    if (options.harness === "opencode") {
      return token ? { callToken: token, sessionId } : {};
    }
    if (options.harness === "cursor") {
      return { permission: "allow" };
    }
    if (options.harness === "gemini") {
      const toolInput = object(payload.tool_input) ? payload.tool_input : {};
      return token
        ? { decision: "allow", hookSpecificOutput: { hookEventName: "BeforeTool", tool_input: { ...toolInput, _meshCall: token } } }
        : { decision: "allow" };
    }
    return {};
  }

  if (options.event === "post-tool-use") {
    const { callId } = extractToolInfo(options.harness, payload);
    if (callId) {
      await rpc(options.socketPath, { type: "call.end", callId });
    }
    if (options.harness === "antigravity") {
      // Antigravity PostToolUse expects `{}`; PreInvocation and Stop handle injection cleanly.
      return {};
    }
    const drained = await rpc(options.socketPath, { type: "mailbox.drain", sessionId, limit: 5 });
    const items = drained.ok && Array.isArray(drained.result?.items) ? drained.result.items : [];
    if (items.length === 0) return {};
    const text = formatDrainedMessages(items as Array<{ text?: unknown }>);
    if (options.harness === "opencode") {
      return { additionalContext: `Incoming hyphae message(s):\n\n${text}` };
    }
    if (options.harness === "cursor") {
      return { additional_context: `Incoming hyphae message(s):\n\n${text}` };
    }
    if (options.harness === "gemini") {
      return {
        hookSpecificOutput: {
          hookEventName: "AfterTool",
          additionalContext: `Incoming hyphae message(s):\n\n${text}`,
        },
      };
    }
    return {
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        additionalContext: `Incoming hyphae message(s):\n\n${text}`,
      },
    };
  }

  if (options.event === "pre-invocation") {
    const drained = await rpc(options.socketPath, { type: "mailbox.drain", sessionId, limit: 5 });
    const items = drained.ok && Array.isArray(drained.result?.items) ? drained.result.items : [];
    if (items.length === 0) return {};
    const text = formatDrainedMessages(items as Array<{ text?: unknown }>);
    if (options.harness === "antigravity") {
      return {
        injectSteps: [
          { systemMessage: { systemMessage: `Incoming hyphae message(s):\n\n${text}` } },
        ],
      };
    }
    return {};
  }

  // `stop` event:
  // 1) Drain any pending mesh messages immediately into the turn.
  // 2) If enrolled on the mesh with no active push waiter/channel, ask once (never looping!)
  //    to arm the zero-cost blocking waiter before going idle.
  const formatStopContinuation = (reason: string): Record<string, unknown> => {
    if (options.harness === "antigravity") return { decision: "continue", reason };
    if (options.harness === "cursor") return { followup_message: reason };
    if (options.harness === "gemini") return { decision: "deny", reason };
    if (options.harness === "opencode") return { followupMessage: reason };
    return { decision: "block", reason };
  };

  const drained = await rpc(options.socketPath, { type: "mailbox.drain", sessionId, limit: 5 });
  const items = drained.ok && Array.isArray(drained.result?.items) ? drained.result.items : [];
  if (items.length > 0) {
    const text = formatDrainedMessages(items as Array<{ text?: unknown }>);
    return formatStopContinuation(`Incoming hyphae message(s):\n\n${text}`);
  }

  // Codex doesn't have a reactive Monitor / background-exit wakeup yet, so don't ask Codex to arm a waiter.
  if (options.harness === "codex") return {};

  const alreadyContinued =
    payload.continuationActive === true ||
    payload.stop_hook_active === true ||
    (typeof payload.loop_count === "number" && payload.loop_count > 0);
  if (alreadyContinued) return {};

  // On Antigravity, only auto-arm on normal turn completion (never after USER_CANCELED or ERROR).
  if (options.harness === "antigravity" && typeof payload.terminationReason === "string" && payload.terminationReason !== "NO_TOOL_CALL") {
    return {};
  }

  const status = await rpc(options.socketPath, { type: "session.status", sessionId });
  if (status.ok && status.result?.enrolled === true && status.result?.hasLiveTransport !== true) {
    const reason = waiterArmPrompt(
      options.harness,
      sessionId,
      options.cliPath ?? "hyp",
      options.explicitSocket ?? "",
    );
    return formatStopContinuation(reason);
  }

  return {};
}

export async function runHook(options: HandleHookOptions): Promise<void> {
  const raw = (await readStdin()).trim();
  let payload: Record<string, unknown> = {};
  if (raw.length > 0) {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (object(parsed)) payload = parsed;
    } catch {}
  }
  const response = await handleHookPayload(payload, options);
  process.stdout.write(JSON.stringify(response) + "\n");
}
