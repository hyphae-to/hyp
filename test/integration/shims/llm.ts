import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { object } from "../../../src/protocol.ts";

export type ScriptedAction =
  | { readonly type: "tool_call"; readonly id?: string; readonly name: string; readonly namespace?: string; readonly arguments: Record<string, unknown> }
  | { readonly type: "text"; readonly text: string };

export interface AdvertisedTool {
  readonly name: string;
  readonly namespace?: string;
  readonly description?: string;
  readonly type?: string;
}

export interface TurnContext {
  readonly protocol: "anthropic" | "openai-responses";
  readonly turnIndex: number;
  readonly model: string;
  readonly tools: readonly AdvertisedTool[];
  readonly raw: Record<string, unknown>;
  /** Serialized full conversation history (messages or Responses input) for easy assertions. */
  allText(): string;
  /** True when the conversation history contains the given substring. */
  hasText(needle: string): boolean;
  /** Find an advertised tool by exact name or suffix (e.g. `hyp_join` matches `mcp__hyphae__hyp_join`). */
  findTool(nameOrSuffix: string): AdvertisedTool | undefined;
  /** Build a tool_call action targeting an advertised tool by exact name or suffix. */
  callTool(nameOrSuffix: string, args: Record<string, unknown>, id?: string): ScriptedAction;
  /** Build an OpenCode v2 Code Mode `execute` call invoking `tools.hyphae.<tool>(args)`. */
  callOpenCodeTool(toolName: string, args?: Record<string, unknown>, id?: string): ScriptedAction;
  /** Build a Claude Code `ToolSearch` call to load deferred Hyphae MCP tools. */
  selectClaudeTools(toolNames: readonly string[], id?: string): ScriptedAction;
  /** Build a plain assistant text response action. */
  reply(text: string): ScriptedAction;
}

export type TurnHandler = (ctx: TurnContext) => Promise<ScriptedAction> | ScriptedAction;

export interface TurnTranscript {
  readonly turnIndex: number;
  readonly model: string;
  readonly toolNames: readonly string[];
  readonly action: ScriptedAction;
  readonly inputSnapshot: string;
}

export interface RunningScriptedServer {
  readonly url: string;
  readonly protocol: "anthropic" | "openai-responses";
  readonly requests: Record<string, unknown>[];
  readonly transcript: TurnTranscript[];
  /** Reset the turn counter (useful when running a second independent CLI invocation against the same server). */
  resetTurns(): void;
  close(): Promise<void>;
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  return Buffer.concat(chunks).toString("utf8");
}

function writeSse(res: ServerResponse, event: string, data: unknown): void {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function makeTurnContext(
  protocol: "anthropic" | "openai-responses",
  turnIndex: number,
  model: string,
  tools: readonly AdvertisedTool[],
  historyPayload: unknown,
  raw: Record<string, unknown>,
): TurnContext {
  let cachedText: string | undefined;
  const allText = () => (cachedText ??= JSON.stringify(historyPayload));
  const findTool = (nameOrSuffix: string): AdvertisedTool | undefined =>
    tools.find((t) => t.name === nameOrSuffix) ??
    tools.find((t) => t.name.endsWith(`__${nameOrSuffix}`) || t.name.endsWith(`.${nameOrSuffix}`) || t.name.endsWith(`_${nameOrSuffix}`) || t.name.endsWith(nameOrSuffix));

  return {
    protocol,
    turnIndex,
    model,
    tools,
    raw,
    allText,
    hasText: (needle) => allText().includes(needle),
    findTool,
    callTool(nameOrSuffix, args, id) {
      const matched = findTool(nameOrSuffix);
      if (!matched) {
        throw new Error(`Scripted agent could not find advertised tool '${nameOrSuffix}'. Available: ${tools.map((t) => t.name).join(", ")}`);
      }
      return {
        type: "tool_call",
        id: id ?? `call_${protocol}_${turnIndex}_${nameOrSuffix}`,
        name: matched.name,
        ...(matched.namespace ? { namespace: matched.namespace } : {}),
        arguments: args,
      };
    },
    callOpenCodeTool(toolName, args = {}, id) {
      const execTool = findTool("execute");
      if (!execTool) {
        throw new Error(`Expected OpenCode 'execute' Code Mode tool; got: ${tools.map((t) => t.name).join(", ")}`);
      }
      return {
        type: "tool_call",
        id: id ?? `call_oc_${turnIndex}_${toolName}`,
        name: execTool.name,
        arguments: { code: `return await tools.hyphae.${toolName}(${JSON.stringify(args)});` },
      };
    },
    selectClaudeTools(toolNames, id) {
      const searchTool = findTool("ToolSearch");
      if (!searchTool) {
        throw new Error(`Expected Claude 'ToolSearch' tool; got: ${tools.map((t) => t.name).join(", ")}`);
      }
      const qualified = toolNames.map((n) => (n.startsWith("mcp__") ? n : `mcp__hyphae__${n}`));
      return {
        type: "tool_call",
        id: id ?? `toolu_search_${turnIndex}`,
        name: searchTool.name,
        arguments: { query: `select:${qualified.join(",")}` },
      };
    },
    reply: (text) => ({ type: "text", text }),
  };
}

/**
 * Helper to build a clean sequential step-by-step scenario handler.
 * Each step runs in order; once exhausted, returns a final text reply.
 */
export function scriptedSteps(
  steps: readonly ((ctx: TurnContext) => Promise<ScriptedAction> | ScriptedAction)[],
  fallbackText = "Done.",
): TurnHandler {
  return async (ctx) => {
    const step = steps[ctx.turnIndex];
    if (!step) return ctx.reply(fallbackText);
    return step(ctx);
  };
}

/**
 * Local deterministic Anthropic Messages API server (`/v1/messages`, `/v1/messages/count_tokens`)
 * for driving the real `claude` CLI binary with `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>`.
 */
export async function startScriptedAnthropicServer(handler: TurnHandler): Promise<RunningScriptedServer> {
  const requests: Record<string, unknown>[] = [];
  const transcript: TurnTranscript[] = [];
  let messageTurn = 0;

  const server = createServer(async (req, res) => {
    try {
      const rawText = await readBody(req);
      const url = new URL(req.url ?? "/", "http://127.0.0.1");

      if (url.pathname.includes("count_tokens")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ input_tokens: 100 }));
        return;
      }
      if (req.method !== "POST" || !url.pathname.endsWith("/v1/messages")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      let body: Record<string, unknown> = {};
      try {
        const parsed: unknown = JSON.parse(rawText);
        if (object(parsed)) body = parsed;
      } catch {}
      requests.push(body);

      const tools: AdvertisedTool[] = Array.isArray(body.tools)
        ? body.tools.filter(object).map((t) => ({
            name: String(t.name ?? ""),
            description: typeof t.description === "string" ? t.description : undefined,
          }))
        : [];
      const messages = Array.isArray(body.messages) ? body.messages : [];
      const model = typeof body.model === "string" ? body.model : "claude-sonnet-4-5";
      const stream = body.stream === true;

      // Auxiliary title/summary/quota calls have no tools; respond cleanly without advancing turns.
      if (tools.length === 0) {
        const replyText = "ok";
        if (stream) {
          res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
          writeSse(res, "message_start", {
            type: "message_start",
            message: { id: `msg_aux_${requests.length}`, type: "message", role: "assistant", content: [], model, stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } },
          });
          writeSse(res, "content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
          writeSse(res, "content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: replyText } });
          writeSse(res, "content_block_stop", { type: "content_block_stop", index: 0 });
          writeSse(res, "message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 2 } });
          writeSse(res, "message_stop", { type: "message_stop" });
          res.end();
        } else {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            id: `msg_aux_${requests.length}`, type: "message", role: "assistant", model,
            content: [{ type: "text", text: replyText }], stop_reason: "end_turn", stop_sequence: null,
            usage: { input_tokens: 10, output_tokens: 2 },
          }));
        }
        return;
      }

      const turn = messageTurn++;
      const ctx = makeTurnContext("anthropic", turn, model, tools, messages, body);
      const action = await handler(ctx);
      transcript.push({
        turnIndex: turn,
        model,
        toolNames: tools.map((t) => t.name),
        action,
        inputSnapshot: ctx.allText().slice(-4000),
      });

      const msgId = `msg_turn_${turn}`;
      const stopReason = action.type === "tool_call" ? "tool_use" : "end_turn";
      const callId = action.type === "tool_call" ? (action.id ?? `toolu_${turn}`) : "";

      if (stream) {
        res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
        writeSse(res, "message_start", {
          type: "message_start",
          message: {
            id: msgId, type: "message", role: "assistant", content: [], model,
            stop_reason: null, stop_sequence: null, usage: { input_tokens: 50, output_tokens: 1 },
          },
        });
        if (action.type === "tool_call") {
          writeSse(res, "content_block_start", {
            type: "content_block_start",
            index: 0,
            content_block: { type: "tool_use", id: callId, name: action.name, input: {} },
          });
          writeSse(res, "content_block_delta", {
            type: "content_block_delta",
            index: 0,
            delta: { type: "input_json_delta", partial_json: JSON.stringify(action.arguments) },
          });
          writeSse(res, "content_block_stop", { type: "content_block_stop", index: 0 });
        } else {
          writeSse(res, "content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
          writeSse(res, "content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: action.text } });
          writeSse(res, "content_block_stop", { type: "content_block_stop", index: 0 });
        }
        writeSse(res, "message_delta", {
          type: "message_delta",
          delta: { stop_reason: stopReason, stop_sequence: null },
          usage: { output_tokens: 20 },
        });
        writeSse(res, "message_stop", { type: "message_stop" });
        res.end();
        return;
      }

      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        id: msgId,
        type: "message",
        role: "assistant",
        model,
        content: action.type === "tool_call"
          ? [{ type: "tool_use", id: callId, name: action.name, input: action.arguments }]
          : [{ type: "text", text: action.text }],
        stop_reason: stopReason,
        stop_sequence: null,
        usage: { input_tokens: 50, output_tokens: 20 },
      }));
    } catch (error) {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { type: "api_error", message: error instanceof Error ? error.message : String(error) } }));
      } else {
        res.end();
      }
    }
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Failed to bind scripted Anthropic server");
  return {
    url: `http://127.0.0.1:${address.port}`,
    protocol: "anthropic",
    requests,
    transcript,
    resetTurns: () => { messageTurn = 0; },
    close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}

function sendResponsesSse(
  res: ServerResponse,
  respId: string,
  itemId: string,
  model: string,
  action: ScriptedAction,
): void {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  writeSse(res, "response.created", {
    type: "response.created",
    response: { id: respId, object: "response", status: "in_progress", model, output: [] },
  });

  if (action.type === "tool_call") {
    const argStr = JSON.stringify(action.arguments);
    const callId = action.id ?? `call_${respId}`;
    const item = {
      id: itemId,
      type: "function_call",
      status: "completed",
      call_id: callId,
      name: action.name,
      ...(action.namespace ? { namespace: action.namespace } : {}),
      arguments: argStr,
    };
    writeSse(res, "response.output_item.added", {
      type: "response.output_item.added",
      output_index: 0,
      item: { ...item, status: "in_progress", arguments: "" },
    });
    writeSse(res, "response.function_call_arguments.delta", {
      type: "response.function_call_arguments.delta",
      item_id: itemId,
      output_index: 0,
      delta: argStr,
    });
    writeSse(res, "response.function_call_arguments.done", {
      type: "response.function_call_arguments.done",
      item_id: itemId,
      output_index: 0,
      arguments: argStr,
    });
    writeSse(res, "response.output_item.done", {
      type: "response.output_item.done",
      output_index: 0,
      item,
    });
    writeSse(res, "response.completed", {
      type: "response.completed",
      response: {
        id: respId, object: "response", status: "completed", model,
        output: [item],
        usage: { input_tokens: 50, output_tokens: 20, total_tokens: 70 },
      },
    });
  } else {
    const item = {
      id: itemId,
      type: "message",
      status: "completed",
      role: "assistant",
      content: [{ type: "output_text", text: action.text, annotations: [] }],
    };
    writeSse(res, "response.output_item.added", {
      type: "response.output_item.added",
      output_index: 0,
      item: { ...item, status: "in_progress", content: [] },
    });
    writeSse(res, "response.content_part.added", {
      type: "response.content_part.added",
      item_id: itemId,
      output_index: 0,
      content_index: 0,
      part: { type: "output_text", text: "", annotations: [] },
    });
    writeSse(res, "response.output_text.delta", {
      type: "response.output_text.delta",
      item_id: itemId,
      output_index: 0,
      content_index: 0,
      delta: action.text,
    });
    writeSse(res, "response.output_text.done", {
      type: "response.output_text.done",
      item_id: itemId,
      output_index: 0,
      content_index: 0,
      text: action.text,
    });
    writeSse(res, "response.content_part.done", {
      type: "response.content_part.done",
      item_id: itemId,
      output_index: 0,
      content_index: 0,
      part: { type: "output_text", text: action.text, annotations: [] },
    });
    writeSse(res, "response.output_item.done", {
      type: "response.output_item.done",
      output_index: 0,
      item,
    });
    writeSse(res, "response.completed", {
      type: "response.completed",
      response: {
        id: respId, object: "response", status: "completed", model,
        output: [item],
        usage: { input_tokens: 50, output_tokens: 20, total_tokens: 70 },
      },
    });
  }
  res.end();
}

/**
 * Local deterministic OpenAI Responses API server (`/v1/responses`) for driving both:
 * - real `codex` CLI (`model_providers.dummy.base_url=http://127.0.0.1:<port>/v1`)
 * - real `opencode` v2 CLI (`providers.openai.settings.baseURL=http://127.0.0.1:<port>/v1`)
 *
 * Automatically answers auxiliary tool-less requests (such as OpenCode title generation)
 * without advancing the main turn counter.
 */
export async function startScriptedOpenAIResponsesServer(
  handler: TurnHandler,
  options: { readonly ignoreAuxiliaryNoToolRequests?: boolean } = {},
): Promise<RunningScriptedServer> {
  const ignoreAux = options.ignoreAuxiliaryNoToolRequests ?? true;
  const requests: Record<string, unknown>[] = [];
  const transcript: TurnTranscript[] = [];
  let turnIndex = 0;

  const server = createServer(async (req, res) => {
    try {
      const rawText = await readBody(req);
      const url = new URL(req.url ?? "/", "http://127.0.0.1");

      if (req.method !== "POST" || !url.pathname.endsWith("/responses")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      let body: Record<string, unknown> = {};
      try {
        const parsed: unknown = JSON.parse(rawText);
        if (object(parsed)) body = parsed;
      } catch {}
      requests.push(body);

      const tools: AdvertisedTool[] = [];
      if (Array.isArray(body.tools)) {
        for (const item of body.tools) {
          if (!object(item)) continue;
          if (item.type === "namespace" && typeof item.name === "string" && Array.isArray(item.tools)) {
            for (const nested of item.tools) {
              if (object(nested) && typeof nested.name === "string") {
                tools.push({
                  name: nested.name,
                  namespace: item.name,
                  type: typeof nested.type === "string" ? nested.type : undefined,
                  description: typeof nested.description === "string" ? nested.description : undefined,
                });
              }
            }
          } else if (typeof item.name === "string") {
            tools.push({
              name: item.name,
              type: typeof item.type === "string" ? item.type : undefined,
              description: typeof item.description === "string" ? item.description : undefined,
            });
          }
        }
      }
      const input = Array.isArray(body.input) ? body.input : [];
      const model = typeof body.model === "string" ? body.model : "gpt-5";

      if (ignoreAux && tools.length === 0) {
        sendResponsesSse(res, `resp_aux_${requests.length}`, `item_aux_${requests.length}`, model, { type: "text", text: "ok" });
        return;
      }

      const turn = turnIndex++;
      const ctx = makeTurnContext("openai-responses", turn, model, tools, input, body);
      const action = await handler(ctx);
      transcript.push({
        turnIndex: turn,
        model,
        toolNames: tools.map((t) => (t.namespace ? `${t.namespace}.${t.name}` : t.name)),
        action,
        inputSnapshot: ctx.allText().slice(-4000),
      });

      sendResponsesSse(res, `resp_turn_${turn}`, `item_turn_${turn}`, model, action);
    } catch (error) {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { message: error instanceof Error ? error.message : String(error) } }));
      } else {
        res.end();
      }
    }
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Failed to bind scripted OpenAI server");
  return {
    url: `http://127.0.0.1:${address.port}`,
    protocol: "openai-responses",
    requests,
    transcript,
    resetTurns: () => { turnIndex = 0; },
    close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}
