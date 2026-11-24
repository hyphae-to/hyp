import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { object } from "../../src/protocol.ts";

export type AnthropicAction =
  | { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
  | { type: "text"; text: string };

export interface AnthropicRequest {
  readonly model?: string;
  readonly messages: unknown[];
  readonly tools: Array<{ name: string; description?: string }>;
  readonly stream?: boolean;
  readonly raw: Record<string, unknown>;
}

export interface RunningDummyServer {
  readonly url: string;
  readonly requests: Record<string, unknown>[];
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

/**
 * Local dummy Anthropic Messages API server for deterministic integration testing of
 * the real `claude` CLI binary (`ANTHROPIC_BASE_URL=http://127.0.0.1:<port>`).
 */
export async function startDummyAnthropicServer(
  handler: (req: AnthropicRequest, turnIndex: number) => Promise<AnthropicAction> | AnthropicAction,
): Promise<RunningDummyServer> {
  const requests: Record<string, unknown>[] = [];
  let messageTurn = 0;

  const server = createServer(async (req, res) => {
    try {
      const rawText = await readBody(req);
      const url = new URL(req.url ?? "/", "http://127.0.0.1");

      // Ancillary Claude Code endpoints (token counting, telemetry, etc.)
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

      const tools = Array.isArray(body.tools)
        ? body.tools.filter(object).map((t) => ({ name: String(t.name ?? ""), description: typeof t.description === "string" ? t.description : undefined }))
        : [];
      const messages = Array.isArray(body.messages) ? body.messages : [];
      const model = typeof body.model === "string" ? body.model : "claude-sonnet-4-5";
      const stream = body.stream === true;

      // Claude Code sometimes sends small auxiliary title/summary/quota calls with no tools.
      // Answer those immediately without advancing the main conversation turn counter.
      if (tools.length === 0) {
        const replyText = "ok";
        if (stream) {
          res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
          const msgId = `msg_aux_${requests.length}`;
          writeSse(res, "message_start", {
            type: "message_start",
            message: { id: msgId, type: "message", role: "assistant", content: [], model, stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } },
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
      const action = await handler({ model, messages, tools, stream, raw: body }, turn);
      const msgId = `msg_turn_${turn}`;
      const stopReason = action.type === "tool_use" ? "tool_use" : "end_turn";

      if (stream) {
        res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
        writeSse(res, "message_start", {
          type: "message_start",
          message: {
            id: msgId, type: "message", role: "assistant", content: [], model,
            stop_reason: null, stop_sequence: null, usage: { input_tokens: 50, output_tokens: 1 },
          },
        });
        if (action.type === "tool_use") {
          writeSse(res, "content_block_start", {
            type: "content_block_start",
            index: 0,
            content_block: { type: "tool_use", id: action.id, name: action.name, input: {} },
          });
          writeSse(res, "content_block_delta", {
            type: "content_block_delta",
            index: 0,
            delta: { type: "input_json_delta", partial_json: JSON.stringify(action.input) },
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
        content: action.type === "tool_use"
          ? [{ type: "tool_use", id: action.id, name: action.name, input: action.input }]
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
  if (!address || typeof address === "string") throw new Error("Failed to bind dummy Anthropic server");
  return {
    url: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}

export type OpenAIAction =
  | { type: "function_call"; callId: string; name: string; namespace?: string; arguments: Record<string, unknown> }
  | { type: "text"; text: string };

export interface OpenAIToolInfo {
  readonly name: string;
  readonly namespace?: string;
  readonly type?: string;
}

export interface OpenAIRequest {
  readonly model?: string;
  readonly input: unknown[];
  readonly tools: OpenAIToolInfo[];
  readonly raw: Record<string, unknown>;
}

/**
 * Local dummy OpenAI Responses API server for deterministic integration testing of
 * the real `codex` CLI binary (`model_providers.dummy.base_url=http://127.0.0.1:<port>/v1`).
 */
export async function startDummyOpenAIServer(
  handler: (req: OpenAIRequest, turnIndex: number) => Promise<OpenAIAction> | OpenAIAction,
): Promise<RunningDummyServer> {
  const requests: Record<string, unknown>[] = [];
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

      const tools: OpenAIToolInfo[] = [];
      if (Array.isArray(body.tools)) {
        for (const item of body.tools) {
          if (!object(item)) continue;
          if (item.type === "namespace" && typeof item.name === "string" && Array.isArray(item.tools)) {
            for (const nested of item.tools) {
              if (object(nested) && typeof nested.name === "string") {
                tools.push({ name: nested.name, namespace: item.name, type: typeof nested.type === "string" ? nested.type : undefined });
              }
            }
          } else if (typeof item.name === "string") {
            tools.push({ name: item.name, type: typeof item.type === "string" ? item.type : undefined });
          }
        }
      }
      const input = Array.isArray(body.input) ? body.input : [];
      const model = typeof body.model === "string" ? body.model : "gpt-5";

      const turn = turnIndex++;
      const action = await handler({ model, input, tools, raw: body }, turn);
      const respId = `resp_turn_${turn}`;
      const itemId = `item_turn_${turn}`;

      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
      writeSse(res, "response.created", {
        type: "response.created",
        response: { id: respId, object: "response", status: "in_progress", model, output: [] },
      });

      if (action.type === "function_call") {
        const argStr = JSON.stringify(action.arguments);
        const item = {
          id: itemId,
          type: "function_call",
          status: "completed",
          call_id: action.callId,
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
  if (!address || typeof address === "string") throw new Error("Failed to bind dummy OpenAI server");
  return {
    url: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}
