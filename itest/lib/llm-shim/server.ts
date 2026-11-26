/**
 * Smart programmable multi-protocol loopback LLM API server (`FakeBrain` / `llm-shim`).
 *
 * Protocols served on a single `127.0.0.1:0` HTTP+SSE server:
 *   - Anthropic Messages: `POST /v1/messages`, `POST /v1/messages/count_tokens`
 *   - OpenAI Chat Completions: `POST /v1/chat/completions`, `GET /v1/models`
 *   - OpenAI Responses: `POST /v1/responses`, `GET /v1/models`
 *   - Google Gemini: `POST /v1beta/models/:model:generateContent`, `:streamGenerateContent`
 *
 * Role routing:
 *   - Path prefix `/s/<role>/...` (e.g. `http://127.0.0.1:<P>/s/oc-alpha/v1/chat/completions`)
 *   - Or bearer/API-key token `sk-itest-<role>` / `sk-ant-itest-<role>`
 *   - Or default role `"default"`.
 */

import crypto from "node:crypto";
import http from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { AuditEngine, extractCanonicalHyphaeToolName } from "./auditors.ts";
import { ScriptEngine, createCanonicalRequest } from "./script-engine.ts";
import type {
  AdvertisedTool,
  AuditViolation,
  AuditorConfig,
  CanonicalLlmRequest,
  CanonicalMessage,
  CanonicalToolCall,
  CanonicalToolResult,
  LlmProtocol,
  RecordedTurn,
  ScriptAction,
  ScriptRule,
  ToolCallSpec,
} from "./types.ts";
import type { Sandbox } from "../sandbox.ts";

function tryParseJson(text: string): any {
  const trimmed = text.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

/**
 * Parses tool result JSON, transparently unwrapping OpenClaw 2026.11+'s
 * `<<<EXTERNAL_UNTRUSTED_CONTENT>>> ... {"tool":...,"result":{"content":[{"type":"text","text":"..."}]}}`
 * wrapper so `req.lastToolResult("hyp_mesh")?.json` works identically across all harnesses!
 */
function parseToolResultJson(text: string): any {
  const direct = tryParseJson(text);
  if (direct !== null) {
    if (
      direct &&
      typeof direct === "object" &&
      Array.isArray(direct?.result?.content)
    ) {
      const innerText = direct.result.content
        .map((c: any) => (typeof c?.text === "string" ? c.text : ""))
        .join("");
      const innerJson = tryParseJson(innerText);
      if (innerJson !== null) return innerJson;
    }
    // Unwrap Gemini CLI `{ output: "<untrusted_context>\n{...}\n</untrusted_context>..." }` wrapper.
    if (direct && typeof direct === "object" && typeof direct.output === "string") {
      const inner = parseToolResultJson(direct.output);
      if (inner !== null) return inner;
    }
    return direct;
  }

  // Unwrap Gemini CLI `<untrusted_context>...</untrusted_context>` wrapper.
  const untrustedMatch = /<untrusted_context>\s*([\s\S]*?)\s*<\/untrusted_context>/.exec(text);
  if (untrustedMatch) {
    const inner = tryParseJson(untrustedMatch[1]);
    if (inner !== null) return inner;
  }

  // Strip Codex CLI `"Wall time: 0.0019 seconds\nOutput:\n{...}"` prefix.
  const codexOutMatch = /(?:^|\n)Output:\s*\n?([\s\S]+)$/.exec(text);
  if (codexOutMatch) {
    const inner = tryParseJson(codexOutMatch[1]);
    if (inner !== null) return inner;
  }

  // Strip Claude Code `<system-reminder>...</system-reminder>` blocks appended to tool_result text.
  const withoutReminders = text.replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, "").trim();
  if (withoutReminders && withoutReminders !== text.trim()) {
    const cleaned = tryParseJson(withoutReminders);
    if (cleaned !== null) return cleaned;
  }

  // Extract JSON object inside OpenClaw `<<<EXTERNAL_UNTRUSTED_CONTENT>>>` block.
  const fenceMatch = /<<<EXTERNAL_UNTRUSTED_CONTENT[^>]*>>>[\s\S]*?\n---\n([\s\S]*?)\n<<<END_EXTERNAL_UNTRUSTED_CONTENT/.exec(
    text,
  );
  if (fenceMatch) {
    const outer = tryParseJson(fenceMatch[1]);
    if (outer && typeof outer === "object") {
      if (Array.isArray(outer?.result?.content)) {
        const innerText = outer.result.content
          .map((c: any) => (typeof c?.text === "string" ? c.text : ""))
          .join("");
        const innerJson = tryParseJson(innerText);
        if (innerJson !== null) return innerJson;
      }
      return outer;
    }
  }

  return null;
}

function flattenContentBlocks(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const block of content) {
    if (typeof block === "string") {
      parts.push(block);
    } else if (block && typeof block === "object") {
      const b = block as any;
      if (typeof b.text === "string") parts.push(b.text);
      else if (b.type === "input_text" && typeof b.text === "string") parts.push(b.text);
      else if (b.type === "output_text" && typeof b.text === "string") parts.push(b.text);
    }
  }
  return parts.join("\n");
}

function makeCallId(prefix = "call"): string {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}`;
}

function extractRoleAndPath(
  rawUrl: string,
  headers: IncomingMessage["headers"],
): { role: string; subPath: string; query: URLSearchParams } {
  const parsed = new URL(rawUrl, "http://127.0.0.1");
  let pathname = parsed.pathname;
  let role = "default";

  const roleMatch = /^\/s\/([A-Za-z0-9._-]+)(\/.*)?$/.exec(pathname);
  if (roleMatch) {
    role = roleMatch[1];
    pathname = roleMatch[2] || "/";
  } else {
    const auth = String(
      headers.authorization ||
        headers["x-api-key"] ||
        headers["x-goog-api-key"] ||
        parsed.searchParams.get("key") ||
        "",
    );
    const tokMatch = /(?:sk-(?:ant-)?itest-|itest-gemini-)([A-Za-z0-9._-]+)/.exec(auth);
    if (tokMatch) {
      role = tokMatch[1];
    }
  }

  return { role, subPath: pathname, query: parsed.searchParams };
}

function parseAnthropicRequest(
  role: string,
  turnIndex: number,
  body: any,
  rawBody: string,
  url: string,
  headers: IncomingMessage["headers"],
): CanonicalLlmRequest {
  const systemPrompt = flattenContentBlocks(body?.system);
  const advertisedTools: AdvertisedTool[] = (Array.isArray(body?.tools) ? body.tools : []).map(
    (t: any) => ({
      name: String(t?.name ?? ""),
      canonicalHyphaeName: extractCanonicalHyphaeToolName(String(t?.name ?? "")),
      description: typeof t?.description === "string" ? t.description : undefined,
      inputSchema: t?.input_schema,
    }),
  );

  // Map tool_use_id -> wire tool name from assistant messages so tool_result blocks resolve cleanly.
  const toolNameByCallId = new Map<string, string>();
  const messages: CanonicalMessage[] = [];

  for (const m of Array.isArray(body?.messages) ? body.messages : []) {
    const mRole = m?.role === "assistant" ? "assistant" : "user";
    const textParts: string[] = [];
    const toolCalls: CanonicalToolCall[] = [];
    const toolResults: CanonicalToolResult[] = [];

    if (typeof m?.content === "string") {
      textParts.push(m.content);
    } else if (Array.isArray(m?.content)) {
      for (const blk of m.content) {
        if (!blk || typeof blk !== "object") continue;
        if (blk.type === "text" && typeof blk.text === "string") {
          textParts.push(blk.text);
        } else if (blk.type === "tool_use") {
          const id = String(blk.id ?? "");
          const name = String(blk.name ?? "");
          if (id && name) toolNameByCallId.set(id, name);
          toolCalls.push({
            id,
            name,
            canonicalName: extractCanonicalHyphaeToolName(name),
            arguments: (blk.input && typeof blk.input === "object" ? blk.input : {}) as Record<
              string,
              unknown
            >,
          });
        } else if (blk.type === "tool_result") {
          const callId = String(blk.tool_use_id ?? "");
          const rawToolName = toolNameByCallId.get(callId);
          const text =
            typeof blk.content === "string"
              ? blk.content
              : flattenContentBlocks(blk.content);
          toolResults.push({
            callId,
            rawToolName,
            canonicalToolName: rawToolName
              ? extractCanonicalHyphaeToolName(rawToolName)
              : undefined,
            text,
            json: parseToolResultJson(text),
            isError: Boolean(blk.is_error),
          });
        }
      }
    }

    messages.push({
      role: mRole,
      text: textParts.join("\n"),
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      toolResults: toolResults.length > 0 ? toolResults : undefined,
      raw: m,
    });
  }

  extractDeferredToolsFromCatalog(advertisedTools, messages);

  const lastMsg = messages[messages.length - 1];
  const lastToolResults = lastMsg?.toolResults ?? [];
  let lastUserText = "";
  if (lastMsg && lastMsg.role === "user" && lastMsg.text) {
    lastUserText = lastMsg.text;
  } else {
    for (let i = messages.length - 1; i >= 0; i -= 1) {
      if (messages[i].role === "user" && messages[i].text) {
        lastUserText = messages[i].text;
        break;
      }
    }
  }

  return createCanonicalRequest({
    role,
    protocol: "anthropic",
    turnIndex,
    model: String(body?.model ?? "claude-sonnet-4-5"),
    stream: Boolean(body?.stream),
    systemPrompt,
    messages,
    lastUserText,
    lastToolResults,
    advertisedTools,
    headers,
    url,
    rawBody,
    parsedBody: body,
    timestampMs: Date.now(),
  });
}

function extractDeferredToolsFromCatalog(
  advertisedTools: AdvertisedTool[],
  messages: CanonicalMessage[] = [],
  systemPrompt = "",
): void {
  const existing = new Set(advertisedTools.map((t) => t.name));

  // 1. OpenClaw 2026.11+ lists deferred MCP tools in `tool_search.description`:
  //    `- mcp:hyphae:hyphae__hyp_mesh: Join/leave mesh/...`
  const toolSearch = advertisedTools.find((t) => t.name === "tool_search");
  if (toolSearch?.description) {
    const deferredRe = /^-\s+(mcp:[^\s:]+:[^\s:]+):\s*(.*)$/gm;
    let match: RegExpExecArray | null;
    while ((match = deferredRe.exec(toolSearch.description)) !== null) {
      const id = match[1].trim();
      if (!id || existing.has(id)) continue;
      existing.add(id);
      advertisedTools.push({
        name: id,
        canonicalHyphaeName: extractCanonicalHyphaeToolName(id),
        deferred: true,
        deferredVia: "dispatch_action",
        description: match[2]?.trim(),
      });
    }
  }

  // 2. Claude Code 2.1.332+ lists deferred tools in `<system-reminder>` blocks:
  //    `The following deferred tools are now available via ToolSearch...`
  const hasToolSearch = advertisedTools.some((t) => t.name === "ToolSearch");
  if (hasToolSearch) {
    const claudeDeferredRe =
      /The following deferred tools are now available via ToolSearch\.[^\n]*\n([\s\S]*?)<\/system-reminder>/g;
    for (const msg of messages) {
      if (msg.role !== "user" || !msg.text) continue;
      claudeDeferredRe.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = claudeDeferredRe.exec(msg.text)) !== null) {
        for (const rawLine of match[1].split(/\r?\n/)) {
          const name = rawLine.trim();
          if (!name || /\s/.test(name) || existing.has(name)) continue;
          existing.add(name);
          advertisedTools.push({
            name,
            canonicalHyphaeName: extractCanonicalHyphaeToolName(name),
            deferred: true,
            deferredVia: "tool_search",
          });
        }
      }
    }
  }

  // 3. OpenCode v2.3+ exposes MCP tools inside the Code Mode catalog (`tools.hyphae.hyp_*`) invoked via `execute`.
  const hasExecute = advertisedTools.some((t) => t.name === "execute");
  if (hasExecute && systemPrompt) {
    const ocToolRe = /\b(tools\.hyphae\.(hyp_[a-z0-9_]+))\s*\(/g;
    let match: RegExpExecArray | null;
    while ((match = ocToolRe.exec(systemPrompt)) !== null) {
      const fullPath = match[1];
      if (!fullPath || existing.has(fullPath)) continue;
      existing.add(fullPath);
      advertisedTools.push({
        name: fullPath,
        canonicalHyphaeName: extractCanonicalHyphaeToolName(fullPath),
        deferred: true,
        deferredVia: "opencode_execute",
      });
    }
  }
}

function collectTrailingUserText(messages: CanonicalMessage[]): string {
  // Collect all contiguous trailing `user` messages (handles harnesses like OpenClaw 2026.11+
  // that append a synthetic "OpenClaw runtime context:" user message after the real user turn).
  const trailing: string[] = [];
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const m = messages[i];
    if (m.role === "user") {
      if (m.text) trailing.unshift(m.text);
    } else {
      break;
    }
  }
  if (trailing.length > 0) return trailing.join("\n\n");
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (
      messages[i].role === "user" &&
      messages[i].text &&
      !messages[i].text.startsWith("OpenClaw runtime context:")
    ) {
      return messages[i].text;
    }
  }
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i].role === "user" && messages[i].text) {
      return messages[i].text;
    }
  }
  return "";
}

function parseOpenAiChatRequest(
  role: string,
  turnIndex: number,
  body: any,
  rawBody: string,
  url: string,
  headers: IncomingMessage["headers"],
): CanonicalLlmRequest {
  const systemParts: string[] = [];
  const advertisedTools: AdvertisedTool[] = (Array.isArray(body?.tools) ? body.tools : []).map(
    (t: any) => {
      const name = String(t?.function?.name ?? t?.name ?? "");
      return {
        name,
        canonicalHyphaeName: extractCanonicalHyphaeToolName(name),
        description: t?.function?.description ?? t?.description,
        inputSchema: t?.function?.parameters ?? t?.parameters,
      };
    },
  );
  extractDeferredToolsFromCatalog(advertisedTools);

  const toolNameByCallId = new Map<string, string>();
  const messages: CanonicalMessage[] = [];

  for (const m of Array.isArray(body?.messages) ? body.messages : []) {
    const rawRole = String(m?.role ?? "user");
    const text = flattenContentBlocks(m?.content);
    if (rawRole === "system" || rawRole === "developer") {
      if (text) systemParts.push(text);
      messages.push({ role: "system", text, raw: m });
    } else if (rawRole === "assistant") {
      const toolCalls: CanonicalToolCall[] = [];
      for (const tc of Array.isArray(m?.tool_calls) ? m.tool_calls : []) {
        const id = String(tc?.id ?? "");
        const name = String(tc?.function?.name ?? tc?.name ?? "");
        const parsedArgs =
          typeof tc?.function?.arguments === "string"
            ? tryParseJson(tc.function.arguments) ?? {}
            : tc?.function?.arguments ?? {};
        // Unwrap OpenClaw `dispatch_action({ id: "mcp:hyphae:hyphae__hyp_mesh", args })`
        // and OpenCode Code Mode `execute({ code: "return await tools.hyphae.hyp_mesh(...)" })`
        // so `toolNameByCallId` resolves `lastToolResult("hyp_mesh")` cleanly!
        let effectiveName =
          name === "dispatch_action" && typeof parsedArgs?.id === "string"
            ? parsedArgs.id
            : name;
        if (effectiveName === "execute" && typeof parsedArgs?.code === "string") {
          const m = /\b(tools\.hyphae\.hyp_[a-z0-9_]+)\s*\(/.exec(parsedArgs.code);
          if (m) effectiveName = m[1];
        }
        if (id && effectiveName) toolNameByCallId.set(id, effectiveName);
        toolCalls.push({
          id,
          name: effectiveName,
          canonicalName: extractCanonicalHyphaeToolName(effectiveName),
          arguments: parsedArgs,
        });
      }
      messages.push({
        role: "assistant",
        text,
        toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
        raw: m,
      });
    } else if (rawRole === "tool") {
      const callId = String(m?.tool_call_id ?? "");
      const mappedName = toolNameByCallId.get(callId);
      const rawToolName = mappedName || m?.name;
      const tr: CanonicalToolResult = {
        callId,
        rawToolName,
        canonicalToolName: rawToolName ? extractCanonicalHyphaeToolName(rawToolName) : undefined,
        text,
        json: parseToolResultJson(text),
      };
      messages.push({ role: "tool", text: "", toolResults: [tr], raw: m });
    } else {
      messages.push({ role: "user", text, raw: m });
    }
  }

  // Collect trailing consecutive tool results as `lastToolResults`.
  const lastToolResults: CanonicalToolResult[] = [];
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i].role === "tool" && messages[i].toolResults) {
      lastToolResults.unshift(...messages[i].toolResults!);
    } else {
      break;
    }
  }

  const lastUserText = collectTrailingUserText(messages);

  return createCanonicalRequest({
    role,
    protocol: "openai-chat",
    turnIndex,
    model: String(body?.model ?? "shim-1"),
    stream: Boolean(body?.stream),
    systemPrompt: systemParts.join("\n"),
    messages,
    lastUserText,
    lastToolResults,
    advertisedTools,
    headers,
    url,
    rawBody,
    parsedBody: body,
    timestampMs: Date.now(),
  });
}

function parseOpenAiResponsesRequest(
  role: string,
  turnIndex: number,
  body: any,
  rawBody: string,
  url: string,
  headers: IncomingMessage["headers"],
): CanonicalLlmRequest {
  const systemParts: string[] = [];
  if (typeof body?.instructions === "string" && body.instructions) {
    systemParts.push(body.instructions);
  }

  const advertisedTools: AdvertisedTool[] = [];
  for (const t of Array.isArray(body?.tools) ? body.tools : []) {
    if (t?.type === "namespace" && Array.isArray(t?.tools)) {
      const ns = String(t.name ?? "");
      for (const inner of t.tools) {
        const innerName = String(inner?.name ?? inner?.function?.name ?? "");
        if (!innerName) continue;
        advertisedTools.push({
          name: innerName,
          namespace: ns || undefined,
          canonicalHyphaeName: extractCanonicalHyphaeToolName(innerName),
          description: inner?.description ?? inner?.function?.description,
          inputSchema: inner?.parameters ?? inner?.function?.parameters,
        });
      }
      continue;
    }
    const name = String(t?.name ?? t?.function?.name ?? "");
    if (!name) continue;
    advertisedTools.push({
      name,
      canonicalHyphaeName: extractCanonicalHyphaeToolName(name),
      description: t?.description ?? t?.function?.description,
      inputSchema: t?.parameters ?? t?.function?.parameters,
    });
  }

  const toolNameByCallId = new Map<string, string>();
  const messages: CanonicalMessage[] = [];
  const rawInput = body?.input;
  const items = Array.isArray(rawInput)
    ? rawInput
    : typeof rawInput === "string"
      ? [{ role: "user", content: rawInput }]
      : [];

  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    if (item.type === "function_call") {
      const id = String(item.call_id ?? item.id ?? "");
      const name = String(item.name ?? "");
      const args =
        typeof item.arguments === "string"
          ? tryParseJson(item.arguments) ?? {}
          : item.arguments ?? {};
      // Unwrap OpenCode v2 `execute({ code: "return await tools.hyphae.hyp_mesh(...)" })`
      // so `lastToolResult("hyp_mesh")` resolves cleanly!
      let effectiveName = name;
      if (name === "execute" && typeof args?.code === "string") {
        const m = /\b(tools\.hyphae\.hyp_[a-z0-9_]+)\s*\(/.exec(args.code);
        if (m) effectiveName = m[1];
      }
      if (id && effectiveName) toolNameByCallId.set(id, effectiveName);
      messages.push({
        role: "assistant",
        text: "",
        toolCalls: [
          {
            id,
            name: effectiveName,
            canonicalName: extractCanonicalHyphaeToolName(effectiveName),
            arguments: args,
          },
        ],
        raw: item,
      });
    } else if (item.type === "function_call_output") {
      const callId = String(item.call_id ?? "");
      const rawToolName = toolNameByCallId.get(callId);
      const text =
        typeof item.output === "string"
          ? item.output
          : Array.isArray(item.output)
            ? flattenContentBlocks(item.output)
            : JSON.stringify(item.output ?? "");
      messages.push({
        role: "tool",
        text: "",
        toolResults: [
          {
            callId,
            rawToolName,
            canonicalToolName: rawToolName
              ? extractCanonicalHyphaeToolName(rawToolName)
              : undefined,
            text,
            json: parseToolResultJson(text),
          },
        ],
        raw: item,
      });
    } else {
      const mRole = item.role === "assistant" ? "assistant" : item.role === "system" || item.role === "developer" ? "system" : "user";
      const text = flattenContentBlocks(item.content);
      if (mRole === "system" && text) systemParts.push(text);
      messages.push({ role: mRole, text, raw: item });
    }
  }

  const systemPrompt = systemParts.join("\n");
  extractDeferredToolsFromCatalog(advertisedTools, messages, systemPrompt);

  const lastToolResults: CanonicalToolResult[] = [];
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i].role === "tool" && messages[i].toolResults) {
      lastToolResults.unshift(...messages[i].toolResults!);
    } else {
      break;
    }
  }

  const lastUserText = collectTrailingUserText(messages);

  return createCanonicalRequest({
    role,
    protocol: "openai-responses",
    turnIndex,
    model: String(body?.model ?? "gpt-5-shim"),
    stream: Boolean(body?.stream),
    systemPrompt,
    messages,
    lastUserText,
    lastToolResults,
    advertisedTools,
    headers,
    url,
    rawBody,
    parsedBody: body,
    timestampMs: Date.now(),
  });
}

function parseGeminiRequest(
  role: string,
  turnIndex: number,
  model: string,
  stream: boolean,
  body: any,
  rawBody: string,
  url: string,
  headers: IncomingMessage["headers"],
): CanonicalLlmRequest {
  const sysObj = body?.systemInstruction ?? body?.system_instruction;
  let systemPrompt = "";
  if (typeof sysObj === "string") {
    systemPrompt = sysObj;
  } else if (Array.isArray(sysObj?.parts)) {
    systemPrompt = sysObj.parts
      .map((p: any) => (typeof p?.text === "string" ? p.text : ""))
      .filter(Boolean)
      .join("\n");
  }

  const advertisedTools: AdvertisedTool[] = [];
  for (const group of Array.isArray(body?.tools) ? body.tools : []) {
    const decls = group?.functionDeclarations ?? group?.function_declarations ?? [];
    for (const d of Array.isArray(decls) ? decls : []) {
      const name = String(d?.name ?? "");
      if (!name) continue;
      advertisedTools.push({
        name,
        canonicalHyphaeName: extractCanonicalHyphaeToolName(name),
        description: d?.description,
        inputSchema: d?.parameters ?? d?.parametersJsonSchema,
      });
    }
  }

  const messages: CanonicalMessage[] = [];
  for (const content of Array.isArray(body?.contents) ? body.contents : []) {
    const mRole = content?.role === "model" ? "assistant" : "user";
    const textParts: string[] = [];
    const toolCalls: CanonicalToolCall[] = [];
    const toolResults: CanonicalToolResult[] = [];
    for (const part of Array.isArray(content?.parts) ? content.parts : []) {
      if (typeof part?.text === "string") {
        textParts.push(part.text);
      } else if (part?.functionCall) {
        const name = String(part.functionCall.name ?? "");
        const callId = typeof part.functionCall.id === "string" && part.functionCall.id
          ? part.functionCall.id
          : makeCallId("gem");
        toolCalls.push({
          id: callId,
          name,
          canonicalName: extractCanonicalHyphaeToolName(name),
          arguments: (part.functionCall.args ?? {}) as Record<string, unknown>,
        });
      } else if (part?.functionResponse) {
        const name = String(part.functionResponse.name ?? "");
        const callId = typeof part.functionResponse.id === "string" && part.functionResponse.id
          ? part.functionResponse.id
          : name;
        const resp = part.functionResponse.response;
        const text = typeof resp === "string" ? resp : JSON.stringify(resp ?? {});
        const unwrappedJson =
          resp && typeof resp === "object" && typeof resp.output === "string"
            ? (parseToolResultJson(resp.output) ?? resp)
            : typeof resp === "object" && resp !== null
              ? resp
              : parseToolResultJson(text);
        toolResults.push({
          callId,
          rawToolName: name,
          canonicalToolName: extractCanonicalHyphaeToolName(name),
          text,
          json: unwrappedJson,
          isError: Boolean(resp?.error),
        });
      }
    }
    messages.push({
      role: toolResults.length > 0 && textParts.length === 0 ? "tool" : mRole,
      text: textParts.join("\n"),
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      toolResults: toolResults.length > 0 ? toolResults : undefined,
      raw: content,
    });
  }

  const lastToolResults: CanonicalToolResult[] = [];
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i].toolResults && messages[i].toolResults!.length > 0) {
      lastToolResults.unshift(...messages[i].toolResults!);
      if (messages[i].role !== "tool") break;
    } else {
      break;
    }
  }
  const lastUserText = collectTrailingUserText(messages);

  return createCanonicalRequest({
    role,
    protocol: "gemini",
    turnIndex,
    model,
    stream,
    systemPrompt,
    messages,
    lastUserText,
    lastToolResults,
    advertisedTools,
    headers,
    url,
    rawBody,
    parsedBody: body,
    timestampMs: Date.now(),
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function writeSseEvent(res: ServerResponse, event: string | null, data: unknown): void {
  if (res.writableEnded || res.destroyed) return;
  const payload = typeof data === "string" ? data : JSON.stringify(data);
  if (event) {
    res.write(`event: ${event}\ndata: ${payload}\n\n`);
  } else {
    res.write(`data: ${payload}\n\n`);
  }
}

export class LlmShimServer {
  private readonly server: http.Server;
  readonly engine = new ScriptEngine();
  readonly auditors: AuditEngine;

  private port = 0;
  private nextTurnRecordId = 1;
  private readonly roleTurnCounts = new Map<string, number>();
  private readonly turns: RecordedTurn[] = [];
  private readonly turnListeners: Array<(turn: RecordedTurn) => void> = [];
  private readonly abortListeners: Array<(turn: RecordedTurn) => void> = [];

  private constructor(auditorConfig: AuditorConfig = {}) {
    this.auditors = new AuditEngine(auditorConfig);
    this.server = http.createServer((req, res) => {
      void this.handleHttpRequest(req, res);
    });
  }

  static async start(options: { sandbox?: Sandbox; auditors?: AuditorConfig } = {}): Promise<LlmShimServer> {
    const shim = new LlmShimServer(options.auditors);
    await new Promise<void>((resolve, reject) => {
      shim.server.once("error", reject);
      shim.server.listen(0, "127.0.0.1", () => {
        const addr = shim.server.address();
        if (addr && typeof addr === "object") {
          shim.port = addr.port;
        }
        resolve();
      });
    });

    if (options.sandbox) {
      options.sandbox.onSecretRegistered((name, val) => shim.auditors.registerSecret(name, val));
      options.sandbox.addForensicsProvider("llm-shim-requests.json", () => shim.exportForensics());
      options.sandbox.onTeardown(() => shim.close());
    }

    return shim;
  }

  get baseUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  roleBaseUrl(role: string): string {
    return `http://127.0.0.1:${this.port}/s/${encodeURIComponent(role)}`;
  }

  script(role: string, rules: ScriptRule[]): void {
    this.engine.setScript(role, rules);
  }

  getTurns(role?: string): RecordedTurn[] {
    return role ? this.turns.filter((t) => t.role === role) : [...this.turns];
  }

  /** Deterministically waits for a matching turn without blind sleeps. */
  awaitTurn(
    role: string,
    predicate: (turn: RecordedTurn) => boolean = () => true,
    timeoutMs = 20_000,
  ): Promise<RecordedTurn> {
    const existing = this.turns.find((t) => (role === "*" || t.role === role) && predicate(t));
    if (existing) return Promise.resolve(existing);

    return new Promise<RecordedTurn>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.turnListeners.indexOf(onTurn);
        if (idx !== -1) this.turnListeners.splice(idx, 1);
        reject(
          new Error(
            `Timed out after ${timeoutMs}ms waiting for llm-shim turn on role '${role}' (observed turns=${this.turns.length})`,
          ),
        );
      }, timeoutMs);

      const onTurn = (turn: RecordedTurn) => {
        if ((role === "*" || turn.role === role) && predicate(turn)) {
          clearTimeout(timer);
          const idx = this.turnListeners.indexOf(onTurn);
          if (idx !== -1) this.turnListeners.splice(idx, 1);
          resolve(turn);
        }
      };
      this.turnListeners.push(onTurn);
    });
  }

  awaitAbort(role: string, timeoutMs = 15_000): Promise<RecordedTurn> {
    const existing = this.turns.find((t) => (role === "*" || t.role === role) && t.aborted);
    if (existing) return Promise.resolve(existing);

    return new Promise<RecordedTurn>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.abortListeners.indexOf(onAbort);
        if (idx !== -1) this.abortListeners.splice(idx, 1);
        reject(new Error(`Timed out after ${timeoutMs}ms waiting for client abort on role '${role}'`));
      }, timeoutMs);

      const onAbort = (turn: RecordedTurn) => {
        if (role === "*" || turn.role === role) {
          clearTimeout(timer);
          const idx = this.abortListeners.indexOf(onAbort);
          if (idx !== -1) this.abortListeners.splice(idx, 1);
          resolve(turn);
        }
      };
      this.abortListeners.push(onAbort);
    });
  }

  assertAllClean(): void {
    this.auditors.assertNoViolations();
    const ruleErrs = this.turns.filter((t) => t.ruleAssertionError);
    if (ruleErrs.length > 0) {
      const lines = ruleErrs.map(
        (t) => `  [rule:${t.ruleName}] role=${t.role} turn=${t.turnIndex}: ${t.ruleAssertionError}`,
      );
      throw new Error(`llm-shim script assertion(s) FAILED:\n${lines.join("\n")}`);
    }
  }

  exportForensics(): object {
    return {
      baseUrl: this.baseUrl,
      totalTurns: this.turns.length,
      observedRoles: this.auditors.getObservedRoles(),
      auditViolations: this.auditors.getViolations(),
      turns: this.turns,
    };
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve) => {
      this.server.closeAllConnections?.();
      this.server.close(() => resolve());
    });
  }

  private emitTurnRecorded(record: RecordedTurn): void {
    for (const listener of [...this.turnListeners]) {
      listener(record);
    }
  }

  private emitTurnAborted(record: RecordedTurn): void {
    for (const listener of [...this.abortListeners]) {
      listener(record);
    }
  }

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      req.on("error", reject);
    });
  }

  private async handleHttpRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const startedMs = Date.now();
    const method = req.method || "GET";
    const { role, subPath, query } = extractRoleAndPath(req.url || "/", req.headers);

    // Health / models discovery endpoints.
    if (method === "GET" && (subPath === "/v1/models" || subPath === "/models")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          object: "list",
          data: [
            { id: "shim-1", object: "model", owned_by: "fakebrain" },
            { id: "claude-sonnet-4-5", object: "model", owned_by: "fakebrain" },
            { id: "gpt-5-shim", object: "model", owned_by: "fakebrain" },
          ],
        }),
      );
      return;
    }

    if (method === "GET" && subPath === "/v1beta/models") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          models: [
            {
              name: "models/gemini-2.5-pro",
              displayName: "FakeBrain Gemini 2.5 Pro",
              supportedGenerationMethods: ["generateContent", "streamGenerateContent", "countTokens"],
            },
            {
              name: "models/gemini-2.5-flash",
              displayName: "FakeBrain Gemini 2.5 Flash",
              supportedGenerationMethods: ["generateContent", "streamGenerateContent", "countTokens"],
            },
          ],
        }),
      );
      return;
    }

    const rawBody = await this.readBody(req);
    const parsedBody = tryParseJson(rawBody) ?? {};

    // Anthropic token counting helper endpoint (Claude Code may call this).
    if (method === "POST" && subPath === "/v1/messages/count_tokens") {
      const approxTokens = Math.max(10, Math.ceil(rawBody.length / 4));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ input_tokens: approxTokens }));
      return;
    }

    // Google Gemini token counting helper endpoint (`:countTokens`).
    if (method === "POST" && /^\/v1beta\/models\/([^/:]+):countTokens$/.test(subPath)) {
      const approxTokens = Math.max(10, Math.ceil(rawBody.length / 4));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ totalTokens: approxTokens }));
      return;
    }

    // Match supported model generation endpoints.
    let protocol: LlmProtocol | null = null;
    let geminiModel = "gemini-2.5-pro";
    let geminiStream = false;
    let geminiUseSse = false;

    if (method === "POST" && (subPath === "/v1/messages" || subPath === "/messages")) {
      protocol = "anthropic";
    } else if (method === "POST" && (subPath === "/v1/chat/completions" || subPath === "/chat/completions")) {
      protocol = "openai-chat";
    } else if (method === "POST" && (subPath === "/v1/responses" || subPath === "/responses")) {
      protocol = "openai-responses";
    } else if (method === "POST") {
      const gemMatch = /^\/v1beta\/models\/([^/:]+):(generateContent|streamGenerateContent)$/.exec(
        subPath,
      );
      if (gemMatch) {
        protocol = "gemini";
        geminiModel = gemMatch[1];
        geminiStream = gemMatch[2] === "streamGenerateContent";
        geminiUseSse = query.get("alt") === "sse";
      }
    }

    if (!protocol) {
      // Quietly acknowledge Claude non-essential telemetry/event probes if any arrive on loopback.
      if (subPath.includes("event_logging") || subPath.includes("telemetry")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { type: "not_found", message: `Unknown llm-shim route ${method} ${subPath}` } }));
      return;
    }

    const turnIndex = this.roleTurnCounts.get(role) ?? 0;
    this.roleTurnCounts.set(role, turnIndex + 1);

    let canonical: CanonicalLlmRequest;
    if (protocol === "anthropic") {
      canonical = parseAnthropicRequest(role, turnIndex, parsedBody, rawBody, req.url || "/", req.headers);
    } else if (protocol === "openai-chat") {
      canonical = parseOpenAiChatRequest(role, turnIndex, parsedBody, rawBody, req.url || "/", req.headers);
    } else if (protocol === "openai-responses") {
      canonical = parseOpenAiResponsesRequest(role, turnIndex, parsedBody, rawBody, req.url || "/", req.headers);
    } else {
      canonical = parseGeminiRequest(
        role,
        turnIndex,
        geminiModel,
        geminiStream || query.get("alt") === "sse",
        parsedBody,
        rawBody,
        req.url || "/",
        req.headers,
      );
    }

    const auditViolations: AuditViolation[] = this.auditors.auditRequest(canonical);
    const { ruleName, action, assertionError } = await this.engine.evaluate(canonical);

    const record: RecordedTurn = {
      id: this.nextTurnRecordId++,
      role,
      protocol,
      turnIndex,
      ruleName,
      request: {
        url: canonical.url,
        model: canonical.model,
        stream: canonical.stream,
        systemPrompt: canonical.systemPrompt,
        messages: canonical.messages,
        lastUserText: canonical.lastUserText,
        lastToolResults: canonical.lastToolResults,
        advertisedTools: canonical.advertisedTools,
        headers: canonical.headers,
        rawBody: canonical.rawBody,
        timestampMs: canonical.timestampMs,
      },
      actionKind: action.kind,
      responseSummary: null,
      statusCode: 200,
      aborted: false,
      durationMs: 0,
      auditViolations,
      ruleAssertionError: assertionError,
    };
    this.turns.push(record);
    this.emitTurnRecorded(record);

    let clientAborted = false;
    const abortCallbacks: Array<() => void> = [];
    const markAborted = () => {
      if (clientAborted || res.writableEnded) return;
      clientAborted = true;
      record.aborted = true;
      for (const cb of abortCallbacks.splice(0)) cb();
      this.emitTurnAborted(record);
    };
    req.on("aborted", markAborted);
    res.on("close", () => {
      if (!res.writableEnded) markAborted();
    });

    try {
      await this.executeAction(
        canonical,
        action,
        record,
        res,
        () => clientAborted,
        (cb) => {
          if (clientAborted) cb();
          else abortCallbacks.push(cb);
        },
        0,
        protocol === "gemini" && geminiStream && !geminiUseSse,
      );
    } finally {
      record.durationMs = Date.now() - startedMs;
    }
  }

  private async executeAction(
    req: CanonicalLlmRequest,
    action: ScriptAction,
    record: RecordedTurn,
    res: ServerResponse,
    isAborted: () => boolean,
    onAbort: (cb: () => void) => void,
    chunkDelay = 0,
    geminiJsonArrayStream = false,
  ): Promise<void> {
    // Unwrap combinators before writing headers.
    if (action.kind === "delay_before_headers") {
      await sleep(action.ms);
      if (isAborted()) return;
      return this.executeAction(
        req,
        action.next,
        record,
        res,
        isAborted,
        onAbort,
        chunkDelay,
        geminiJsonArrayStream,
      );
    }

    if (action.kind === "chunk_delay") {
      return this.executeAction(
        req,
        action.next,
        record,
        res,
        isAborted,
        onAbort,
        action.ms,
        geminiJsonArrayStream,
      );
    }

    if (action.kind === "pause_until") {
      await Promise.race([
        action.gate.wait(),
        new Promise<void>((resolve) => onAbort(resolve)),
      ]);
      if (isAborted()) return;
      return this.executeAction(
        req,
        action.next,
        record,
        res,
        isAborted,
        onAbort,
        chunkDelay,
        geminiJsonArrayStream,
      );
    }

    if (action.kind === "fail_once") {
      if (this.engine.consumeFaultOnce(req.role, action.key)) {
        record.statusCode = action.status;
        const headers: Record<string, string> = { "content-type": "application/json" };
        if (action.retryAfter !== undefined) {
          headers["retry-after"] = String(action.retryAfter);
        }
        const errBody =
          action.body ??
          (req.protocol === "anthropic"
            ? {
                type: "error",
                error: {
                  type: action.status === 429 ? "rate_limit_error" : "api_error",
                  message: `Simulated HTTP ${action.status}`,
                },
              }
            : req.protocol === "gemini"
              ? {
                  error: {
                    code: action.status,
                    message: `Simulated HTTP ${action.status}`,
                    status: action.status === 429 ? "RESOURCE_EXHAUSTED" : "INTERNAL",
                  },
                }
              : {
                  error: {
                    message: `Simulated HTTP ${action.status}`,
                    type: "simulated_error",
                    code: String(action.status),
                  },
                });
        record.responseSummary = errBody;
        res.writeHead(action.status, headers);
        res.end(JSON.stringify(errBody));
        return;
      }
      return this.executeAction(
        req,
        action.fallback,
        record,
        res,
        isAborted,
        onAbort,
        chunkDelay,
        geminiJsonArrayStream,
      );
    }

    if (action.kind === "abort_mid_stream") {
      await this.writeProtocolStream(
        req,
        {
          initialText: action.initialText ?? "PARTIAL_",
          abortAfterInitial: true,
        },
        record,
        res,
        isAborted,
        onAbort,
        chunkDelay,
        geminiJsonArrayStream,
      );
      return;
    }

    if (action.kind === "pause_mid_stream") {
      await this.writeProtocolStream(
        req,
        {
          initialText: action.initialText,
          midStreamGate: action.gate,
          restText: action.restText,
          restAction: action.restAction,
        },
        record,
        res,
        isAborted,
        onAbort,
        chunkDelay,
        geminiJsonArrayStream,
      );
      return;
    }

    // Standard `text` or `tool_calls` leaf action.
    if (req.stream) {
      await this.writeProtocolStream(
        req,
        { leafAction: action },
        record,
        res,
        isAborted,
        onAbort,
        chunkDelay,
        geminiJsonArrayStream,
      );
    } else {
      this.writeProtocolJson(req, action, record, res);
    }
  }

  private writeProtocolJson(
    req: CanonicalLlmRequest,
    action: Extract<ScriptAction, { kind: "text" | "tool_calls" }>,
    record: RecordedTurn,
    res: ServerResponse,
  ): void {
    let payload: unknown;

    if (req.protocol === "anthropic") {
      const content: any[] = [];
      if (action.kind === "text") {
        content.push({ type: "text", text: action.text });
      } else {
        if (action.preambleText) content.push({ type: "text", text: action.preambleText });
        for (const call of action.calls) {
          content.push({
            type: "tool_use",
            id: call.callId ?? makeCallId("toolu"),
            name: call.wireName ?? req.resolveTool(call.logicalName),
            input: call.args,
          });
        }
      }
      payload = {
        id: `msg_${crypto.randomBytes(6).toString("hex")}`,
        type: "message",
        role: "assistant",
        model: req.model,
        content,
        stop_reason: action.kind === "tool_calls" ? "tool_use" : (action.stopReason ?? "end_turn"),
        stop_sequence: null,
        usage: { input_tokens: 24, output_tokens: 16 },
      };
    } else if (req.protocol === "openai-chat") {
      const message: any = { role: "assistant" };
      if (action.kind === "text") {
        message.content = action.text;
      } else {
        message.content = action.preambleText ?? null;
        message.tool_calls = action.calls.map((c) => ({
          id: c.callId ?? makeCallId("call"),
          type: "function",
          function: {
            name: c.wireName ?? req.resolveTool(c.logicalName),
            arguments: JSON.stringify(c.args),
          },
        }));
      }
      payload = {
        id: `chatcmpl_${crypto.randomBytes(6).toString("hex")}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: req.model,
        choices: [
          {
            index: 0,
            message,
            finish_reason: action.kind === "tool_calls" ? "tool_calls" : "stop",
          },
        ],
        usage: { prompt_tokens: 24, completion_tokens: 16, total_tokens: 40 },
      };
    } else if (req.protocol === "openai-responses") {
      const output: any[] = [];
      if (action.kind === "text") {
        output.push({
          id: `msg_${crypto.randomBytes(6).toString("hex")}`,
          type: "message",
          status: "completed",
          role: "assistant",
          content: [{ type: "output_text", text: action.text, annotations: [] }],
        });
      } else {
        if (action.preambleText) {
          output.push({
            id: `msg_${crypto.randomBytes(6).toString("hex")}`,
            type: "message",
            status: "completed",
            role: "assistant",
            content: [{ type: "output_text", text: action.preambleText, annotations: [] }],
          });
        }
        for (const c of action.calls) {
          const cid = c.callId ?? makeCallId("call");
          const wireName = c.wireName ?? req.resolveTool(c.logicalName);
          const ns =
            c.namespace ?? req.advertisedTools.find((t) => t.name === wireName)?.namespace;
          output.push({
            id: `fc_${crypto.randomBytes(6).toString("hex")}`,
            type: "function_call",
            status: "completed",
            call_id: cid,
            ...(ns ? { namespace: ns } : {}),
            name: wireName,
            arguments: JSON.stringify(c.args),
          });
        }
      }
      payload = {
        id: `resp_${crypto.randomBytes(6).toString("hex")}`,
        object: "response",
        created_at: Math.floor(Date.now() / 1000),
        status: "completed",
        model: req.model,
        output,
        usage: { input_tokens: 24, output_tokens: 16, total_tokens: 40 },
      };
    } else {
      // Google Gemini JSON response.
      const parts: any[] = [];
      if (action.kind === "text") {
        parts.push({ text: action.text });
      } else {
        if (action.preambleText) parts.push({ text: action.preambleText });
        for (const c of action.calls) {
          parts.push({
            functionCall: {
              ...(c.callId ? { id: c.callId } : {}),
              name: c.wireName ?? req.resolveTool(c.logicalName),
              args: c.args,
            },
          });
        }
      }
      payload = {
        candidates: [
          {
            content: { role: "model", parts },
            finishReason: "STOP",
            index: 0,
          },
        ],
        usageMetadata: { promptTokenCount: 24, candidatesTokenCount: 16, totalTokenCount: 40 },
      };
    }

    record.responseSummary = payload;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(payload));
  }

  private async writeProtocolStream(
    req: CanonicalLlmRequest,
    plan: {
      leafAction?: Extract<ScriptAction, { kind: "text" | "tool_calls" }>;
      initialText?: string;
      midStreamGate?: { wait(): Promise<void> };
      restText?: string;
      restAction?: ScriptAction;
      abortAfterInitial?: boolean;
    },
    record: RecordedTurn,
    res: ServerResponse,
    isAborted: () => boolean,
    onAbort: (cb: () => void) => void,
    chunkDelay: number,
    geminiJsonArrayStream = false,
  ): Promise<void> {
    if (req.protocol === "gemini" && geminiJsonArrayStream) {
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-cache",
      });
    } else {
      res.writeHead(200, {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache",
        connection: "keep-alive",
      });
    }
    res.flushHeaders?.();

    const delayIf = async () => {
      if (chunkDelay > 0 && !isAborted()) await sleep(chunkDelay);
    };

    const waitMidStreamGate = async (): Promise<boolean> => {
      if (!plan.midStreamGate) return !isAborted();
      await Promise.race([
        plan.midStreamGate.wait(),
        new Promise<void>((resolve) => onAbort(resolve)),
      ]);
      return !isAborted();
    };

    const finalTextFromPlan = (): string | undefined => {
      if (plan.restText !== undefined) return plan.restText;
      if (plan.restAction?.kind === "text") return plan.restAction.text;
      if (plan.leafAction?.kind === "text") return plan.leafAction.text;
      return undefined;
    };

    const finalToolCallsFromPlan = (): ToolCallSpec[] => {
      if (plan.leafAction?.kind === "tool_calls") return plan.leafAction.calls;
      if (plan.restAction?.kind === "tool_calls") return plan.restAction.calls;
      return [];
    };

    if (req.protocol === "anthropic") {
      const msgId = `msg_${crypto.randomBytes(6).toString("hex")}`;
      writeSseEvent(res, "message_start", {
        type: "message_start",
        message: {
          id: msgId,
          type: "message",
          role: "assistant",
          model: req.model,
          content: [],
          stop_reason: null,
          stop_sequence: null,
          usage: { input_tokens: 24, output_tokens: 1 },
        },
      });

      let blockIndex = 0;

      if (plan.initialText !== undefined || plan.leafAction?.kind === "text" || plan.leafAction?.preambleText) {
        const firstText =
          plan.initialText ??
          (plan.leafAction?.kind === "text"
            ? plan.leafAction.text
            : plan.leafAction?.preambleText ?? "");

        writeSseEvent(res, "content_block_start", {
          type: "content_block_start",
          index: blockIndex,
          content_block: { type: "text", text: "" },
        });
        if (firstText) {
          writeSseEvent(res, "content_block_delta", {
            type: "content_block_delta",
            index: blockIndex,
            delta: { type: "text_delta", text: firstText },
          });
        }
        await delayIf();

        if (plan.abortAfterInitial) {
          record.responseSummary = { stream: "aborted_mid_stream", initialText: firstText };
          res.destroy();
          return;
        }

        if (plan.midStreamGate) {
          const ok = await waitMidStreamGate();
          if (!ok) {
            record.responseSummary = { stream: "client_aborted", initialText: firstText };
            return;
          }
          const tailText = finalTextFromPlan();
          if (tailText) {
            writeSseEvent(res, "content_block_delta", {
              type: "content_block_delta",
              index: blockIndex,
              delta: { type: "text_delta", text: tailText },
            });
          }
        }

        writeSseEvent(res, "content_block_stop", {
          type: "content_block_stop",
          index: blockIndex,
        });
        blockIndex += 1;
      }

      const calls = finalToolCallsFromPlan();
      for (const call of calls) {
        const wireName = call.wireName ?? req.resolveTool(call.logicalName);
        const callId = call.callId ?? makeCallId("toolu");
        writeSseEvent(res, "content_block_start", {
          type: "content_block_start",
          index: blockIndex,
          content_block: { type: "tool_use", id: callId, name: wireName, input: {} },
        });
        const argsJson = JSON.stringify(call.args);
        await delayIf();
        writeSseEvent(res, "content_block_delta", {
          type: "content_block_delta",
          index: blockIndex,
          delta: { type: "input_json_delta", partial_json: argsJson },
        });
        writeSseEvent(res, "content_block_stop", {
          type: "content_block_stop",
          index: blockIndex,
        });
        blockIndex += 1;
      }

      const stopReason = calls.length > 0 ? "tool_use" : "end_turn";
      writeSseEvent(res, "message_delta", {
        type: "message_delta",
        delta: { stop_reason: stopReason, stop_sequence: null },
        usage: { output_tokens: 16 },
      });
      writeSseEvent(res, "message_stop", { type: "message_stop" });
      record.responseSummary = {
        protocol: "anthropic-sse",
        stopReason,
        text: `${plan.initialText ?? ""}${finalTextFromPlan() ?? ""}`,
        toolCalls: calls.map((c) => ({ name: c.wireName ?? c.logicalName, args: c.args })),
      };
      res.end();
      return;
    }

    if (req.protocol === "openai-chat") {
      const id = `chatcmpl_${crypto.randomBytes(6).toString("hex")}`;
      const created = Math.floor(Date.now() / 1000);
      const sendChunk = (delta: Record<string, unknown>, finishReason: string | null = null) => {
        writeSseEvent(res, null, {
          id,
          object: "chat.completion.chunk",
          created,
          model: req.model,
          choices: [{ index: 0, delta, finish_reason: finishReason }],
        });
      };

      const firstText =
        plan.initialText ??
        (plan.leafAction?.kind === "text"
          ? plan.leafAction.text
          : plan.leafAction?.preambleText);

      if (firstText !== undefined) {
        sendChunk({ role: "assistant", content: firstText });
        await delayIf();
        if (plan.abortAfterInitial) {
          record.responseSummary = { stream: "aborted_mid_stream", initialText: firstText };
          res.destroy();
          return;
        }
        if (plan.midStreamGate) {
          const ok = await waitMidStreamGate();
          if (!ok) {
            record.responseSummary = { stream: "client_aborted", initialText: firstText };
            return;
          }
          const tail = finalTextFromPlan();
          if (tail) sendChunk({ content: tail });
        }
      }

      const calls = finalToolCallsFromPlan();
      calls.forEach((call, idx) => {
        const wireName = call.wireName ?? req.resolveTool(call.logicalName);
        const callId = call.callId ?? makeCallId("call");
        sendChunk({
          ...(idx === 0 && firstText === undefined ? { role: "assistant" } : {}),
          tool_calls: [
            {
              index: idx,
              id: callId,
              type: "function",
              function: { name: wireName, arguments: JSON.stringify(call.args) },
            },
          ],
        });
      });

      const finishReason = calls.length > 0 ? "tool_calls" : "stop";
      writeSseEvent(res, null, {
        id,
        object: "chat.completion.chunk",
        created,
        model: req.model,
        choices: [{ index: 0, delta: {}, finish_reason: finishReason }],
        usage: { prompt_tokens: 24, completion_tokens: 16, total_tokens: 40 },
      });
      writeSseEvent(res, null, "[DONE]");
      record.responseSummary = {
        protocol: "openai-chat-sse",
        finishReason,
        text: `${plan.initialText ?? ""}${finalTextFromPlan() ?? ""}`,
        toolCalls: calls.map((c) => ({ name: c.wireName ?? c.logicalName, args: c.args })),
      };
      res.end();
      return;
    }

    if (req.protocol === "openai-responses") {
      const respId = `resp_${crypto.randomBytes(6).toString("hex")}`;
      const outputItems: any[] = [];
      let outputIndex = 0;

      writeSseEvent(res, "response.created", {
        type: "response.created",
        response: { id: respId, object: "response", status: "in_progress", model: req.model, output: [] },
      });

      const firstText =
        plan.initialText ??
        (plan.leafAction?.kind === "text"
          ? plan.leafAction.text
          : plan.leafAction?.preambleText);

      if (firstText !== undefined) {
        const msgId = `msg_${crypto.randomBytes(6).toString("hex")}`;
        writeSseEvent(res, "response.output_item.added", {
          type: "response.output_item.added",
          output_index: outputIndex,
          item: { id: msgId, type: "message", status: "in_progress", role: "assistant", content: [] },
        });
        writeSseEvent(res, "response.output_text.delta", {
          type: "response.output_text.delta",
          item_id: msgId,
          output_index: outputIndex,
          content_index: 0,
          delta: firstText,
        });
        await delayIf();
        if (plan.abortAfterInitial) {
          record.responseSummary = { stream: "aborted_mid_stream", initialText: firstText };
          res.destroy();
          return;
        }
        let fullText = firstText;
        if (plan.midStreamGate) {
          const ok = await waitMidStreamGate();
          if (!ok) {
            record.responseSummary = { stream: "client_aborted", initialText: firstText };
            return;
          }
          const tail = finalTextFromPlan();
          if (tail) {
            fullText += tail;
            writeSseEvent(res, "response.output_text.delta", {
              type: "response.output_text.delta",
              item_id: msgId,
              output_index: outputIndex,
              content_index: 0,
              delta: tail,
            });
          }
        }
        const doneMsg = {
          id: msgId,
          type: "message",
          status: "completed",
          role: "assistant",
          content: [{ type: "output_text", text: fullText, annotations: [] }],
        };
        outputItems.push(doneMsg);
        writeSseEvent(res, "response.output_item.done", {
          type: "response.output_item.done",
          output_index: outputIndex,
          item: doneMsg,
        });
        outputIndex += 1;
      }

      const calls = finalToolCallsFromPlan();
      for (const call of calls) {
        const fcId = `fc_${crypto.randomBytes(6).toString("hex")}`;
        const callId = call.callId ?? makeCallId("call");
        const wireName = call.wireName ?? req.resolveTool(call.logicalName);
        const ns =
          call.namespace ?? req.advertisedTools.find((t) => t.name === wireName)?.namespace;
        const argsJson = JSON.stringify(call.args);
        writeSseEvent(res, "response.output_item.added", {
          type: "response.output_item.added",
          output_index: outputIndex,
          item: {
            id: fcId,
            type: "function_call",
            status: "in_progress",
            call_id: callId,
            ...(ns ? { namespace: ns } : {}),
            name: wireName,
            arguments: "",
          },
        });
        await delayIf();
        writeSseEvent(res, "response.function_call_arguments.delta", {
          type: "response.function_call_arguments.delta",
          item_id: fcId,
          output_index: outputIndex,
          delta: argsJson,
        });
        const doneFc = {
          id: fcId,
          type: "function_call",
          status: "completed",
          call_id: callId,
          ...(ns ? { namespace: ns } : {}),
          name: wireName,
          arguments: argsJson,
        };
        outputItems.push(doneFc);
        writeSseEvent(res, "response.output_item.done", {
          type: "response.output_item.done",
          output_index: outputIndex,
          item: doneFc,
        });
        outputIndex += 1;
      }

      writeSseEvent(res, "response.completed", {
        type: "response.completed",
        response: {
          id: respId,
          object: "response",
          status: "completed",
          model: req.model,
          output: outputItems,
          usage: { input_tokens: 24, output_tokens: 16, total_tokens: 40 },
        },
      });
      record.responseSummary = { protocol: "openai-responses-sse", output: outputItems };
      res.end();
      return;
    }

    // Google Gemini streaming (`:streamGenerateContent?alt=sse` or JSON-array stream without `alt=sse`).
    let jsonArrayChunkCount = 0;
    const emitGeminiChunk = (chunk: unknown) => {
      if (res.writableEnded || res.destroyed) return;
      if (geminiJsonArrayStream) {
        res.write(jsonArrayChunkCount === 0 ? `[${JSON.stringify(chunk)}` : `,${JSON.stringify(chunk)}`);
        jsonArrayChunkCount += 1;
      } else {
        writeSseEvent(res, null, chunk);
      }
    };

    const firstText =
      plan.initialText ??
      (plan.leafAction?.kind === "text" ? plan.leafAction.text : plan.leafAction?.preambleText);

    if (firstText !== undefined) {
      emitGeminiChunk({
        candidates: [{ content: { role: "model", parts: [{ text: firstText }] }, index: 0 }],
      });
      await delayIf();
      if (plan.abortAfterInitial) {
        record.responseSummary = { stream: "aborted_mid_stream", initialText: firstText };
        res.destroy();
        return;
      }
      if (plan.midStreamGate) {
        const ok = await waitMidStreamGate();
        if (!ok) {
          record.responseSummary = { stream: "client_aborted", initialText: firstText };
          return;
        }
        const tail = finalTextFromPlan();
        if (tail) {
          emitGeminiChunk({
            candidates: [{ content: { role: "model", parts: [{ text: tail }] }, index: 0 }],
          });
        }
      }
    }

    const calls = finalToolCallsFromPlan();
    if (calls.length > 0) {
      emitGeminiChunk({
        candidates: [
          {
            content: {
              role: "model",
              parts: calls.map((c) => ({
                functionCall: {
                  ...(c.callId ? { id: c.callId } : {}),
                  name: c.wireName ?? req.resolveTool(c.logicalName),
                  args: c.args,
                },
              })),
            },
            finishReason: "STOP",
            index: 0,
          },
        ],
        usageMetadata: { promptTokenCount: 24, candidatesTokenCount: 16, totalTokenCount: 40 },
      });
    } else {
      emitGeminiChunk({
        candidates: [{ content: { role: "model", parts: [] }, finishReason: "STOP", index: 0 }],
        usageMetadata: { promptTokenCount: 24, candidatesTokenCount: 16, totalTokenCount: 40 },
      });
    }

    if (geminiJsonArrayStream && !res.writableEnded && !res.destroyed) {
      res.write("]");
    }
    record.responseSummary = {
      protocol: geminiJsonArrayStream ? "gemini-json-stream" : "gemini-sse",
      text: `${plan.initialText ?? ""}${finalTextFromPlan() ?? ""}`,
      toolCalls: calls.map((c) => ({ name: c.wireName ?? c.logicalName, args: c.args })),
    };
    res.end();
  }
}
