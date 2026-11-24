// Line-delimited JSON between the stdio MCP shim and the daemon, over a 0600 Unix socket.
import * as Schema from "effect/Schema";

export const ToolRequest = Schema.Struct({
  tool: Schema.String,
  arguments: Schema.Unknown,
  /** Provider tool-call ID from MCP `_meta` (Claude toolUseId, Codex callId); null when absent. */
  callId: Schema.NullOr(Schema.String),
});
export type ToolRequest = typeof ToolRequest.Type;

export const ToolError = Schema.Struct({ code: Schema.String, message: Schema.String });
export type ToolError = typeof ToolError.Type;

export const ToolResponse = Schema.Union([
  Schema.Struct({ ok: Schema.Literal(true), result: Schema.Unknown }),
  Schema.Struct({ ok: Schema.Literal(false), error: ToolError }),
]);
export type ToolResponse = typeof ToolResponse.Type;

/** Metadata is local connector information and needs no provider tool-call identity. */
export const MetadataRequest = Schema.Struct({ type: Schema.Literal("metadata") });
export const IpcRequest = Schema.Union([ToolRequest, MetadataRequest]);
export type IpcRequest = typeof IpcRequest.Type;
export const decodeIpcRequest = Schema.decodeUnknownSync(IpcRequest);

export const decodeToolResponse = Schema.decodeUnknownSync(ToolResponse);

export const toolError = (code: string, message: string): ToolResponse => ({ ok: false, error: { code, message } });
