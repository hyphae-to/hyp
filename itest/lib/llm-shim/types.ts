/**
 * Shared TypeScript types for `llm-shim` (FakeBrain), turn script engine, and invariant auditors.
 */

export type LlmProtocol = "anthropic" | "openai-chat" | "openai-responses" | "gemini";

export interface AdvertisedTool {
  /** Exact wire tool name sent by the harness (e.g., `mcp__hyphae__hyp_mesh`, `hyphae__hyp_mesh`, `hyp_mesh`, or `mcp:hyphae:hyphae__hyp_mesh`). */
  name: string;
  /** Optional OpenAI Responses namespace containing this tool (e.g., `mcp__hyphae` in Codex 0.172+). */
  namespace?: string;
  /** Canonical normalized Hyphae tool name if this is a Hyphae tool (e.g., `hyp_mesh`), else undefined. */
  canonicalHyphaeName?: string;
  /** If true, tool is deferred (e.g., OpenClaw `dispatch_action`, Claude Code `ToolSearch`, or OpenCode `execute`). */
  deferred?: boolean;
  /** Mechanism required for a deferred tool (`"dispatch_action"` in OpenClaw, `"tool_search"` in Claude Code, `"opencode_execute"` in OpenCode v2 Code Mode). */
  deferredVia?: "dispatch_action" | "tool_search" | "opencode_execute";
  description?: string;
  inputSchema?: unknown;
}

export interface CanonicalToolCall {
  id: string;
  name: string;
  canonicalName?: string;
  arguments: Record<string, unknown>;
}

export interface CanonicalToolResult {
  callId: string;
  rawToolName?: string;
  canonicalToolName?: string;
  text: string;
  json: any;
  isError?: boolean;
}

export interface CanonicalMessage {
  role: "system" | "user" | "assistant" | "tool";
  text: string;
  toolCalls?: CanonicalToolCall[];
  toolResults?: CanonicalToolResult[];
  raw?: unknown;
}

export interface CanonicalLlmRequest {
  role: string;
  protocol: LlmProtocol;
  turnIndex: number;
  model: string;
  stream: boolean;
  systemPrompt: string;
  messages: CanonicalMessage[];
  lastUserText: string;
  lastToolResults: CanonicalToolResult[];
  advertisedTools: AdvertisedTool[];
  headers: Record<string, string | string[] | undefined>;
  url: string;
  rawBody: string;
  parsedBody: any;
  timestampMs: number;

  /** Returns the latest tool result matching a logical tool name (e.g. `"hyp_mesh"` or exact name). */
  lastToolResult(logicalToolName: string): CanonicalToolResult | undefined;
  /** Returns true if any message text, tool result, or system prompt matches `needle`. */
  anyMessageContains(needle: string | RegExp): boolean;
  /** Returns true if any user/system/tool_result context matches `pattern`. */
  hasContextMatching(pattern: RegExp): boolean;
  /** Resolves a logical tool name (e.g. `"hyp_mesh"`) to the exact advertised wire tool name. */
  resolveTool(logicalToolName: string): string;
  /** Returns true if a tool is advertised only as a deferred ToolSearch entry (schema not yet loaded). */
  isToolDeferred(logicalToolName: string): boolean;
}

export interface Gate {
  readonly label: string;
  readonly promise: Promise<void>;
  readonly isReleased: boolean;
  readonly waitCount: number;
  /** Resolves once at least `n` (default 1) callers have entered `wait()`. */
  waitForWaiters(n?: number, timeoutMs?: number): Promise<void>;
  wait(): Promise<void>;
  release(): void;
}

export interface ToolCallSpec {
  logicalName: string;
  wireName?: string;
  namespace?: string;
  args: Record<string, unknown>;
  callId?: string;
}

export type ScriptAction =
  | { kind: "text"; text: string; stopReason?: string }
  | { kind: "tool_calls"; calls: ToolCallSpec[]; preambleText?: string }
  | { kind: "pause_until"; gate: Gate; next: ScriptAction }
  | {
      kind: "pause_mid_stream";
      gate: Gate;
      initialText: string;
      restText?: string;
      restAction?: ScriptAction;
    }
  | { kind: "delay_before_headers"; ms: number; next: ScriptAction }
  | { kind: "chunk_delay"; ms: number; next: ScriptAction }
  | {
      kind: "fail_once";
      key: string;
      status: number;
      retryAfter?: number | string;
      body?: unknown;
      fallback: ScriptAction;
    }
  | { kind: "abort_mid_stream"; initialText?: string };

export interface ScriptRule {
  name: string;
  when: (req: CanonicalLlmRequest) => boolean;
  assert?: (req: CanonicalLlmRequest) => void | Promise<void>;
  do: (req: CanonicalLlmRequest) => ScriptAction | Promise<ScriptAction>;
  /** If true, this rule fires at most once per role. */
  once?: boolean;
}

export type AuditorId =
  | "secret-leak"
  | "untrusted-provenance"
  | "metadata-only-wake"
  | "duplicate-delivery"
  | "mcp-schema-footprint";

export interface AuditViolation {
  auditor: AuditorId;
  role: string;
  turnIndex: number;
  message: string;
  detail?: Record<string, unknown>;
}

export interface AuditorConfig {
  /** Allow `hyp_bridge` in advertised MCP tools (default false). */
  allowBridge?: boolean;
  /** Allow `hyp_kv` in advertised MCP tools (default false). */
  allowKv?: boolean;
  /** Roles where wake nudges MUST be strictly metadata-only across the entire wake turn (e.g. promptInjection=false). */
  nudgeOnlyRoles?: string[];
  /** Optional explicit allowlist of expected roles; any other role triggers session-coherence violation. */
  allowedRoles?: string[];
  /** Waive specific auditor IDs (intended only for negative/mutation self-tests). */
  waiveAuditors?: AuditorId[];
}

export interface RecordedTurn {
  id: number;
  role: string;
  protocol: LlmProtocol;
  turnIndex: number;
  ruleName: string;
  request: {
    url: string;
    model: string;
    stream: boolean;
    systemPrompt: string;
    messages: CanonicalMessage[];
    lastUserText: string;
    lastToolResults: CanonicalToolResult[];
    advertisedTools: AdvertisedTool[];
    headers: Record<string, string | string[] | undefined>;
    rawBody: string;
    timestampMs: number;
  };
  actionKind: string;
  responseSummary: unknown;
  statusCode: number;
  aborted: boolean;
  durationMs: number;
  auditViolations: AuditViolation[];
  ruleAssertionError?: string;
}
