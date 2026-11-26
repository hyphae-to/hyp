/**
 * Wire-Exact Compiled-Binary Lifecycle Replay Drivers for Cursor & Antigravity IDE Harnesses
 * + Opt-In Tier 3 Live Cloud Smoke Runners (`HYPHAE_ITEST_LIVE_CURSOR=1`, `HYPHAE_ITEST_LIVE_AGY=1`).
 *
 * Neither `cursor-agent` nor `agy` currently permits routing their LLM API traffic to a local
 * loopback shim without cloud authentication. Rather than mocking Hyphae internals, these drivers
 * execute 100% of Hyphae's real compiled black-box surface (`hyp setup`, `hyp hook`, `hyp mcp`,
 * `hyp wait`, `hyp statusline`, and `hyp node start --if-not-running`) with wire-exact IDE hook
 * payloads and JSON-RPC 2.0 MCP traffic.
 */

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { HypMcpClient } from "../hyp-cli.ts";
import type { HypCli } from "../hyp-cli.ts";
import type { Sandbox, TrackedProcess } from "../sandbox.ts";

export interface McpToolOutcome {
  text: string;
  json: any;
  isError: boolean;
  raw: any;
}

export interface WaitHandle {
  proc: TrackedProcess;
  done: Promise<{ exitCode: number | null; stdout: string; stderr: string; json: any }>;
}

function tryParseJson(raw: string): any {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    const idx = trimmed.indexOf("{");
    if (idx !== -1) {
      try {
        return JSON.parse(trimmed.slice(idx));
      } catch {
        return null;
      }
    }
    return null;
  }
}

function spawnHypWait(
  sandbox: Sandbox,
  hyp: HypCli,
  sessionId: string,
  timeoutSec = 15,
  label = "hyp-wait",
): WaitHandle {
  const proc = sandbox.reaper.spawn(
    label,
    hyp.bin,
    ["wait", "--session", sessionId, "--socket", hyp.socketPath, "--timeout", String(timeoutSec), "--json"],
    {
      env: sandbox.env,
      cwd: sandbox.paths.workspaceDir,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const done = (async () => {
    await proc.exitPromise;
    return {
      exitCode: proc.exitCode,
      stdout: proc.stdout,
      stderr: proc.stderr,
      json: tryParseJson(proc.stdout),
    };
  })();
  return { proc, done };
}

// ============================================================================
// 1. Cursor Wire-Exact Compiled-Binary Lifecycle Replay Driver
// ============================================================================

export class CursorReplayDriver {
  readonly sandbox: Sandbox;
  readonly hyp: HypCli;
  readonly conversationId: string;
  readonly sessionId: string;
  readonly mcp: HypMcpClient;

  private constructor(init: {
    sandbox: Sandbox;
    hyp: HypCli;
    conversationId: string;
    mcp: HypMcpClient;
  }) {
    this.sandbox = init.sandbox;
    this.hyp = init.hyp;
    this.conversationId = init.conversationId;
    this.sessionId = `cursor:${init.conversationId}`;
    this.mcp = init.mcp;
  }

  static async create(options: {
    sandbox: Sandbox;
    hyp: HypCli;
    conversationId?: string;
    runSetup?: boolean;
  }): Promise<CursorReplayDriver> {
    if (options.runSetup !== false) {
      await options.hyp.setup("cursor", { noSkills: true, noCommands: true });
    }
    const conversationId = options.conversationId ?? `cur-${crypto.randomUUID()}`;
    const mcp = new HypMcpClient(
      options.sandbox,
      options.hyp.bin,
      ["mcp", options.hyp.socketPath, "--backend", "cursor"],
      `cursor-mcp-${conversationId.slice(0, 12)}`,
    );
    await mcp.initialize("cursor-replay");
    return new CursorReplayDriver({
      sandbox: options.sandbox,
      hyp: options.hyp,
      conversationId,
      mcp,
    });
  }

  async runHook(event: string, payload: Record<string, unknown>): Promise<any> {
    const res = await this.hyp.exec(["hook", "cursor", event, "--socket", this.hyp.socketPath], {
      input: JSON.stringify({ conversation_id: this.conversationId, ...payload }),
    });
    if (res.exitCode !== 0) {
      throw new Error(`hyp hook cursor ${event} failed (exit=${res.exitCode}): ${res.stderr}`);
    }
    return res.json ?? {};
  }

  async beforeSubmitPrompt(prompt = "check mesh"): Promise<any> {
    return this.runHook("before-submit-prompt", { prompt });
  }

  async beforeMcpExecution(
    toolName: string,
    callId: string,
    toolInput: Record<string, unknown> = {},
  ): Promise<any> {
    return this.runHook("pre-tool-use", {
      tool_name: toolName,
      call_id: callId,
      tool_input: toolInput,
    });
  }

  async afterMcpExecution(toolName: string, callId: string): Promise<any> {
    return this.runHook("post-tool-use", {
      tool_name: toolName,
      call_id: callId,
    });
  }

  async stop(options: { loopCount?: number } = {}): Promise<any> {
    return this.runHook("stop", {
      loop_count: options.loopCount ?? 0,
    });
  }

  /**
   * Executes a full Cursor MCP tool lifecycle:
   *   `beforeMCPExecution` -> JSON-RPC `tools/call` (`_meta.callId`) -> `afterMCPExecution`.
   */
  async callVerifiedTool(
    toolName: string,
    args: Record<string, unknown> = {},
    options: { runAfterHook?: boolean } = {},
  ): Promise<{ preHook: any; tool: McpToolOutcome; postHook: any | null; callId: string }> {
    const callId = `cur_call_${crypto.randomUUID()}`;
    const preHook = await this.beforeMcpExecution(toolName, callId, args);
    const rpc = await this.mcp.request("tools/call", {
      name: toolName,
      arguments: args,
      _meta: { callId },
    });
    if (!rpc.result) {
      throw new Error(`Cursor MCP tools/call '${toolName}' protocol error: ${JSON.stringify(rpc)}`);
    }
    const text = (rpc.result.content || []).map((c: any) => c?.text || "").join("");
    const tool: McpToolOutcome = {
      text,
      json: tryParseJson(text),
      isError: Boolean(rpc.result.isError),
      raw: rpc.result,
    };
    const postHook = options.runAfterHook === false ? null : await this.afterMcpExecution(toolName, callId);
    return { preHook, tool, postHook, callId };
  }

  /** Sends an unverified or spoofed MCP `tools/call` bypassing `beforeMCPExecution`. */
  async callSpoofedTool(
    toolName: string,
    args: Record<string, unknown> = {},
    meta?: Record<string, unknown>,
  ): Promise<McpToolOutcome> {
    const params: Record<string, unknown> = { name: toolName, arguments: args };
    if (meta) params._meta = meta;
    const rpc = await this.mcp.request("tools/call", params);
    if (!rpc.result) {
      throw new Error(`Cursor spoofed tools/call '${toolName}' protocol error: ${JSON.stringify(rpc)}`);
    }
    const text = (rpc.result.content || []).map((c: any) => c?.text || "").join("");
    return {
      text,
      json: tryParseJson(text),
      isError: Boolean(rpc.result.isError),
      raw: rpc.result,
    };
  }

  spawnWait(timeoutSec = 15): WaitHandle {
    return spawnHypWait(this.sandbox, this.hyp, this.sessionId, timeoutSec, "cursor-hyp-wait");
  }

  async close(): Promise<void> {
    await this.mcp.close();
  }
}

// ============================================================================
// 2. Antigravity Wire-Exact Compiled-Binary Lifecycle Replay Driver
// ============================================================================

export class AntigravityReplayDriver {
  readonly sandbox: Sandbox;
  readonly hyp: HypCli;
  readonly conversationId: string;
  readonly sessionId: string;
  readonly mcp: HypMcpClient;

  private constructor(init: {
    sandbox: Sandbox;
    hyp: HypCli;
    conversationId: string;
    mcp: HypMcpClient;
  }) {
    this.sandbox = init.sandbox;
    this.hyp = init.hyp;
    this.conversationId = init.conversationId;
    this.sessionId = `antigravity:${init.conversationId}`;
    this.mcp = init.mcp;
  }

  static async create(options: {
    sandbox: Sandbox;
    hyp: HypCli;
    conversationId?: string;
    runSetup?: boolean;
    statusline?: boolean;
  }): Promise<AntigravityReplayDriver> {
    if (options.runSetup !== false) {
      await options.hyp.setup("antigravity", {
        noSkills: true,
        noCommands: true,
        extraArgs: options.statusline ? ["--statusline"] : [],
      });
    }
    const conversationId = options.conversationId ?? `agy-${crypto.randomUUID()}`;
    const mcp = new HypMcpClient(
      options.sandbox,
      options.hyp.bin,
      ["mcp", options.hyp.socketPath, "--backend", "antigravity"],
      `agy-mcp-${conversationId.slice(0, 12)}`,
    );
    await mcp.initialize("antigravity-replay");
    return new AntigravityReplayDriver({
      sandbox: options.sandbox,
      hyp: options.hyp,
      conversationId,
      mcp,
    });
  }

  async runHook(event: string, payload: Record<string, unknown>): Promise<any> {
    const res = await this.hyp.exec(["hook", "antigravity", event, "--socket", this.hyp.socketPath], {
      input: JSON.stringify({ conversationId: this.conversationId, ...payload }),
    });
    if (res.exitCode !== 0) {
      throw new Error(`hyp hook antigravity ${event} failed (exit=${res.exitCode}): ${res.stderr}`);
    }
    return res.json ?? {};
  }

  async preInvocation(): Promise<any> {
    return this.runHook("pre-invocation", {});
  }

  async preToolUseDirect(
    toolName: string,
    args: Record<string, unknown>,
    callId = `tc_${crypto.randomUUID()}`,
  ): Promise<any> {
    return this.runHook("pre-tool-use", {
      toolCall: { id: callId, name: toolName, args },
    });
  }

  /**
   * Simulates Antigravity's lazy MCP wrapper `call_mcp_tool`:
   *   `{ ServerName: "hyphae_hyphae", ToolName: "hyp_send", Arguments: { ... } }`
   * returning `{ decision: "allow", overwrite: { Arguments: { ..., _meshCall: "ct_..." } } }`.
   */
  async preToolUseLazyWrapper(
    toolName: string,
    innerArgs: Record<string, unknown>,
    options: { serverName?: string; callId?: string } = {},
  ): Promise<any> {
    const callId = options.callId ?? `tc_lazy_${crypto.randomUUID()}`;
    return this.runHook("pre-tool-use", {
      toolCall: {
        id: callId,
        name: "call_mcp_tool",
        args: {
          ServerName: options.serverName ?? "hyphae_hyphae",
          ToolName: toolName,
          Arguments: innerArgs,
        },
      },
    });
  }

  async postToolUse(toolName: string, callId: string): Promise<any> {
    return this.runHook("post-tool-use", {
      toolCall: { id: callId, name: toolName },
    });
  }

  async stop(options: { continuationActive?: boolean; terminationReason?: string } = {}): Promise<any> {
    return this.runHook("stop", {
      continuationActive: options.continuationActive ?? false,
      terminationReason: options.terminationReason ?? "NO_TOOL_CALL",
    });
  }

  /**
   * Executes a full Antigravity tool call — either direct (`mode: "direct"`) or wrapped in
   * Antigravity's lazy `call_mcp_tool` (`mode: "lazy"`) — applying the hook's `overwrite`
   * `_meshCall` token directly to the real `hyp mcp --backend antigravity` `tools/call`!
   */
  async callVerifiedTool(
    toolName: string,
    args: Record<string, unknown>,
    options: { mode?: "direct" | "lazy"; serverName?: string } = {},
  ): Promise<{ preHook: any; tool: McpToolOutcome; postHook: any; meshCallToken: string }> {
    const mode = options.mode ?? "direct";
    const callId = `agy_${mode}_${crypto.randomUUID()}`;
    const preHook =
      mode === "lazy"
        ? await this.preToolUseLazyWrapper(toolName, args, {
            serverName: options.serverName ?? "hyphae_hyphae",
            callId,
          })
        : await this.preToolUseDirect(toolName, args, callId);

    const effectiveArgs: Record<string, unknown> =
      mode === "lazy"
        ? { ...(preHook?.overwrite?.Arguments ?? args) }
        : { ...args, ...(preHook?.overwrite ?? {}) };

    const meshCallToken = String(effectiveArgs._meshCall ?? "");
    const tool = await this.mcp.callTool(toolName, effectiveArgs);
    const postHook = await this.postToolUse(mode === "lazy" ? "call_mcp_tool" : toolName, callId);
    return { preHook, tool, postHook, meshCallToken };
  }

  spawnWait(timeoutSec = 15): WaitHandle {
    return spawnHypWait(this.sandbox, this.hyp, this.sessionId, timeoutSec, "agy-hyp-wait");
  }

  async close(): Promise<void> {
    await this.mcp.close();
  }
}

// ============================================================================
// 3. Opt-In Tier 3 Live Binary Resolvers (`HYPHAE_ITEST_LIVE_CURSOR=1` / `LIVE_AGY=1`)
// ============================================================================

export function resolveLiveIdeBinary(name: "cursor-agent" | "agy"): string | null {
  const envKey = name === "cursor-agent" ? "CURSOR_AGENT_BIN" : "AGY_BIN";
  const explicit = process.env[envKey]?.trim();
  if (explicit && fs.existsSync(explicit)) return path.resolve(explicit);

  try {
    const found = execFileSync("which", [name], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    if (found && fs.existsSync(found)) return found;
  } catch {
    // not in PATH
  }
  const home = process.env.HOME || "";
  const localCand = path.join(home, ".local", "bin", name);
  if (home && fs.existsSync(localCand)) return localCand;
  return null;
}
