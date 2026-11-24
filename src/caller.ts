import { randomBytes } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Backend } from "./delivery.ts";
import { normalizeMeshToolName, object, sessionIdPattern, type HarnessKind } from "./protocol.ts";

export interface RegisteredCall {
  readonly sessionId: string;
  readonly backend: Backend;
  readonly tool: string;
  readonly callId?: string;
  readonly token: string;
  readonly expiresAt: number;
}

export type CallerResolution =
  | { readonly ok: true; readonly sessionId: string; readonly backend: Backend; readonly verifiedBy: "callId" | "token" }
  | { readonly ok: false; readonly code: "caller_unverifiable" | "caller_not_found" | "caller_ambiguous"; readonly message: string };

export interface RegisterCallInput {
  readonly harness: HarnessKind;
  readonly sessionId: string;
  readonly backend: Backend;
  readonly tool: string;
  readonly callId?: string;
  readonly ttlMs?: number;
}

const DEFAULT_TTL_MS = 60_000;
const RESOLVE_WAIT_MS = 1_500;
const MAX_PENDING_CALLS = 512;

/**
 * Authoritative per-call caller verification modeled on t3-mesh's `resolveCaller`:
 * PreToolUse hooks register the host-verified `(sessionId, tool, callId)` immediately before
 * the tool executes and receive a single-use `callToken` (for harnesses like Antigravity whose
 * PreToolUse hook can inject arguments via `overwrite`). Every MCP `tools/call` must present
 * either the matching in-flight `callId` (from `_meta`) or `callToken`, verified against the
 * exact tool name and consumed on first use.
 */
export class CallRegistry {
  readonly #byToken = new Map<string, RegisteredCall>();
  readonly #byCallId = new Map<string, RegisteredCall[]>();
  readonly #waiters = new Set<() => void>();

  register(input: RegisterCallInput, now = Date.now()): RegisteredCall {
    this.prune(now);
    if (this.#byToken.size >= MAX_PENDING_CALLS) {
      throw new Error("Too many in-flight tool calls registered");
    }
    const normalizedTool = normalizeMeshToolName(input.tool);
    if (!normalizedTool) throw new Error(`Not a mesh tool: ${input.tool}`);
    if (!sessionIdPattern.test(input.sessionId)) throw new Error(`Invalid session ID: ${input.sessionId}`);
    const token = randomBytes(24).toString("base64url");
    const entry: RegisteredCall = {
      sessionId: input.sessionId,
      backend: input.backend,
      tool: normalizedTool,
      ...(input.callId ? { callId: input.callId } : {}),
      token,
      expiresAt: now + (input.ttlMs ?? DEFAULT_TTL_MS),
    };
    this.#byToken.set(token, entry);
    if (entry.callId) {
      const list = this.#byCallId.get(entry.callId) ?? [];
      list.push(entry);
      this.#byCallId.set(entry.callId, list);
    }
    this.#notifyWaiters();
    return entry;
  }

  /** Called by PostToolUse to clean up any unconsumed entry for a completed call. */
  release(callId?: string, token?: string): void {
    if (token) {
      const entry = this.#byToken.get(token);
      if (entry) this.#remove(entry);
    }
    if (callId) {
      const list = this.#byCallId.get(callId);
      if (list) {
        for (const entry of [...list]) this.#remove(entry);
      }
    }
  }

  prune(now = Date.now()): void {
    for (const entry of this.#byToken.values()) {
      if (entry.expiresAt <= now) this.#remove(entry);
    }
  }

  #remove(entry: RegisteredCall): void {
    this.#byToken.delete(entry.token);
    if (entry.callId) {
      const list = this.#byCallId.get(entry.callId);
      if (list) {
        const next = list.filter((item) => item.token !== entry.token);
        if (next.length === 0) this.#byCallId.delete(entry.callId);
        else this.#byCallId.set(entry.callId, next);
      }
    }
  }

  #notifyWaiters(): void {
    for (const wake of this.#waiters) wake();
  }

  #tryResolve(tool: string, callId: string | undefined, callToken: string | undefined, now: number): CallerResolution | null {
    this.prune(now);
    const normalizedTool = normalizeMeshToolName(tool);
    if (!normalizedTool) {
      return { ok: false, code: "caller_unverifiable", message: `Unknown mesh tool ${tool}` };
    }
    if (callToken) {
      const entry = this.#byToken.get(callToken);
      if (entry && entry.tool === normalizedTool) {
        this.#remove(entry);
        return { ok: true, sessionId: entry.sessionId, backend: entry.backend, verifiedBy: "token" };
      }
      if (!callId) return null;
    }
    if (callId) {
      const matches = (this.#byCallId.get(callId) ?? []).filter((entry) => entry.tool === normalizedTool);
      if (matches.length === 1) {
        const [entry] = matches;
        this.#remove(entry);
        return { ok: true, sessionId: entry.sessionId, backend: entry.backend, verifiedBy: "callId" };
      }
      if (matches.length > 1) {
        const sessions = new Set(matches.map((item) => item.sessionId));
        if (sessions.size > 1) {
          return {
            ok: false,
            code: "caller_ambiguous",
            message: `Tool call ${callId} matched ${sessions.size} distinct sessions`,
          };
        }
        const entry = matches[matches.length - 1];
        for (const item of matches) this.#remove(item);
        return { ok: true, sessionId: entry.sessionId, backend: entry.backend, verifiedBy: "callId" };
      }
      return null;
    }
    return {
      ok: false,
      code: "caller_unverifiable",
      message: "No verified tool-call ID or hook token present. Run 'hph setup <antigravity|claude|codex>' to install hooks.",
    };
  }

  async resolve(
    tool: string,
    callId: string | undefined,
    callToken: string | undefined,
    waitMs = RESOLVE_WAIT_MS,
  ): Promise<CallerResolution> {
    if (!callId && !callToken) {
      return {
        ok: false,
        code: "caller_unverifiable",
        message: "No verified tool-call ID or hook token present. Run 'hph setup <antigravity|claude|codex>' to install hooks.",
      };
    }
    const immediate = this.#tryResolve(tool, callId, callToken, Date.now());
    if (immediate) return immediate;
    if (waitMs <= 0) {
      return {
        ok: false,
        code: "caller_not_found",
        message: `No verified PreToolUse hook registration found for ${tool}. Ensure hooks are installed ('hph setup <harness>').`,
      };
    }

    const deadline = Date.now() + waitMs;
    while (true) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          this.#waiters.delete(wake);
          resolve();
        }, Math.min(remaining, 150));
        timer.unref();
        const wake = () => {
          clearTimeout(timer);
          this.#waiters.delete(wake);
          resolve();
        };
        this.#waiters.add(wake);
      });
      const result = this.#tryResolve(tool, callId, callToken, Date.now());
      if (result) return result;
    }

    return {
      ok: false,
      code: "caller_not_found",
      message: `No verified PreToolUse hook registration found for ${tool}. Ensure hooks are installed ('hph setup <harness>').`,
    };
  }
}

const ROLLOUT_RECENT_MS = 10 * 60 * 1000;
const ROLLOUT_MAX_FILES = 32;
const ROLLOUT_UUID_RE = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$/i;

function recentRolloutFiles(codexHome: string, now: number): string[] {
  const sessionsDir = join(codexHome, "sessions");
  if (!existsSync(sessionsDir)) return [];
  const files: Array<{ path: string; mtimeMs: number }> = [];
  const stack = [sessionsDir];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile() && entry.name.startsWith("rollout-") && entry.name.endsWith(".jsonl")) {
        try {
          const st = statSync(full);
          if (st.mtimeMs >= now - ROLLOUT_RECENT_MS) files.push({ path: full, mtimeMs: st.mtimeMs });
        } catch {}
      }
    }
  }
  files.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return files.slice(0, ROLLOUT_MAX_FILES).map((f) => f.path);
}

function inspectCodexRollout(filePath: string, callId: string, normalizedTool: string): string | null {
  let content: string;
  try { content = readFileSync(filePath, "utf8"); } catch { return null; }
  if (!content.includes(callId)) return null;

  let threadId: string | null = null;
  let sawInFlightCall = false;
  let sawCompletedOutput = false;

  for (const line of content.split("\n")) {
    if (!line.trim()) continue;
    let record: unknown;
    try { record = JSON.parse(line); } catch { continue; }
    if (!object(record)) continue;

    if (record.type === "session_meta" && object(record.payload) && typeof record.payload.id === "string") {
      threadId = record.payload.id;
      continue;
    }
    if (record.type === "response_item" && object(record.payload)) {
      const p = record.payload;
      if (p.type === "function_call" && p.call_id === callId && typeof p.name === "string") {
        if (normalizeMeshToolName(p.name) === normalizedTool) sawInFlightCall = true;
      } else if (p.type === "function_call_output" && p.call_id === callId) {
        sawCompletedOutput = true;
      }
    }
  }

  if (!sawInFlightCall || sawCompletedOutput) return null;
  if (!threadId) {
    const match = ROLLOUT_UUID_RE.exec(filePath);
    if (match) threadId = match[1];
  }
  return threadId;
}

/**
 * Authoritative Codex caller verification directly from `$CODEX_HOME/sessions/.../rollout-*.jsonl`
 * (mirroring t3-mesh's `resolveCaller` against T3 projections):
 * Codex flushes the `function_call` record with `call_id` before dispatching the MCP tool call,
 * and sends the same `callId` in MCP `params._meta.callId`. Works for both Codex CLI and Codex
 * Desktop across shared MCP servers with zero manual `--thread` flags or hook trust prompts.
 */
export async function resolveCodexCallerFromRollouts(
  callId: string,
  tool: string,
  options: { codexHome?: string; remote?: string; resume?: boolean; timeoutMs?: number } = {},
): Promise<CallerResolution> {
  const normalizedTool = normalizeMeshToolName(tool);
  if (!normalizedTool) {
    return { ok: false, code: "caller_unverifiable", message: `Unknown mesh tool ${tool}` };
  }
  const codexHome = options.codexHome ?? join(homedir(), ".codex");
  const deadline = Date.now() + (options.timeoutMs ?? 1_500);
  let delay = 40;

  while (true) {
    const files = recentRolloutFiles(codexHome, Date.now());
    const matchedThreads = new Set<string>();
    for (const file of files) {
      const threadId = inspectCodexRollout(file, callId, normalizedTool);
      if (threadId) matchedThreads.add(threadId);
    }
    if (matchedThreads.size === 1) {
      const [threadId] = matchedThreads;
      return {
        ok: true,
        sessionId: `codex:${threadId}`,
        backend: {
          kind: "codex",
          threadId,
          codexHome,
          bin: "codex",
          resume: options.resume === true,
          ...(options.remote ? { remote: options.remote } : {}),
          queue: true,
        },
        verifiedBy: "callId",
      };
    }
    if (matchedThreads.size > 1) {
      return {
        ok: false,
        code: "caller_ambiguous",
        message: `Codex call ${callId} matched ${matchedThreads.size} active rollouts`,
      };
    }
    if (Date.now() + delay > deadline) break;
    await new Promise<void>((r) => setTimeout(r, delay));
    delay = Math.min(delay * 2, 250);
  }

  return {
    ok: false,
    code: "caller_not_found",
    message: `No in-flight Codex rollout call found for ${tool} (${callId}) under ${codexHome}`,
  };
}
