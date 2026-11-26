/**
 * Deterministic turn-script engine, dynamic MCP tool-name resolver, latches (`createGate`,
 * `pauseUntil`, `pauseMidStream`), wall-clock delays, and fault injection helpers.
 */

import { extractCanonicalHyphaeToolName } from "./auditors.ts";
import type {
  AdvertisedTool,
  CanonicalLlmRequest,
  CanonicalMessage,
  CanonicalToolResult,
  Gate,
  LlmProtocol,
  ScriptAction,
  ScriptRule,
  ToolCallSpec,
} from "./types.ts";

/**
 * Creates a deterministic barrier latch (`gate.release()` unblocks all waiting turns).
 * Also exposes `waitForWaiters(n)` so tests can deterministically synchronize on the exact
 * moment the harness enters the paused LLM call without flaky `sleep()` calls!
 */
export function createGate(label = "gate"): Gate {
  let released = false;
  let waiters = 0;
  let resolvePromise!: () => void;
  const promise = new Promise<void>((resolve) => {
    resolvePromise = resolve;
  });
  const waiterListeners: Array<() => void> = [];

  return {
    get label() {
      return label;
    },
    get promise() {
      return promise;
    },
    get isReleased() {
      return released;
    },
    get waitCount() {
      return waiters;
    },
    wait(): Promise<void> {
      waiters += 1;
      for (const fn of waiterListeners.splice(0)) fn();
      return promise;
    },
    waitForWaiters(n = 1, timeoutMs = 15_000): Promise<void> {
      if (waiters >= n) return Promise.resolve();
      return new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(
            new Error(
              `Timed out waiting for ${n} waiter(s) on gate '${label}' (current=${waiters}) after ${timeoutMs}ms`,
            ),
          );
        }, timeoutMs);
        const check = () => {
          if (waiters >= n) {
            clearTimeout(timer);
            resolve();
          } else {
            waiterListeners.push(check);
          }
        };
        waiterListeners.push(check);
      });
    },
    release(): void {
      if (released) return;
      released = true;
      resolvePromise();
    },
  };
}

/** Resolves a logical tool name (e.g. `"hyp_mesh"`, `"Read"`, `"Bash"`) against advertised `tools[]`. */
export function resolveAdvertisedToolName(
  advertisedTools: AdvertisedTool[],
  logicalName: string,
): string {
  // 1. Exact wire name match.
  const exact = advertisedTools.find((t) => t.name === logicalName);
  if (exact) return exact.name;

  // 2. Canonical Hyphae tool match (`mcp__hyphae__hyp_mesh`, `hyphae__hyp_mesh`, `hyp_mesh`, etc.).
  const targetCanonical = extractCanonicalHyphaeToolName(logicalName) ?? logicalName;
  const byCanonical = advertisedTools.find((t) => t.canonicalHyphaeName === targetCanonical);
  if (byCanonical) return byCanonical.name;

  // 3. Suffix match (`__<logicalName>`, `:<logicalName>`, `/<logicalName>`, `_<logicalName>`).
  const suffix = advertisedTools.find(
    (t) =>
      t.name.endsWith(`__${logicalName}`) ||
      t.name.endsWith(`:${logicalName}`) ||
      t.name.endsWith(`/${logicalName}`) ||
      t.name.endsWith(`.${logicalName}`),
  );
  if (suffix) return suffix.name;

  // 4. Case-insensitive fallback (for built-in tools like `read` vs `Read`).
  const lower = logicalName.toLowerCase();
  const ci = advertisedTools.find((t) => t.name.toLowerCase() === lower);
  if (ci) return ci.name;

  // Fallback to logical name (caller may be testing a request without tools[]).
  return logicalName;
}

export function emitText(text: string, options: { stopReason?: string } = {}): ScriptAction {
  return { kind: "text", text, stopReason: options.stopReason };
}

export function callTool(
  req: CanonicalLlmRequest,
  logicalToolName: string,
  args: Record<string, unknown> = {},
  options: { callId?: string; preambleText?: string } = {},
): ScriptAction {
  const wireName = req.resolveTool(logicalToolName);
  const matchedTool = req.advertisedTools.find((t) => t.name === wireName);
  const hasDispatchAction = req.advertisedTools.some((t) => t.name === "dispatch_action");
  if (matchedTool?.deferred && matchedTool.deferredVia === "dispatch_action" && hasDispatchAction) {
    return {
      kind: "tool_calls",
      preambleText: options.preambleText,
      calls: [
        {
          logicalName: "dispatch_action",
          wireName: "dispatch_action",
          args: { id: wireName, args },
          callId: options.callId,
        },
      ],
    };
  }
  return {
    kind: "tool_calls",
    preambleText: options.preambleText,
    calls: [
      {
        logicalName: logicalToolName,
        wireName,
        args,
        callId: options.callId,
      },
    ],
  };
}

export function callTools(
  req: CanonicalLlmRequest,
  specs: Array<{ name: string; args?: Record<string, unknown>; callId?: string }>,
  options: { preambleText?: string } = {},
): ScriptAction {
  return {
    kind: "tool_calls",
    preambleText: options.preambleText,
    calls: specs.map((s) => ({
      logicalName: s.name,
      wireName: req.resolveTool(s.name),
      args: s.args ?? {},
      callId: s.callId,
    })),
  };
}

export function pauseUntil(gate: Gate, next: ScriptAction): ScriptAction {
  return { kind: "pause_until", gate, next };
}

export function pauseMidStream(
  gate: Gate,
  initialText: string,
  rest?: string | ScriptAction,
): ScriptAction {
  if (typeof rest === "string") {
    return { kind: "pause_mid_stream", gate, initialText, restText: rest };
  }
  return { kind: "pause_mid_stream", gate, initialText, restAction: rest };
}

export function delayBeforeHeadersMs(ms: number, next: ScriptAction): ScriptAction {
  return { kind: "delay_before_headers", ms, next };
}

export function chunkDelayMs(ms: number, next: ScriptAction): ScriptAction {
  return { kind: "chunk_delay", ms, next };
}

export function failOnceWith(
  status: number,
  options: { retryAfter?: number | string; body?: unknown; key?: string; then?: ScriptAction } = {},
): ScriptAction {
  return {
    kind: "fail_once",
    key: options.key ?? `http-${status}`,
    status,
    retryAfter: options.retryAfter,
    body: options.body,
    fallback: options.then ?? emitText("RECOVERED_AFTER_FAULT"),
  };
}

export function abortMidStream(initialText = "PARTIAL_"): ScriptAction {
  return { kind: "abort_mid_stream", initialText };
}

export function createCanonicalRequest(init: {
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
}): CanonicalLlmRequest {
  return {
    ...init,
    lastToolResult(logicalToolName: string): CanonicalToolResult | undefined {
      const targetCanonical = extractCanonicalHyphaeToolName(logicalToolName) ?? logicalToolName;
      for (let i = init.lastToolResults.length - 1; i >= 0; i -= 1) {
        const tr = init.lastToolResults[i];
        if (
          tr.rawToolName === logicalToolName ||
          tr.canonicalToolName === targetCanonical ||
          tr.rawToolName?.endsWith(`__${logicalToolName}`) ||
          tr.rawToolName?.endsWith(`:${logicalToolName}`)
        ) {
          return tr;
        }
      }
      return undefined;
    },
    anyMessageContains(needle: string | RegExp): boolean {
      const check = (s: string) => (typeof needle === "string" ? s.includes(needle) : needle.test(s));
      if (check(init.systemPrompt)) return true;
      for (const m of init.messages) {
        if (m.text && check(m.text)) return true;
        for (const tr of m.toolResults || []) {
          if (check(tr.text)) return true;
        }
      }
      return false;
    },
    hasContextMatching(pattern: RegExp): boolean {
      if (pattern.test(init.systemPrompt)) return true;
      for (const m of init.messages) {
        if (m.role === "assistant") continue;
        if (m.text && pattern.test(m.text)) return true;
        for (const tr of m.toolResults || []) {
          if (pattern.test(tr.text)) return true;
        }
      }
      return false;
    },
    resolveTool(logicalToolName: string): string {
      return resolveAdvertisedToolName(init.advertisedTools, logicalToolName);
    },
    isToolDeferred(logicalToolName: string): boolean {
      const wire = resolveAdvertisedToolName(init.advertisedTools, logicalToolName);
      const found = init.advertisedTools.find((t) => t.name === wire);
      return Boolean(found?.deferred);
    },
  };
}

export class ScriptEngine {
  private readonly scripts = new Map<string, ScriptRule[]>();
  private readonly firedOnce = new Map<string, Set<string>>();
  private readonly firedFaultKeys = new Set<string>();
  private defaultAction: (req: CanonicalLlmRequest) => ScriptAction = () => emitText("SHIM_OK");

  setScript(role: string, rules: ScriptRule[]): void {
    this.scripts.set(role, rules);
    this.firedOnce.delete(role);
  }

  setDefaultAction(fn: (req: CanonicalLlmRequest) => ScriptAction): void {
    this.defaultAction = fn;
  }

  consumeFaultOnce(role: string, key: string): boolean {
    const composite = `${role}:${key}`;
    if (this.firedFaultKeys.has(composite)) {
      return false;
    }
    this.firedFaultKeys.add(composite);
    return true;
  }

  async evaluate(
    req: CanonicalLlmRequest,
  ): Promise<{ ruleName: string; action: ScriptAction; assertionError?: string }> {
    const rules = this.scripts.get(req.role) ?? this.scripts.get("*") ?? [];
    let firedSet = this.firedOnce.get(req.role);
    if (!firedSet) {
      firedSet = new Set<string>();
      this.firedOnce.set(req.role, firedSet);
    }

    for (const rule of rules) {
      if (rule.once && firedSet.has(rule.name)) continue;
      if (!rule.when(req)) continue;

      if (rule.once) firedSet.add(rule.name);

      let assertionError: string | undefined;
      if (rule.assert) {
        try {
          await rule.assert(req);
        } catch (err) {
          assertionError = err instanceof Error ? err.message : String(err);
        }
      }
      const action = await rule.do(req);
      return { ruleName: rule.name, action, assertionError };
    }

    return {
      ruleName: "__default__",
      action: this.defaultAction(req),
    };
  }
}
