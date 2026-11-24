import { execFile } from "node:child_process";
import { delivered, hold, object, reject, type Mode, type Outcome } from "./protocol.ts";
import { deliverToT3Thread } from "./t3.ts";

export interface Delivery {
  readonly modes: readonly Mode[];
  deliver(text: string, mode: Mode, submit: Submit): Promise<Outcome>;
}

// Only call submit after deciding an external effect might happen.
export type AttemptOutcome = Outcome & { interrupted?: true };
export type Submit = (attempt: () => Promise<AttemptOutcome>) => Promise<Outcome>;
export type Channel = (text: string) => Promise<Outcome>;
export type Backend =
  | { kind: "antigravity" }
  | { kind: "cursor" }
  | { kind: "opencode" }
  | { kind: "gemini" }
  | { kind: "openclaw" }
  | { kind: "codex"; threadId?: string; codexHome?: string; bin?: string; resume?: boolean; remote?: string; queue?: boolean }
  | { kind: "herdr"; terminalId: string; createdMs: number; pid: number; app: string; bin: string }
  | { kind: "t3"; threadId: string; serverUrl: string; baseDir?: string; tokenSecret?: string; configDir?: string }
  | { kind: "claude"; channel?: boolean };

export type Command = (bin: string, args: string[], timeout: number, env?: NodeJS.ProcessEnv) =>
  Promise<{ code: number | null; stdout: string; stderr: string; missing?: boolean }>;

export const command: Command = (bin, args, timeout, env) => new Promise((resolve) => {
  execFile(bin, args, { timeout, maxBuffer: 256_000, ...(env ? { env } : {}) }, (error, stdout, stderr) => {
    resolve({
      code: error === null ? 0 : typeof error.code === "number" ? error.code : null,
      missing: error?.code === "ENOENT",
      stdout,
      stderr,
    });
  });
});

const parse = (text: string): unknown => {
  try { return JSON.parse(text); } catch { return null; }
};

/**
 * Backends without an external push CLI/RPC (`herdr` or `codex queue`) deliver
 * through the connector's durable SQLite mailbox (`Connector.#deliverPrepared`),
 * which immediately wakes live `hyp wait` / `hyp watch` waiters, `--claude-channel`
 * push streams, and harness hooks (`PreInvocation` / `PostToolUse` / `Stop`).
 */
export function usesDurableMailbox(backend: Backend): boolean {
  if (backend.kind === "herdr" || backend.kind === "t3") return false;
  if (backend.kind === "codex" && backend.queue === true && Boolean(backend.threadId)) return false;
  return true;
}

export function createDelivery(backend: Backend, channel: () => Channel | undefined, run = command): Delivery {
  if (backend.kind === "codex" && backend.queue !== false && backend.threadId) {
    const threadId = backend.threadId;
    const bin = backend.bin ?? "codex";
    return {
      modes: ["queue"],
      deliver: (text, _mode, submit) => submit(async () => {
        const args = ["queue", "--thread", threadId, "--message", text];
        if (backend.resume) args.push("--resume");
        if (backend.remote) args.push("--remote", backend.remote);
        const env = backend.codexHome ? { ...process.env, CODEX_HOME: backend.codexHome } : undefined;
        const result = await run(bin, args, 25_000, env);
        if (result.code === 0) return delivered;
        if (result.missing) return hold("codex_binary_missing");
        if (/not found|offline|connect|socket|refused|daemon/i.test(result.stderr)) {
          return hold("codex_queue_unavailable");
        }
        return reject("codex_queue_outcome_unknown");
      }),
    };
  }
  if (backend.kind === "t3") {
    return {
      modes: ["queue", "interrupt"],
      deliver: (text, mode, submit) =>
        submit(() =>
          deliverToT3Thread({
            serverUrl: backend.serverUrl,
            threadId: backend.threadId,
            text,
            mode,
            ...(backend.tokenSecret ? { tokenSecret: backend.tokenSecret } : {}),
            ...(backend.configDir ? { configDir: backend.configDir } : {}),
          }),
        ),
    };
  }
  if (backend.kind === "claude") {
    return {
      modes: ["queue"],
      deliver: (text, _mode, submit) => {
        const active = channel();
        return active === undefined ? Promise.resolve(hold("claude_channel_offline")) : submit(() => active(text));
      },
    };
  }
  if (backend.kind !== "herdr") {
    // Durable-mailbox backends (antigravity, cursor, opencode, gemini, openclaw, hook-only codex)
    // must be persisted by Connector.#deliverPrepared; never silently no-op `delivered`.
    return {
      modes: ["queue"],
      deliver: () => Promise.resolve(reject("durable_mailbox_required")),
    };
  }
  const get = async () => {
    const result = await run(backend.bin, ["get", "--json", backend.terminalId], 5_000);
    if (result.code !== 0) return undefined;
    const term = parse(result.stdout);
    if (!object(term) || term.address !== backend.terminalId || term.created_ms !== backend.createdMs ||
        term.pid !== backend.pid || term.state !== "live" || !object(term.status) || term.status.app !== backend.app) return;
    return term.status.state;
  };
  return {
    modes: ["queue", "interrupt"],
    async deliver(text, mode, submit) {
      const initial = await get();
      if (initial !== "idle" && initial !== "done" && (initial !== "working" || mode === "queue")) {
        return hold(initial === undefined ? "herdr_target_unavailable" : `herdr_${String(initial)}`);
      }
      return submit(async () => {
        if (initial === "working") {
          const stopped = await run(backend.bin, ["interrupt", "--json", "--timeout", "8", backend.terminalId], 12_000);
          const result = parse(stopped.stdout);
          if (stopped.code !== 0 || !object(result) || result.outcome !== "stopped") {
            return reject("herdr_interrupt_outcome_unknown");
          }
        }
        const deferred = (reason: string): AttemptOutcome => ({
          ...hold(reason),
          ...(initial === "working" ? { interrupted: true } : {}),
        });
        const state = await get();
        if (state !== "idle" && state !== "done") return deferred("herdr_agent_not_ready");
        // Core 0.1 accepts idle and working guards. It reports done as a distinct state.
        const guard = state === "idle" ? ["--if", "idle"] : [];
        const sent = await run(backend.bin, ["send", "--json", ...guard, backend.terminalId, text], 75_000);
        if (sent.code === 0) return delivered;
        if (sent.code === 9 || sent.code === 10) return deferred("herdr_send_guard_refused");
        return reject("herdr_send_outcome_unknown");
      });
    },
  };
}
