import { createConnection } from "node:net";
import { createInterface } from "node:readline";
import { object } from "./protocol.ts";

export interface WaitOptions {
  readonly socketPath: string;
  readonly mode: "once" | "stream";
  readonly sessionId?: string;
  readonly handle?: string;
  readonly timeoutSeconds?: number;
}

/**
 * Resolves the session ID automatically when omitted:
 * 1. Explicit `--session`
 * 2. Antigravity's host-injected `ANTIGRAVITY_SOURCE_METADATA` (`antigravity:<conversationId>`)
 * 3. `CLAUDE_SESSION_ID` / `CODEX_THREAD_ID` if present in the environment
 */
export function inferSessionIdFromEnv(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (typeof env.ANTIGRAVITY_SOURCE_METADATA === "string" && env.ANTIGRAVITY_SOURCE_METADATA.length > 0) {
    try {
      const parsed: unknown = JSON.parse(env.ANTIGRAVITY_SOURCE_METADATA);
      if (object(parsed) && object(parsed.tool) && typeof parsed.tool.conversationId === "string" && parsed.tool.conversationId.length > 0) {
        return `antigravity:${parsed.tool.conversationId}`;
      }
    } catch {}
  }
  if (typeof env.CLAUDE_SESSION_ID === "string" && env.CLAUDE_SESSION_ID.length > 0) {
    return `claude:${env.CLAUDE_SESSION_ID}`;
  }
  if (typeof env.CODEX_THREAD_ID === "string" && env.CODEX_THREAD_ID.length > 0) {
    return `codex:${env.CODEX_THREAD_ID}`;
  }
  return undefined;
}

/**
 * Blocking zero-CPU, zero-polling event waiter/watcher on `connector.sock`:
 * - `mode: "once"` (`hyp wait`): blocks until ≥1 item arrives, prints formatted payload, exits 0.
 *   Ideal for Antigravity `run_command` (WaitMsBeforeAsync: 500) and Claude `Bash(run_in_background=true)`.
 * - `mode: "stream"` (`hyp watch`): stays open and writes one flushed line per event/message.
 *   Ideal for Claude Code's `Monitor` tool.
 */
export function runWait(options: WaitOptions): Promise<number> {
  const sessionId = options.sessionId ?? inferSessionIdFromEnv();
  if (!sessionId && !options.handle) {
    return Promise.reject(new Error("Could not infer session ID. Pass --session <id> or --handle <handle>."));
  }

  return new Promise((resolve, reject) => {
    const socket = createConnection(options.socketPath);
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const finish = (code: number, error?: Error) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(code);
    };

    if (options.timeoutSeconds !== undefined && options.timeoutSeconds > 0) {
      timer = setTimeout(() => finish(0), options.timeoutSeconds * 1000);
      timer.unref();
    }

    const onSignal = () => finish(0);
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);

    socket.on("error", (error) => {
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
      finish(1, new Error(`Could not connect to hyp daemon at ${options.socketPath}: ${error.message}`));
    });

    socket.on("close", () => {
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
      finish(0);
    });

    socket.on("connect", () => {
      socket.write(JSON.stringify({
        type: "wait.subscribe",
        mode: options.mode,
        ...(sessionId ? { sessionId } : {}),
        ...(options.handle ? { handle: options.handle } : {}),
      }) + "\n");
    });

    const rl = createInterface({ input: socket });
    rl.on("error", () => {});
    rl.on("line", (line) => {
      let packet: unknown;
      try { packet = JSON.parse(line); } catch { return; }
      if (!object(packet)) return;
      if (packet.type === "wait.error") {
        finish(1, new Error(typeof packet.message === "string" ? packet.message : "Wait failed"));
        return;
      }
      if (packet.type === "wait.items" && Array.isArray(packet.items)) {
        const items = packet.items.filter(object);
        if (options.mode === "once") {
          const formatted = items
            .map((item) => (typeof item.text === "string" ? item.text : ""))
            .filter((text) => text.length > 0)
            .join("\n\n---\n\n");
          process.stdout.write(formatted + "\n", () => finish(0));
        } else {
          for (const item of items) {
            process.stdout.write(JSON.stringify({
              router: item.router,
              received: item.received,
              text: item.text,
            }) + "\n");
          }
        }
      }
    });
  });
}
