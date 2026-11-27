import fs from "node:fs";
import net from "node:net";

export async function waitForCondition(
  predicate: () => Promise<boolean> | boolean,
  timeoutMs = 20_000,
  label = "condition",
  intervalMs = 200,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`Timed out after ${timeoutMs}ms waiting for ${label}`);
}

export function pickFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = addr && typeof addr === "object" ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

export function writeNodeJson(path: string, config: Record<string, unknown>): void {
  fs.writeFileSync(path, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
}

export function tryParseJson(raw: string, allowLeadingText = false): unknown {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    const idx = allowLeadingText ? trimmed.indexOf("{") : -1;
    if (idx <= 0) return null;
    try {
      return JSON.parse(trimmed.slice(idx));
    } catch {
      return null;
    }
  }
}

export function parseJsonLines<T extends object>(stdout: string): T[] {
  const events: T[] = [];
  for (const raw of stdout.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line.startsWith("{")) continue;
    const parsed = tryParseJson(line);
    if (parsed !== null) events.push(parsed as T);
  }
  return events;
}

interface InspectSession {
  sessionId: string;
  handle?: string;
  enrolled?: boolean;
  focusMode?: boolean;
  transportKind?: string;
  hasLiveTransport?: boolean;
  counts?: { queued?: number; unnotified?: number };
  unreadBreakdown?: { messages?: number };
  [key: string]: unknown;
}

/** Reads both current inspect replies and the older item and single-session shapes. */
export function extractSessionsFromInspect(inspectJson: unknown): InspectSession[] {
  const envelope = inspectJson as { data?: unknown } | null;
  const data = (envelope?.data ?? inspectJson ?? {}) as {
    sessions?: InspectSession[];
    items?: InspectSession[];
    session?: InspectSession;
  };
  if (Array.isArray(data.sessions)) return data.sessions;
  if (Array.isArray(data.items)) return data.items;
  if (data.session) return [data.session];
  return [];
}
