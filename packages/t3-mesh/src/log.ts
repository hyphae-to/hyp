// JSON-lines logging to stderr. Never log message bodies or secrets.

export type LogLevel = "info" | "warn" | "error";

export function log(level: LogLevel, event: string, fields: Readonly<Record<string, unknown>> = {}): void {
  process.stderr.write(JSON.stringify({ at: new Date().toISOString(), level, event, ...fields }) + "\n");
}

export const errorMessage = (error: unknown): string => (error instanceof Error ? error.message : String(error));
