// Claude Code session transcripts (<CLAUDE_CONFIG_DIR>/projects/<dir>/<session-id>.jsonl): one JSON
// record per line, most carrying the working directory as `cwd`.

/** Claude's project directory name for a working directory. */
export const claudeProjectDir = (cwd: string): string => cwd.replace(/[^a-zA-Z0-9]/g, "-");

const parseRecord = (line: string): unknown => {
  try {
    return JSON.parse(line);
  } catch {
    return undefined;
  }
};

const recordCwd = (record: unknown): string | undefined =>
  typeof record === "object" && record !== null && "cwd" in record && typeof record.cwd === "string"
    ? record.cwd
    : undefined;

/** The first `cwd` recorded in a transcript. */
export function transcriptCwd(transcript: string): string | undefined {
  for (const line of transcript.split("\n")) {
    const cwd = line.trim() === "" ? undefined : recordCwd(parseRecord(line));
    if (cwd !== undefined) return cwd;
  }
  return undefined;
}

/** Rewrites every record's `cwd` at or under `from` to the same place under `to`; other lines are kept verbatim. */
export function moveTranscriptCwd(transcript: string, from: string, to: string): { text: string; moved: number } {
  let moved = 0;
  const lines = transcript.split("\n").map((line) => {
    if (line.trim() === "") return line;
    const record = parseRecord(line);
    const cwd = recordCwd(record);
    if (cwd === undefined || typeof record !== "object" || record === null) return line;
    const next = cwd === from ? to : cwd.startsWith(`${from}/`) ? `${to}${cwd.slice(from.length)}` : undefined;
    if (next === undefined) return line;
    moved += 1;
    return JSON.stringify({ ...record, cwd: next });
  });
  return { text: lines.join("\n"), moved };
}

const recordUuid = (record: unknown): string | undefined =>
  typeof record === "object" && record !== null && "uuid" in record && typeof record.uuid === "string" ? record.uuid : undefined;

/**
 * The transcript up to and including the record with `uuid` (a completed turn's last assistant
 * message), or null if no record has it. Later records (the turn in progress) are dropped.
 */
export function cutTranscriptAfter(transcript: string, uuid: string): string | null {
  const lines = transcript.split("\n");
  const index = lines.findIndex((line) => line.trim() !== "" && recordUuid(parseRecord(line)) === uuid);
  return index === -1 ? null : `${lines.slice(0, index + 1).join("\n")}\n`;
}
