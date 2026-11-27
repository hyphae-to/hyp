export function sanitizeControlValue(raw: unknown): string;
export function sanitizeUiText(raw: unknown, maxLen?: number): string;
export function stripMetadataOnly(value: unknown, depth?: number): unknown;
export function resolveUiStateCandidates(
  homeDir: string,
  envStateDir?: string | null,
  nodeJsonText?: string | null,
): { dirs: string[]; files: string[] };
export function parseSnapshotMetadata(rawText: unknown): Record<string, unknown> | null;
