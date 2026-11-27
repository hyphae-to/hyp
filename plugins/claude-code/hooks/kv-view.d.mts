export interface KvKey {
  key: string;
  version: number;
  updatedBy: string;
  updatedAt: number;
  expiresAt: number | null;
  sizeBytes: number;
}

export interface KvNamespace {
  name: string;
  originNode: string;
  epoch: number | null;
  memberCount: number;
  entryCount: number;
  watchCount: number;
  entries: KvKey[];
}

export interface KvInspection {
  namespaces: KvNamespace[];
  namespacesTruncated: boolean;
}

export interface KvKeyPage {
  entries: KvKey[];
  nextAfter: string | null;
}

export interface KvPreview {
  text: string;
  version: number;
  truncated: boolean;
}

export interface KvCoordinate {
  originNode?: string;
  namespace?: string;
  key?: string;
  after?: string | null;
}

export type KvAction = "inspect" | "keys" | "preview";
export function parseKvInspection(value: unknown): KvInspection | null;
export function parseKvKeyPage(value: unknown): KvKeyPage | null;
export function parseKvPreview(value: unknown, sanitizeLine: (line: string, maxLen: number) => string): KvPreview | null;
export function buildKvCommandArgs(action: KvAction, coordinate?: KvCoordinate): string[] | null;
export function readKvCommandData(stdout: unknown, code: number | undefined): unknown;

type KvRun = (args: string[]) => Promise<unknown>;
export class KvBrowser {
  inspection: KvInspection | null;
  namespace: KvNamespace | null;
  page: KvKeyPage | null;
  preview: (KvPreview & { key: string }) | null;
  cursorHistory: Array<string | null>;
  busy: boolean;
  error: string | null;
  reset(): void;
  back(): void;
  reconcileSnapshot(snapshot: KvInspection | null, localOrigin: string): void;
  inspect(run: KvRun): Promise<void>;
  open(namespace: KvNamespace, run: KvRun): Promise<void>;
  turnPage(next: boolean, run: KvRun): Promise<void>;
  refreshPage(run: KvRun): Promise<void>;
  show(key: string, run: KvRun, sanitizeLine: (line: string, maxLen: number) => string): Promise<void>;
}
export function combineKvInspection(snapshot: KvInspection | null, fetched: KvInspection | null, localOrigin: string): KvInspection | null;
