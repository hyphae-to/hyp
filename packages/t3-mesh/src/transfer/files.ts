// Sending and receiving files (SPEC.md section 15.4): what may be packed, where received files are
// written, and the turn that tells the receiving thread about them.
import { constants, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, writeSync, closeSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import * as Schema from "effect/Schema";
import { fenceFor } from "../eventDelivery.ts";
import { neutralizeContextLinks } from "../header.ts";
import { MAX_PACK_BYTES, MAX_PACK_FILES, type PackFile } from "./pack.ts";

export const MAX_NOTE_BYTES = 4 * 1024;

/** Names that look like credentials are never sent, wherever they are. */
const SENSITIVE_EXACT = new Set([".ssh", ".gnupg", ".aws", ".t3-mesh", ".netrc", ".git-credentials", ".env"]);
const SENSITIVE_PREFIX = [".env.", "id_rsa", "id_ecdsa", "id_ed25519"];
const SENSITIVE_SUFFIX = [".pem", ".key", ".token"];
const SKIPPED_DIRS = new Set([".git"]);

export const isSensitiveName = (name: string): boolean =>
  SENSITIVE_EXACT.has(name) || SENSITIVE_PREFIX.some((prefix) => name.startsWith(prefix)) || SENSITIVE_SUFFIX.some((suffix) => name.endsWith(suffix));

const within = (root: string, path: string): boolean => {
  const inside = relative(root, path);
  return inside === "" || (!inside.startsWith("..") && !isAbsolute(inside));
};

export class FilesRefused extends Error {
  readonly code: "refused_path" | "too_large";
  constructor(code: "refused_path" | "too_large", message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * Reads `paths` (absolute, or relative to `cwd`) into pack files, directories recursively. Refuses
 * the whole set, naming every offending path, if anything is outside `roots`, a link, not a
 * regular file or directory, or looks like a credential. `.git` directories are skipped.
 */
export function collectFiles(paths: readonly string[], cwd: string, roots: readonly string[]): PackFile[] {
  const realRoots = roots.flatMap((root) => {
    try {
      return [realpathSync(root)];
    } catch {
      return [];
    }
  });
  const refused: string[] = [];
  const files: PackFile[] = [];
  let bytes = 0;
  const visit = (absolute: string, packPath: string): void => {
    const name = basename(absolute);
    if (isSensitiveName(name) || absolute.includes("/.t3/userdata")) {
      refused.push(`${absolute} (looks like a credential or T3 state)`);
      return;
    }
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) {
      refused.push(`${absolute} (symbolic link)`);
      return;
    }
    if (stat.isDirectory()) {
      if (SKIPPED_DIRS.has(name) && packPath.includes("/")) return;
      for (const child of readdirSync(absolute).sort()) visit(join(absolute, child), `${packPath}/${child}`);
      return;
    }
    if (!stat.isFile()) {
      refused.push(`${absolute} (not a regular file or directory)`);
      return;
    }
    bytes += stat.size;
    if (bytes > MAX_PACK_BYTES) throw new FilesRefused("too_large", `more than ${MAX_PACK_BYTES} bytes`);
    if (files.length >= MAX_PACK_FILES) throw new FilesRefused("too_large", `more than ${MAX_PACK_FILES} files`);
    files.push({ path: packPath, data: readFileSync(absolute) });
  };
  for (const path of paths) {
    const absolute = resolve(cwd, path);
    let real: string;
    try {
      // The parent is resolved, not the path itself, so a link given directly is caught by lstat.
      real = join(realpathSync(dirname(absolute)), basename(absolute));
      lstatSync(real);
    } catch {
      refused.push(`${absolute} (does not exist)`);
      continue;
    }
    if (!realRoots.some((root) => within(root, real))) {
      refused.push(`${absolute} (outside the thread's working directory, the T3 scratch directory and the temporary directory)`);
      continue;
    }
    visit(real, basename(real));
  }
  if (refused.length > 0) throw new FilesRefused("refused_path", `refused: ${refused.join("; ")}`);
  if (files.length === 0) throw new FilesRefused("refused_path", "nothing to send");
  return files;
}

/** Writes received files under a new directory `dir` (0700, files 0600, created exclusively, never through links). */
export function writeReceived(dir: string, files: readonly PackFile[]): void {
  mkdirSync(dirname(dir), { recursive: true, mode: 0o700 });
  mkdirSync(dir, { mode: 0o700 });
  for (const file of files) {
    const target = join(dir, ...file.path.split("/"));
    if (!within(dir, target)) throw new Error(`${file.path} escapes ${dir}`);
    mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    const fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      writeSync(fd, file.data);
    } finally {
      closeSync(fd);
    }
  }
}

/** The encrypted `meta` of a files pack. */
export const FilesMeta = Schema.Struct({ fromAddress: Schema.String, note: Schema.NullOr(Schema.String) });
export type FilesMeta = typeof FilesMeta.Type;

const humanBytes = (bytes: number): string =>
  bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KiB` : `${(bytes / 1024 / 1024).toFixed(1)} MiB`;

const MAX_LISTED = 50;

/** The turn that tells the receiving thread where the files are. Paths are listed inside a fence. */
export function formatFilesDelivery(fromAddress: string, note: string | null, dir: string, files: readonly PackFile[]): string {
  const bytes = files.reduce((total, file) => total + file.data.length, 0);
  const count = `${files.length} ${files.length === 1 ? "file" : "files"}`;
  const listed = files.slice(0, MAX_LISTED).map((file) => `${file.path} (${humanBytes(file.data.length)})`);
  if (files.length > MAX_LISTED) listed.push(`... and ${files.length - MAX_LISTED} more`);
  const list = listed.join("\n");
  const fence = fenceFor(list);
  return [
    `mesh files from ${fromAddress} · ${count}, ${humanBytes(bytes)} · saved in ${dir} · reply with mesh_send`,
    ...(note === null || note.trim() === "" ? [] : ["", neutralizeContextLinks(note)]),
    "",
    `${fence}\n${neutralizeContextLinks(list)}\n${fence}`,
  ].join("\n");
}
