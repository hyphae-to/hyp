// Safe zero-dependency compressed file pack for E2EE transfers.
// Binary frame before gzip: [4B "HYP1"][4B uint32BE manifestLen][UTF-8 JSON manifest][concatenated raw file bytes].
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, resolve } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";

export const PACK_MAGIC = "HYP1";
export const MAX_PACK_FILES = 200;
export const MAX_PACK_RAW_BYTES = 256 * 1024 * 1024;

const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_FILENAME_LENGTH = 200;
const SHA256_HEX = /^[0-9a-f]{64}$/;
// eslint-disable-next-line no-control-regex
const UNSAFE_CHAR_RE = /[\x00-\x1f\x7f/\\]/;

export interface TransferPackFileEntry {
  readonly name: string;
  readonly size: number;
  readonly sha256: string;
}

export interface TransferPackManifest {
  readonly v: 1;
  readonly fromHandle?: string;
  readonly note?: string;
  readonly files: readonly TransferPackFileEntry[];
}

export interface PackFilesOptions {
  readonly fromHandle?: string;
  readonly note?: string;
  readonly maxRawBytes?: number;
  readonly maxFiles?: number;
}

export interface PackedTransfer {
  readonly payload: Buffer;
  readonly manifest: TransferPackManifest;
  readonly rawBytes: number;
}

export interface UnpackFilesOptions {
  readonly maxRawBytes?: number;
  readonly maxFiles?: number;
}

export interface UnpackedFile {
  readonly name: string;
  readonly path: string;
  readonly size: number;
  readonly sha256: string;
}

export interface UnpackedTransfer {
  readonly destDir: string;
  readonly fromHandle?: string;
  readonly note?: string;
  readonly files: readonly UnpackedFile[];
}

/** Validates a single flat filename segment (no path separators, traversal, hidden leading dots, or control chars). */
export function isSafePackFilename(name: string): boolean {
  if (typeof name !== "string" || name.length === 0 || name.length > MAX_FILENAME_LENGTH) return false;
  if (UNSAFE_CHAR_RE.test(name)) return false;
  if (name === "." || name === ".." || name.includes("..") || name.startsWith(".")) return false;
  if (basename(name) !== name) return false;
  return true;
}

function sanitizeBasename(rawPath: string): string {
  const base = basename(rawPath)
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1f\x7f/\\]/g, "_")
    .replace(/\.\.+/g, "_")
    .replace(/^\.+/, "");
  const clean = base.length > 0 ? base : "file";
  if (clean.length <= MAX_FILENAME_LENGTH) return clean;
  const ext = extname(clean);
  if (ext.length > 0 && ext.length < 32) {
    return `${clean.slice(0, MAX_FILENAME_LENGTH - ext.length)}${ext}`;
  }
  return clean.slice(0, MAX_FILENAME_LENGTH);
}

function allocateUniqueName(baseName: string, seenLower: Set<string>): string {
  if (!seenLower.has(baseName.toLowerCase())) {
    seenLower.add(baseName.toLowerCase());
    return baseName;
  }
  const ext = extname(baseName);
  const hasExt = ext.length > 0 && ext.length < baseName.length && ext.length <= 32;
  const stem = hasExt ? baseName.slice(0, -ext.length) : baseName;
  const suffixExt = hasExt ? ext : "";
  for (let n = 2; n < 100_000; n += 1) {
    const tag = `-${n}`;
    const maxStem = MAX_FILENAME_LENGTH - tag.length - suffixExt.length;
    const candidate = `${stem.slice(0, Math.max(1, maxStem))}${tag}${suffixExt}`;
    if (!seenLower.has(candidate.toLowerCase())) {
      seenLower.add(candidate.toLowerCase());
      return candidate;
    }
  }
  throw new Error(`Could not allocate unique filename for ${baseName}`);
}

/**
 * Validates and packs regular files into a gzipped HYP1 binary frame with per-file SHA-256 digests.
 * Rejects missing files, directories, devices/pipes, oversized payloads, and excessive file counts.
 */
export function packFiles(filePaths: readonly string[], options: PackFilesOptions = {}): PackedTransfer {
  const maxRawBytes = options.maxRawBytes ?? MAX_PACK_RAW_BYTES;
  const maxFiles = options.maxFiles ?? MAX_PACK_FILES;

  if (!Array.isArray(filePaths) || filePaths.length === 0) {
    throw new Error("Expected at least one file path to pack");
  }
  if (filePaths.length > maxFiles) {
    throw new Error(`Too many files (${filePaths.length}); limit is ${maxFiles}`);
  }

  const seenLower = new Set<string>();
  const entries: TransferPackFileEntry[] = [];
  const chunks: Buffer[] = [];
  let totalRawBytes = 0;

  for (const filePath of filePaths) {
    if (typeof filePath !== "string" || filePath.length === 0 || filePath.includes("\0")) {
      throw new Error("Invalid file path");
    }
    let st;
    try {
      st = statSync(filePath);
    } catch {
      throw new Error(`File not found or unreadable: ${filePath}`);
    }
    if (!st.isFile()) {
      throw new Error(`Path is not a regular file: ${filePath}`);
    }
    if (totalRawBytes + st.size > maxRawBytes) {
      throw new Error(`Total file bytes exceed limit of ${maxRawBytes} bytes`);
    }
    const content = readFileSync(filePath);
    if (totalRawBytes + content.length > maxRawBytes) {
      throw new Error(`Total file bytes exceed limit of ${maxRawBytes} bytes`);
    }
    totalRawBytes += content.length;

    const sanitized = sanitizeBasename(filePath);
    const name = allocateUniqueName(sanitized, seenLower);
    if (!isSafePackFilename(name)) {
      throw new Error(`Could not derive safe filename from ${filePath}`);
    }
    const sha256 = createHash("sha256").update(content).digest("hex");
    entries.push({ name, size: content.length, sha256 });
    chunks.push(content);
  }

  const manifest: TransferPackManifest = {
    v: 1,
    ...(options.fromHandle ? { fromHandle: options.fromHandle } : {}),
    ...(options.note !== undefined && options.note.length > 0 ? { note: options.note } : {}),
    files: entries,
  };

  const manifestBuf = Buffer.from(JSON.stringify(manifest), "utf8");
  if (manifestBuf.length > MAX_MANIFEST_BYTES) {
    throw new Error(`Pack manifest exceeds limit of ${MAX_MANIFEST_BYTES} bytes`);
  }

  const magicBuf = Buffer.from(PACK_MAGIC, "ascii");
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(manifestBuf.length, 0);

  const raw = Buffer.concat([magicBuf, lenBuf, manifestBuf, ...chunks]);
  const payload = gzipSync(raw);
  return { payload, manifest, rawBytes: totalRawBytes };
}

/**
 * Safely inflates, verifies, and extracts a HYP1 compressed file pack into `destDir` (`0o700`, files `0o600`).
 * Defends against gzip bombs, path traversal, duplicate filenames, truncated/trailing data, and SHA-256 tampering.
 * On any validation or I/O error, zero files are left on disk.
 */
export function unpackFiles(payload: Buffer, destDir: string, options: UnpackFilesOptions = {}): UnpackedTransfer {
  const maxRawBytes = options.maxRawBytes ?? MAX_PACK_RAW_BYTES;
  const maxFiles = options.maxFiles ?? MAX_PACK_FILES;

  const raw = gunzipSync(payload, { maxOutputLength: maxRawBytes + MAX_MANIFEST_BYTES });
  if (raw.length < 8) {
    throw new Error("Corrupt transfer pack: truncated header");
  }
  if (raw.subarray(0, 4).toString("ascii") !== PACK_MAGIC) {
    throw new Error("Corrupt transfer pack: invalid magic");
  }
  const manifestLen = raw.readUInt32BE(4);
  if (manifestLen === 0 || manifestLen > MAX_MANIFEST_BYTES || 8 + manifestLen > raw.length) {
    throw new Error("Corrupt transfer pack: invalid manifest length");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.subarray(8, 8 + manifestLen).toString("utf8"));
  } catch {
    throw new Error("Corrupt transfer pack: manifest is not valid JSON");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Corrupt transfer pack: manifest must be an object");
  }
  const rec = parsed as Record<string, unknown>;
  if (rec.v !== 1) {
    throw new Error("Corrupt transfer pack: unsupported manifest version");
  }
  if (rec.fromHandle !== undefined && typeof rec.fromHandle !== "string") {
    throw new Error("Corrupt transfer pack: invalid fromHandle");
  }
  if (rec.note !== undefined && typeof rec.note !== "string") {
    throw new Error("Corrupt transfer pack: invalid note");
  }
  if (!Array.isArray(rec.files) || rec.files.length === 0 || rec.files.length > maxFiles) {
    throw new Error(`Corrupt transfer pack: expected 1..${maxFiles} files`);
  }

  // Validate every entry and verify every SHA-256 BEFORE touching the filesystem.
  const seenLower = new Set<string>();
  const verified: Array<{ readonly name: string; readonly size: number; readonly sha256: string; readonly data: Buffer }> = [];
  let offset = 8 + manifestLen;
  let totalRawBytes = 0;

  for (const item of rec.files) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error("Corrupt transfer pack: malformed file entry");
    }
    const entry = item as Record<string, unknown>;
    const name = entry.name;
    const size = entry.size;
    const sha256 = entry.sha256;

    if (typeof name !== "string" || !isSafePackFilename(name)) {
      throw new Error(`Corrupt transfer pack: unsafe filename ${JSON.stringify(name)}`);
    }
    const lower = name.toLowerCase();
    if (seenLower.has(lower)) {
      throw new Error(`Corrupt transfer pack: duplicate filename ${JSON.stringify(name)}`);
    }
    seenLower.add(lower);

    if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) {
      throw new Error(`Corrupt transfer pack: invalid size for ${name}`);
    }
    if (typeof sha256 !== "string" || !SHA256_HEX.test(sha256)) {
      throw new Error(`Corrupt transfer pack: invalid sha256 for ${name}`);
    }

    totalRawBytes += size;
    if (totalRawBytes > maxRawBytes) {
      throw new Error(`Corrupt transfer pack: raw size exceeds limit of ${maxRawBytes} bytes`);
    }
    if (offset + size > raw.length) {
      throw new Error(`Corrupt transfer pack: truncated data for ${name}`);
    }

    const data = raw.subarray(offset, offset + size);
    offset += size;

    const actualSha256 = createHash("sha256").update(data).digest("hex");
    if (actualSha256 !== sha256) {
      throw new Error(`Corrupt transfer pack: sha256 mismatch for ${name}`);
    }
    verified.push({ name, size, sha256, data });
  }

  if (offset !== raw.length) {
    throw new Error("Corrupt transfer pack: unexpected trailing bytes");
  }

  const absDestDir = resolve(destDir);
  mkdirSync(absDestDir, { recursive: true, mode: 0o700 });
  chmodSync(absDestDir, 0o700);

  const files: UnpackedFile[] = [];
  try {
    for (const entry of verified) {
      const filePath = resolve(absDestDir, entry.name);
      if (dirname(filePath) !== absDestDir) {
        throw new Error(`Corrupt transfer pack: path escape for ${entry.name}`);
      }
      writeFileSync(filePath, entry.data, { mode: 0o600, flag: "wx" });
      chmodSync(filePath, 0o600);
      files.push({ name: entry.name, path: filePath, size: entry.size, sha256: entry.sha256 });
    }
  } catch (error) {
    rmSync(absDestDir, { recursive: true, force: true });
    throw error;
  }

  return {
    destDir: absDestDir,
    ...(typeof rec.fromHandle === "string" && rec.fromHandle.length > 0 ? { fromHandle: rec.fromHandle } : {}),
    ...(typeof rec.note === "string" && rec.note.length > 0 ? { note: rec.note } : {}),
    files,
  };
}
