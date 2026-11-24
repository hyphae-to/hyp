// Packs: what a transfer's plaintext holds (SPEC.md section 15.3). A manifest and regular files,
// nothing else, so unpacking cannot create links, devices or paths outside its directory.
import { createHash } from "node:crypto";
import { once } from "node:events";
import { promisify } from "node:util";
import { brotliDecompress, constants, createBrotliCompress } from "node:zlib";
import * as Schema from "effect/Schema";

const MAGIC = Buffer.from("T3MPACK1", "ascii");
/** A pack compressed with brotli: what transfers carry (SPEC.md section 15.3). */
const COMPRESSED_MAGIC = Buffer.from("T3MPBR1\n", "ascii");
export const MAX_PACK_FILES = 1000;
/** Total file bytes in a pack, uncompressed. */
export const MAX_PACK_BYTES = 1024 * 1024 * 1024;
/** A compressed pack, before sealing; the router's per-transfer limit leaves room for the tag. */
export const MAX_COMPRESSED_PACK_BYTES = 256 * 1024 * 1024;
const MAX_PATH_BYTES = 512;
const MAX_SEGMENT_BYTES = 255;
const MAX_MANIFEST_BYTES = 1024 * 1024;

const Manifest = Schema.Struct({
  v: Schema.Literal(1),
  meta: Schema.Unknown,
  files: Schema.Array(Schema.Struct({ path: Schema.String, size: Schema.Number, sha256: Schema.String })),
});

export interface PackFile {
  readonly path: string;
  readonly data: Buffer;
}

export interface Pack {
  readonly meta: unknown;
  readonly files: readonly PackFile[];
}

export class PackError extends Error {}
/** A pack over a size limit, compressed or not. */
export class PackTooLarge extends PackError {}

/** Why a pack path is not acceptable, or null. */
export function pathProblem(path: string): string | null {
  if (Buffer.byteLength(path, "utf8") > MAX_PATH_BYTES) return "longer than 512 bytes";
  if (path.includes("\0") || path.includes("\\")) return "contains NUL or a backslash";
  const segments = path.split("/");
  for (const segment of segments) {
    if (segment === "" || segment === "." || segment === "..") return "has an empty, . or .. segment";
    if (Buffer.byteLength(segment, "utf8") > MAX_SEGMENT_BYTES) return "has a segment longer than 255 bytes";
  }
  return null;
}

const sha256 = (data: Buffer): string => createHash("sha256").update(data).digest("hex");

function checkFiles(files: readonly { readonly path: string; readonly size: number }[]): void {
  if (files.length > MAX_PACK_FILES) throw new PackError(`${files.length} files; at most ${MAX_PACK_FILES}`);
  const seen = new Set<string>();
  const dirs = new Set<string>();
  let total = 0;
  for (const file of files) {
    const problem = pathProblem(file.path);
    if (problem !== null) throw new PackError(`${JSON.stringify(file.path)} ${problem}`);
    if (seen.has(file.path)) throw new PackError(`${file.path} appears twice`);
    seen.add(file.path);
    const parts = file.path.split("/");
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join("/"));
    if (!Number.isSafeInteger(file.size) || file.size < 0) throw new PackError(`${file.path} has an invalid size`);
    total += file.size;
  }
  // A file and a directory of the same name cannot both be written.
  for (const path of seen) if (dirs.has(path)) throw new PackError(`${path} is both a file and a directory`);
  if (total > MAX_PACK_BYTES) throw new PackTooLarge(`${total} bytes; at most ${MAX_PACK_BYTES}`);
}

/** Magic, manifest length and manifest: everything before the file contents. */
function packHead(pack: Pack): Buffer {
  checkFiles(pack.files.map((file) => ({ path: file.path, size: file.data.length })));
  const manifest = Buffer.from(
    JSON.stringify({
      v: 1,
      meta: pack.meta,
      files: pack.files.map((file) => ({ path: file.path, size: file.data.length, sha256: sha256(file.data) })),
    }),
    "utf8",
  );
  if (manifest.length > MAX_MANIFEST_BYTES) throw new PackError("manifest too large");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(manifest.length);
  return Buffer.concat([MAGIC, length, manifest]);
}

export function encodePack(pack: Pack): Buffer {
  return Buffer.concat([packHead(pack), ...pack.files.map((file) => file.data)]);
}

/**
 * The pack, brotli-compressed as it is streamed (the files are never concatenated uncompressed).
 * Throws PackError past MAX_COMPRESSED_PACK_BYTES.
 */
export async function compressPack(pack: Pack): Promise<Buffer> {
  const head = packHead(pack);
  const total = head.length + pack.files.reduce((sum, file) => sum + file.data.length, 0);
  const brotli = createBrotliCompress({
    params: { [constants.BROTLI_PARAM_QUALITY]: 5, [constants.BROTLI_PARAM_SIZE_HINT]: Math.min(total, 0x7fffffff) },
  });
  const chunks: Buffer[] = [COMPRESSED_MAGIC];
  let size = COMPRESSED_MAGIC.length;
  brotli.on("data", (chunk: Buffer) => {
    chunks.push(chunk);
    size += chunk.length;
  });
  const ended = once(brotli, "end");
  for (const part of [head, ...pack.files.map((file) => file.data)]) {
    if (!brotli.write(part)) await once(brotli, "drain");
  }
  brotli.end();
  await ended;
  if (size > MAX_COMPRESSED_PACK_BYTES) {
    throw new PackTooLarge(`${total} bytes compress to ${size}; limit ${MAX_COMPRESSED_PACK_BYTES} compressed`);
  }
  return Buffer.concat(chunks, size);
}

const decompress = promisify(brotliDecompress);

/** Decodes a compressed pack (or an uncompressed one), refusing anything that decompresses past the pack limits. */
export async function decompressPack(bytes: Buffer, maxOutputLength = MAGIC.length + 4 + MAX_MANIFEST_BYTES + MAX_PACK_BYTES): Promise<Pack> {
  if (!bytes.subarray(0, COMPRESSED_MAGIC.length).equals(COMPRESSED_MAGIC)) return decodePack(bytes);
  let plain: Buffer;
  try {
    plain = await decompress(bytes.subarray(COMPRESSED_MAGIC.length), { maxOutputLength });
  } catch (error) {
    throw new PackError(error instanceof RangeError ? "the pack decompresses past the size limit" : "the pack does not decompress");
  }
  return decodePack(plain);
}

/** Decodes and checks a pack: magic, manifest, paths, sizes and every file's SHA-256. */
export function decodePack(bytes: Buffer): Pack {
  if (bytes.length < MAGIC.length + 4 || !bytes.subarray(0, MAGIC.length).equals(MAGIC)) throw new PackError("not a pack");
  const manifestLength = bytes.readUInt32BE(MAGIC.length);
  if (manifestLength > MAX_MANIFEST_BYTES) throw new PackError("manifest too large");
  const start = MAGIC.length + 4;
  if (bytes.length < start + manifestLength) throw new PackError("truncated manifest");
  let manifest: typeof Manifest.Type;
  try {
    manifest = Schema.decodeUnknownSync(Manifest)(JSON.parse(bytes.subarray(start, start + manifestLength).toString("utf8")));
  } catch {
    throw new PackError("invalid manifest");
  }
  checkFiles(manifest.files);
  let offset = start + manifestLength;
  const files = manifest.files.map((file) => {
    const data = bytes.subarray(offset, offset + file.size);
    offset += file.size;
    if (data.length !== file.size || sha256(data) !== file.sha256) throw new PackError(`${file.path} does not match its checksum`);
    return { path: file.path, data };
  });
  if (offset !== bytes.length) throw new PackError("trailing bytes after the last file");
  return { meta: manifest.meta, files };
}
