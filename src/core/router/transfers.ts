// The router's side of transfers (SPEC.md section 15.2): ciphertext stored in files, metadata in
// SQLite, offered to the recipient connector one at a time and deleted once acked or expired. The
// router checks the sender's signature and both sides' scopes; it cannot read the contents.
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import * as Schema from "effect/Schema";
import type { Identity } from "../identity/grant.ts";
import { publicKeyFromRaw, type Signed } from "../identity/keys.ts";
import { ScopeSet } from "../identity/scopes.ts";
import { readHeader, verifyHeader, type TransferHeader } from "../transfer/seal.ts";
import type { InboundOutcome, InboundTransfer } from "./types.ts";

export const TRANSFERS_SCHEMA = `
CREATE TABLE IF NOT EXISTS transfers (
  id TEXT PRIMARY KEY,
  from_connector TEXT NOT NULL,
  to_connector TEXT NOT NULL,
  type TEXT NOT NULL,
  header TEXT NOT NULL,
  size INTEGER NOT NULL,
  sent_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending', 'delivered', 'rejected', 'expired')),
  reason TEXT,
  hold_until INTEGER NOT NULL DEFAULT 0,
  settled_at INTEGER
);
CREATE INDEX IF NOT EXISTS transfers_pending ON transfers (to_connector, sent_at) WHERE state = 'pending';
`;

export interface TransferLimits {
  readonly maxBytes: number;
  readonly maxPendingBytesPerRecipient: number;
  readonly maxPendingPerRecipient: number;
  readonly holdRetryMs: number;
}

/** Ciphertext of a compressed pack (SPEC.md section 15.2); the sealing adds a 16-byte tag. */
export const DEFAULT_TRANSFER_LIMITS: TransferLimits = {
  maxBytes: 256 * 1024 * 1024 + 4096,
  maxPendingBytesPerRecipient: 512 * 1024 * 1024,
  maxPendingPerRecipient: 20,
  holdRetryMs: 30_000,
};

export type TransferError = "invalid" | "unauthorized" | "not_granted" | "unknown_recipient" | "too_large" | "queue_full" | "id_conflict";

export type TransferResult = { readonly ok: true } | { readonly ok: false; readonly error: TransferError; readonly message: string };

const TransferRow = Schema.Struct({
  id: Schema.String,
  from_connector: Schema.String,
  to_connector: Schema.String,
  type: Schema.String,
  header: Schema.String,
  size: Schema.Number,
  sent_at: Schema.Number,
  expires_at: Schema.Number,
  hold_until: Schema.Number,
});
const decodeRow = Schema.decodeUnknownSync(TransferRow);
const decodeRows = Schema.decodeUnknownSync(Schema.Array(TransferRow));
const SumRow = Schema.Struct({ n: Schema.Number, bytes: Schema.NullOr(Schema.Number) });
const decodeSignedJson = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Struct({ payload: Schema.String, sig: Schema.String })));

export interface TransferStoreOptions {
  readonly db: DatabaseSync;
  /** Where ciphertext files live (0700). */
  readonly dir: string;
  readonly limits: TransferLimits;
  readonly now: () => number;
  readonly audit: (fields: Readonly<Record<string, unknown>>) => void;
  /** The connector's current paired identity; transfers need both ends paired. */
  readonly identity: (connectorId: string) => Identity | undefined;
}

/** Whether `from` may send a `type` transfer to `to`, by both sides' scopes (SPEC.md section 15.2). */
export function transferAllowed(type: TransferHeader["type"], from: ScopeSet, to: ScopeSet, toId: string): boolean {
  switch (type) {
    case "files":
      return from.maySend("files", toId) && to.has("files:receive");
    case "fork":
      return from.maySend("forks", toId) && to.forkCeiling() !== null;
    case "fork.result":
      return from.forkCeiling() !== null && to.mayForkOut();
  }
}

export class TransferStore {
  readonly #options: TransferStoreOptions;

  constructor(options: TransferStoreOptions) {
    this.#options = options;
    mkdirSync(options.dir, { recursive: true, mode: 0o700 });
    // Uploads cut off by a restart never reached store().
    for (const name of readdirSync(options.dir)) if (name.includes(".part-")) rmSync(join(options.dir, name), { force: true });
  }

  static migrate(db: DatabaseSync): void {
    db.exec(TRANSFERS_SCHEMA);
  }

  get maxBytes(): number {
    return this.#options.limits.maxBytes;
  }

  #file(id: string): string {
    return join(this.#options.dir, id);
  }

  /**
   * `PUT /v1/transfers/<pathId>`, before the body is read: everything the signed header decides
   * (signature, scopes, size limit, queue). `duplicate`: this exact transfer is already stored.
   */
  check(
    connectorId: string,
    pathId: string,
    signed: Signed,
  ): { readonly ok: true; readonly header: TransferHeader; readonly duplicate: boolean } | Extract<TransferResult, { ok: false }> {
    const { db, limits, now, audit, identity } = this.#options;
    const refuse = (error: TransferError, message: string): Extract<TransferResult, { ok: false }> => {
      audit({ event: "transfer.refused", connector: connectorId, error, message });
      return { ok: false, error, message };
    };
    const header = readHeader(signed);
    if (header === null) return refuse("invalid", "malformed transfer header");
    if (header.id !== pathId) return refuse("invalid", "the path and header ids differ");
    if (header.from !== connectorId) return refuse("unauthorized", `the header is from ${header.from}, not ${connectorId}`);
    const sender = identity(connectorId);
    if (sender === undefined) return refuse("not_granted", `${connectorId} has not paired; transfers need a paired connector`);
    if (!verifyHeader(signed, publicKeyFromRaw(sender.signingKey, "ed25519"))) {
      return refuse("unauthorized", "the header is not signed with the sender's current key");
    }
    const recipient = identity(header.to);
    if (recipient === undefined) return refuse("unknown_recipient", `${header.to} is not a paired connector`);
    if (!transferAllowed(header.type, new ScopeSet(sender.scopes), new ScopeSet(recipient.scopes), header.to)) {
      return refuse("not_granted", `${header.from} may not send a ${header.type} transfer to ${header.to}`);
    }
    const existing = db.prepare("SELECT * FROM transfers WHERE id = ?").get(header.id);
    if (existing !== undefined) {
      return decodeRow(existing).header === JSON.stringify(signed)
        ? { ok: true, header, duplicate: true }
        : refuse("id_conflict", `transfer id ${header.id} was used for a different transfer`);
    }
    if (Date.parse(header.expiresAt) <= now()) return refuse("invalid", "the transfer has already expired");
    if (header.size > limits.maxBytes) return refuse("too_large", `${header.size} bytes; limit ${limits.maxBytes}`);
    const pending = Schema.decodeUnknownSync(SumRow)(
      db.prepare("SELECT COUNT(*) AS n, SUM(size) AS bytes FROM transfers WHERE to_connector = ? AND state = 'pending'").get(header.to),
    );
    if (pending.n >= limits.maxPendingPerRecipient || (pending.bytes ?? 0) + header.size > limits.maxPendingBytesPerRecipient) {
      return refuse("queue_full", `${header.to} has ${pending.n} pending transfers (${pending.bytes ?? 0} bytes)`);
    }
    return { ok: true, header, duplicate: false };
  }

  /** Where an upload for `id` is written while it arrives; `store` moves it into place. */
  uploadPath(id: string): string {
    return `${this.#file(id)}.part-${randomUUID()}`;
  }

  /**
   * Stores a checked transfer whose body was written to `upload`, if its size and SHA-256 match
   * the header. The upload file is moved into place or removed.
   */
  store(signed: Signed, header: TransferHeader, upload: { readonly path: string; readonly size: number; readonly sha256: string }): TransferResult {
    const { db, now, audit } = this.#options;
    if (upload.size !== header.size || upload.sha256 !== header.sha256) {
      rmSync(upload.path, { force: true });
      audit({ event: "transfer.refused", connector: header.from, error: "invalid", message: "body does not match the header" });
      return { ok: false, error: "invalid", message: "the body does not match the header's size and sha256" };
    }
    // Renamed into place before the row exists, so a row never points at a half-written file.
    renameSync(upload.path, this.#file(header.id));
    db.prepare(
      "INSERT OR IGNORE INTO transfers (id, from_connector, to_connector, type, header, size, sent_at, expires_at, state) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
    ).run(header.id, header.from, header.to, header.type, JSON.stringify(signed), upload.size, now(), Date.parse(header.expiresAt));
    audit({ event: "transfer.stored", id: header.id, from: header.from, to: header.to, type: header.type, bytes: upload.size });
    return { ok: true };
  }

  /** `check` and `store` for a body already in memory (tests, small transfers). */
  submit(connectorId: string, pathId: string, signed: Signed, body: Buffer): TransferResult {
    const checked = this.check(connectorId, pathId, signed);
    if (!checked.ok) return checked;
    if (checked.duplicate) return { ok: true };
    const path = this.uploadPath(checked.header.id);
    writeFileSync(path, body, { mode: 0o600 });
    return this.store(signed, checked.header, { path, size: body.length, sha256: createHash("sha256").update(body).digest("hex") });
  }

  /** The ciphertext file and its size, for the recipient while the transfer is pending. */
  readPath(connectorId: string, id: string): { readonly path: string; readonly size: number } | null {
    const row = this.#options.db.prepare("SELECT * FROM transfers WHERE id = ? AND state = 'pending'").get(id);
    if (row === undefined) return null;
    const transfer = decodeRow(row);
    return transfer.to_connector === connectorId ? { path: this.#file(id), size: transfer.size } : null;
  }

  /** The oldest due pending transfer for the connector, unless one is already in flight. */
  due(connectorId: string, inFlight: (id: string) => boolean): InboundTransfer | null {
    const { db, now } = this.#options;
    const rows = decodeRows(
      db.prepare("SELECT * FROM transfers WHERE to_connector = ? AND state = 'pending' ORDER BY sent_at, id").all(connectorId),
    );
    const [first] = rows;
    if (first === undefined || rows.some((row) => inFlight(row.id))) return null;
    if (first.hold_until > now() || first.expires_at <= now()) return null;
    const header = decodeSignedJson(first.header);
    const parsed = readHeader(header);
    if (parsed === null) return null;
    return { id: first.id, from: first.from_connector, type: parsed.type, size: first.size, header, sentAt: new Date(first.sent_at).toISOString() };
  }

  /** Settles a pending transfer for its recipient; false if it is not one. */
  ack(connectorId: string, id: string, outcome: InboundOutcome): boolean {
    const { db, now, audit, limits } = this.#options;
    const row = db.prepare("SELECT * FROM transfers WHERE id = ? AND state = 'pending'").get(id);
    if (row === undefined) return false;
    const transfer = decodeRow(row);
    if (transfer.to_connector !== connectorId) return false;
    if (outcome.kind === "hold") {
      db.prepare("UPDATE transfers SET reason = ?, hold_until = ? WHERE id = ?").run(outcome.reason, now() + limits.holdRetryMs, id);
    } else {
      db.prepare("UPDATE transfers SET state = ?, reason = ?, settled_at = ? WHERE id = ?").run(
        outcome.kind,
        outcome.kind === "rejected" ? outcome.reason : null,
        now(),
        id,
      );
      rmSync(this.#file(id), { force: true });
    }
    audit({
      event: `transfer.${outcome.kind === "hold" ? "held" : outcome.kind}`,
      id,
      from: transfer.from_connector,
      to: transfer.to_connector,
      type: transfer.type,
      ...(outcome.kind === "delivered" ? {} : { reason: outcome.reason }),
    });
    return true;
  }

  tick(): void {
    const { db, now, audit } = this.#options;
    for (const row of decodeRows(db.prepare("SELECT * FROM transfers WHERE state = 'pending' AND expires_at <= ?").all(now()))) {
      db.prepare("UPDATE transfers SET state = 'expired', settled_at = ? WHERE id = ?").run(now(), row.id);
      rmSync(this.#file(row.id), { force: true });
      audit({ event: "transfer.expired", id: row.id, from: row.from_connector, to: row.to_connector, type: row.type });
    }
  }

  /** Drops a revoked connector's pending transfers, both ways. */
  removeConnector(connectorId: string): void {
    const { db, now, audit } = this.#options;
    const rows = decodeRows(
      db.prepare("SELECT * FROM transfers WHERE state = 'pending' AND (to_connector = ? OR from_connector = ?)").all(connectorId, connectorId),
    );
    for (const row of rows) {
      db.prepare("UPDATE transfers SET state = 'rejected', reason = 'connector_revoked', settled_at = ? WHERE id = ?").run(now(), row.id);
      rmSync(this.#file(row.id), { force: true });
      audit({ event: "transfer.rejected", id: row.id, from: row.from_connector, to: row.to_connector, reason: "connector_revoked" });
    }
  }
}
