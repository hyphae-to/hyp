// The router's side of pairing (SPEC.md sections 14.2-14.5): grants uploaded by the admin, entries
// made by pairing connectors, revocations, and the directory. Everything stored here is checked
// against the pinned admin key; the router can store and serve entries but not create them.
import type { KeyObject } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import * as Schema from "../validate.ts";
import {
  EntrySchema,
  SignedBindingSchema,
  SignedSchema,
  openGrant,
  openRevocation,
  verifyEntry,
  type Entry,
  type Identity,
  type SignedBinding,
} from "../identity/grant.ts";
import { publicKeyFromRaw, type Signed } from "../identity/keys.ts";

export const PAIRING_SCHEMA = `
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  connector_id TEXT NOT NULL,
  signed TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  pair_by INTEGER NOT NULL,
  entry TEXT,
  paired_at INTEGER
);
CREATE INDEX IF NOT EXISTS grants_connector ON grants (connector_id, issued_at);
CREATE TABLE IF NOT EXISTS revocations (
  grant_id TEXT PRIMARY KEY,
  connector_id TEXT NOT NULL,
  signed TEXT NOT NULL,
  revoked_at INTEGER NOT NULL
);
`;

const GrantRow = Schema.Struct({
  id: Schema.String,
  connector_id: Schema.String,
  signed: Schema.String,
  pair_by: Schema.Number,
  entry: Schema.NullOr(Schema.String),
});
const decodeGrantRow = Schema.decodeUnknownSync(GrantRow);
const EntryRow = Schema.Struct({ entry: Schema.String });
const SignedRow = Schema.Struct({ signed: Schema.String });
const decodeEntryJson = Schema.decodeUnknownSync(Schema.fromJsonString(EntrySchema));
const decodeSignedJson = Schema.decodeUnknownSync(Schema.fromJsonString(SignedSchema));

export type PairingError = "not_configured" | "unauthorized" | "not_found" | "already_paired" | "expired" | "invalid";

export type PairingResult<A> = { readonly ok: true; readonly value: A } | { readonly ok: false; readonly error: PairingError; readonly message: string };

const refuse = <A>(error: PairingError, message: string): PairingResult<A> => ({ ok: false, error, message });

export interface PairingOptions {
  readonly db: DatabaseSync;
  /** Raw Ed25519 public key (base64url) of the mesh admin; null when pairing is not configured. */
  readonly adminKey: string | null;
  readonly now: () => number;
  readonly audit: (fields: Readonly<Record<string, unknown>>) => void;
  /** Issues a fresh connector token for a newly paired connector, replacing any older one. */
  readonly issueToken: (connectorId: string) => string;
  /** Revokes the connector's token, handles and subscriptions. */
  readonly revokeConnector: (connectorId: string) => void;
}

export interface Directory {
  readonly adminKey: string;
  readonly entries: readonly Entry[];
  readonly revocations: readonly Signed[];
}

export class Pairing {
  readonly #options: PairingOptions;
  readonly #adminKey: KeyObject | null;
  /** Current identity per connector ID, rebuilt after every change. */
  #current = new Map<string, Identity>();

  constructor(options: PairingOptions) {
    this.#options = options;
    this.#adminKey = options.adminKey === null ? null : publicKeyFromRaw(options.adminKey, "ed25519");
    this.#reload();
  }

  static migrate(db: DatabaseSync): void {
    db.exec(PAIRING_SCHEMA);
  }

  get configured(): boolean {
    return this.#adminKey !== null;
  }

  /** The connector's current identity, or undefined if it never paired (or its grant was revoked). */
  identity(connectorId: string): Identity | undefined {
    return this.#current.get(connectorId);
  }

  /** `POST /v1/grants`: stores an admin-signed grant until it is paired or its window ends. */
  addGrant(signed: unknown): PairingResult<{ readonly grantId: string }> {
    const adminKey = this.#adminKey;
    if (adminKey === null) return refuse("not_configured", "the router has no admin key (serve --admin-key)");
    const decoded = Schema.decodeUnknownOption(SignedSchema)(signed);
    if (decoded._tag === "None") return refuse("invalid", "expected {payload, sig}");
    const grant = openGrant(decoded.value, adminKey);
    if (grant === null) return refuse("unauthorized", "the grant is not signed by this mesh's admin key");
    const { db, now, audit } = this.#options;
    const existing = db.prepare("SELECT signed FROM grants WHERE id = ?").get(grant.id);
    if (existing !== undefined) {
      return Schema.decodeUnknownSync(SignedRow)(existing).signed === JSON.stringify(decoded.value)
        ? { ok: true, value: { grantId: grant.id } }
        : refuse("invalid", `grant ${grant.id} exists with different content`);
    }
    if (Date.parse(grant.pairBy) <= now()) return refuse("expired", "the grant's pairing window has already ended");
    db.prepare("INSERT INTO grants (id, connector_id, signed, issued_at, pair_by) VALUES (?, ?, ?, ?, ?)").run(
      grant.id,
      grant.connectorId,
      JSON.stringify(decoded.value),
      Date.parse(grant.issuedAt),
      Date.parse(grant.pairBy),
    );
    audit({ event: "grant.added", connector: grant.connectorId, grant: grant.id, scopes: grant.scopes });
    return { ok: true, value: { grantId: grant.id } };
  }

  /** `GET /v1/pairing/<grant id>`: the signed grant a pairing connector checks against its code. */
  pendingGrant(grantId: string): PairingResult<{ readonly grant: Signed; readonly adminKey: string }> {
    const adminKey = this.#options.adminKey;
    if (adminKey === null) return refuse("not_configured", "the router has no admin key");
    const row = this.#grantRow(grantId);
    if (row === undefined) return refuse("not_found", "no such grant");
    if (row.entry !== null) return refuse("already_paired", "this grant has been used");
    if (row.pair_by <= this.#options.now()) return refuse("expired", "the pairing window has ended");
    return { ok: true, value: { grant: decodeSignedJson(row.signed), adminKey } };
  }

  /** `POST /v1/pairing/<grant id>`: binds the connector's keys to the grant and issues its token. */
  pair(grantId: string, body: unknown): PairingResult<{ readonly connectorId: string; readonly token: string; readonly scopes: readonly string[] }> {
    const adminKey = this.#adminKey;
    if (adminKey === null) return refuse("not_configured", "the router has no admin key");
    const decoded = Schema.decodeUnknownOption(Schema.Struct({ binding: SignedBindingSchema }))(body);
    if (decoded._tag === "None") return refuse("invalid", "expected {binding: {payload, pairingSig, selfSig}}");
    const binding: SignedBinding = decoded.value.binding;
    const { db, now, audit } = this.#options;
    const row = this.#grantRow(grantId);
    if (row === undefined) return refuse("not_found", "no such grant");
    if (row.entry !== null) return refuse("already_paired", "this grant has been used");
    if (row.pair_by <= now()) return refuse("expired", "the pairing window has ended");
    const entry: Entry = { grant: decodeSignedJson(row.signed), binding };
    const verified = verifyEntry(entry, adminKey);
    if (!verified.ok) {
      audit({ event: "pairing.refused", grant: grantId, reason: verified.reason });
      return refuse("unauthorized", verified.reason);
    }
    // Claimed in the same statement that checks it, so two pairings racing for one grant cannot both win.
    const claimed = db
      .prepare("UPDATE grants SET entry = ?, paired_at = ? WHERE id = ? AND entry IS NULL")
      .run(JSON.stringify(entry), now(), grantId).changes;
    if (Number(claimed) === 0) return refuse("already_paired", "this grant has been used");
    const { connectorId, scopes, signingKey } = verified.identity;
    const token = this.#options.issueToken(connectorId);
    this.#reload();
    audit({ event: "connector.paired", connector: connectorId, grant: grantId, scopes, signingKey });
    return { ok: true, value: { connectorId, token, scopes } };
  }

  /** `POST /v1/revocations`: an admin-signed revocation; revoking a connector's current grant cuts it off. */
  addRevocation(signed: unknown): PairingResult<{ readonly connectorId: string; readonly current: boolean }> {
    const adminKey = this.#adminKey;
    if (adminKey === null) return refuse("not_configured", "the router has no admin key");
    const decoded = Schema.decodeUnknownOption(SignedSchema)(signed);
    if (decoded._tag === "None") return refuse("invalid", "expected {payload, sig}");
    const revocation = openRevocation(decoded.value, adminKey);
    if (revocation === null) return refuse("unauthorized", "the revocation is not signed by this mesh's admin key");
    const { db, now, audit } = this.#options;
    const current = this.#current.get(revocation.connectorId)?.grantId === revocation.grantId;
    db.prepare("INSERT OR IGNORE INTO revocations (grant_id, connector_id, signed, revoked_at) VALUES (?, ?, ?, ?)").run(
      revocation.grantId,
      revocation.connectorId,
      JSON.stringify(decoded.value),
      now(),
    );
    this.#reload();
    if (current) this.#options.revokeConnector(revocation.connectorId);
    audit({ event: "grant.revoked", connector: revocation.connectorId, grant: revocation.grantId, current });
    return { ok: true, value: { connectorId: revocation.connectorId, current } };
  }

  directory(): PairingResult<Directory> {
    const adminKey = this.#options.adminKey;
    if (adminKey === null) return refuse("not_configured", "the router has no admin key");
    const { db } = this.#options;
    const entries = Schema.decodeUnknownSync(Schema.Array(EntryRow))(
      db.prepare("SELECT entry FROM grants WHERE entry IS NOT NULL ORDER BY connector_id, issued_at").all(),
    ).map((row) => decodeEntryJson(row.entry));
    const revocations = Schema.decodeUnknownSync(Schema.Array(SignedRow))(
      db.prepare("SELECT signed FROM revocations ORDER BY revoked_at").all(),
    ).map((row) => decodeSignedJson(row.signed));
    return { ok: true, value: { adminKey, entries, revocations } };
  }

  #grantRow(grantId: string): typeof GrantRow.Type | undefined {
    const row = this.#options.db.prepare("SELECT id, connector_id, signed, pair_by, entry FROM grants WHERE id = ?").get(grantId);
    return row === undefined ? undefined : decodeGrantRow(row);
  }

  /** Recomputes the current identities: per connector, the latest valid paired entry, unless revoked. */
  #reload(): void {
    const adminKey = this.#adminKey;
    const next = new Map<string, Identity>();
    if (adminKey !== null) {
      const { db } = this.#options;
      const revoked = new Set(
        Schema.decodeUnknownSync(Schema.Array(Schema.Struct({ grant_id: Schema.String })))(
          db.prepare("SELECT grant_id FROM revocations").all(),
        ).map((row) => row.grant_id),
      );
      const rows = Schema.decodeUnknownSync(Schema.Array(EntryRow))(
        db.prepare("SELECT entry FROM grants WHERE entry IS NOT NULL ORDER BY issued_at").all(),
      );
      for (const row of rows) {
        const verified = verifyEntry(decodeEntryJson(row.entry), adminKey);
        if (!verified.ok) continue;
        const { identity } = verified;
        const previous = next.get(identity.connectorId);
        if (previous !== undefined && Date.parse(previous.issuedAt) > Date.parse(identity.issuedAt)) continue;
        next.set(identity.connectorId, identity);
      }
      for (const [connectorId, identity] of next) if (revoked.has(identity.grantId)) next.delete(connectorId);
    }
    this.#current = next;
  }
}
