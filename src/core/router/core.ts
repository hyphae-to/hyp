// Router state and rules (SPEC.md sections 7-8 and 12), on SQLite. Used by the HTTP router (file DB)
// and the loopback router (in-memory DB). Transport-agnostic: a connector attaches an `offer`
// callback and answers each offered message or event batch with `ack`.
import { createHash, randomBytes, type KeyObject } from "node:crypto";
import { appendFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import * as Schema from "../validate.ts";
import { formatAddress, isConnectorId, isHandle, parseAddress } from "../address.ts";
import { SignedSchema, type Identity } from "../identity/grant.ts";
import { isRawKey, isSmallOrderKey, publicKeyFromRaw, verifyPayload } from "../identity/keys.ts";
import { ScopeSet, UNPAIRED_SCOPES } from "../identity/scopes.ts";
import { DEFAULT_EVENT_LIMITS, EventRouter, type EventLimits } from "./events.ts";
import { Pairing } from "./pairing.ts";
import { DEFAULT_TRANSFER_LIMITS, TransferStore, type TransferLimits } from "./transfers.ts";
import {
  MAX_TEXT_BYTES,
  type InboundOutcome,
  type InboxItem,
  type OutboundMessage,
  type Peer,
  type SendResult,
} from "./types.ts";

export interface RouterLimits {
  readonly ttlMs: number;
  readonly maxPendingPerRecipient: number;
  readonly maxPerHourPerRecipient: number;
  /** How long a held message waits before it is offered again. */
  readonly holdRetryMs: number;
  /** How long an offered message may go unanswered before it is offered again. */
  readonly ackTimeoutMs: number;
  /** How long settled (`delivered` / `rejected` / `expired`) message rows are retained before pruning. Defaults to 7 days. */
  readonly settledRetentionMs?: number;
}

export const DEFAULT_LIMITS: RouterLimits = {
  ttlMs: 24 * 60 * 60 * 1000,
  maxPendingPerRecipient: 100,
  maxPerHourPerRecipient: 30,
  holdRetryMs: 30_000,
  ackTimeoutMs: 60_000,
  settledRetentionMs: 7 * 24 * 60 * 60 * 1000,
};

const DEFAULT_SETTLED_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const MESSAGE_PRUNE_INTERVAL_MS = 60_000;

const HOUR_MS = 60 * 60 * 1000;
/**
 * How long a connection waits for another's write lock on the same database: the admin commands
 * (add-connector, add-publisher, ...) write while the router serves. Both sides hold it for milliseconds.
 */
const BUSY_TIMEOUT_MS = 2_000;

const MessageRow = Schema.Struct({
  id: Schema.String,
  from_addr: Schema.String,
  to_addr: Schema.String,
  text: Schema.String,
  digest: Schema.String,
  sent_at: Schema.Number,
  origin_environment_id: Schema.NullOr(Schema.String),
  origin_thread_id: Schema.NullOr(Schema.String),
});
const decodeMessageRow = Schema.decodeUnknownSync(MessageRow);
const decodeMessageRows = Schema.decodeUnknownSync(Schema.Array(MessageRow));
const ConnectorRow = Schema.Struct({ id: Schema.String });
const decodeConnectorRow = Schema.decodeUnknownSync(ConnectorRow);
const HandleRow = Schema.Struct({ connector_id: Schema.String, handle: Schema.String });
const decodeHandleRows = Schema.decodeUnknownSync(Schema.Array(HandleRow));
const CountRow = Schema.Struct({ n: Schema.Number });
const decodeCount = (row: unknown): number => Schema.decodeUnknownSync(CountRow)(row).n;
const ConnectorKeyRow = Schema.Struct({
  connector_id: Schema.String,
  signing_key: Schema.String,
  encryption_key: Schema.String,
  registered_at: Schema.Number,
});
const decodeConnectorKeyRow = Schema.decodeUnknownSync(ConnectorKeyRow);
const decodeConnectorKeyRows = Schema.decodeUnknownSync(Schema.Array(ConnectorKeyRow));
const RegisterKeysBody = Schema.Struct({
  signingKey: Schema.String,
  encryptionKey: Schema.String,
  proof: SignedSchema,
});
const decodeRegisterKeysBody = Schema.decodeUnknownOption(RegisterKeysBody);
const KeyRegPayload = Schema.Struct({
  v: Schema.Literal(1),
  connectorId: Schema.String,
  signingKey: Schema.String,
  encryptionKey: Schema.String,
});
const decodeKeyRegPayload = Schema.decodeUnknownOption(KeyRegPayload);
const REGISTERED_KEY_SCOPES: readonly string[] = [
  "messages:send",
  "messages:receive",
  "events:subscribe",
  "files:send",
  "files:receive",
];

const SCHEMA = `
CREATE TABLE IF NOT EXISTS connectors (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS connector_keys (
  connector_id TEXT PRIMARY KEY REFERENCES connectors(id) ON DELETE CASCADE,
  signing_key TEXT NOT NULL,
  encryption_key TEXT NOT NULL,
  proof TEXT NOT NULL,
  registered_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS handles (
  connector_id TEXT NOT NULL REFERENCES connectors(id),
  handle TEXT NOT NULL,
  PRIMARY KEY (connector_id, handle)
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  from_addr TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  text TEXT NOT NULL,
  digest TEXT NOT NULL,
  sent_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending', 'delivered', 'rejected', 'expired')),
  reason TEXT,
  hold_until INTEGER NOT NULL DEFAULT 0,
  settled_at INTEGER
);
CREATE INDEX IF NOT EXISTS messages_pending ON messages (to_addr, sent_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS messages_recent ON messages (to_addr, sent_at);
CREATE TABLE IF NOT EXISTS channel_members (
  channel TEXT NOT NULL,
  address TEXT NOT NULL,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (channel, address)
);
CREATE INDEX IF NOT EXISTS channel_members_address ON channel_members (address);
`;

const CHANNEL_NAME = /^#[a-z0-9][a-z0-9._-]{0,62}$/;

/** Columns added after the first deployed schema. */
const ADDED_COLUMNS = [
  ["messages", "origin_environment_id", "TEXT"],
  ["messages", "origin_thread_id", "TEXT"],
] as const;
const ColumnRow = Schema.Struct({ name: Schema.String });

const hashToken = (token: string): string => createHash("sha256").update(token).digest("hex");

const digestOf = (from: string, to: string, text: string): string =>
  createHash("sha256").update(JSON.stringify([from, to, text])).digest("hex");

type Offer = (item: InboxItem) => void;

interface Attachment {
  readonly offer: Offer;
  /** Offered and not yet answered, by message or batch ID -> offered at. */
  readonly inFlight: Map<string, number>;
}

export interface RouterCoreOptions {
  readonly dbPath: string;
  readonly auditPath?: string | undefined;
  readonly limits?: RouterLimits;
  readonly eventLimits?: EventLimits;
  /** Topic -> publisher IDs allowed to publish to it (SPEC.md section 12.1). No topics by default. */
  readonly topics?: ReadonlyMap<string, readonly string[]>;
  readonly now?: () => number;
  /** Receives errors of work deferred past the caller (the first offer after attach). Thrown if unset. */
  readonly onDeferredError?: (error: unknown) => void;
  /** Raw Ed25519 public key of the mesh admin (SPEC.md section 14.1); without it there is no pairing. */
  readonly adminKey?: string | null;
  /** Refuse tokens of connectors that have not paired (SPEC.md section 14.4). */
  readonly requirePairing?: boolean;
  /** Where transfer ciphertext is kept; default `<db dir>/transfers` (a temporary dir for `:memory:`). */
  readonly transferDir?: string;
  readonly transferLimits?: TransferLimits;
}

const JournalModeRow = Schema.Struct({ journal_mode: Schema.String });

export class RouterCore {
  readonly #db: DatabaseSync;
  readonly #auditPath: string | undefined;
  readonly #limits: RouterLimits;
  readonly #now: () => number;
  readonly #attached = new Map<string, Attachment>();
  readonly #onDeferredError: ((error: unknown) => void) | undefined;
  #scheduleListener: (() => void) | null = null;
  #closed = false;
  #lastMessagePruneAt = -Infinity;
  /** Topics, publishers, subscriptions and event batches. */
  readonly events: EventRouter;
  /** Grants, paired entries, revocations and the directory. */
  readonly pairing: Pairing;
  /** Sealed transfers between paired connectors. */
  readonly transfers: TransferStore;
  readonly #requirePairing: boolean;

  constructor(options: RouterCoreOptions) {
    this.#db = new DatabaseSync(options.dbPath);
    this.#db.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}; PRAGMA foreign_keys = ON;`);
    this.#enableWal();
    this.#migrate();
    this.#auditPath = options.auditPath;
    this.#limits = options.limits ?? DEFAULT_LIMITS;
    this.#now = options.now ?? Date.now;
    this.#onDeferredError = options.onDeferredError;
    this.events = new EventRouter(this.#db, {
      topics: options.topics ?? new Map(),
      limits: options.eventLimits ?? DEFAULT_EVENT_LIMITS,
      holdRetryMs: this.#limits.holdRetryMs,
      now: this.#now,
      audit: (fields) => this.#audit(fields),
      ready: (connectorId) => this.#drain(connectorId),
      inFlight: (connectorId, batchId) => this.#attached.get(connectorId)?.inFlight.has(batchId) ?? false,
      onScheduleChange: () => this.#notifyScheduleChange(),
    });
    this.#requirePairing = options.requirePairing ?? false;
    this.pairing = new Pairing({
      db: this.#db,
      adminKey: options.adminKey ?? null,
      now: this.#now,
      audit: (fields) => this.#audit(fields),
      issueToken: (connectorId) => this.#issueToken(connectorId),
      revokeConnector: (connectorId) => void this.revokeConnector(connectorId),
    });
    this.transfers = new TransferStore({
      db: this.#db,
      dir:
        options.transferDir ??
        (options.dbPath === ":memory:" ? mkdtempSync(join(tmpdir(), "hyphae-transfers-")) : join(dirname(options.dbPath), "transfers")),
      limits: options.transferLimits ?? { ...DEFAULT_TRANSFER_LIMITS, holdRetryMs: this.#limits.holdRetryMs },
      now: this.#now,
      audit: (fields) => this.#audit(fields),
      identity: (connectorId) => this.#transferIdentity(connectorId),
      onStored: (connectorId) => this.#drain(connectorId),
      onScheduleChange: () => this.#notifyScheduleChange(),
    });
  }

  /**
   * Switching a database to WAL needs an exclusive lock and SQLite does not apply busy_timeout to
   * it, so a process opening a fresh database while another one does would fail at once. Retry
   * for up to the busy timeout instead. Already-WAL databases (every one after its first open)
   * skip the switch.
   */
  #enableWal(): void {
    const mode = () => Schema.decodeUnknownSync(JournalModeRow)(this.#db.prepare("PRAGMA journal_mode").get()).journal_mode;
    const deadline = Date.now() + BUSY_TIMEOUT_MS;
    for (;;) {
      try {
        if (mode() === "wal") return;
        this.#db.exec("PRAGMA journal_mode = WAL");
        return;
      } catch (error) {
        if (Date.now() >= deadline || !(error instanceof Error) || !/database is locked/.test(error.message)) throw error;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
      }
    }
  }

  /**
   * Creates and upgrades the schema in one write transaction, so the router and an admin command
   * starting together on the same database cannot both add a column: the second waits for the
   * first's lock (busy_timeout) and then finds the schema up to date.
   */
  #migrate(): void {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      this.#db.exec(SCHEMA);
      for (const [table, column, type] of ADDED_COLUMNS) {
        const columns = Schema.decodeUnknownSync(Schema.Array(ColumnRow))(
          this.#db.prepare(`PRAGMA table_info(${table})`).all(),
        );
        if (!columns.some((row) => row.name === column)) this.#db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
      }
      EventRouter.migrate(this.#db);
      Pairing.migrate(this.#db);
      TransferStore.migrate(this.#db);
      this.#db.exec("COMMIT");
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  now(): number {
    return this.#now();
  }

  /** Registers (or clears) a listener notified whenever `nextDeadlineMs()` may have moved. */
  setScheduleListener(fn: (() => void) | null): void {
    this.#scheduleListener = fn;
  }

  #notifyScheduleChange(): void {
    this.#scheduleListener?.();
  }

  /**
   * Earliest timestamp (ms) when `tick()` has work to do (event batch close/expiry/hold/wake-cap,
   * transfer expiry/hold, message expiry/hold, in-flight ack timeout, or retention pruning),
   * or `null` when completely idle.
   */
  nextDeadlineMs(): number | null {
    const now = this.#now();
    let earliest: number | null = null;
    const consider = (t: number | null | undefined) => {
      if (typeof t === "number" && Number.isFinite(t)) {
        earliest = earliest === null ? t : Math.min(earliest, t);
      }
    };

    consider(this.events.nextDeadlineMs());
    consider(this.transfers.nextDeadlineMs());

    const oldestPending = this.#db
      .prepare("SELECT MIN(sent_at) AS t FROM messages WHERE state = 'pending'")
      .get() as { t?: unknown } | undefined;
    if (typeof oldestPending?.t === "number") {
      consider(oldestPending.t + this.#limits.ttlMs);
    }

    const nextHold = this.#db
      .prepare("SELECT MIN(hold_until) AS t FROM messages WHERE state = 'pending' AND hold_until > ?")
      .get(now) as { t?: unknown } | undefined;
    if (typeof nextHold?.t === "number") consider(nextHold.t);

    for (const attachment of this.#attached.values()) {
      for (const offeredAt of attachment.inFlight.values()) {
        consider(offeredAt + this.#limits.ackTimeoutMs);
      }
    }

    const oldestSettled = this.#db
      .prepare("SELECT MIN(settled_at) AS t FROM messages WHERE state != 'pending' AND settled_at IS NOT NULL")
      .get() as { t?: unknown } | undefined;
    if (typeof oldestSettled?.t === "number") {
      const settledRetentionMs = this.#limits.settledRetentionMs ?? DEFAULT_SETTLED_RETENTION_MS;
      const pruneTarget = oldestSettled.t + settledRetentionMs;
      const nextPrune = Number.isFinite(this.#lastMessagePruneAt)
        ? Math.max(pruneTarget, this.#lastMessagePruneAt + MESSAGE_PRUNE_INTERVAL_MS)
        : pruneTarget;
      consider(nextPrune);
    }

    return earliest;
  }

  close(): void {
    this.#closed = true;
    this.#scheduleListener = null;
    this.#attached.clear();
    this.#db.close();
  }

  // ---- connectors ----

  /** Registers a connector and returns its bearer token (shown once; only the hash is stored). */
  addConnector(id: string): string {
    if (!isConnectorId(id)) throw new Error(`invalid connector id ${id}`);
    if (this.events.isPublisher(id)) throw new Error(`${id} is a publisher; publishers and connectors need different ids`);
    const token = `t3m_${randomBytes(32).toString("base64url")}`;
    this.#db
      .prepare("INSERT INTO connectors (id, token_hash, created_at) VALUES (?, ?, ?)")
      .run(id, hashToken(token), this.#now());
    this.#audit({ event: "connector.added", connector: id });
    return token;
  }

  /** Revokes a connector's token and unregisters its handles and subscriptions. */
  revokeConnector(id: string): boolean {
    const changed = this.#db
      .prepare("UPDATE connectors SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
      .run(this.#now(), id).changes;
    if (Number(changed) === 0) return false;
    this.setHandles(id, []);
    this.#db.prepare("DELETE FROM connector_keys WHERE connector_id = ?").run(id);
    this.events.removeConnector(id);
    this.transfers.removeConnector(id);
    this.#attached.delete(id);
    this.#audit({ event: "connector.revoked", connector: id });
    this.#notifyScheduleChange();
    return true;
  }

  /**
   * Registers a connector's self-signed Ed25519/X25519 public keys (`PUT /v1/keys`).
   * On strict paired routers (`--admin-key`), `TransferStore` still uses admin-signed pairing grants exclusively.
   */
  registerKeys(
    connectorId: string,
    body: unknown,
  ):
    | { readonly ok: true; readonly connectorId: string; readonly signingKey: string; readonly encryptionKey: string }
    | { readonly ok: false; readonly error: "invalid" | "unauthorized"; readonly message: string } {
    const active = this.#db.prepare("SELECT id FROM connectors WHERE id = ? AND revoked_at IS NULL").get(connectorId);
    if (active === undefined) {
      return { ok: false, error: "unauthorized", message: `connector ${connectorId} is not active` };
    }
    const decoded = decodeRegisterKeysBody(body);
    if (decoded._tag === "None") {
      return { ok: false, error: "invalid", message: "expected {signingKey, encryptionKey, proof: {payload, sig}}" };
    }
    const { signingKey, encryptionKey, proof } = decoded.value;
    if (!isRawKey(signingKey) || isSmallOrderKey(signingKey)) {
      return { ok: false, error: "invalid", message: "invalid Ed25519 signingKey" };
    }
    if (!isRawKey(encryptionKey) || Buffer.from(encryptionKey, "base64url").every((byte) => byte === 0)) {
      return { ok: false, error: "invalid", message: "invalid X25519 encryptionKey" };
    }
    let signingPub: KeyObject;
    try {
      signingPub = publicKeyFromRaw(signingKey, "ed25519");
      publicKeyFromRaw(encryptionKey, "x25519");
    } catch {
      return { ok: false, error: "invalid", message: "malformed public key material" };
    }
    if (!verifyPayload("key-reg", proof.payload, proof.sig, signingPub)) {
      return { ok: false, error: "unauthorized", message: "key registration proof signature is invalid" };
    }
    let parsedPayload: unknown;
    try {
      parsedPayload = JSON.parse(proof.payload);
    } catch {
      return { ok: false, error: "invalid", message: "key registration payload is not valid JSON" };
    }
    const payload = decodeKeyRegPayload(parsedPayload);
    if (
      payload._tag === "None" ||
      payload.value.connectorId !== connectorId ||
      payload.value.signingKey !== signingKey ||
      payload.value.encryptionKey !== encryptionKey
    ) {
      return { ok: false, error: "invalid", message: "key registration payload does not match connector and keys" };
    }
    this.#db
      .prepare(
        "INSERT INTO connector_keys (connector_id, signing_key, encryption_key, proof, registered_at) " +
          "VALUES (?, ?, ?, ?, ?) " +
          "ON CONFLICT (connector_id) DO UPDATE SET " +
          "signing_key = excluded.signing_key, encryption_key = excluded.encryption_key, " +
          "proof = excluded.proof, registered_at = excluded.registered_at",
      )
      .run(connectorId, signingKey, encryptionKey, JSON.stringify(proof), this.#now());
    this.#audit({ event: "connector.keys_registered", connector: connectorId, signingKey, encryptionKey });
    return { ok: true, connectorId, signingKey, encryptionKey };
  }

  /** Returns unrevoked connectors' public keys, preferring admin-paired identities whenever pairing is configured. */
  connectorKeys(): Array<{
    readonly connectorId: string;
    readonly signingKey: string;
    readonly encryptionKey: string;
    readonly source: "paired" | "registered";
  }> {
    const connectors = Schema.decodeUnknownSync(Schema.Array(ConnectorRow))(
      this.#db.prepare("SELECT id FROM connectors WHERE revoked_at IS NULL ORDER BY id").all(),
    );
    const registeredRows = decodeConnectorKeyRows(
      this.#db
        .prepare(
          "SELECT k.connector_id, k.signing_key, k.encryption_key, k.registered_at " +
            "FROM connector_keys k JOIN connectors c ON c.id = k.connector_id WHERE c.revoked_at IS NULL",
        )
        .all(),
    );
    const registered = new Map(registeredRows.map((row) => [row.connector_id, row]));
    const keys: Array<{
      readonly connectorId: string;
      readonly signingKey: string;
      readonly encryptionKey: string;
      readonly source: "paired" | "registered";
    }> = [];
    for (const { id } of connectors) {
      if (this.pairing.configured) {
        const paired = this.pairing.identity(id);
        if (paired !== undefined) {
          keys.push({
            connectorId: id,
            signingKey: paired.signingKey,
            encryptionKey: paired.encryptionKey,
            source: "paired",
          });
          continue;
        }
      }
      const reg = registered.get(id);
      if (reg !== undefined) {
        keys.push({
          connectorId: id,
          signingKey: reg.signing_key,
          encryptionKey: reg.encryption_key,
          source: "registered",
        });
      }
    }
    return keys;
  }

  /** Triggers an immediate inbox drain for `connectorId` when a transfer becomes ready. */
  notifyTransferReady(connectorId: string): void {
    this.#drain(connectorId);
  }

  #transferIdentity(connectorId: string): Identity | undefined {
    if (this.pairing.configured) return this.pairing.identity(connectorId);
    const row = this.#db
      .prepare(
        "SELECT k.connector_id, k.signing_key, k.encryption_key, k.registered_at " +
          "FROM connector_keys k JOIN connectors c ON c.id = k.connector_id " +
          "WHERE k.connector_id = ? AND c.revoked_at IS NULL",
      )
      .get(connectorId);
    if (row === undefined) return undefined;
    const parsed = decodeConnectorKeyRow(row);
    return {
      connectorId: parsed.connector_id,
      grantId: `registered:${parsed.connector_id}`,
      issuedAt: new Date(parsed.registered_at).toISOString(),
      scopes: REGISTERED_KEY_SCOPES,
      signingKey: parsed.signing_key,
      encryptionKey: parsed.encryption_key,
    };
  }

  /** Issues a new token for a connector that just paired; any older token of that ID stops working. */
  #issueToken(connectorId: string): string {
    if (this.events.isPublisher(connectorId)) throw new Error(`${connectorId} is a publisher`);
    const token = `t3m_${randomBytes(32).toString("base64url")}`;
    this.#db
      .prepare(
        "INSERT INTO connectors (id, token_hash, created_at) VALUES (?, ?, ?) " +
          "ON CONFLICT (id) DO UPDATE SET token_hash = excluded.token_hash, revoked_at = NULL",
      )
      .run(connectorId, hashToken(token), this.#now());
    return token;
  }

  /** Returns the connector ID for a valid, unrevoked token. */
  authenticate(token: string): string | null {
    const row = this.#db
      .prepare("SELECT id FROM connectors WHERE token_hash = ? AND revoked_at IS NULL")
      .get(hashToken(token));
    if (row === undefined) return null;
    const { id } = decodeConnectorRow(row);
    return this.#requirePairing && this.pairing.identity(id) === undefined ? null : id;
  }

  /** What the connector may do: its current grant's scopes, or those of an unpaired token. */
  scopesOf(connectorId: string): ScopeSet {
    return new ScopeSet(this.pairing.identity(connectorId)?.scopes ?? UNPAIRED_SCOPES);
  }

  /** Ensures a connector row exists without a usable token (loopback mode). */
  ensureLocalConnector(id: string): void {
    this.#db
      .prepare("INSERT OR IGNORE INTO connectors (id, token_hash, created_at) VALUES (?, ?, ?)")
      .run(id, hashToken(randomBytes(32).toString("hex")), this.#now());
  }

  // ---- handles ----

  setHandles(connectorId: string, handles: readonly string[]): { readonly ok: boolean; readonly invalid: string[] } {
    const invalid = handles.filter((handle) => !isHandle(handle));
    if (invalid.length > 0) return { ok: false, invalid };
    const next = new Set(handles);
    const current = this.#handlesOf(connectorId);
    for (const handle of current) {
      if (next.has(handle)) continue;
      this.#db.prepare("DELETE FROM handles WHERE connector_id = ? AND handle = ?").run(connectorId, handle);
      const to = formatAddress({ connectorId, handle });
      this.#db.prepare("DELETE FROM channel_members WHERE address = ?").run(to);
      const dropped = this.#db
        .prepare(
          "UPDATE messages SET state = 'rejected', reason = 'not_enrolled', settled_at = ? " +
            "WHERE to_addr = ? AND state = 'pending'",
        )
        .run(this.#now(), to).changes;
      this.#audit({ event: "handle.removed", to, dropped: Number(dropped) });
    }
    for (const handle of next) {
      if (current.has(handle)) continue;
      this.#db.prepare("INSERT INTO handles (connector_id, handle) VALUES (?, ?)").run(connectorId, handle);
      this.#audit({ event: "handle.added", to: formatAddress({ connectorId, handle }) });
    }
    this.#drain(connectorId);
    this.#notifyScheduleChange();
    return { ok: true, invalid: [] };
  }

  #handlesOf(connectorId: string): Set<string> {
    const rows = decodeHandleRows(
      this.#db.prepare("SELECT connector_id, handle FROM handles WHERE connector_id = ?").all(connectorId),
    );
    return new Set(rows.map((row) => row.handle));
  }

  #isEnrolled(address: string): boolean {
    const parsed = parseAddress(address);
    if (parsed === null) return false;
    return this.#handlesOf(parsed.connectorId).has(parsed.handle);
  }

  peers(): Peer[] {
    const rows = decodeHandleRows(
      this.#db
        .prepare(
          "SELECT h.connector_id, h.handle FROM handles h JOIN connectors c ON c.id = h.connector_id " +
            "WHERE c.revoked_at IS NULL ORDER BY h.connector_id, h.handle",
        )
        .all(),
    );
    return rows.map((row) => ({
      address: formatAddress({ connectorId: row.connector_id, handle: row.handle }),
      online: this.#attached.has(row.connector_id),
    }));
  }

  // ---- channels ----

  #channelMembers(channel: string): string[] {
    const rows = this.#db
      .prepare("SELECT address FROM channel_members WHERE channel = ? ORDER BY address")
      .all(channel) as Array<{ address?: unknown }>;
    return rows.map((r) => String(r.address)).filter((addr) => this.#isEnrolled(addr));
  }

  joinChannel(
    connectorId: string,
    handle: string,
    channel: string,
  ): { ok: true; channel: string; address: string; members: string[] } | { ok: false; error: "invalid" | "not_enrolled"; message: string } {
    if (!CHANNEL_NAME.test(channel)) return { ok: false, error: "invalid", message: `invalid channel name ${channel} (expected e.g. #incidents)` };
    if (!this.#handlesOf(connectorId).has(handle)) {
      return { ok: false, error: "not_enrolled", message: `handle ${handle} is not enrolled` };
    }
    const address = formatAddress({ connectorId, handle });
    this.#db
      .prepare("INSERT OR REPLACE INTO channel_members (channel, address, joined_at) VALUES (?, ?, ?)")
      .run(channel, address, this.#now());
    this.#audit({ event: "channel.joined", channel, address });
    return { ok: true, channel, address, members: this.#channelMembers(channel) };
  }

  leaveChannel(
    connectorId: string,
    handle: string,
    channel: string,
  ): { ok: true; channel: string; address: string; left: boolean } | { ok: false; error: "invalid"; message: string } {
    if (!CHANNEL_NAME.test(channel)) return { ok: false, error: "invalid", message: `invalid channel name ${channel}` };
    const address = formatAddress({ connectorId, handle });
    const changed = this.#db
      .prepare("DELETE FROM channel_members WHERE channel = ? AND address = ?")
      .run(channel, address).changes;
    const left = Number(changed) > 0;
    if (left) this.#audit({ event: "channel.left", channel, address });
    return { ok: true, channel, address, left };
  }

  channels(filterChannel?: string): Array<{ channel: string; members: string[] }> {
    const rows = (filterChannel
      ? this.#db.prepare("SELECT channel, address FROM channel_members WHERE channel = ? ORDER BY channel, address").all(filterChannel)
      : this.#db.prepare("SELECT channel, address FROM channel_members ORDER BY channel, address").all()
    ) as Array<{ channel?: unknown; address?: unknown }>;
    const byChannel = new Map<string, string[]>();
    for (const row of rows) {
      const ch = String(row.channel);
      const addr = String(row.address);
      if (!this.#isEnrolled(addr)) continue;
      const list = byChannel.get(ch) ?? [];
      list.push(addr);
      byChannel.set(ch, list);
    }
    return [...byChannel.entries()].map(([channel, members]) => ({ channel, members }));
  }

  postChannel(
    connectorId: string,
    input: { readonly id: string; readonly channel: string; readonly fromHandle: string; readonly text: string },
  ):
    | { ok: true; channel: string; deliveredTo: string[]; failed: Array<{ to: string; error: string }> }
    | { ok: false; error: "invalid" | "not_enrolled" | "not_member"; message: string } {
    if (!CHANNEL_NAME.test(input.channel)) return { ok: false, error: "invalid", message: `invalid channel name ${input.channel}` };
    if (!this.#handlesOf(connectorId).has(input.fromHandle)) {
      return { ok: false, error: "not_enrolled", message: `sender handle ${input.fromHandle} is not enrolled` };
    }
    const senderAddress = formatAddress({ connectorId, handle: input.fromHandle });
    const members = this.#channelMembers(input.channel);
    if (!members.includes(senderAddress)) {
      return { ok: false, error: "not_member", message: `join ${input.channel} before posting` };
    }
    const taggedText = `[${input.channel}] ${input.text}`;
    const deliveredTo: string[] = [];
    const failed: Array<{ to: string; error: string }> = [];
    for (const recipient of members) {
      if (recipient === senderAddress) continue;
      const res = this.submit(connectorId, {
        id: `${input.id}:${recipient}`,
        fromHandle: input.fromHandle,
        to: recipient,
        text: taggedText,
        origin: null,
      });
      if (res.ok) deliveredTo.push(recipient);
      else failed.push({ to: recipient, error: res.error });
    }
    this.#audit({ event: "channel.posted", channel: input.channel, from: senderAddress, recipients: deliveredTo.length });
    return { ok: true, channel: input.channel, deliveredTo, failed };
  }

  // ---- sending ----

  submit(connectorId: string, message: OutboundMessage): SendResult {
    if (!this.#handlesOf(connectorId).has(message.fromHandle)) {
      return { ok: false, error: "invalid", message: `sender handle ${message.fromHandle} is not enrolled` };
    }
    if (!this.scopesOf(connectorId).has("messages:send")) {
      return { ok: false, error: "not_granted", message: `${connectorId} is not granted messages:send` };
    }
    const from = formatAddress({ connectorId, handle: message.fromHandle });
    const digest = digestOf(from, message.to, message.text);
    const existing = this.#db.prepare("SELECT * FROM messages WHERE id = ?").get(message.id);
    if (existing !== undefined) {
      return decodeMessageRow(existing).digest === digest
        ? { ok: true, status: "stored" }
        : { ok: false, error: "id_conflict", message: `message id ${message.id} was used for different content` };
    }
    const refused = this.#refusal(message.to, message.text);
    if (refused !== null) {
      this.#audit({ event: "send.refused", id: message.id, from, to: message.to, error: refused.error });
      return refused;
    }
    this.#db
      .prepare(
        "INSERT INTO messages (id, from_addr, to_addr, text, digest, sent_at, state, origin_environment_id, origin_thread_id) " +
          "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
      )
      .run(
        message.id,
        from,
        message.to,
        message.text,
        digest,
        this.#now(),
        message.origin?.environmentId ?? null,
        message.origin?.threadId ?? null,
      );
    this.#audit({
      event: "send.stored",
      id: message.id,
      from,
      to: message.to,
      bytes: Buffer.byteLength(message.text, "utf8"),
    });
    const target = parseAddress(message.to);
    if (target !== null) this.#drain(target.connectorId);
    this.#notifyScheduleChange();
    return { ok: true, status: "stored" };
  }

  #refusal(to: string, text: string): Extract<SendResult, { ok: false }> | null {
    if (Buffer.byteLength(text, "utf8") > MAX_TEXT_BYTES) {
      return { ok: false, error: "too_large", message: `text exceeds ${MAX_TEXT_BYTES} bytes` };
    }
    if (!this.#isEnrolled(to)) return { ok: false, error: "unknown_recipient", message: `${to} is not enrolled` };
    const recipient = parseAddress(to);
    if (recipient !== null && !this.scopesOf(recipient.connectorId).has("messages:receive")) {
      return { ok: false, error: "not_granted", message: `${recipient.connectorId} is not granted messages:receive` };
    }
    const now = this.#now();
    const recent = decodeCount(
      this.#db
        .prepare("SELECT COUNT(*) AS n FROM messages WHERE to_addr = ? AND sent_at > ? AND state != 'rejected'")
        .get(to, now - HOUR_MS),
    );
    if (recent >= this.#limits.maxPerHourPerRecipient) {
      return { ok: false, error: "rate_limited", message: `${to} already received ${recent} messages in the last hour` };
    }
    const pending = decodeCount(
      this.#db.prepare("SELECT COUNT(*) AS n FROM messages WHERE to_addr = ? AND state = 'pending'").get(to),
    );
    if (pending >= this.#limits.maxPendingPerRecipient) {
      return { ok: false, error: "queue_full", message: `${to} has ${pending} undelivered messages` };
    }
    return null;
  }

  // ---- receiving ----

  /** Starts offering this connector's pending messages; returns a detach function. */
  attach(connectorId: string, offer: Offer): () => void {
    const attachment: Attachment = { offer, inFlight: new Map() };
    this.#attached.set(connectorId, attachment);
    this.#audit({ event: "connector.online", connector: connectorId });
    queueMicrotask(() => {
      if (this.#closed || this.#attached.get(connectorId) !== attachment) return;
      try {
        this.#drain(connectorId);
        this.#notifyScheduleChange();
      } catch (error) {
        if (this.#onDeferredError === undefined) throw error;
        this.#onDeferredError(error);
      }
    });
    return () => {
      if (this.#attached.get(connectorId) !== attachment) return;
      this.#attached.delete(connectorId);
      this.#audit({ event: "connector.offline", connector: connectorId });
      this.#notifyScheduleChange();
    };
  }

  ack(connectorId: string, id: string, outcome: InboundOutcome): boolean {
    const row = this.#db.prepare("SELECT * FROM messages WHERE id = ? AND state = 'pending'").get(id);
    if (row === undefined) {
      if (!this.events.ack(connectorId, id, outcome) && !this.transfers.ack(connectorId, id, outcome)) return false;
      this.#attached.get(connectorId)?.inFlight.delete(id);
      this.#drain(connectorId);
      this.#notifyScheduleChange();
      return true;
    }
    const message = decodeMessageRow(row);
    if (parseAddress(message.to_addr)?.connectorId !== connectorId) return false;
    this.#attached.get(connectorId)?.inFlight.delete(id);
    const now = this.#now();
    switch (outcome.kind) {
      case "delivered":
        this.#db.prepare("UPDATE messages SET state = 'delivered', settled_at = ? WHERE id = ?").run(now, id);
        break;
      case "rejected":
        this.#db
          .prepare("UPDATE messages SET state = 'rejected', reason = ?, settled_at = ? WHERE id = ?")
          .run(outcome.reason, now, id);
        break;
      case "hold":
        this.#db
          .prepare("UPDATE messages SET reason = ?, hold_until = ? WHERE id = ?")
          .run(outcome.reason, now + this.#limits.holdRetryMs, id);
        break;
    }
    this.#audit({
      event: `message.${outcome.kind}`,
      id,
      from: message.from_addr,
      to: message.to_addr,
      ...(outcome.kind === "delivered" ? {} : { reason: outcome.reason }),
    });
    this.#drain(connectorId);
    this.#notifyScheduleChange();
    return true;
  }

  /** Periodic housekeeping: expiry, hold and ack-timeout retries, closing event batches. */
  tick(): void {
    this.events.tick();
    this.transfers.tick();
    const now = this.#now();
    const expired = decodeMessageRows(
      this.#db.prepare("SELECT * FROM messages WHERE state = 'pending' AND sent_at <= ?").all(now - this.#limits.ttlMs),
    );
    for (const message of expired) {
      this.#db.prepare("UPDATE messages SET state = 'expired', settled_at = ? WHERE id = ?").run(now, message.id);
      this.#audit({ event: "message.expired", id: message.id, from: message.from_addr, to: message.to_addr });
    }
    const settledRetentionMs = this.#limits.settledRetentionMs ?? DEFAULT_SETTLED_RETENTION_MS;
    if (now - this.#lastMessagePruneAt >= MESSAGE_PRUNE_INTERVAL_MS) {
      this.#lastMessagePruneAt = now;
      this.#db
        .prepare("DELETE FROM messages WHERE state != 'pending' AND settled_at IS NOT NULL AND settled_at <= ?")
        .run(now - settledRetentionMs);
    }
    for (const [connectorId, attachment] of this.#attached) {
      for (const [id, offeredAt] of attachment.inFlight) {
        if (now - offeredAt >= this.#limits.ackTimeoutMs) attachment.inFlight.delete(id);
      }
      this.#drain(connectorId);
    }
    this.#notifyScheduleChange();
  }

  /**
   * Offers the oldest due pending message of each of the connector's recipients, and the oldest
   * due batch of each of its subscriptions: one in flight per recipient or subscription, so order
   * is kept and a held item blocks the ones behind it.
   */
  #drain(connectorId: string): void {
    const attachment = this.#attached.get(connectorId);
    if (attachment === undefined) return;
    const now = this.#now();
    for (const handle of this.#handlesOf(connectorId)) {
      const to = formatAddress({ connectorId, handle });
      const row = this.#db
        .prepare("SELECT * FROM messages WHERE to_addr = ? AND state = 'pending' ORDER BY sent_at, id LIMIT 1")
        .get(to);
      if (row === undefined) continue;
      const message = decodeMessageRow(row);
      if (attachment.inFlight.has(message.id) || now - message.sent_at >= this.#limits.ttlMs) continue;
      const holdUntil = decodeCount(
        this.#db.prepare("SELECT hold_until AS n FROM messages WHERE id = ?").get(message.id),
      );
      if (holdUntil > now) continue;
      attachment.inFlight.set(message.id, now);
      attachment.offer({
        kind: "message",
        id: message.id,
        from: message.from_addr,
        to: message.to_addr,
        text: message.text,
        sentAt: new Date(message.sent_at).toISOString(),
        origin:
          message.origin_environment_id !== null && message.origin_thread_id !== null
            ? { environmentId: message.origin_environment_id, threadId: message.origin_thread_id }
            : null,
      });
    }
    for (const batch of this.events.dueBatches(connectorId, (id) => attachment.inFlight.has(id))) {
      attachment.inFlight.set(batch.id, now);
      attachment.offer(batch);
    }
    const transfer = this.transfers.due(connectorId, (id) => attachment.inFlight.has(id));
    if (transfer !== null) {
      attachment.inFlight.set(transfer.id, now);
      attachment.offer({ kind: "transfer", ...transfer });
    }
  }

  #audit(fields: Readonly<Record<string, unknown>>): void {
    if (this.#auditPath === undefined) return;
    appendFileSync(this.#auditPath, JSON.stringify({ at: new Date(this.#now()).toISOString(), ...fields }) + "\n", {
      mode: 0o600,
    });
  }
}
