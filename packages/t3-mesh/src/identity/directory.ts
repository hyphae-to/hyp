// The connector's view of the directory (SPEC.md section 14.5): every entry and revocation checked
// against the pinned admin key, the current identity per connector, and a rollback guard kept in
// `transfers.json` so a router cannot bring back a superseded key.
import type { KeyObject } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import * as Schema from "effect/Schema";
import { EntrySchema, SignedSchema, openRevocation, verifyEntry, type Identity } from "./grant.ts";
import { publicKeyFromRaw } from "./keys.ts";
import type { DirectoryResponse } from "../router/types.ts";

const SEEN_TRANSFER_MS = 48 * 60 * 60 * 1000;

const StateFile = Schema.Struct({
  v: Schema.Literal(1),
  /** Latest grant accepted per connector. */
  pins: Schema.Array(Schema.Struct({ connectorId: Schema.String, grantId: Schema.String, issuedAt: Schema.String })),
  /** Transfers already handled, so a replayed one is refused (SPEC.md section 15.4). */
  seen: Schema.Array(Schema.Struct({ id: Schema.String, at: Schema.Number })),
  /** Forks this connector sent and is waiting for a fork.result on (SPEC.md section 16). */
  forks: Schema.optionalKey(Schema.Array(Schema.Struct({ id: Schema.String, threadId: Schema.String, to: Schema.String, at: Schema.Number }))),
});
type StateFile = typeof StateFile.Type;

export interface DirectoryProblem {
  readonly kind: "invalid" | "rollback" | "admin_key_mismatch";
  readonly connectorId?: string;
  readonly reason: string;
}

export class ConnectorDirectory {
  readonly #adminKeyRaw: string;
  readonly #adminKey: KeyObject;
  readonly #statePath: string;
  readonly #now: () => number;
  #state: StateFile;
  #current = new Map<string, Identity>();

  constructor(adminKey: string, statePath: string, now: () => number = Date.now) {
    this.#adminKeyRaw = adminKey;
    this.#adminKey = publicKeyFromRaw(adminKey, "ed25519");
    this.#statePath = statePath;
    this.#now = now;
    this.#state = ConnectorDirectory.#load(statePath);
  }

  static #load(path: string): StateFile {
    try {
      return Schema.decodeUnknownSync(StateFile)(JSON.parse(readFileSync(path, "utf8")));
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return { v: 1, pins: [], seen: [] };
      throw error;
    }
  }

  #save(): void {
    const temporary = `${this.#statePath}.tmp`;
    writeFileSync(temporary, JSON.stringify(this.#state) + "\n", { mode: 0o600 });
    renameSync(temporary, this.#statePath);
  }

  /** A connector's current identity, if the last refresh had a valid one. */
  identity(connectorId: string): Identity | undefined {
    return this.#current.get(connectorId);
  }

  /** Replaces the current identities with those of a fetched directory; returns what was refused. */
  apply(response: DirectoryResponse): DirectoryProblem[] {
    if (response.adminKey !== this.#adminKeyRaw) {
      return [{ kind: "admin_key_mismatch", reason: "the router serves a different admin key than the one pinned at pairing" }];
    }
    const problems: DirectoryProblem[] = [];
    const revoked = new Set<string>();
    for (const item of response.revocations) {
      const signed = Schema.decodeUnknownOption(SignedSchema)(item);
      const revocation = signed._tag === "Some" ? openRevocation(signed.value, this.#adminKey) : null;
      if (revocation === null) problems.push({ kind: "invalid", reason: "a revocation does not check against the admin key" });
      else revoked.add(revocation.grantId);
    }
    const latest = new Map<string, Identity>();
    for (const item of response.entries) {
      const entry = Schema.decodeUnknownOption(EntrySchema)(item);
      if (entry._tag === "None") {
        problems.push({ kind: "invalid", reason: "a malformed entry" });
        continue;
      }
      const verified = verifyEntry(entry.value, this.#adminKey);
      if (!verified.ok) {
        problems.push({ kind: "invalid", reason: verified.reason });
        continue;
      }
      const previous = latest.get(verified.identity.connectorId);
      if (previous === undefined || Date.parse(verified.identity.issuedAt) > Date.parse(previous.issuedAt)) {
        latest.set(verified.identity.connectorId, verified.identity);
      }
    }
    const pins = new Map(this.#state.pins.map((pin) => [pin.connectorId, pin]));
    const next = new Map<string, Identity>();
    for (const [connectorId, identity] of latest) {
      const pin = pins.get(connectorId);
      if (pin !== undefined && Date.parse(identity.issuedAt) < Date.parse(pin.issuedAt)) {
        problems.push({ kind: "rollback", connectorId, reason: `the router serves grant ${identity.grantId}, older than accepted grant ${pin.grantId}` });
        continue;
      }
      if (revoked.has(identity.grantId)) continue;
      next.set(connectorId, identity);
      pins.set(connectorId, { connectorId, grantId: identity.grantId, issuedAt: identity.issuedAt });
    }
    this.#current = next;
    this.#state = { ...this.#state, pins: [...pins.values()] };
    this.#save();
    return problems;
  }

  /** Records a transfer as handled; false if it was seen before (a replay). */
  markSeen(id: string): boolean {
    const cutoff = this.#now() - SEEN_TRANSFER_MS;
    const seen = this.#state.seen.filter((item) => item.at >= cutoff);
    if (seen.some((item) => item.id === id)) return false;
    this.#state = { ...this.#state, seen: [...seen, { id, at: this.#now() }] };
    this.#save();
    return true;
  }

  hasSeen(id: string): boolean {
    return this.#state.seen.some((item) => item.id === id);
  }

  addPendingFork(id: string, threadId: string, to: string): void {
    this.#state = { ...this.#state, forks: [...(this.#state.forks ?? []), { id, threadId, to, at: this.#now() }] };
    this.#save();
  }

  /** The pending fork `id` sent to `from`, removed; undefined if there is none (or it went elsewhere). */
  takePendingFork(id: string, from: string): { readonly threadId: string } | undefined {
    const fork = (this.#state.forks ?? []).find((item) => item.id === id && item.to === from);
    if (fork === undefined) return undefined;
    this.#state = { ...this.#state, forks: (this.#state.forks ?? []).filter((item) => item.id !== id) };
    this.#save();
    return { threadId: fork.threadId };
  }
}
