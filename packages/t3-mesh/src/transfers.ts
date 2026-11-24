// The connector's transfers (SPEC.md sections 14.5 and 15): the checked directory, sealing and
// sending, and receiving: common checks here, then files (15.4) or forks (section 16, src/fork.ts).
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as Schema from "effect/Schema";
import { formatAddress, parseAddress } from "./address.ts";
import type { ConnectorConfig } from "./config.ts";
import { ConnectorDirectory } from "./identity/directory.ts";
import type { Identity } from "./identity/grant.ts";
import { publicKeyFromRaw } from "./identity/keys.ts";
import { readKeys, type ConnectorKeys } from "./identity/pairClient.ts";
import { ScopeSet } from "./identity/scopes.ts";
import { toolError, type ToolResponse } from "./ipc.ts";
import { errorMessage, log } from "./log.ts";
import type { InboundOutcome, InboundTransfer, RouterLink, TransferSendResult } from "./router/types.ts";
import { FilesMeta, FilesRefused, MAX_NOTE_BYTES, collectFiles, formatFilesDelivery, writeReceived } from "./transfer/files.ts";
import { PackError, PackTooLarge, compressPack, decompressPack, type Pack, type PackFile } from "./transfer/pack.ts";
import { OpenError, open, readHeader, seal, type TransferHeader, type TransferType } from "./transfer/seal.ts";

const DIRECTORY_REFRESH_MS = 5 * 60 * 1000;
export const TRANSFER_TTL_MS = 24 * 60 * 60 * 1000;

export const SendFilesArgs = Schema.Struct({
  to: Schema.String,
  paths: Schema.Array(Schema.String),
  note: Schema.optionalKey(Schema.String),
});

/** Delivers a formatted turn into a thread with the delivery policy applied (the daemon's dispatch). */
export type DispatchInto = (threadId: string, prefix: "mesh-files", id: string, text: string) => Promise<InboundOutcome>;

/** A received transfer whose signature, addressing and contents have been checked. */
export interface OpenedTransfer {
  readonly header: TransferHeader;
  readonly sender: Identity;
  readonly pack: Pack;
}

/** Handles fork transfers (src/fork.ts). */
export interface ForkHandler {
  receiveFork(opened: OpenedTransfer): Promise<InboundOutcome>;
  receiveResult(opened: OpenedTransfer): Promise<InboundOutcome>;
  /** Tells the sender a fork was refused before it was opened, so its thread is not left waiting. */
  refuseFork(header: TransferHeader, sender: Identity, reason: string): Promise<void>;
}

export class Transfers {
  readonly #config: ConnectorConfig;
  readonly #router: RouterLink;
  readonly #keys: ConnectorKeys;
  readonly directory: ConnectorDirectory;
  #forks: ForkHandler | null = null;
  #timer: NodeJS.Timeout | null = null;

  private constructor(config: ConnectorConfig, router: RouterLink, keys: ConnectorKeys, directory: ConnectorDirectory) {
    this.#config = config;
    this.#router = router;
    this.#keys = keys;
    this.directory = directory;
  }

  /** Null until the connector has paired (no keys, no admin key to check the directory with). */
  static open(config: ConnectorConfig, router: RouterLink): Transfers | null {
    if (config.identity === null) return null;
    return new Transfers(
      config,
      router,
      readKeys(config.identity.keysPath),
      new ConnectorDirectory(config.identity.adminKey, join(config.stateDir, "transfers.json")),
    );
  }

  attachForks(handler: ForkHandler): void {
    this.#forks = handler;
  }

  /** Fetches and checks the directory now and every 5 minutes. */
  start(): void {
    if (this.#timer !== null) return;
    void this.refresh();
    this.#timer = setInterval(() => void this.refresh(), DIRECTORY_REFRESH_MS);
  }

  async refresh(): Promise<void> {
    try {
      const response = await this.#router.directory();
      if (response === null) return;
      for (const problem of this.directory.apply(response)) {
        log(problem.kind === "invalid" ? "warn" : "error", `directory.${problem.kind}`, {
          connector: problem.connectorId,
          reason: problem.reason,
        });
      }
    } catch (error) {
      log("warn", "directory.refresh_failed", { error: errorMessage(error) });
    }
  }

  /** This connector's scopes, from its own entry in the directory. */
  myScopes(): ScopeSet {
    return new ScopeSet(this.directory.identity(this.#config.connectorId)?.scopes ?? []);
  }

  /** A connector's current identity, refreshing the directory once if it is not known yet. */
  async identityOf(connectorId: string): Promise<Identity | undefined> {
    const known = this.directory.identity(connectorId);
    if (known !== undefined) return known;
    await this.refresh();
    return this.directory.identity(connectorId);
  }

  /** Seals `pack` to `to` and hands it to the router. */
  async send(type: TransferType, to: Identity, toHandle: string | null, pack: Pack): Promise<{ readonly id: string; readonly sent: TransferSendResult }> {
    const id = randomUUID();
    const sealed = seal(
      { id, type, from: this.#config.connectorId, to: to.connectorId, toHandle, ttlMs: TRANSFER_TTL_MS },
      await compressPack(pack),
      this.#keys.signing,
      to.encryptionKey,
    );
    return { id, sent: await this.#router.sendTransfer(sealed.header, sealed.ciphertext) };
  }

  /** `mesh_send_files`, for a joined thread whose working directory is `cwd`. */
  async sendFiles(fromHandle: string, cwd: string, args: unknown): Promise<ToolResponse> {
    const parsed = Schema.decodeUnknownOption(SendFilesArgs)(args);
    if (parsed._tag === "None") return toolError("invalid", "mesh_send_files needs {to, paths, note?}");
    const { to, paths, note } = parsed.value;
    const address = parseAddress(to);
    if (address === null) return toolError("invalid_address", "to must be <connector>/<handle>, see mesh_peers");
    if (note !== undefined && Buffer.byteLength(note, "utf8") > MAX_NOTE_BYTES) return toolError("too_large", `note exceeds ${MAX_NOTE_BYTES} bytes`);
    await this.refresh();
    const recipient = this.directory.identity(address.connectorId);
    if (recipient === undefined) return toolError("unknown_recipient", `${address.connectorId} is not a paired connector`);
    if (!this.myScopes().maySend("files", address.connectorId)) {
      return toolError("not_granted", `${this.#config.connectorId} is not granted files:send to ${address.connectorId}`);
    }
    if (!new ScopeSet(recipient.scopes).has("files:receive")) {
      return toolError("not_granted", `${address.connectorId} is not granted files:receive`);
    }
    let files: PackFile[];
    try {
      files = this.collect(paths, cwd);
    } catch (error) {
      if (error instanceof FilesRefused) return toolError(error.code, error.message);
      throw error;
    }
    const meta: FilesMeta = { fromAddress: formatAddress({ connectorId: this.#config.connectorId, handle: fromHandle }), note: note ?? null };
    let result;
    try {
      result = await this.send("files", recipient, address.handle, { meta, files });
    } catch (error) {
      if (error instanceof PackError) return toolError(error instanceof PackTooLarge ? "too_large" : "refused_path", error.message);
      throw error;
    }
    const bytes = files.reduce((total, file) => total + file.data.length, 0);
    const { id, sent } = result;
    log(sent.ok ? "info" : "warn", "files.sent", { id, to, files: files.length, bytes, ...(sent.ok ? {} : { error: sent.error }) });
    return sent.ok ? { ok: true, result: { transferId: id, files: files.length, bytes } } : toolError(sent.error, sent.message);
  }

  /** Files a thread may send: under its working directory, the T3 scratch directory or the temporary directory. */
  collect(paths: readonly string[], cwd: string): PackFile[] {
    return collectFiles(paths, cwd, [cwd, join(this.#config.t3Home, "scratch"), tmpdir(), "/tmp"]);
  }

  /** An inbound transfer, logged with its outcome. `threadOfHandle` finds the enrolled thread for files. */
  async receive(item: InboundTransfer, threadOfHandle: (handle: string) => string | undefined, dispatch: DispatchInto): Promise<InboundOutcome> {
    let outcome: InboundOutcome;
    try {
      outcome = await this.#receive(item, threadOfHandle, dispatch);
    } catch (error) {
      outcome = { kind: "hold", reason: `failed: ${errorMessage(error)}` };
    }
    log(outcome.kind === "delivered" ? "info" : "warn", "transfer.received", {
      id: item.id,
      from: item.from,
      type: item.type,
      outcome: outcome.kind,
      ...(outcome.kind === "delivered" ? {} : { reason: outcome.reason }),
    });
    return outcome;
  }

  async #receive(item: InboundTransfer, threadOfHandle: (handle: string) => string | undefined, dispatch: DispatchInto): Promise<InboundOutcome> {
    const header = readHeader(item.header);
    if (header === null) return { kind: "rejected", reason: "corrupt" };
    if (header.to !== this.#config.connectorId) return { kind: "rejected", reason: "wrong_connector" };
    if (Date.parse(header.expiresAt) <= Date.now()) return { kind: "rejected", reason: "expired" };
    const sender = await this.identityOf(header.from);
    if (sender === undefined) return { kind: "rejected", reason: "unknown_sender" };
    const senderScopes = new ScopeSet(sender.scopes);
    const mine = this.myScopes();

    if (header.type === "files") {
      if (!senderScopes.maySend("files", this.#config.connectorId) || !mine.has("files:receive")) return { kind: "rejected", reason: "not_granted" };
      const accept = this.#config.accept.files;
      if (accept !== null && !accept.includes(header.from)) return { kind: "rejected", reason: "not_accepted" };
      const threadId = header.toHandle === null ? undefined : threadOfHandle(header.toHandle);
      if (threadId === undefined) return { kind: "rejected", reason: "not_enrolled" };
      // Offered again after a held delivery: the files are already written, so only the turn is retried.
      const dir = join(this.#config.stateDir, "received", header.id);
      const written = this.directory.hasSeen(header.id) && existsSync(dir);
      if (this.directory.hasSeen(header.id) && !written) return { kind: "rejected", reason: "replayed" };
      const opened = await this.#open(item, header, sender);
      if (!opened.ok) return opened.outcome;
      const meta = Schema.decodeUnknownOption(FilesMeta)(opened.value.pack.meta);
      // The sender address is a claim inside the sealed pack; its connector must be the signer.
      if (meta._tag === "None" || parseAddress(meta.value.fromAddress)?.connectorId !== header.from) return { kind: "rejected", reason: "corrupt" };
      if (!written) {
        if (!this.directory.markSeen(header.id)) return { kind: "rejected", reason: "replayed" };
        try {
          writeReceived(dir, opened.value.pack.files);
        } catch (error) {
          return { kind: "rejected", reason: `write_failed: ${errorMessage(error)}` };
        }
      }
      return dispatch(threadId, "mesh-files", header.id, formatFilesDelivery(meta.value.fromAddress, meta.value.note, dir, opened.value.pack.files));
    }

    const forks = this.#forks;
    if (forks === null) return { kind: "rejected", reason: "forks_unavailable" };
    if (header.type === "fork") {
      const accept = this.#config.accept.forks;
      const refusal =
        !senderScopes.maySend("forks", this.#config.connectorId) || mine.forkCeiling() === null
          ? "not_granted"
          : accept !== null && !accept.includes(header.from)
            ? "not_accepted"
            : null;
      if (refusal !== null) {
        await forks.refuseFork(header, sender, refusal);
        return { kind: "rejected", reason: refusal };
      }
      const opened = await this.#open(item, header, sender);
      return opened.ok ? forks.receiveFork(opened.value) : opened.outcome;
    }
    if (senderScopes.forkCeiling() === null || !mine.mayForkOut()) return { kind: "rejected", reason: "not_granted" };
    const opened = await this.#open(item, header, sender);
    return opened.ok ? forks.receiveResult(opened.value) : opened.outcome;
  }

  /** Fetches, checks and decrypts a transfer, then decodes its pack. */
  async #open(
    item: InboundTransfer,
    header: TransferHeader,
    sender: Identity,
  ): Promise<{ readonly ok: true; readonly value: OpenedTransfer } | { readonly ok: false; readonly outcome: InboundOutcome }> {
    let ciphertext: Buffer;
    try {
      ciphertext = await this.#router.fetchTransfer(header.id);
    } catch (error) {
      return { ok: false, outcome: { kind: "hold", reason: `fetch_failed: ${errorMessage(error)}` } };
    }
    try {
      const opened = open(item.header, ciphertext, publicKeyFromRaw(sender.signingKey, "ed25519"), this.#keys.encryption);
      return { ok: true, value: { header: opened.header, sender, pack: await decompressPack(opened.plaintext) } };
    } catch (error) {
      if (error instanceof OpenError) return { ok: false, outcome: { kind: "rejected", reason: error.reason } };
      if (error instanceof PackError) return { ok: false, outcome: { kind: "rejected", reason: "corrupt" } };
      throw error;
    }
  }
}
