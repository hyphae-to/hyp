// Forks (SPEC.md section 16): mesh_fork copies the calling Claude thread, with its session, to
// another connector's T3; the target creates a thread bound to the session, moves the mesh handle
// and subscriptions to it, and answers with a fork.result so the source can let go of them.
import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import * as Schema from "effect/Schema";
import {
  CommandId,
  ModelSelection,
  ProjectId,
  ProviderDriverKind,
  ProviderInteractionMode,
  ThreadId,
  type OrchestrationMessageContext,
  type OrchestrationProjectShell,
} from "@t3tools/contracts";
import { formatAddress, parseAddress } from "./address.ts";
import type { ConnectorConfig } from "./config.ts";
import { fenceFor } from "./eventDelivery.ts";
import { contextLink, isContextId, neutralizeContextLinks, threadContext } from "./header.ts";
import { isRuntimeMode, lowerMode, ScopeSet, type RuntimeMode } from "./identity/scopes.ts";
import { toolError, type ToolResponse } from "./ipc.ts";
import { errorMessage, log } from "./log.ts";
import type { InboundOutcome } from "./router/types.ts";
import type { EnrollmentStore, Subscription } from "./store.ts";
import type { SetAutoSettle, Subscriptions } from "./subscriptions.ts";
import { optsOutOfAutoSettle } from "./tidy.ts";
import { SUBSCRIPTION_KEY } from "./tools.ts";
import { claudeProjectDir, cutTranscriptAfter, moveTranscriptCwd } from "./t3/claudeTranscript.ts";
import type { T3Connection } from "./t3/connection.ts";
import { classifyThread } from "./t3/threadState.ts";
import { FilesRefused, writeReceived } from "./transfer/files.ts";
import { PackError, PackTooLarge, type PackFile } from "./transfer/pack.ts";
import type { Identity } from "./identity/grant.ts";
import type { TransferHeader } from "./transfer/seal.ts";
import type { ForkHandler, OpenedTransfer, Transfers } from "./transfers.ts";

const run = promisify(execFile);
const MAX_FORK_NOTE_BYTES = 16 * 1024;
const SESSION_FILE = "session.jsonl";
const FILES_PREFIX = "files/";
const SHELL_WAIT_MS = 10_000;

export const ForkArgs = Schema.Struct({
  to: Schema.String,
  note: Schema.String,
  paths: Schema.optionalKey(Schema.Array(Schema.String)),
  project: Schema.optionalKey(Schema.String),
});

const ForkMeta = Schema.Struct({
  v: Schema.Literal(1),
  sourceEnvironmentId: Schema.String,
  sourceThreadId: Schema.String,
  sourceAddress: Schema.NullOr(Schema.String),
  title: Schema.String,
  /** The source thread's ModelSelection, encoded. */
  modelSelection: Schema.Unknown,
  runtimeMode: Schema.String,
  interactionMode: Schema.String,
  repository: Schema.NullOr(Schema.String),
  branch: Schema.NullOr(Schema.String),
  commit: Schema.NullOr(Schema.String),
  /** The source's working directory, rewritten to the target's in the transcript. */
  cwd: Schema.String,
  sessionId: Schema.String,
  handle: Schema.NullOr(Schema.String),
  // `key` since mesh_subscribe needs one; forks from older connectors carry none and get one here.
  subscriptions: Schema.Array(
    Schema.Struct({ key: Schema.optionalKey(Schema.String), topic: Schema.String, filters: Schema.Array(Schema.Unknown), coalesceSeconds: Schema.Number }),
  ),
  note: Schema.String,
  /** A target project ID, when repository matching is not enough. */
  project: Schema.NullOr(Schema.String),
});
type ForkMeta = typeof ForkMeta.Type;

const ForkResultMeta = Schema.Struct({
  v: Schema.Literal(1),
  forkId: Schema.String,
  ok: Schema.Boolean,
  environmentId: Schema.NullOr(Schema.String),
  threadId: Schema.NullOr(Schema.String),
  address: Schema.NullOr(Schema.String),
  subscriptions: Schema.Number,
  reason: Schema.NullOr(Schema.String),
});
type ForkResultMeta = typeof ForkResultMeta.Type;

type ForkedSubscription = ForkMeta["subscriptions"][number];

/** The subscriptions a fork carries, each with its key; one stored before keys gets `legacy:<id>`. */
export const forkedSubscriptions = (stored: readonly Subscription[]): ForkedSubscription[] =>
  stored.filter((subscription) => (subscription.router ?? "primary") === "primary")
    .map(({ id, key, topic, filters, coalesceSeconds }) => ({ key: key ?? `legacy:${id}`, topic, filters, coalesceSeconds }));

/** Keep v1 unchanged: describe host-local subscriptions in the existing handoff note, never in its set. */
export function forkNote(note: string, stored: readonly Subscription[]): string {
  const local = stored.filter((subscription) => (subscription.router ?? "primary") !== "primary");
  if (local.length === 0) return note;
  return `${note}\n\nExtra-router subscriptions left on the source host (not carried by this fork):\n` +
    local.map(({ id, key, router, topic }) => JSON.stringify({ key: key ?? `legacy:${id}`, router, topic })).join("\n") +
    "\nSubscribe again only after the destination connector has that router configured. Always pass router explicitly to mesh_subscribe; never omit router.";
}

/** mesh_subscribe arguments for a forked subscription; one from an older sender, without a key, gets a stable one. */
export const recreateArgs = (forkId: string, index: number, forked: ForkedSubscription) => ({
  ...forked,
  key: forked.key ?? `forked:${forkId}-${index}`,
});

/** What recreating a fork's subscriptions on the target did. */
export interface RecreatedSubscriptions {
  /** Forked subscriptions the thread got. */
  readonly recreated: number;
  /** Keys the thread got, each recorded as soon as it was stored. */
  readonly done: readonly string[];
  /** Subscriptions not recreated: the key (null when it is not a valid key), and the refusal's code. */
  readonly failed: ReadonlyArray<{ readonly key: string | null; readonly code: string }>;
  /** Protected keys whose auto-settle opt-out failed, and why. */
  readonly optOutFailed: ReadonlyArray<{ readonly key: string; readonly reason: string }>;
}

const idOf = (result: unknown): string | undefined =>
  typeof result === "object" && result !== null && "id" in result && typeof result.id === "string" ? result.id : undefined;

/**
 * Recreates a fork's subscriptions on the target thread, keys kept, and opts the thread out of T3's
 * auto-settle for each assignment or role key, as `mesh_subscribe` does. Each key is created only if
 * the thread has none (checked in the queue `mesh_subscribe` uses), and `record` gets the keys done so far as
 * soon as each is stored, before anything else runs. Keys in `done`, from an earlier run cut short,
 * are not created again; a held protected key among them gets its opt-out again (same command ID).
 */
export async function recreateForkedSubscriptions(
  subscriptions: Pick<Subscriptions, "subscribeIfMissing">,
  setAutoSettle: SetAutoSettle,
  threadId: string,
  forkId: string,
  forked: readonly ForkedSubscription[],
  done: ReadonlySet<string>,
  held: readonly Pick<Subscription, "id" | "key">[],
  record: (done: readonly string[]) => void,
): Promise<RecreatedSubscriptions> {
  const heldIds = new Map(held.flatMap(({ id, key }) => (key === undefined ? [] : [[key, id] as const])));
  const nowDone = new Set(done);
  let recreated = 0;
  const failed: Array<{ key: string | null; code: string }> = [];
  const optOutFailed: Array<{ key: string; reason: string }> = [];
  for (const [index, each] of forked.entries()) {
    const { key, ...subscription } = recreateArgs(forkId, index, each);
    let id: string | undefined;
    if (done.has(key)) {
      id = heldIds.get(key);
    } else {
      const response = await subscriptions.subscribeIfMissing(threadId, { ...subscription, key }, () => {
        nowDone.add(key);
        record([...nowDone]);
      });
      if (!response.ok) {
        log("warn", "fork.subscription_failed", { forkId, topic: subscription.topic, key, error: response.error.code });
        // The key comes from the source connector: only name it here if it is one.
        failed.push({ key: SUBSCRIPTION_KEY.test(key) ? key : null, code: response.error.code });
        continue;
      }
      id = idOf(response.result);
    }
    recreated += 1;
    if (id !== undefined && optsOutOfAutoSettle(key)) {
      const reason = await setAutoSettle(threadId, false, id);
      if (reason !== null) optOutFailed.push({ key, reason });
    }
  }
  return { recreated, done: [...nowDone], failed, optOutFailed };
}

/** The target's first-turn lines about subscriptions it could not recreate or keep parked. */
export function recreateNotes(result: Pick<RecreatedSubscriptions, "failed" | "optOutFailed">): { notMoved: string | null; optOut: string | null } {
  const named = result.failed.map(({ key, code }) => `${key ?? "one with an invalid key"} (${code})`);
  return {
    notMoved:
      named.length === 0
        ? null
        : `the subscription(s) ${named.join(", ")}; call mesh_subscribe with the same key and the topic and filters from the source to recreate them`,
    optOut:
      result.optOutFailed.length === 0
        ? null
        : `T3 auto-settle could not be turned off for ${result.optOutFailed.map(({ key, reason }) => `${key} (${reason})`).join(", ")}; ` +
          "this thread may be settled while it waits. Call mesh_subscribe again with the same key, topic and filters to retry.",
  };
}

/** A fork's recreate on the target, kept across offers of the same fork. */
const ForkProgress = Schema.Struct({
  v: Schema.Literal(1),
  /** Keys the thread got, recorded as each was stored. */
  done: Schema.Array(Schema.String),
  /** Set once the recreate finished; a later offer reuses it and recreates nothing. */
  outcome: Schema.NullOr(
    Schema.Struct({
      recreated: Schema.Number,
      failed: Schema.Array(Schema.Struct({ key: Schema.NullOr(Schema.String), code: Schema.String })),
      optOutFailed: Schema.Array(Schema.Struct({ key: Schema.String, reason: Schema.String })),
    }),
  ),
});
type ForkProgress = typeof ForkProgress.Type;

export const forkProgressPath = (stateDir: string, forkId: string): string => join(stateDir, "forks", `${forkId}.json`);

/** The progress kept so far, or null on a first offer. A file that cannot be read counts as none (logged). */
function readProgress(path: string): ForkProgress | null {
  if (!existsSync(path)) return null;
  try {
    const decoded = Schema.decodeUnknownOption(ForkProgress)(JSON.parse(readFileSync(path, "utf8")));
    if (decoded._tag === "Some") return decoded.value;
  } catch {
    // Reported below.
  }
  log("warn", "fork.progress_unreadable", { path });
  return null;
}

function writeProgress(path: string, progress: ForkProgress): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.${process.pid}.tmp`;
  writeFileSync(temp, `${JSON.stringify(progress)}\n`, { mode: 0o600 });
  renameSync(temp, path);
}

/** Recreates running in this daemon, by progress path: an overlapping offer of a fork joins its run. */
const recreating = new Map<string, Promise<RecreatedSubscriptions>>();

/**
 * Runs a fork's recreate once, before its first turn. A later offer of the same fork (its result could
 * not be sent) gets the recorded outcome and recreates nothing, so nothing the thread did after its
 * first turn is undone, and that turn's subscription notes are the same. An offer that overlaps a run
 * still going (the router offers a transfer again after 60 s without an ack) joins that run. A run cut
 * short (the daemon stopped) is finished by the next offer, without creating again the keys recorded
 * as stored. What failed is named in the first turn, for the agent to retry with `mesh_subscribe`,
 * which also retries the opt-out.
 *
 * Limit: an event for a subscription already recreated can wake the thread before its first turn.
 * A key it removes then stays removed if it was already recorded, but one the run has not reached yet
 * is created when the run gets to it.
 */
export function recreateOnce(
  path: string,
  run: (done: ReadonlySet<string>, record: (done: readonly string[]) => void) => Promise<RecreatedSubscriptions>,
): Promise<RecreatedSubscriptions> {
  const running = recreating.get(path);
  if (running !== undefined) return running;
  const started = (async () => {
    const before = readProgress(path);
    if (before !== null && before.outcome !== null) return { ...before.outcome, done: before.done };
    const result = await run(new Set(before?.done ?? []), (done) => writeProgress(path, { v: 1, done, outcome: null }));
    const { recreated, failed, optOutFailed } = result;
    writeProgress(path, { v: 1, done: result.done, outcome: { recreated, failed, optOutFailed } });
    return result;
  })().finally(() => recreating.delete(path));
  recreating.set(path, started);
  return started;
}

/** What a fork needs from the daemon. */
export interface ForkHost {
  readonly config: ConnectorConfig;
  readonly store: EnrollmentStore;
  readonly subscriptions: Subscriptions;
  connection(): T3Connection | null;
  /** Re-sends the handle set after a join or leave. */
  syncHandles(): Promise<void>;
  /** Dispatches a turn into a thread, with the delivery policy applied. */
  dispatch(threadId: string, prefix: "mesh-fork", id: string, text: string, context: OrchestrationMessageContext | null): Promise<InboundOutcome>;
  /** Turns T3's auto-settle off (an assignment or role key is held) or back on (its last protected key left). */
  readonly setAutoSettle: SetAutoSettle;
}

/** Every Claude home on this host: ~/.claude and ~/.claude-* (other provider instances). */
const claudeHomes = (): string[] =>
  readdirSync(homedir())
    .filter((name) => name === ".claude" || name.startsWith(".claude-"))
    .map((name) => join(homedir(), name));

function findSessionFile(sessionId: string): string | undefined {
  for (const home of claudeHomes()) {
    const projects = join(home, "projects");
    if (!existsSync(projects)) continue;
    for (const dir of readdirSync(projects)) {
      const file = join(projects, dir, `${sessionId}.jsonl`);
      if (existsSync(file)) return file;
    }
  }
  return undefined;
}

const git = async (cwd: string, ...args: string[]): Promise<string | null> =>
  run("git", ["-C", cwd, ...args]).then(
    (result) => result.stdout.trim(),
    () => null,
  );

interface GitState {
  readonly branch: string | null;
  readonly commit: string | null;
}

/** The branch and commit, or why the work is not safe to leave behind (uncommitted or unpushed). */
export async function gitState(cwd: string): Promise<{ ok: true; state: GitState } | { ok: false; message: string }> {
  if ((await git(cwd, "rev-parse", "--is-inside-work-tree")) !== "true") return { ok: true, state: { branch: null, commit: null } };
  const status = await git(cwd, "status", "--porcelain");
  if (status === null) return { ok: false, message: "git status failed" };
  if (status !== "") {
    return {
      ok: false,
      message: `uncommitted changes in ${cwd}; commit and push them (or send scratch files with paths):\n${status.split("\n").slice(0, 20).join("\n")}`,
    };
  }
  const commit = await git(cwd, "rev-parse", "HEAD");
  const branch = await git(cwd, "rev-parse", "--abbrev-ref", "HEAD");
  const upstream = await git(cwd, "rev-parse", "@{u}");
  if (upstream === null) return { ok: false, message: `branch ${branch ?? "HEAD"} has no upstream; push it first` };
  if (upstream !== commit) return { ok: false, message: `branch ${branch ?? "HEAD"} is not pushed (HEAD ${commit}, upstream ${upstream}); push it first` };
  return { ok: true, state: { branch: branch === "HEAD" ? null : branch, commit } };
}

/** The worktree of `root`'s repository that has `branch` checked out, else `root`. */
export async function workingDirectoryFor(root: string, branch: string | null): Promise<string> {
  if (branch === null) return root;
  const list = await git(root, "worktree", "list", "--porcelain");
  if (list === null) return root;
  let current: string | null = null;
  for (const line of list.split("\n")) {
    if (line.startsWith("worktree ")) current = line.slice("worktree ".length);
    else if (line === `branch refs/heads/${branch}` && current !== null) return current;
  }
  return root;
}

const fenced = (text: string): string => {
  const fence = fenceFor(text);
  return `${fence}\n${text}\n${fence}`;
};

export class Forks implements ForkHandler {
  readonly #host: ForkHost;
  readonly #transfers: Transfers;

  constructor(host: ForkHost, transfers: Transfers) {
    this.#host = host;
    this.#transfers = transfers;
  }

  // ---- source ----

  /** `mesh_fork` from `threadId`. */
  async start(threadId: string, args: unknown): Promise<ToolResponse> {
    const parsed = Schema.decodeUnknownOption(ForkArgs)(args);
    if (parsed._tag === "None") return toolError("invalid", "mesh_fork needs {to, note, paths?, project?}");
    const { to, note, paths, project } = parsed.value;
    if (Buffer.byteLength(note, "utf8") > MAX_FORK_NOTE_BYTES) return toolError("too_large", `note exceeds ${MAX_FORK_NOTE_BYTES} bytes`);
    const { config, store } = this.#host;
    if (to === config.connectorId) return toolError("invalid", "a fork goes to another connector");
    await this.#transfers.refresh();
    const recipient = this.#transfers.directory.identity(to);
    if (recipient === undefined) return toolError("unknown_recipient", `${to} is not a paired connector`);
    if (!this.#transfers.myScopes().maySend("forks", to)) return toolError("not_granted", `${config.connectorId} is not granted forks:send to ${to}`);
    if (new ScopeSet(recipient.scopes).forkCeiling() === null) return toolError("not_granted", `${to} is not granted forks:receive`);

    const connection = this.#host.connection();
    const entry = connection?.shellEntry(threadId);
    if (connection === null || entry === undefined) return toolError("unknown_thread", "cannot find this thread");
    const projection = await connection.threadProjection(ThreadId.make(threadId));
    const own = projection.providerThreads
      .filter((provider) => provider.appThreadId === threadId && provider.ownerNodeId === null)
      .sort((a, b) => (a.lastRunOrdinal ?? 0) - (b.lastRunOrdinal ?? 0));
    const current = own.at(-1);
    if (current === undefined || current.driver !== "claudeAgent") {
      return toolError("unsupported_provider", "only Claude threads can be forked so far");
    }
    const sessionId = current.nativeThreadRef?.nativeId ?? null;
    if (sessionId === null) return toolError("unsupported_provider", "this thread's Claude session id is not known yet");
    // The session as of the last completed turn, as T3's own fork cuts it; the current turn is in the note.
    const lastTurn = projection.providerTurns
      .filter((turn) => turn.providerThreadId === current.id && turn.status === "completed" && turn.nativeTurnRef?.nativeId != null)
      .sort((a, b) => a.ordinal - b.ordinal)
      .at(-1);
    const cutAt = lastTurn?.nativeTurnRef?.nativeId ?? null;
    if (cutAt === null) return toolError("nothing_to_fork", "this thread has no completed turn yet");
    const sessionFile = findSessionFile(sessionId);
    if (sessionFile === undefined) return toolError("unsupported_provider", `no transcript for Claude session ${sessionId}`);
    const transcript = cutTranscriptAfter(readFileSync(sessionFile, "utf8"), cutAt);
    if (transcript === null) return toolError("internal", `the transcript has no record ${cutAt} (the last completed turn)`);

    const thread = projection.thread;
    const cwd = thread.worktreePath ?? connection.project(thread.projectId)?.workspaceRoot;
    if (cwd === undefined) return toolError("unknown_thread", "cannot find this thread's working directory");
    const git = await gitState(cwd);
    if (!git.ok) return toolError("unpushed_work", git.message);

    let files: PackFile[] = [];
    try {
      if (paths !== undefined && paths.length > 0) files = this.#transfers.collect(paths, cwd);
    } catch (error) {
      if (error instanceof FilesRefused) return toolError(error.code, error.message);
      throw error;
    }
    const enrollment = store.byThread(threadId);
    const meta: ForkMeta = {
      v: 1,
      sourceEnvironmentId: connection.descriptor.environmentId,
      sourceThreadId: threadId,
      sourceAddress: enrollment === undefined ? null : formatAddress({ connectorId: config.connectorId, handle: enrollment.handle }),
      title: thread.title,
      modelSelection: Schema.encodeSync(ModelSelection)(thread.modelSelection),
      runtimeMode: thread.runtimeMode,
      interactionMode: thread.interactionMode,
      repository: connection.project(thread.projectId)?.repositoryIdentity?.canonicalKey ?? null,
      branch: git.state.branch,
      commit: git.state.commit,
      cwd,
      sessionId,
      handle: enrollment?.handle ?? null,
      subscriptions: forkedSubscriptions(store.subscriptionsOf(threadId)),
      note: forkNote(note, store.subscriptionsOf(threadId)),
      project: project ?? null,
    };
    let result;
    try {
      result = await this.#transfers.send("fork", recipient, null, {
        meta,
        files: [{ path: SESSION_FILE, data: Buffer.from(transcript, "utf8") }, ...files.map((file) => ({ path: `${FILES_PREFIX}${file.path}`, data: file.data }))],
      });
    } catch (error) {
      if (error instanceof PackError) return toolError(error instanceof PackTooLarge ? "too_large" : "refused_path", error.message);
      throw error;
    }
    const { id, sent } = result;
    log(sent.ok ? "info" : "warn", "fork.sent", { id, threadId, to, files: files.length, ...(sent.ok ? {} : { error: sent.error }) });
    if (!sent.ok) return toolError(sent.error, sent.message);
    this.#transfers.directory.addPendingFork(id, threadId, to);
    return {
      ok: true,
      result: {
        forkId: id,
        to,
        status: "sent",
        next: "The target creates the thread and replies; this thread gets a turn with a link to it. Until then, keep working or end your turn.",
      },
    };
  }

  /** A fork.result for a fork this connector sent. */
  async receiveResult(opened: OpenedTransfer): Promise<InboundOutcome> {
    const meta = Schema.decodeUnknownOption(ForkResultMeta)(opened.pack.meta);
    if (meta._tag === "None") return { kind: "rejected", reason: "corrupt" };
    const result = meta.value;
    const pending = this.#transfers.directory.takePendingFork(result.forkId, opened.header.from);
    if (pending === undefined) return { kind: "rejected", reason: "unknown_fork" };
    const { threadId } = pending;
    const { store, subscriptions } = this.#host;
    if (!result.ok || result.environmentId === null || result.threadId === null) {
      return this.#host.dispatch(
        threadId,
        "mesh-fork",
        opened.header.id,
        `mesh fork result · the fork to ${opened.header.from} failed · ${result.reason ?? "no reason given"}\n\nThis thread keeps its mesh handle and subscriptions.`,
        null,
      );
    }
    // A fork moves only primary subscriptions. Host-local event subscriptions keep running here.
    const moved = await subscriptions.pruneThreadWithAutoSettle(threadId, this.#host.setAutoSettle, "primary");
    const left = store.byThread(threadId);
    if (left !== undefined && result.address !== null) {
      store.leave(threadId);
      await this.#host.syncHandles();
    }
    log("info", "fork.completed", { forkId: result.forkId, threadId, to: opened.header.from, target: result.threadId, subscriptions: moved });
    const label = result.address ?? `${opened.header.from} thread`;
    const lines = [
      `mesh fork result · forked to ${contextLink(label)} · remote thread`,
      "",
      `The fork runs on ${opened.header.from}.` +
        (moved > 0 ? ` ${moved} subscription(s) moved there (${result.subscriptions} recreated).` : "") +
        (left !== undefined && result.address !== null ? ` This thread left the mesh; the fork is ${result.address}.` : ""),
      "This thread stays as a record of the work so far.",
    ];
    const context = isContextId(result.environmentId) && isContextId(result.threadId) ? threadContext(label, result.environmentId, result.threadId) : null;
    return this.#host.dispatch(threadId, "mesh-fork", opened.header.id, lines.join("\n"), context);
  }

  // ---- target ----

  async refuseFork(header: TransferHeader, sender: Identity, reason: string): Promise<void> {
    const result: ForkResultMeta = { v: 1, forkId: header.id, ok: false, environmentId: null, threadId: null, address: null, subscriptions: 0, reason };
    // Best effort: without forks:receive this connector may not send results either.
    const { sent } = await this.#transfers.send("fork.result", sender, null, { meta: result, files: [] });
    log("warn", "fork.refused", { forkId: header.id, from: header.from, reason, resultSent: sent.ok });
  }

  async receiveFork(opened: OpenedTransfer): Promise<InboundOutcome> {
    const connection = this.#host.connection();
    if (connection === null) return { kind: "hold", reason: "t3_unavailable" };
    const meta = Schema.decodeUnknownOption(ForkMeta)(opened.pack.meta);
    const session = opened.pack.files.find((file) => file.path === SESSION_FILE);
    if (meta._tag === "None" || session === undefined) return { kind: "rejected", reason: "corrupt" };
    const forkId = opened.header.id;
    let outcome: { ok: true; threadId: string; address: string | null; subscriptions: number } | { ok: false; reason: string };
    try {
      outcome = await this.#createFork(connection, forkId, meta.value, session.data, opened);
    } catch (error) {
      outcome = { ok: false, reason: `failed: ${errorMessage(error)}` };
    }
    const result: ForkResultMeta = outcome.ok
      ? { v: 1, forkId, ok: true, environmentId: connection.descriptor.environmentId, threadId: outcome.threadId, address: outcome.address, subscriptions: outcome.subscriptions, reason: null }
      : { v: 1, forkId, ok: false, environmentId: null, threadId: null, address: null, subscriptions: 0, reason: outcome.reason };
    const { sent } = await this.#transfers.send("fork.result", opened.sender, null, { meta: result, files: [] });
    log(outcome.ok ? "info" : "warn", "fork.received", {
      forkId,
      from: opened.header.from,
      ...(outcome.ok ? { threadId: outcome.threadId } : { reason: outcome.reason }),
      resultSent: sent.ok,
    });
    if (!sent.ok) return { kind: "hold", reason: `result_not_sent: ${sent.error}` };
    return outcome.ok ? { kind: "delivered" } : { kind: "rejected", reason: outcome.reason };
  }

  async #targetProject(connection: T3Connection, meta: ForkMeta): Promise<OrchestrationProjectShell | string> {
    if (meta.project !== null) return connection.project(meta.project) ?? `no project ${meta.project} here`;
    if (meta.repository === null) return "the source project has no repository identity; fork again with project";
    // Repository identities can arrive a few seconds after connecting.
    const deadline = Date.now() + SHELL_WAIT_MS;
    for (;;) {
      const all = [...connection.projects()];
      const matches = all.filter((project) => project.repositoryIdentity?.canonicalKey === meta.repository);
      const [only] = matches;
      if (matches.length === 1 && only !== undefined) return only;
      if (matches.length > 1) return `${matches.length} projects match ${meta.repository}; fork again with project (${matches.map((p) => p.id).join(", ")})`;
      if (Date.now() >= deadline || all.every((project) => project.repositoryIdentity != null)) return `no project matches ${meta.repository}`;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }

  async #createFork(
    connection: T3Connection,
    forkId: string,
    meta: ForkMeta,
    transcript: Buffer,
    opened: OpenedTransfer,
  ): Promise<{ ok: true; threadId: string; address: string | null; subscriptions: number } | { ok: false; reason: string }> {
    const { config, store, subscriptions } = this.#host;
    // Deterministic, so a transfer offered again after a held delivery finds the thread it made.
    const threadId = `mesh-fork:${forkId}`;
    const existing = connection.shellEntry(threadId);
    if (existing === undefined) {
      const project = await this.#targetProject(connection, meta);
      if (typeof project === "string") return { ok: false, reason: `no_project: ${project}` };
      const cwd = await workingDirectoryFor(project.workspaceRoot, meta.branch);
      const dir = join(homedir(), ".claude", "projects", claudeProjectDir(cwd));
      const file = join(dir, `${meta.sessionId}.jsonl`);
      const { text } = moveTranscriptCwd(transcript.toString("utf8"), meta.cwd, cwd);
      if (existsSync(file) && readFileSync(file, "utf8") !== text) return { ok: false, reason: `session_exists: ${file} has other content` };
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      writeFileSync(file, text, { mode: 0o600 });
      const ceiling = this.#transfers.myScopes().forkCeiling() ?? "approval-required";
      const sourceMode: RuntimeMode = isRuntimeMode(meta.runtimeMode) ? meta.runtimeMode : "approval-required";
      const interaction = Schema.decodeUnknownOption(ProviderInteractionMode)(meta.interactionMode);
      const created = await connection.dispatch({
        type: "thread.create",
        commandId: CommandId.make(`mesh-fork:create:${forkId}`),
        threadId: ThreadId.make(threadId),
        projectId: ProjectId.make(project.id),
        title: meta.title,
        modelSelection: Schema.decodeUnknownSync(ModelSelection)(meta.modelSelection),
        runtimeMode: lowerMode(sourceMode, ceiling),
        interactionMode: interaction._tag === "Some" ? interaction.value : "default",
        branch: meta.branch,
        worktreePath: cwd === project.workspaceRoot ? null : cwd,
        createdBy: "agent",
        creationSource: "server",
        importedNativeThread: { ref: { driver: ProviderDriverKind.make("claudeAgent"), nativeId: meta.sessionId, strength: "strong" } },
      });
      if (!created.ok) return { ok: false, reason: `create_failed: ${created.message}` };
      const deadline = Date.now() + SHELL_WAIT_MS;
      while (connection.shellEntry(threadId) === undefined && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 250));
    }
    const entry = connection.shellEntry(threadId);
    if (entry === undefined || classifyThread(entry.thread, entry.location) === "archived") return { ok: false, reason: "thread_not_created" };

    const files = opened.pack.files.filter((file) => file.path.startsWith(FILES_PREFIX)).map((file) => ({ path: file.path.slice(FILES_PREFIX.length), data: file.data }));
    const filesDir = join(config.stateDir, "received", forkId);
    if (files.length > 0 && !existsSync(filesDir)) writeReceived(filesDir, files);

    // Once per fork, before its first turn; an overlapping offer joins the run (see recreateOnce).
    const result = await recreateOnce(forkProgressPath(config.stateDir, forkId), (done, record) =>
      recreateForkedSubscriptions(subscriptions, this.#host.setAutoSettle, threadId, forkId, meta.subscriptions, done, store.subscriptionsOf(threadId), record),
    );
    const { recreated } = result;
    const notes = recreateNotes(result);
    let address: string | null = null;
    if (meta.handle !== null) {
      const holder = store.byHandle(meta.handle);
      if (holder === undefined || holder.threadId === threadId) {
        if (holder === undefined && store.join(threadId, meta.handle).ok) await this.#host.syncHandles();
        address = formatAddress({ connectorId: config.connectorId, handle: meta.handle });
      }
    }

    // Built by the source connector, but only used if it names the connector that signed the fork.
    const source =
      meta.sourceAddress !== null && parseAddress(meta.sourceAddress)?.connectorId === opened.header.from
        ? meta.sourceAddress
        : `${opened.header.from} thread`;
    const notMoved = [
      meta.handle !== null && address === null ? `the handle ${meta.handle} (taken here; join with another)` : null,
      notes.notMoved,
      "running processes, T3 attachments and subagent threads from the source",
    ].filter((item): item is string => item !== null);
    const text = [
      `mesh fork from ${contextLink(source)} · remote thread · reply with mesh_send`,
      "",
      `This thread was forked from ${source} on ${opened.header.from}; the conversation above is the source thread's up to its last completed turn.` +
        ` It runs in ${entry.thread.worktreePath ?? "the project root"}` +
        (meta.branch === null ? "." : `; the source was on branch ${meta.branch} at ${meta.commit ?? "?"} (pushed), check it out if this directory is on another branch.`),
      address === null ? "" : `Mesh address: ${address}. Subscriptions recreated: ${recreated}.`,
      files.length === 0 ? "" : `Files sent with the fork are in ${filesDir}.`,
      `Not moved: ${notMoved.join("; ")}.`,
      notes.optOut ?? "",
      "",
      "Handoff note from the source thread:",
      fenced(neutralizeContextLinks(meta.note)),
    ]
      .filter((line, index, all) => !(line === "" && all[index - 1] === ""))
      .join("\n");
    const context =
      isContextId(meta.sourceEnvironmentId) && isContextId(meta.sourceThreadId) ? threadContext(source, meta.sourceEnvironmentId, meta.sourceThreadId) : null;
    const delivered = await this.#host.dispatch(threadId, "mesh-fork", forkId, text, context);
    if (delivered.kind !== "delivered") log("warn", "fork.first_turn_not_delivered", { forkId, threadId, outcome: delivered.kind, reason: delivered.reason });
    return { ok: true, threadId, address, subscriptions: recreated };
  }
}
