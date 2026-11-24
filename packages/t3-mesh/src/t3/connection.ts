// One authenticated WebSocket RPC connection to the connector's own T3 server (loopback only).
// Keeps a live cache of the thread shell and exposes the few RPCs the connector uses.
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as Layer from "effect/Layer";
import * as Result from "effect/Result";
import * as Schedule from "effect/Schedule";
import * as Schema from "effect/Schema";
import * as Scope from "effect/Scope";
import * as Stream from "effect/Stream";
import * as RpcClient from "effect/rpc/RpcClient";
import * as RpcSerialization from "effect/rpc/RpcSerialization";
import * as Socket from "effect/socket/Socket";
import { randomUUID } from "node:crypto";
import {
  CommandId,
  ProjectId,
  type AgentSessionImportInput,
  type AgentSessionImportResult,
  type AgentSessionScanResult,
  ExecutionEnvironmentDescriptor,
  ORCHESTRATION_PROTOCOL_VERSION,
  ORCHESTRATION_V2_WS_METHODS,
  type OrchestrationProjectShell,
  type Project,
  type OrchestrationV2Command,
  type OrchestrationV2ShellStreamItem,
  type OrchestrationV2ThreadProjection,
  type OrchestrationV2ThreadShell,
  type ThreadId,
  WS_METHODS,
  WsRpcGroup,
} from "@t3tools/contracts";
import type { ShellLocation } from "./threadState.ts";

// client-runtime stopped exporting its factory; this is the same one.
const makeWsRpcProtocolClient = RpcClient.make(WsRpcGroup);
type WsClient = Effect.Success<typeof makeWsRpcProtocolClient>;

export interface ShellEntry {
  readonly thread: OrchestrationV2ThreadShell;
  readonly location: ShellLocation;
}

export type DispatchOutcome =
  | { readonly ok: true; readonly sequence: number }
  /** T3 refused the command; its receipt for this command ID is now permanently rejected. */
  | { readonly ok: false; readonly kind: "rejected"; readonly message: string }
  /** The command may or may not have been applied; retry with the same command ID. */
  | { readonly ok: false; readonly kind: "transport"; readonly message: string };

export class IncompatibleServerError extends Error {}

const decodeDescriptor = Schema.decodeUnknownSync(ExecutionEnvironmentDescriptor);
const TicketResponse = Schema.Struct({ ticket: Schema.String });
const decodeTicket = Schema.decodeUnknownSync(TicketResponse);

/** How long one connection attempt may take, from the descriptor fetch to the first shell snapshot. */
export const OPEN_TIMEOUT_MS = 30_000;

export async function fetchDescriptor(baseUrl: string, signal?: AbortSignal): Promise<ExecutionEnvironmentDescriptor> {
  const response = await fetch(`${baseUrl}/.well-known/t3/environment`, signal === undefined ? {} : { signal });
  if (!response.ok) throw new Error(`environment descriptor: HTTP ${response.status}`);
  return decodeDescriptor(await response.json());
}

async function fetchWebSocketTicket(baseUrl: string, token: string, signal: AbortSignal): Promise<string> {
  const response = await fetch(`${baseUrl}/api/auth/websocket-ticket`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
    signal,
  });
  if (!response.ok) throw new Error(`websocket ticket: HTTP ${response.status}`);
  return decodeTicket(await response.json()).ticket;
}

/** Settles like `promise`, or rejects when `signal` aborts first. */
const untilAborted = <A>(promise: Promise<A>, signal: AbortSignal): Promise<A> =>
  new Promise<A>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    if (signal.aborted) return onAbort();
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });

const describeCause = (error: unknown): string => {
  if (typeof error === "object" && error !== null && "message" in error && typeof error.message === "string") {
    return error.message;
  }
  return String(error);
};

export class T3Connection {
  readonly descriptor: ExecutionEnvironmentDescriptor;
  /** Resolves when the shell subscription ends, i.e. the connection is no longer usable. */
  readonly closed: Promise<string>;
  readonly #client: WsClient;
  readonly #scope: Scope.Closeable;
  readonly #shell: Map<string, ShellEntry>;
  readonly #projects: Map<string, OrchestrationProjectShell>;

  private constructor(
    descriptor: ExecutionEnvironmentDescriptor,
    client: WsClient,
    scope: Scope.Closeable,
    shell: Map<string, ShellEntry>,
    projects: Map<string, OrchestrationProjectShell>,
    closed: Promise<string>,
  ) {
    this.descriptor = descriptor;
    this.#client = client;
    this.#scope = scope;
    this.#shell = shell;
    this.#projects = projects;
    this.closed = closed;
  }

  /**
   * Connects, checks the orchestration protocol, and waits for the first shell snapshot.
   * Throws IncompatibleServerError when the server speaks a different protocol, and fails after
   * `timeoutMs`: a T3 that accepts connections while still starting up can otherwise stall an
   * attempt indefinitely.
   */
  static async open(baseUrl: string, token: string, timeoutMs = OPEN_TIMEOUT_MS): Promise<T3Connection> {
    const deadline = AbortSignal.timeout(timeoutMs);
    let stage = "environment descriptor";
    try {
      return await T3Connection.#open(baseUrl, token, deadline, (next) => (stage = next));
    } catch (error) {
      if (deadline.aborted) throw new Error(`no answer from T3 within ${timeoutMs / 1000}s (${stage})`);
      throw error;
    }
  }

  static async #open(
    baseUrl: string,
    token: string,
    deadline: AbortSignal,
    setStage: (stage: string) => void,
  ): Promise<T3Connection> {
    const descriptor = await fetchDescriptor(baseUrl, deadline);
    const serverProtocol = descriptor.orchestrationProtocolVersion ?? 1;
    if (serverProtocol !== ORCHESTRATION_PROTOCOL_VERSION) {
      throw new IncompatibleServerError(
        `T3 ${descriptor.serverVersion} speaks orchestration protocol ${serverProtocol}; ` +
          `this connector was built for ${ORCHESTRATION_PROTOCOL_VERSION}. Update the t3-mesh pin.`,
      );
    }
    setStage("websocket ticket");
    const ticket = await fetchWebSocketTicket(baseUrl, token, deadline);
    const socketUrl =
      `${baseUrl.replace(/^http/, "ws")}/ws?wsTicket=${encodeURIComponent(ticket)}` +
      `&orchestrationProtocol=${ORCHESTRATION_PROTOCOL_VERSION}`;

    const protocolLayer = Layer.effect(
      RpcClient.Protocol,
      RpcClient.makeProtocolSocket({ retryTransientErrors: false, retryPolicy: Schedule.recurs(0) }),
    ).pipe(
      Layer.provide(
        Layer.mergeAll(
          Socket.layerWebSocket(socketUrl).pipe(Layer.provide(Socket.layerWebSocketConstructorGlobal)),
          RpcSerialization.layerJson,
        ),
      ),
    );

    const scope = await Effect.runPromise(Scope.make());
    const shell = new Map<string, ShellEntry>();
    const projects = new Map<string, OrchestrationProjectShell>();
    let markReady: () => void = () => {};
    const ready = new Promise<void>((resolve) => {
      markReady = resolve;
    });

    try {
      setStage("websocket");
      const { client, fiber } = await untilAborted(
        Effect.runPromise(
          Effect.gen(function* () {
            const context = yield* Layer.buildWithScope(protocolLayer, scope);
            const client = yield* makeWsRpcProtocolClient.pipe(Effect.provide(context), Scope.provide(scope));
            const fiber = yield* client[ORCHESTRATION_V2_WS_METHODS.subscribeShell]({}).pipe(
              Stream.runForEach((item) =>
                Effect.sync(() => {
                  applyProjectItem(projects, item);
                  if (applyShellItem(shell, item)) markReady();
                }),
              ),
              Effect.forkIn(scope),
            );
            return { client, fiber };
          }),
        ),
        deadline,
      );
      const closed = Effect.runPromise(Fiber.await(fiber)).then((exit) =>
        Exit.isSuccess(exit) ? "shell subscription ended" : `shell subscription failed: ${describeCause(exit.cause)}`,
      );
      setStage("first shell snapshot");
      const outcome = await untilAborted(Promise.race([ready.then(() => null), closed]), deadline);
      if (outcome !== null) throw new Error(outcome);
      return new T3Connection(descriptor, client, scope, shell, projects, closed);
    } catch (error) {
      await Effect.runPromise(Scope.close(scope, Exit.void));
      throw error;
    }
  }

  shellEntry(threadId: string): ShellEntry | undefined {
    return this.#shell.get(threadId);
  }

  shellEntries(): IterableIterator<ShellEntry> {
    return this.#shell.values();
  }

  project(projectId: string): OrchestrationProjectShell | undefined {
    return this.#projects.get(projectId);
  }

  projects(): IterableIterator<OrchestrationProjectShell> {
    return this.#projects.values();
  }

  /** Finds Claude/Codex/pi sessions on this host's disk, grouped by working directory. */
  async scanAgentSessions(): Promise<AgentSessionScanResult> {
    return Effect.runPromise(this.#client[WS_METHODS.agentSessionsScan]({}));
  }

  /** Imports every not-yet-imported session whose cwd is the project's root as a thread with history. */
  async importAgentSessions(input: AgentSessionImportInput): Promise<AgentSessionImportResult> {
    return Effect.runPromise(this.#client[WS_METHODS.agentSessionsImport](input));
  }

  /**
   * Creates a project rooted at an existing directory. Without project scripts, projects.mutate
   * needs only orchestration:operate, which the connector's token has.
   */
  async createProject(title: string, workspaceRoot: string): Promise<Project> {
    return Effect.runPromise(
      this.#client[WS_METHODS.projectsMutate]({
        type: "project.create",
        commandId: CommandId.make(`t3-mesh:project:${randomUUID()}`),
        projectId: ProjectId.make(randomUUID()),
        title,
        workspaceRoot,
      }),
    );
  }

  async dispatch(command: OrchestrationV2Command): Promise<DispatchOutcome> {
    const result = await Effect.runPromise(
      Effect.result(this.#client[ORCHESTRATION_V2_WS_METHODS.dispatchCommand](command)),
    );
    if (Result.isSuccess(result)) return { ok: true, sequence: result.success.sequence };
    const error = result.failure;
    return error._tag === "OrchestrationV2DispatchCommandError"
      ? { ok: false, kind: "rejected", message: error.detail ?? error.message }
      : { ok: false, kind: "transport", message: describeCause(error) };
  }

  async threadProjection(threadId: ThreadId): Promise<OrchestrationV2ThreadProjection> {
    return Effect.runPromise(this.#client[ORCHESTRATION_V2_WS_METHODS.getThreadProjection]({ threadId }));
  }

  async close(): Promise<void> {
    await Effect.runPromise(Scope.close(this.#scope, Exit.void));
  }
}

/** Applies one shell stream item's project changes. Enrichment snapshots refresh projects only. */
export function applyProjectItem(
  projects: Map<string, OrchestrationProjectShell>,
  item: OrchestrationV2ShellStreamItem,
): void {
  switch (item.kind) {
    case "snapshot":
      if (item.resolvedRepositoryIdentityRoots === undefined) projects.clear();
      for (const project of item.snapshot.projects) projects.set(project.id, project);
      return;
    case "project.updated":
      projects.set(item.project.id, item.project);
      return;
    case "project.removed":
      projects.delete(item.projectId);
      return;
    default:
      return;
  }
}

/** Applies one shell stream item; returns true once a full snapshot has been seen. */
export function applyShellItem(shell: Map<string, ShellEntry>, item: OrchestrationV2ShellStreamItem): boolean {
  switch (item.kind) {
    case "snapshot":
      // Enrichment refreshes (repository identity) carry projects only, not threads; T3's own
      // shell reducer merges just their project metadata. Only authoritative snapshots replace threads.
      if (item.resolvedRepositoryIdentityRoots !== undefined) return false;
      shell.clear();
      for (const thread of item.snapshot.threads) shell.set(thread.id, { thread, location: "active" });
      for (const thread of item.snapshot.archivedThreads) shell.set(thread.id, { thread, location: "archive" });
      return true;
    case "thread.updated":
      shell.set(item.thread.id, { thread: item.thread, location: item.location });
      return false;
    case "thread.removed":
      shell.delete(item.threadId);
      return false;
    default:
      return false;
  }
}
