import { chmodSync, lstatSync, mkdirSync, rmSync } from "node:fs";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { dirname, join } from "node:path";
import { CallRegistry, resolveCodexCallerFromRollouts } from "./caller.ts";
import { parseBackend, type Config } from "./config.ts";
import { Connector } from "./connector.ts";
import { command, type Backend, type Channel } from "./delivery.ts";
import { PluginHost } from "./plugins.ts";
import { delivered, hold, isHarness, object, reject, sessionIdPattern, type Outcome } from "./protocol.ts";
import { RouterError } from "./router.ts";
import { State } from "./state.ts";
import { buildStreamTopicMap, RouterStreamHost } from "./streams.ts";
import { LineSplitter } from "./core/plugins/protocol.ts";
import { RouterCore } from "./core/router/core.ts";
import { serveRouter, type RunningRouter } from "./core/router/server.ts";

interface Waiter {
  readonly socket: Socket;
  readonly mode: "once" | "stream";
}

interface ChannelBinding {
  readonly socket: Socket;
  readonly deliver: Channel;
}

interface McpSocketContext {
  backend?: string;
  channel: boolean;
  channelReady: boolean;
  channelSessionId?: string;
  ephemeralClientId?: string;
  codexThreadId?: string;
  codexHome?: string;
  codexResume?: boolean;
  codexRemote?: string;
  herdrTerminalId?: string;
}

const DEFAULT_STALE_SESSION_MS = 7 * 86_400_000;
const STALE_SWEEP_MS = 60 * 60 * 1000;
const MAX_SOCKET_LINE_BYTES = 1024 * 1024;

const send = (socket: Socket, packet: unknown) => {
  if (!socket.destroyed) socket.write(JSON.stringify(packet) + "\n");
};

function probeSocketAlive(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = createConnection(path);
    const done = (alive: boolean) => {
      probe.destroy();
      resolve(alive);
    };
    probe.once("connect", () => done(true));
    probe.once("error", () => done(false));
    probe.setTimeout(500, () => done(false));
  });
}

async function resolveHerdr(terminalId: string): Promise<{ id: string; backend: Backend } | null> {
  if (!/^t[a-z0-9]+$/.test(terminalId)) return null;
  const result = await command("hc", ["get", "--json", terminalId], 5_000);
  if (result.code !== 0) return null;
  let terminal: unknown;
  try { terminal = JSON.parse(result.stdout); } catch { return null; }
  if (!object(terminal) || terminal.address !== terminalId || terminal.state !== "live" || !object(terminal.status)) return null;
  let backend: Backend;
  try {
    backend = parseBackend({
      kind: "herdr",
      terminalId: terminal.address,
      createdMs: terminal.created_ms,
      pid: terminal.pid,
      app: terminal.status.app,
    });
  } catch {
    return null;
  }
  if (backend.kind !== "herdr") return null;
  return { id: `herdr:${backend.terminalId}:${backend.createdMs}:${backend.pid}`, backend };
}

export interface RunningDaemon {
  readonly socketPath: string;
  readonly localRouterUrl: string | null;
  readonly connector: Connector;
  readonly state: State;
  readonly calls: CallRegistry;
  stop(): Promise<void>;
}

export interface StartDaemonOptions {
  readonly socketPath?: string;
  readonly staleSessionMs?: number;
  readonly quiet?: boolean;
}

export async function startDaemon(config: Config, options: StartDaemonOptions = {}): Promise<RunningDaemon> {
  mkdirSync(config.directory, { mode: 0o700, recursive: true });
  const directory = lstatSync(config.directory);
  if (!directory.isDirectory() || directory.uid !== process.getuid?.() || (directory.mode & 0o077) !== 0) {
    throw new Error("State directory must be private and owned by the current user");
  }
  const socketPath = options.socketPath ?? join(config.directory, "connector.sock");
  if (await probeSocketAlive(socketPath)) {
    throw new Error(`hyp daemon is already running at ${socketPath}`);
  }
  rmSync(socketPath, { force: true });

  // Optional embedded local router (configured by `hyp onboard`) so a single daemon
  // process provides a complete working local mesh with zero extra services to supervise.
  let embeddedCore: RouterCore | undefined;
  let embeddedRouter: RunningRouter | undefined;
  let streamHost: RouterStreamHost | undefined;
  let effectiveConfig = config;
  if (config.localRouter) {
    mkdirSync(dirname(config.localRouter.dbPath), { mode: 0o700, recursive: true });
    const streamTopics = config.localRouter.streams && config.localRouter.streams.length > 0
      ? buildStreamTopicMap(config.localRouter.streams)
      : undefined;
    const core = new RouterCore({
      dbPath: config.localRouter.dbPath,
      ...(config.localRouter.auditPath ? { auditPath: config.localRouter.auditPath } : {}),
      ...(streamTopics ? { topics: streamTopics } : {}),
    });
    try {
      embeddedRouter = await serveRouter({ core, host: config.localRouter.host, port: config.localRouter.port });
      embeddedCore = core;
      if (config.localRouter.port === 0) {
        effectiveConfig = {
          ...config,
          routers: config.routers.map((r) => (r.name === "primary" ? { ...r, url: embeddedRouter!.url } : r)),
        };
      }
      if (config.localRouter.streams && config.localRouter.streams.length > 0) {
        streamHost = new RouterStreamHost(core, embeddedRouter.url, config.localRouter.streams);
        await streamHost.start();
      }
      if (!options.quiet) console.error(`Embedded local router listening at ${embeddedRouter.url}`);
    } catch (error) {
      if (streamHost) await streamHost.stop().catch(() => {});
      core.close();
      if ((error as NodeJS.ErrnoException)?.code !== "EADDRINUSE") throw error;
      if (!options.quiet) {
        console.error(`Port ${config.localRouter.port} already in use; connecting to existing router`);
      }
    }
  }

  const state = new State(join(effectiveConfig.directory, "state.sqlite"), JSON.stringify([effectiveConfig.connectorId, "multi-session-v1"]));
  state.bindRouters(effectiveConfig.routers);
  const calls = new CallRegistry();
  const sockets = new Set<Socket>();
  const channels = new Map<string, ChannelBinding>();
  const waiters = new Map<string, Set<Waiter>>();
  const flushing = new Set<string>();
  let nextDelivery = 0;

  const hasLiveTransport = (sessionId: string): boolean => {
    if (channels.has(sessionId)) return true;
    const set = waiters.get(sessionId);
    return set !== undefined && set.size > 0;
  };

  const activeSessionIds = (): Set<string> => {
    const active = new Set<string>();
    for (const id of channels.keys()) active.add(id);
    for (const [id, set] of waiters) {
      if (set.size > 0) active.add(id);
    }
    return active;
  };

  const pluginHost = effectiveConfig.plugins && effectiveConfig.plugins.length > 0
    ? new PluginHost(effectiveConfig.directory, effectiveConfig.plugins, state)
    : undefined;

  const connector = new Connector(effectiveConfig, state, {
    channel: (id) => channels.get(id)?.deliver,
    hasLiveTransport,
    onMailboxItem: (sessionId) => { void flushSession(sessionId); },
    ...(pluginHost
      ? {
          listPluginTargets: (sessionId) => pluginHost.listForSession(sessionId),
          handoffPluginTarget: (sessionId, args) => pluginHost.handoff(sessionId, args),
          postPluginTarget: (sessionId, args) => pluginHost.postToPlugin(sessionId, args),
          linkBridgeTarget: (sessionId, args) => pluginHost.linkBridge(sessionId, args),
          unlinkBridgeTarget: (sessionId, args) => pluginHost.unlinkBridge(sessionId, args),
        }
      : {}),
  });
  pluginHost?.start(connector);

  async function flushSession(sessionId: string): Promise<void> {
    if (flushing.has(sessionId)) return;
    flushing.add(sessionId);
    try {
      while (true) {
        const peeked = connector.peekForPush(sessionId, 10);
        if (peeked.items.length === 0) break;

        // Priority 1: Live Claude native channel
        const channel = channels.get(sessionId);
        if (channel && !channel.socket.destroyed) {
          const [first] = peeked.items;
          const outcome = await channel.deliver(first.text).catch(() => hold("claude_channel_failed"));
          if (outcome.outcome === "delivered") {
            connector.ackPush(sessionId, [first.receipt], peeked.notifyOnly);
            continue;
          }
          break;
        }

        const set = waiters.get(sessionId);
        if (!set || set.size === 0) break;

        // Priority 2: Streaming watcher (`hyp watch` / Claude Monitor)
        const streamWaiter = [...set].find((entry) => entry.mode === "stream" && !entry.socket.destroyed);
        if (streamWaiter) {
          const items = connector.drainForPush(sessionId, 10);
          if (items.length === 0) break;
          send(streamWaiter.socket, { type: "wait.items", items });
          continue;
        }

        // Priority 3: One-shot blocking waiter (`hyp wait` / Antigravity run_command)
        const onceWaiter = [...set].find((entry) => entry.mode === "once" && !entry.socket.destroyed);
        if (onceWaiter) {
          const items = connector.drainForPush(sessionId, 10);
          if (items.length === 0) break;
          set.delete(onceWaiter);
          if (set.size === 0) waiters.delete(sessionId);
          send(onceWaiter.socket, { type: "wait.items", items });
          onceWaiter.socket.end();
          continue;
        }

        break;
      }
    } finally {
      flushing.delete(sessionId);
    }
  }

  const server: Server = createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => {});

    let mcpContext: McpSocketContext | undefined;
    const channelRequests = new Map<number, { resolve: (value: Outcome) => void; timer: NodeJS.Timeout }>();
    let attachedWaiter: { sessionId: string; waiter: Waiter } | undefined;

    const bindChannelTransport = (sessionId: string) => {
      if (!mcpContext || !mcpContext.channel || socket.destroyed) return;
      mcpContext.channelSessionId = sessionId;
      if (!mcpContext.channelReady) return;
      channels.set(sessionId, {
        socket,
        deliver: (text) => {
          if (socket.destroyed) return Promise.resolve(hold("claude_channel_offline"));
          return new Promise((resolve) => {
            const delivery = ++nextDelivery;
            const timer = setTimeout(() => {
              channelRequests.delete(delivery);
              resolve(hold("claude_channel_timeout"));
            }, 10_000).unref();
            channelRequests.set(delivery, { resolve, timer });
            send(socket, { type: "channel.deliver", delivery, text });
          });
        },
      });
      void flushSession(sessionId);
    };

    socket.on("close", () => {
      sockets.delete(socket);
      if (mcpContext?.channelSessionId) {
        const current = channels.get(mcpContext.channelSessionId);
        if (current?.socket === socket) channels.delete(mcpContext.channelSessionId);
      }
      if (attachedWaiter) {
        const set = waiters.get(attachedWaiter.sessionId);
        if (set) {
          set.delete(attachedWaiter.waiter);
          if (set.size === 0) waiters.delete(attachedWaiter.sessionId);
        }
      }
      for (const pending of channelRequests.values()) {
        clearTimeout(pending.timer);
        pending.resolve(hold("claude_channel_disconnected"));
      }
      channelRequests.clear();
    });

    const splitter = new LineSplitter(MAX_SOCKET_LINE_BYTES, false);
    let rejecting = false;
    const rejectAndClose = (error: string) => {
      if (rejecting) return;
      rejecting = true;
      socket.pause();
      if (!socket.destroyed && socket.writable) {
        socket.end(JSON.stringify({ ok: false, error }) + "\n");
      } else {
        socket.destroy();
      }
      setTimeout(() => { if (!socket.destroyed) socket.destroy(); }, 250).unref();
    };

    const handleLine = (line: string) => {
      if (rejecting || socket.destroyed) return;
      let packet: unknown;
      try { packet = JSON.parse(line); } catch { rejectAndClose("invalid_json"); return; }
      if (!object(packet)) return;

      void (async () => {
        const type = packet.type;

        // ---- Hook RPCs (short-lived single-request sockets) ----
        if (type === "call.start") {
          const { harness, sessionId, tool, callId } = packet;
          if (!isHarness(harness) || typeof sessionId !== "string" || !sessionIdPattern.test(sessionId) || typeof tool !== "string") {
            send(socket, { ok: false, error: "invalid_call_start" });
            socket.end();
            return;
          }
          try {
            const backend = parseBackend({
              kind: harness,
              ...(harness === "codex" ? { threadId: sessionId.slice("codex:".length), queue: false } : {}),
            });
            state.register(sessionId, backend);
            const registered = calls.register({
              harness,
              sessionId,
              backend,
              tool,
              ...(typeof callId === "string" && callId.length > 0 ? { callId } : {}),
            });
            send(socket, { ok: true, result: { callToken: registered.token, sessionId } });
          } catch (error) {
            send(socket, { ok: false, error: error instanceof Error ? error.message : "call_start_failed" });
          }
          socket.end();
          return;
        }

        if (type === "call.end") {
          calls.release(
            typeof packet.callId === "string" ? packet.callId : undefined,
            typeof packet.callToken === "string" ? packet.callToken : undefined,
          );
          send(socket, { ok: true, result: {} });
          socket.end();
          return;
        }

        if (type === "mailbox.drain") {
          const sessionId = packet.sessionId;
          const limit = typeof packet.limit === "number" && Number.isInteger(packet.limit) && packet.limit > 0 && packet.limit <= 50
            ? packet.limit : 10;
          if (typeof sessionId !== "string" || !sessionIdPattern.test(sessionId)) {
            send(socket, { ok: false, error: "invalid_session" });
            socket.end();
            return;
          }
          const items = state.session(sessionId) ? connector.drainMailbox(sessionId, limit) : [];
          send(socket, { ok: true, result: { items } });
          socket.end();
          return;
        }

        if (type === "session.status") {
          const sessionId = packet.sessionId;
          if (typeof sessionId !== "string") {
            send(socket, { ok: false, error: "invalid_session" });
            socket.end();
            return;
          }
          const status = connector.sessionStatus(sessionId);
          send(socket, { ok: true, result: status ?? { id: sessionId, enrolled: false, pending: 0, hasLiveTransport: false } });
          socket.end();
          return;
        }

        if (type === "daemon.status") {
          send(socket, {
            ok: true,
            result: {
              connectorId: connector.connectorId,
              socketPath,
              localRouter: embeddedRouter?.url ?? null,
              routers: connector.routerNames,
              plugins: pluginHost?.names ?? [],
              streams: streamHost?.names ?? [],
              topics: streamHost?.topics ?? [],
              mutes: connector.listMutes(),
              sessions: connector.listSessions(),
            },
          });
          socket.end();
          return;
        }

        if (type === "mute.add") {
          try {
            const target = typeof packet.target === "string" ? packet.target : "";
            const rule = connector.muteTarget(target, "*", "cli");
            send(socket, { ok: true, result: { rule } });
          } catch (error) {
            send(socket, { ok: false, error: error instanceof Error ? error.message : "mute_failed" });
          }
          socket.end();
          return;
        }

        if (type === "mute.remove") {
          try {
            const target = typeof packet.target === "string" ? packet.target : "";
            const res = connector.unmuteTarget(target, "*");
            send(socket, { ok: true, result: res });
          } catch (error) {
            send(socket, { ok: false, error: error instanceof Error ? error.message : "unmute_failed" });
          }
          socket.end();
          return;
        }

        if (type === "mute.list") {
          send(socket, { ok: true, result: { mutes: connector.listMutes() } });
          socket.end();
          return;
        }

        if (type === "daemon.prune") {
          const maxAgeMs = typeof packet.maxAgeMs === "number" && packet.maxAgeMs >= 0 ? packet.maxAgeMs : DEFAULT_STALE_SESSION_MS;
          const pruned = await connector.pruneStale(maxAgeMs, activeSessionIds());
          send(socket, { ok: true, result: { pruned } });
          socket.end();
          return;
        }

        // ---- Blocking waiter / streaming watcher ----
        if (type === "wait.subscribe") {
          const mode = packet.mode === "stream" ? "stream" : "once";
          let sessionId = typeof packet.sessionId === "string" && sessionIdPattern.test(packet.sessionId) ? packet.sessionId : undefined;
          if (!sessionId && typeof packet.handle === "string") {
            sessionId = state.byHandle(packet.handle)?.id;
          }
          if (!sessionId) {
            send(socket, { type: "wait.error", message: "Unknown session or handle. Join the mesh first or pass --session <id>." });
            socket.end();
            return;
          }
          const waiter: Waiter = { socket, mode };
          let set = waiters.get(sessionId);
          if (!set) {
            set = new Set();
            waiters.set(sessionId, set);
          }
          set.add(waiter);
          attachedWaiter = { sessionId, waiter };
          state.touch(sessionId);
          send(socket, { type: "wait.ready", sessionId, mode });
          await flushSession(sessionId);
          return;
        }

        // ---- Stateless MCP shim protocol ----
        if (type === "mcp.hello") {
          mcpContext = {
            backend: typeof packet.backend === "string" ? packet.backend : undefined,
            channel: packet.channel === true,
            channelReady: false,
            ephemeralClientId: typeof packet.clientId === "string" && /^[0-9a-f-]{36}$/.test(packet.clientId) ? packet.clientId : undefined,
            codexThreadId: typeof packet.threadId === "string" ? packet.threadId : undefined,
            codexHome: typeof packet.codexHome === "string" ? packet.codexHome : undefined,
            codexResume: packet.resume === true,
            codexRemote: typeof packet.remote === "string" ? packet.remote : undefined,
            herdrTerminalId: typeof packet.terminalId === "string" ? packet.terminalId : undefined,
          };
          return;
        }

        if (type === "channel.ready" && mcpContext?.channel) {
          mcpContext.channelReady = true;
          if (mcpContext.channelSessionId) {
            bindChannelTransport(mcpContext.channelSessionId);
          } else if (mcpContext.ephemeralClientId) {
            const sessionId = `claude:${mcpContext.ephemeralClientId}`;
            state.register(sessionId, { kind: "claude", channel: true });
            bindChannelTransport(sessionId);
          }
          return;
        }

        if (type === "channel.ack" && typeof packet.delivery === "number") {
          const pending = channelRequests.get(packet.delivery);
          if (pending) {
            channelRequests.delete(packet.delivery);
            clearTimeout(pending.timer);
            pending.resolve(packet.submitted === true ? delivered : hold("claude_channel_write_failed"));
          }
          return;
        }

        if (type === "tool.call" && typeof packet.id === "number" && typeof packet.name === "string" && object(packet.args)) {
          const requestId = packet.id;
          const toolName = packet.name;
          const args = packet.args;
          const callId = typeof packet.callId === "string" ? packet.callId : undefined;
          const callToken = typeof packet.callToken === "string" ? packet.callToken : undefined;

          try {
            let resolved: { sessionId: string; backend: Backend } | undefined;

            // 1. Primary path: authoritative per-call verification from PreToolUse hook,
            //    with automatic fallback to Codex rollout JSONL verification (for Codex CLI & Desktop).
            if (callId || callToken) {
              const verification = await calls.resolve(toolName, callId, callToken, callToken ? 1_500 : 200);
              if (verification.ok) {
                resolved = { sessionId: verification.sessionId, backend: verification.backend };
                state.register(resolved.sessionId, resolved.backend);
                if (mcpContext?.channel && resolved.backend.kind === "claude") {
                  bindChannelTransport(resolved.sessionId);
                }
              } else if (callId && !callToken) {
                const codexResolved = await resolveCodexCallerFromRollouts(callId, toolName, {
                  codexHome: mcpContext?.codexHome,
                  remote: mcpContext?.codexRemote,
                  resume: mcpContext?.codexResume,
                });
                if (codexResolved.ok) {
                  resolved = { sessionId: codexResolved.sessionId, backend: codexResolved.backend };
                  state.register(resolved.sessionId, resolved.backend);
                } else if (!mcpContext?.herdrTerminalId && !mcpContext?.codexThreadId && !mcpContext?.ephemeralClientId) {
                  send(socket, { id: requestId, error: { code: verification.code, message: verification.message } });
                  return;
                }
              } else if (!mcpContext?.herdrTerminalId && !mcpContext?.codexThreadId && !mcpContext?.ephemeralClientId) {
                send(socket, { id: requestId, error: { code: verification.code, message: verification.message } });
                return;
              }
            }

            // 2. Herdr Core verified terminal identity
            if (!resolved && mcpContext?.herdrTerminalId) {
              const herdr = await resolveHerdr(mcpContext.herdrTerminalId);
              if (herdr) {
                resolved = { sessionId: herdr.id, backend: herdr.backend };
                state.register(resolved.sessionId, resolved.backend);
              }
            }

            // 3. Explicit legacy standalone Codex `--thread <uuid>`
            if (!resolved && mcpContext?.codexThreadId) {
              const backend = parseBackend({
                kind: "codex",
                threadId: mcpContext.codexThreadId,
                ...(mcpContext.codexHome ? { codexHome: mcpContext.codexHome } : {}),
                resume: mcpContext.codexResume,
                ...(mcpContext.codexRemote ? { remote: mcpContext.codexRemote } : {}),
                queue: true,
              });
              const sessionId = `codex:${mcpContext.codexThreadId.toLowerCase()}`;
              state.register(sessionId, backend);
              resolved = { sessionId, backend };
            }

            // 4. Explicit opt-in `--ephemeral` scratch mode (or OpenClaw MCP orchestrator)
            if (!resolved && mcpContext?.ephemeralClientId) {
              const kind = mcpContext.backend === "antigravity" || mcpContext.backend === "openclaw" || mcpContext.backend === "cursor" || mcpContext.backend === "opencode" || mcpContext.backend === "gemini"
                ? mcpContext.backend
                : "claude";
              const backend: Backend = kind === "claude"
                ? { kind: "claude", ...(mcpContext.channel ? { channel: true } : {}) }
                : { kind };
              const sessionId = `${kind}:${mcpContext.ephemeralClientId}`;
              state.register(sessionId, backend);
              resolved = { sessionId, backend };
              if (mcpContext.channel && kind === "claude") bindChannelTransport(sessionId);
            }

            if (!resolved) {
              send(socket, {
                id: requestId,
                error: {
                  code: "caller_unverifiable",
                  message: "Could not verify calling thread/conversation. Run 'hyp setup <antigravity|claude|codex>' to install PreToolUse hooks (or pass --ephemeral for scratch testing).",
                },
              });
              return;
            }

            const result = await connector.call(resolved.sessionId, toolName, args);
            send(socket, { id: requestId, result });
          } catch (error) {
            send(socket, {
              id: requestId,
              error: error instanceof RouterError
                ? { code: error.code, message: error.message }
                : { code: "connector_error", message: error instanceof Error ? error.message : "Local operation failed" },
            });
          }
        }
      })().catch(() => {});
    };

    socket.on("data", (rawChunk: Buffer | string) => {
      if (rejecting || socket.destroyed) return;
      const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
      splitter.push(chunk, (line, truncated) => {
        if (rejecting || socket.destroyed) return;
        if (truncated) {
          rejectAndClose("line_too_large");
          return;
        }
        handleLine(line);
      });
      if (!rejecting && splitter.overflowing) {
        rejectAndClose("line_too_large");
      }
    });
  });

  try {
    await new Promise<void>((resolveListen, rejectListen) => {
      server.once("error", rejectListen);
      server.listen(socketPath, () => {
        try { chmodSync(socketPath, 0o600); } catch {}
        resolveListen();
      });
    });
  } catch (error) {
    if (pluginHost) await pluginHost.stop().catch(() => {});
    if (streamHost) await streamHost.stop().catch(() => {});
    try { state.close(); } catch {}
    if (embeddedRouter) await embeddedRouter.close().catch(() => {});
    try { embeddedCore?.close(); } catch {}
    throw error;
  }

  const shutdown = new AbortController();
  const staleMs = options.staleSessionMs ?? DEFAULT_STALE_SESSION_MS;
  const sweep = setInterval(() => {
    void connector.pruneStale(staleMs, activeSessionIds()).catch(() => {});
  }, STALE_SWEEP_MS).unref();

  const loop = connector.run(shutdown.signal);
  if (!options.quiet) console.error(`Connector ready at ${socketPath}`);

  let stopped = false;
  return {
    socketPath,
    localRouterUrl: embeddedRouter?.url ?? null,
    connector,
    state,
    calls,
    async stop() {
      if (stopped) return;
      stopped = true;
      clearInterval(sweep);
      shutdown.abort();
      for (const sock of sockets) sock.destroy();
      await new Promise<void>((resolveClose) => {
        if (server.listening) server.close(() => resolveClose());
        else resolveClose();
      });
      if (pluginHost) await pluginHost.stop();
      if (streamHost) await streamHost.stop();
      await loop;
      await connector.drain();
      state.close();
      if (embeddedRouter) await embeddedRouter.close();
      embeddedCore?.close();
      rmSync(socketPath, { force: true });
    },
  };
}
