/**
 * Zero-dependency RFC 6455 loopback WebSocket server (`127.0.0.1:0`) built strictly on
 * `node:http` + `node:crypto`.
 *
 * Supports:
 *  - Text/binary frames of any payload length (<126, 16-bit, 64-bit) & fragmented messages
 *  - Ping/pong, graceful close handshake, and abrupt TCP disconnect injection
 *  - Query string & HTTP upgrade header inspection
 *  - Optional regular HTTP request handler on the same `http.Server`
 */

import crypto from "node:crypto";
import http from "node:http";
import type net from "node:net";
import { closeHttpServer, waitUntil } from "./helpers.ts";

const WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export interface WsConnection {
  readonly id: number;
  readonly url: string;
  readonly pathname: string;
  readonly searchParams: URLSearchParams;
  readonly headers: http.IncomingHttpHeaders;
  readonly receivedTexts: string[];
  readonly receivedJson: any[];
  readonly closed: boolean;
  sendText(text: string): void;
  sendJson(obj: unknown): void;
  ping(payload?: Buffer | string): void;
  close(code?: number, reason?: string): void;
  destroy(): void;
  onMessage(handler: (text: string, parsed: any) => void): void;
  onClose(handler: () => void): void;
}

export interface LoopbackWsServerOptions {
  /** Optional non-upgrade HTTP request handler sharing the same loopback port. */
  httpHandler?: (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void> | void;
  /** Optional upgrade gate; return a non-200 HTTP status to reject the WS handshake fail-closed. */
  validateUpgrade?: (req: http.IncomingMessage) => number | null | undefined;
  /** Called immediately after each RFC 6455 handshake completes. */
  onConnection?: (conn: WsConnection) => void;
}

function encodeServerFrame(opcode: number, payload: Buffer): Buffer {
  const len = payload.length;
  let header: Buffer;
  if (len < 126) {
    header = Buffer.from([0x80 | (opcode & 0x0f), len]);
  } else if (len < 65_536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

function decodeCloseFramePayload(code: number, reason: string): Buffer {
  const reasonBuf = Buffer.from(reason, "utf8");
  const out = Buffer.alloc(2 + reasonBuf.length);
  out.writeUInt16BE(code, 0);
  reasonBuf.copy(out, 2);
  return out;
}

export class LoopbackWsServer {
  readonly server: http.Server;
  readonly port: number;
  readonly baseHttpUrl: string;
  readonly baseWsUrl: string;
  readonly connections: WsConnection[] = [];
  readonly allMessages: Array<{ connId: number; text: string; json: any }> = [];
  readonly upgradeRequests: Array<{ url: string; headers: http.IncomingHttpHeaders }> = [];

  private readonly rawSockets = new Set<net.Socket>();
  private readonly messageWaiters: Array<() => void> = [];
  private readonly connWaiters: Array<() => void> = [];
  private nextConnId = 1;
  private onConnectionCb?: (conn: WsConnection) => void;

  private constructor(server: http.Server, port: number, options: LoopbackWsServerOptions) {
    this.server = server;
    this.port = port;
    this.baseHttpUrl = `http://127.0.0.1:${port}`;
    this.baseWsUrl = `ws://127.0.0.1:${port}`;
    this.onConnectionCb = options.onConnection;

    server.on("upgrade", (req, socket) => {
      const sock = socket as net.Socket;
      this.upgradeRequests.push({ url: req.url ?? "/", headers: { ...req.headers } });

      const rejectStatus = options.validateUpgrade?.(req);
      if (typeof rejectStatus === "number" && rejectStatus >= 400) {
        sock.write(`HTTP/1.1 ${rejectStatus} Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
        sock.destroy();
        return;
      }

      const key = req.headers["sec-websocket-key"];
      if (typeof key !== "string" || !key.trim()) {
        sock.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
        sock.destroy();
        return;
      }

      const accept = crypto
        .createHash("sha1")
        .update(key.trim() + WS_MAGIC_GUID)
        .digest("base64");

      sock.setNoDelay(true);
      sock.write(
        "HTTP/1.1 101 Switching Protocols\r\n" +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
      );

      this.rawSockets.add(sock);
      const parsedUrl = new URL(req.url ?? "/", this.baseHttpUrl);
      const connId = this.nextConnId++;
      const receivedTexts: string[] = [];
      const receivedJson: any[] = [];
      const msgHandlers: Array<(text: string, parsed: any) => void> = [];
      const closeHandlers: Array<() => void> = [];
      let isClosed = false;

      const markClosed = () => {
        if (isClosed) return;
        isClosed = true;
        this.rawSockets.delete(sock);
        for (const fn of closeHandlers.splice(0)) {
          try {
            fn();
          } catch {
            // ignore
          }
        }
      };

      const writeSafe = (frame: Buffer) => {
        if (isClosed || sock.destroyed || !sock.writable) return;
        try {
          sock.write(frame);
        } catch {
          // ignore write races during teardown
        }
      };

      const conn: WsConnection = {
        id: connId,
        url: req.url ?? "/",
        pathname: parsedUrl.pathname,
        searchParams: parsedUrl.searchParams,
        headers: { ...req.headers },
        receivedTexts,
        receivedJson,
        get closed() {
          return isClosed;
        },
        sendText(text: string) {
          writeSafe(encodeServerFrame(0x1, Buffer.from(text, "utf8")));
        },
        sendJson(obj: unknown) {
          writeSafe(encodeServerFrame(0x1, Buffer.from(JSON.stringify(obj), "utf8")));
        },
        ping(payload: Buffer | string = "") {
          const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
          writeSafe(encodeServerFrame(0x9, buf));
        },
        close(code = 1000, reason = "") {
          if (isClosed) return;
          writeSafe(encodeServerFrame(0x8, decodeCloseFramePayload(code, reason)));
          try {
            sock.end();
          } catch {
            // ignore
          }
          markClosed();
        },
        destroy() {
          markClosed();
          try {
            sock.destroy();
          } catch {
            // ignore
          }
        },
        onMessage(handler) {
          msgHandlers.push(handler);
        },
        onClose(handler) {
          if (isClosed) handler();
          else closeHandlers.push(handler);
        },
      };

      let buffer: Buffer = Buffer.alloc(0);
      let fragOpcode = 0;
      let fragChunks: Buffer[] = [];

      const dispatchMessage = (opcode: number, payload: Buffer) => {
        if (opcode !== 0x1 && opcode !== 0x2) return;
        const text = payload.toString("utf8");
        let parsed: any = null;
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = null;
        }
        receivedTexts.push(text);
        if (parsed !== null) receivedJson.push(parsed);
        this.allMessages.push({ connId, text, json: parsed });
        for (const fn of msgHandlers) {
          try {
            fn(text, parsed);
          } catch {
            // ignore handler exceptions
          }
        }
        for (const waiter of this.messageWaiters.splice(0)) waiter();
      };

      sock.on("data", (chunk: Buffer) => {
        buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
        while (buffer.length >= 2) {
          const b0 = buffer[0];
          const b1 = buffer[1];
          const fin = (b0 & 0x80) !== 0;
          const opcode = b0 & 0x0f;
          const masked = (b1 & 0x80) !== 0;
          let len = b1 & 0x7f;
          let offset = 2;

          if (len === 126) {
            if (buffer.length < 4) return;
            len = buffer.readUInt16BE(2);
            offset = 4;
          } else if (len === 127) {
            if (buffer.length < 10) return;
            const bigLen = buffer.readBigUInt64BE(2);
            if (bigLen > BigInt(16 * 1024 * 1024)) {
              conn.close(1009, "message too large");
              return;
            }
            len = Number(bigLen);
            offset = 10;
          }

          const maskBytes = masked ? 4 : 0;
          if (buffer.length < offset + maskBytes + len) return;

          let payload: Buffer;
          if (masked) {
            const mask = buffer.subarray(offset, offset + 4);
            payload = Buffer.from(buffer.subarray(offset + 4, offset + 4 + len));
            for (let i = 0; i < payload.length; i += 1) {
              payload[i] ^= mask[i & 3];
            }
          } else {
            payload = Buffer.from(buffer.subarray(offset, offset + len));
          }

          buffer = buffer.subarray(offset + maskBytes + len);

          if (opcode === 0x8) {
            // RFC 6455 close frame: reply with close frame and end cleanly.
            writeSafe(encodeServerFrame(0x8, Buffer.alloc(0)));
            try {
              sock.end();
            } catch {
              // ignore
            }
            markClosed();
            return;
          }
          if (opcode === 0x9) {
            // Ping -> Pong echoing payload.
            writeSafe(encodeServerFrame(0xa, payload));
            continue;
          }
          if (opcode === 0xa) {
            // Pong -> ignore.
            continue;
          }

          if (opcode === 0x0) {
            if (fragOpcode !== 0) {
              fragChunks.push(payload);
              if (fin) {
                const full = Buffer.concat(fragChunks);
                const doneOp = fragOpcode;
                fragOpcode = 0;
                fragChunks = [];
                dispatchMessage(doneOp, full);
              }
            }
          } else if (fin) {
            dispatchMessage(opcode, payload);
          } else {
            fragOpcode = opcode;
            fragChunks = [payload];
          }
        }
      });

      sock.on("close", markClosed);
      sock.on("error", markClosed);

      this.connections.push(conn);
      for (const waiter of this.connWaiters.splice(0)) waiter();
      this.onConnectionCb?.(conn);
    });
  }

  static async start(options: LoopbackWsServerOptions = {}): Promise<LoopbackWsServer> {
    const server = http.createServer(async (req, res) => {
      if (options.httpHandler) {
        try {
          await options.httpHandler(req, res);
        } catch (err) {
          if (!res.headersSent) {
            res
              .writeHead(500, { "content-type": "application/json" })
              .end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
          }
        }
        return;
      }
      res.writeHead(404).end();
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    return new LoopbackWsServer(server, port, options);
  }

  setOnConnection(cb: (conn: WsConnection) => void): void {
    this.onConnectionCb = cb;
  }

  get activeConnections(): WsConnection[] {
    return this.connections.filter((c) => !c.closed);
  }

  waitForConnections(count = 1, timeoutMs = 15_000): Promise<WsConnection[]> {
    return waitUntil(
      () => (this.connections.length >= count ? this.connections : false),
      `ws connections >= ${count}`,
      timeoutMs,
      15,
    );
  }

  waitForMessage(
    predicate: (msg: { connId: number; text: string; json: any }) => boolean,
    timeoutMs = 15_000,
  ): Promise<{ connId: number; text: string; json: any }> {
    return waitUntil(
      () => this.allMessages.find(predicate) ?? false,
      "matching ws message",
      timeoutMs,
      15,
    );
  }

  async close(): Promise<void> {
    for (const sock of Array.from(this.rawSockets)) {
      try {
        sock.destroy();
      } catch {
        // ignore
      }
    }
    this.rawSockets.clear();
    await closeHttpServer(this.server);
  }
}
