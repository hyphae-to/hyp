"""Python 3 stdlib JSON-RPC 2.0 plugin client (Unix fd 3 or authenticated loopback TCP)."""
from __future__ import annotations

import json
import os
import queue
import socket
import sys
import threading
from typing import Any, Callable

MAX_FRAME_BYTES = 64 * 1024
RPC_UNAVAILABLE = -32005
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class PluginRpcError(RuntimeError):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


def _parse_loopback_addr(raw: str) -> tuple[str, int]:
    trimmed = raw.strip()
    if trimmed.startswith("["):
        end = trimmed.find("]")
        if end < 0 or trimmed[end + 1:end + 2] != ":":
            raise ValueError("Invalid HYPHAE_PLUGIN_ADDR")
        host, port_str = trimmed[1:end], trimmed[end + 2:]
    else:
        end = trimmed.rfind(":")
        if end <= 0 or trimmed.find(":") != end:
            raise ValueError("Invalid HYPHAE_PLUGIN_ADDR")
        host, port_str = trimmed[:end], trimmed[end + 1:]
    host = host.strip().lower()
    if host not in _LOOPBACK_HOSTS:
        raise ValueError("Refusing non-loopback HYPHAE_PLUGIN_ADDR")
    if not port_str.isdigit() or not 1 <= int(port_str) <= 65535:
        raise ValueError("Invalid HYPHAE_PLUGIN_ADDR port")
    return host, int(port_str)


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) or (type(value) is int and abs(value) <= 2**53 - 1)


class MeshPluginClient:
    def __init__(
        self,
        fd: int | None = None,
        on_status: Callable[[dict[str, Any]], None] | None = None,
        on_delivery_failed: Callable[[dict[str, Any]], None] | None = None,
        on_post: Callable[[dict[str, Any]], Any] | None = None,
        on_request: Callable[[dict[str, Any]], Any] | None = None,
        on_wake: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.plugin = os.environ.get("HYPHAE_PLUGIN") or os.environ.get("AGENTS_MESH_PLUGIN") or os.environ.get("T3_MESH_PLUGIN") or "plugin"
        addr = (os.environ.get("HYPHAE_PLUGIN_ADDR") or "").strip() if fd is None else ""
        if addr:
            host, port = _parse_loopback_addr(addr)
            token = os.environ.pop("HYPHAE_PLUGIN_TOKEN", "")
            if not token:
                raise RuntimeError("HYPHAE_PLUGIN_TOKEN is required when HYPHAE_PLUGIN_ADDR is set")
            self.sock = socket.create_connection((host, port), timeout=10)
            try:
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # Transport authentication is separate from the JSON-RPC plugin protocol.
                self.sock.sendall((json.dumps({"type": "auth", "token": token}) + "\n").encode())
            except Exception:
                self.sock.close()
                raise
        else:
            raw_fd = fd if fd is not None else int(os.environ.get("HYPHAE_FD") or os.environ.get("AGENTS_MESH_FD") or os.environ.get("T3_MESH_FD") or "3")
            self.sock = socket.socket(fileno=raw_fd)
        self.reader = self.sock.makefile("rb")
        self._outbound: queue.Queue[bytes | None] = queue.Queue(maxsize=128)
        self._pending_lock = threading.Lock()
        self._pending: dict[str, queue.Queue[Any]] = {}
        self._next_id = 0
        self._dead = threading.Event()
        self._handlers = threading.BoundedSemaphore(32)
        self._on_status, self._on_delivery_failed = on_status, on_delivery_failed
        self._on_post, self._on_request, self._on_wake = on_post, on_request, on_wake
        try:
            self.sock.settimeout(10)
            hello = self._read()
            params = hello.get("params")
            if (hello.get("jsonrpc") != "2.0" or hello.get("method") != "hyphae/hello"
                or any(k in hello for k in ("id", "result", "error")) or not isinstance(params, dict)
                or type(params.get("protocol")) is not int or params["protocol"] != 2
                or not isinstance(params.get("targets"), list)
                or not all(isinstance(t, str) for t in params["targets"])):
                raise RuntimeError("Host JSON-RPC v2 hello required")
            self.targets: list[str] = list(params["targets"])
            self.sock.settimeout(None)
        except Exception:
            self.close()
            raise
        threading.Thread(target=self._write_loop, daemon=True).start()
        threading.Thread(target=self._listen, daemon=True).start()

    def on_post(self, handler: Callable[[dict[str, Any]], Any] | None) -> None:
        self._on_post = handler

    def on_request(self, handler: Callable[[dict[str, Any]], Any] | None) -> None:
        self._on_request = handler

    def on_wake(self, handler: Callable[[dict[str, Any]], None] | None) -> None:
        self._on_wake = handler

    def _read(self) -> dict[str, Any]:
        line = self.reader.readline(MAX_FRAME_BYTES + 3)
        if not line or not line.endswith(b"\n"):
            raise RuntimeError("Mesh plugin channel closed or incomplete frame")
        body = line[:-1].removesuffix(b"\r")
        if len(body) > MAX_FRAME_BYTES:
            raise RuntimeError("Plugin frame exceeds 64 KiB")
        def reject_constant(value: str) -> None:
            raise ValueError("Non-finite JSON number")
        value = json.loads(body.decode("utf-8"), parse_constant=reject_constant)
        if not isinstance(value, dict):
            raise RuntimeError("JSON-RPC object required")
        return value

    def _write_frame(self, frame: dict[str, Any]) -> None:
        payload = json.dumps(frame, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(payload) > MAX_FRAME_BYTES:
            raise PluginRpcError(-32001, "Plugin frame exceeds 64 KiB")
        if self._dead.is_set():
            raise RuntimeError("Mesh plugin channel closed")
        try:
            self._outbound.put_nowait(payload + b"\n")
        except queue.Full:
            raise RuntimeError("Plugin outbound queue full") from None

    def _write_loop(self) -> None:
        try:
            while not self._dead.is_set():
                payload = self._outbound.get()
                if payload is None:
                    return
                self.sock.sendall(payload)
        except Exception:
            self.close()

    def close(self) -> None:
        if self._dead.is_set():
            return
        self._dead.set()
        try:
            self._outbound.put_nowait(None)
        except queue.Full:
            pass
        with self._pending_lock:
            for waiter in self._pending.values():
                waiter.put_nowait(RuntimeError("Mesh plugin channel closed"))
            self._pending.clear()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.reader.close()
        self.sock.close()

    def _reply(self, req_id: Any, **payload: Any) -> None:
        if not self._dead.is_set():
            self._write_frame({"jsonrpc": "2.0", "id": req_id, **payload})

    def _handle_request(self, msg: dict[str, Any]) -> None:
        try:
            if callable(self._on_request):
                result = self._on_request(msg)
            elif msg["method"] == "hyphae/post" and callable(self._on_post):
                params = msg.get("params")
                if not isinstance(params, dict) or not isinstance(params.get("target"), str) or not isinstance(params.get("params"), dict):
                    self._reply(msg["id"], error={"code": -32602, "message": "invalid post params"})
                    return
                result = self._on_post({**params["params"], "target": params["target"]})
            else:
                self._reply(msg["id"], error={"code": -32601, "message": "method not supported"})
                return
            self._reply(msg["id"], result=result if result is not None else {"sent": True})
        except Exception as exc:
            try:
                self._reply(msg["id"], error={"code": -32603, "message": str(exc)[:512]})
            except Exception:
                self.close()
        finally:
            self._handlers.release()

    def _listen(self) -> None:
        try:
            while not self._dead.is_set():
                msg = self._read()
                if msg.get("jsonrpc") != "2.0":
                    raise RuntimeError("JSON-RPC 2.0 required")
                if "method" in msg:
                    if not isinstance(msg["method"], str) or "result" in msg or "error" in msg:
                        raise RuntimeError("Invalid JSON-RPC request")
                    if "id" in msg:
                        if not _valid_id(msg["id"]):
                            raise RuntimeError("Invalid JSON-RPC request ID")
                        if self._handlers.acquire(blocking=False):
                            threading.Thread(target=self._handle_request, args=(msg,), daemon=True).start()
                        else:
                            self._reply(msg["id"], error={"code": RPC_UNAVAILABLE, "message": "plugin busy"})
                    else:
                        handler = {"hyphae/status": self._on_status, "hyphae/deliveryFailed": self._on_delivery_failed,
                                   "system.wake": self._on_wake}.get(msg["method"])
                        if handler:
                            # A notification callback can publish and wait without blocking replies.
                            if self._handlers.acquire(blocking=False):
                                def notify(callback: Callable[..., Any] = handler, params: Any = msg.get("params")) -> None:
                                    try:
                                        callback(params)
                                    except Exception:
                                        pass
                                    finally:
                                        self._handlers.release()
                                threading.Thread(target=notify, daemon=True).start()
                            else:
                                self.close()
                                return
                    continue
                if ("id" not in msg or (msg["id"] is not None and not _valid_id(msg["id"]))
                    or ("result" in msg) == ("error" in msg)):
                    raise RuntimeError("Invalid JSON-RPC response")
                if "error" in msg:
                    error = msg["error"]
                    if not isinstance(error, dict) or type(error.get("code")) is not int or not isinstance(error.get("message"), str):
                        raise RuntimeError("Invalid JSON-RPC error")
                    result: Any = PluginRpcError(error["code"], error["message"], error.get("data"))
                else:
                    result = msg["result"]
                with self._pending_lock:
                    waiter = self._pending.pop(msg["id"], None)
                if waiter:
                    waiter.put_nowait(result)
                elif msg["id"] is None and isinstance(result, Exception):
                    sys.stderr.write(f"hyphae plugin protocol error: {result}\n")
        except Exception:
            self.close()

    def send(self, target: str, event: dict[str, Any], retry_unavailable: bool = True, timeout: float = 60) -> Any:
        while True:
            waiter: queue.Queue[Any] = queue.Queue(maxsize=1)
            with self._pending_lock:
                if self._dead.is_set():
                    raise RuntimeError("Mesh plugin channel closed")
                if len(self._pending) >= 128:
                    raise RuntimeError("Too many pending plugin requests")
                self._next_id += 1
                req_id = f"publish-{self._next_id}"
                self._pending[req_id] = waiter
            try:
                self._write_frame({"jsonrpc": "2.0", "id": req_id, "method": "hyphae/publish", "params": {"to": target, "event": event}})
                try:
                    result = waiter.get(timeout=timeout)
                except queue.Empty:
                    raise TimeoutError("Plugin publish timed out") from None
                if isinstance(result, Exception):
                    raise result
                if not isinstance(result, dict) or result.get("status") not in ("stored", "duplicate"):
                    raise RuntimeError("Invalid publish result")
                return result
            except PluginRpcError as exc:
                if not retry_unavailable or exc.code != RPC_UNAVAILABLE:
                    raise
                if self._dead.wait(5):
                    raise RuntimeError("Mesh plugin channel closed") from None
            finally:
                with self._pending_lock:
                    self._pending.pop(req_id, None)
