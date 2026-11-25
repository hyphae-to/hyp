"""Minimal Python 3 stdlib client for the Hyphae plugin channel (Unix fd 3 or authenticated loopback TCP, protocol v1)."""
from __future__ import annotations

from collections import deque
import json
import os
import queue
import socket
import sys
import threading
import time
from typing import Any, Callable

MAX_ECHO_ID_CHARS = 256
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _parse_loopback_addr(raw: str) -> tuple[str, int]:
    trimmed = raw.strip()
    if trimmed.startswith("["):
        close_idx = trimmed.find("]")
        if close_idx < 0 or close_idx + 1 >= len(trimmed) or trimmed[close_idx + 1] != ":":
            raise ValueError(f"Invalid HYPHAE_PLUGIN_ADDR: {trimmed!r}")
        host = trimmed[1:close_idx]
        port_str = trimmed[close_idx + 2:]
    else:
        colon_idx = trimmed.rfind(":")
        if colon_idx <= 0 or trimmed.find(":") != colon_idx:
            raise ValueError(f"Invalid HYPHAE_PLUGIN_ADDR: {trimmed!r}")
        host = trimmed[:colon_idx]
        port_str = trimmed[colon_idx + 1:]

    normalized_host = host.strip().lower()
    if normalized_host not in _LOOPBACK_HOSTS:
        raise ValueError(f"Refusing non-loopback HYPHAE_PLUGIN_ADDR host {host!r}")
    if not port_str.isdigit():
        raise ValueError(f"Invalid HYPHAE_PLUGIN_ADDR port: {port_str!r}")
    port = int(port_str)
    if port < 1 or port > 65535:
        raise ValueError(f"Invalid HYPHAE_PLUGIN_ADDR port: {port_str!r}")
    return normalized_host, port


def _correlation_id_for_event(event: Any) -> str | None:
    if not isinstance(event, dict):
        return None
    raw_id = event.get("id")
    if isinstance(raw_id, str) and len(raw_id) > 0:
        return raw_id[:MAX_ECHO_ID_CHARS]
    return None


class MeshPluginClient:
    def __init__(
        self,
        fd: int | None = None,
        on_status: Callable[[dict[str, Any]], None] | None = None,
        on_delivery_failed: Callable[[dict[str, Any]], None] | None = None,
        on_post: Callable[[dict[str, Any]], Any] | None = None,
        on_request: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.plugin = os.environ.get("HYPHAE_PLUGIN") or os.environ.get("AGENTS_MESH_PLUGIN") or os.environ.get("T3_MESH_PLUGIN") or "plugin"
        plugin_addr = (os.environ.get("HYPHAE_PLUGIN_ADDR") or "").strip() if fd is None else ""
        if plugin_addr:
            host, port = _parse_loopback_addr(plugin_addr)
            token = os.environ.pop("HYPHAE_PLUGIN_TOKEN", "")
            if not token:
                raise RuntimeError("HYPHAE_PLUGIN_TOKEN is required when HYPHAE_PLUGIN_ADDR is set")
            sock = socket.create_connection((host, port), timeout=10.0)
            try:
                sock.settimeout(None)
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                auth_line = (json.dumps({"type": "auth", "token": token}) + "\n").encode("utf-8")
                sock.sendall(auth_line)
            except Exception:
                sock.close()
                raise
            self.sock = sock
        else:
            raw_fd = fd if fd is not None else int(os.environ.get("HYPHAE_FD") or os.environ.get("AGENTS_MESH_FD") or os.environ.get("T3_MESH_FD") or "3")
            self.sock = socket.socket(fileno=raw_fd)
        self.reader = self.sock.makefile("rb")
        self._write_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending: dict[str, deque[queue.Queue[dict[str, Any]]]] = {}
        self._pending_no_id: deque[queue.Queue[dict[str, Any]]] = deque()
        self._dead = threading.Event()
        self._on_status = on_status
        self._on_delivery_failed = on_delivery_failed
        self._on_post = on_post
        self._on_request = on_request

        hello = self._read()
        if hello.get("type") != "hello" or hello.get("protocol") != 1 or not isinstance(hello.get("targets"), list):
            raise RuntimeError(f"Unexpected mesh plugin hello: {hello!r}")
        self.targets: list[str] = list(hello["targets"])
        threading.Thread(target=self._listen, daemon=True).start()

    def on_post(self, handler: Callable[[dict[str, Any]], Any] | None) -> None:
        """Register or replace the outbound `hyp_plugin_post` handler for this plugin."""
        self._on_post = handler

    def on_request(self, handler: Callable[[dict[str, Any]], Any] | None) -> None:
        """Register or replace a generic incoming fd-3 request handler."""
        self._on_request = handler

    def _read(self) -> dict[str, Any]:
        line = self.reader.readline(65537)
        if not line or len(line) > 65536:
            raise RuntimeError("Mesh plugin channel closed or line too large")
        return json.loads(line.decode("utf-8"))

    def _write_frame(self, frame: dict[str, Any]) -> None:
        payload = (json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8")
        with self._write_lock:
            self.sock.sendall(payload)

    def _dispatch_ack_or_nack(self, msg: dict[str, Any]) -> None:
        raw_id = msg.get("id")
        msg_id = raw_id if isinstance(raw_id, str) and len(raw_id) > 0 else None
        waiter: queue.Queue[dict[str, Any]] | None = None
        with self._pending_lock:
            if msg_id is not None:
                bucket = self._pending.get(msg_id)
                if bucket:
                    waiter = bucket.popleft()
                    if not bucket:
                        del self._pending[msg_id]
            elif self._pending_no_id:
                waiter = self._pending_no_id.popleft()
        if waiter is not None:
            waiter.put(msg)
        elif msg_id is None:
            sys.stderr.write(
                f"hyphae plugin id-less {msg.get('type')}: {msg.get('error') or msg.get('message') or 'unknown'}\n"
            )
            sys.stderr.flush()

    def _handle_request(self, msg: dict[str, Any]) -> None:
        req_id = msg["id"]

        def reply(ok: bool, result: Any = None, error: str | None = None) -> None:
            if self._dead.is_set():
                return
            frame: dict[str, Any] = {"type": "response", "id": req_id, "ok": ok}
            if ok:
                frame["result"] = result if result is not None else {"sent": True}
            else:
                frame["error"] = error or "request_failed"
            try:
                self._write_frame(frame)
            except OSError:
                pass

        on_request = self._on_request
        if callable(on_request):
            try:
                res = on_request(msg)
                reply(True, result=res)
            except Exception as exc:
                reply(False, error=str(exc))
            return

        method = msg.get("method")
        if method != "post":
            reply(False, error=f"unsupported_method:{method or ''}")
            return

        on_post = self._on_post
        if not callable(on_post):
            reply(False, error="post_not_supported")
            return

        raw_params = msg.get("params")
        call_params: dict[str, Any] = {"target": msg.get("target")}
        if isinstance(raw_params, dict):
            call_params.update(raw_params)
        try:
            res = on_post(call_params)
            reply(True, result=res)
        except Exception as exc:
            reply(False, error=str(exc))

    def _listen(self) -> None:
        try:
            while True:
                msg = self._read()
                kind = msg.get("type")
                if kind in ("ack", "nack"):
                    self._dispatch_ack_or_nack(msg)
                elif kind == "status" and self._on_status:
                    self._on_status(msg)
                elif kind == "delivery_failed" and self._on_delivery_failed:
                    self._on_delivery_failed(msg)
                elif kind == "request" and isinstance(msg.get("id"), str):
                    threading.Thread(
                        target=self._handle_request,
                        args=(msg,),
                        daemon=True,
                    ).start()
        except Exception:
            self._dead.set()
            with self._pending_lock:
                for bucket in self._pending.values():
                    while bucket:
                        bucket.popleft().put({"type": "closed"})
                self._pending.clear()
                while self._pending_no_id:
                    self._pending_no_id.popleft().put({"type": "closed"})

    def _remove_waiter(self, corr_id: str | None, waiter: queue.Queue[dict[str, Any]]) -> None:
        with self._pending_lock:
            if corr_id is not None:
                bucket = self._pending.get(corr_id)
                if bucket:
                    try:
                        bucket.remove(waiter)
                    except ValueError:
                        pass
                    if not bucket:
                        del self._pending[corr_id]
            else:
                try:
                    self._pending_no_id.remove(waiter)
                except ValueError:
                    pass

    def send(self, target: str, event: dict[str, Any], retry_unavailable: bool = True) -> dict[str, Any]:
        if self._dead.is_set():
            raise RuntimeError("Mesh plugin channel closed")
        frame = {"type": "event", "to": target, "event": event}
        corr_id = _correlation_id_for_event(event)
        while True:
            waiter: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
            with self._pending_lock:
                if self._dead.is_set():
                    raise RuntimeError("Mesh plugin channel closed")
                if corr_id is not None:
                    self._pending.setdefault(corr_id, deque()).append(waiter)
                else:
                    self._pending_no_id.append(waiter)
            try:
                self._write_frame(frame)
            except Exception:
                self._remove_waiter(corr_id, waiter)
                raise
            try:
                reply = waiter.get(timeout=60)
            except queue.Empty:
                self._remove_waiter(corr_id, waiter)
                raise
            if reply.get("type") == "closed":
                raise RuntimeError("Mesh plugin channel closed")
            if reply.get("type") == "ack":
                return reply
            if retry_unavailable and reply.get("error") == "unavailable":
                time.sleep(5)
                continue
            raise RuntimeError(f"Mesh plugin event rejected: {reply}")
