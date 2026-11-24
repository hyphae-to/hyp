"""Minimal Python 3 stdlib client for the hyphae / t3-mesh fd-3 plugin channel (protocol v1)."""
from __future__ import annotations

import json
import os
import queue
import socket
import sys
import threading
import time
from typing import Any, Callable


class MeshPluginClient:
    def __init__(
        self,
        fd: int | None = None,
        on_status: Callable[[dict[str, Any]], None] | None = None,
        on_delivery_failed: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        raw_fd = fd if fd is not None else int(os.environ.get("T3_MESH_FD") or os.environ.get("AGENTS_MESH_FD") or "3")
        self.plugin = os.environ.get("T3_MESH_PLUGIN") or os.environ.get("AGENTS_MESH_PLUGIN") or "plugin"
        self.sock = socket.socket(fileno=raw_fd)
        self.reader = self.sock.makefile("rb")
        self._replies: queue.Queue[dict[str, Any]] = queue.Queue()
        self._dead = threading.Event()
        self._on_status = on_status
        self._on_delivery_failed = on_delivery_failed

        hello = self._read()
        if hello.get("type") != "hello" or hello.get("protocol") != 1 or not isinstance(hello.get("targets"), list):
            raise RuntimeError(f"Unexpected mesh plugin hello: {hello!r}")
        self.targets: list[str] = list(hello["targets"])
        threading.Thread(target=self._listen, daemon=True).start()

    def _read(self) -> dict[str, Any]:
        line = self.reader.readline(65537)
        if not line or len(line) > 65536:
            raise RuntimeError("Mesh plugin channel closed or line too large")
        return json.loads(line.decode("utf-8"))

    def _listen(self) -> None:
        try:
            while True:
                msg = self._read()
                kind = msg.get("type")
                if kind in ("ack", "nack"):
                    self._replies.put(msg)
                elif kind == "status" and self._on_status:
                    self._on_status(msg)
                elif kind == "delivery_failed" and self._on_delivery_failed:
                    self._on_delivery_failed(msg)
        except Exception:
            self._dead.set()
            self._replies.put({"type": "closed"})

    def send(self, target: str, event: dict[str, Any], retry_unavailable: bool = True) -> dict[str, Any]:
        if self._dead.is_set():
            raise RuntimeError("Mesh plugin channel closed")
        payload = (json.dumps({"type": "event", "to": target, "event": event}, ensure_ascii=False) + "\n").encode("utf-8")
        while True:
            self.sock.sendall(payload)
            reply = self._replies.get(timeout=60)
            if reply.get("type") == "closed":
                raise RuntimeError("Mesh plugin channel closed")
            if reply.get("type") == "ack":
                return reply
            if retry_unavailable and reply.get("error") == "unavailable":
                time.sleep(5)
                continue
            raise RuntimeError(f"Mesh plugin event rejected: {reply}")
