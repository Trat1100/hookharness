from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .signing import SignatureError, verify_signature
from .transport import MAX_BODY_BYTES


class ReplayCache:
    def __init__(self, *, ttl_seconds: int = 600, max_entries: int = 10_000):
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def add_once(self, key: str, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            expired = [item for item, expiry in self._seen.items() if expiry <= current]
            for item in expired:
                self._seen.pop(item, None)
            if key in self._seen:
                return False
            self._seen[key] = current + self.ttl_seconds
            while len(self._seen) > self.max_entries:
                self._seen.popitem(last=False)
            return True


def make_handler(
    secret: str | bytes,
    *,
    tolerance_seconds: int = 300,
    cache: ReplayCache | None = None,
    report: Callable[[dict], None] = print,
):
    replay_cache = cache or ReplayCache()

    class Handler(BaseHTTPRequestHandler):
        server_version = "HookHarness/0.1"

        def log_message(self, _format: str, *_args) -> None:
            return

        def _respond(self, status: int, data: dict) -> None:
            encoded = json.dumps(data, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self) -> None:
            if self.path != "/webhook":
                self._respond(404, {"accepted": False, "reason": "not_found"})
                return
            try:
                size = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._respond(400, {"accepted": False, "reason": "invalid_length"})
                return
            if size < 0 or size > MAX_BODY_BYTES:
                self._respond(413, {"accepted": False, "reason": "payload_too_large"})
                return

            body = self.rfile.read(size)
            if len(body) != size:
                self._respond(400, {"accepted": False, "reason": "incomplete_body"})
                return
            try:
                json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._respond(400, {"accepted": False, "reason": "invalid_json"})
                return

            header = self.headers.get("X-HookHarness-Signature", "")
            try:
                timestamp = verify_signature(
                    body,
                    secret,
                    header,
                    tolerance_seconds=tolerance_seconds,
                )
            except SignatureError:
                self._respond(401, {"accepted": False, "reason": "invalid_signature"})
                return
            if not replay_cache.add_once(header):
                self._respond(409, {"accepted": False, "reason": "replay"})
                return

            report({"accepted": True, "bytes": len(body), "timestamp": timestamp})
            self._respond(202, {"accepted": True})

    return Handler


def create_server(
    secret: str | bytes,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    tolerance_seconds: int = 300,
    report: Callable[[dict], None] = print,
) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("receiver may bind only to loopback")
    server = ThreadingHTTPServer(
        (host, port),
        make_handler(secret, tolerance_seconds=tolerance_seconds, report=report),
    )
    server.daemon_threads = True
    return server
