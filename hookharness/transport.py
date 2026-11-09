from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from .signing import format_signature

MAX_BODY_BYTES = 1024 * 1024
MAX_ATTEMPTS = 5


class DeliveryError(RuntimeError):
    """A safe-to-display delivery error that contains no URL or payload."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class DeliveryResult:
    status: int
    attempts: int
    request_id: str | None = None


def validate_destination(url: str) -> None:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if parsed.scheme not in {"https", "http"} or not host:
            raise ValueError
        _ = parsed.port
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError
        if parsed.scheme == "http":
            if host.lower() == "localhost":
                return
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError
    except (ValueError, TypeError):
        raise DeliveryError("destination must be HTTPS, or HTTP on loopback, without URL credentials") from None


def _opener():
    return urllib.request.build_opener(NoRedirect())


def send_webhook(
    url: str,
    body: bytes,
    secret: str | bytes,
    *,
    signature_header: str = "X-HookHarness-Signature",
    timeout_seconds: float = 5.0,
    attempts: int = 1,
    opener_factory: Callable[[], object] = _opener,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> DeliveryResult:
    validate_destination(url)
    if len(body) > MAX_BODY_BYTES:
        raise DeliveryError("payload exceeds the 1 MiB limit")
    if not 1 <= attempts <= MAX_ATTEMPTS:
        raise DeliveryError(f"attempts must be between 1 and {MAX_ATTEMPTS}")
    if not 0.1 <= timeout_seconds <= 30:
        raise DeliveryError("timeout must be between 0.1 and 30 seconds")
    if not signature_header or len(signature_header) > 128 or any(ch in signature_header for ch in "\r\n:"):
        raise DeliveryError("invalid signature header name")

    for attempt in range(1, attempts + 1):
        signature = format_signature(body, secret, int(clock()))
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "HookHarness/0.1",
                signature_header: signature,
            },
        )
        opener = opener_factory()
        try:
            response = opener.open(request, timeout=timeout_seconds)
            try:
                status = int(response.status)
                headers = response.headers
            finally:
                response.close()
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            headers = exc.headers
            exc.close()
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError):
            if attempt >= attempts:
                raise DeliveryError("delivery failed after the configured attempts") from None
            sleep(min(0.25 * (2 ** (attempt - 1)), 2.0))
            continue

        request_id = headers.get("X-Request-ID") if headers else None
        if status == 429 or 500 <= status <= 599:
            if attempt < attempts:
                retry_after = headers.get("Retry-After") if headers else None
                try:
                    delay = min(max(float(retry_after), 0.0), 2.0) if retry_after else min(0.25 * (2 ** (attempt - 1)), 2.0)
                except ValueError:
                    delay = min(0.25 * (2 ** (attempt - 1)), 2.0)
                sleep(delay)
                continue
        return DeliveryResult(status=status, attempts=attempt, request_id=request_id)

    raise DeliveryError("delivery did not complete")


def load_json_payload(path: str) -> bytes:
    try:
        with open(path, "rb") as stream:
            body = stream.read(MAX_BODY_BYTES + 1)
    except OSError:
        raise DeliveryError("payload file could not be read") from None
    if len(body) > MAX_BODY_BYTES:
        raise DeliveryError("payload exceeds the 1 MiB limit")
    try:
        json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DeliveryError("payload must contain valid JSON") from None
    return body
