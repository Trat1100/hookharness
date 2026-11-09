from __future__ import annotations

import hashlib
import hmac
import re
import time

SIGNATURE_RE = re.compile(r"^t=(0|[1-9][0-9]*),v1=([0-9a-f]{64})$")


class SignatureError(ValueError):
    """A webhook signature is malformed, invalid, or outside its time window."""


def signature_digest(body: bytes, secret: str | bytes, timestamp: int) -> str:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    signed = str(timestamp).encode("ascii") + b"." + body
    return hmac.new(key, signed, hashlib.sha256).hexdigest()


def format_signature(body: bytes, secret: str | bytes, timestamp: int) -> str:
    return f"t={timestamp},v1={signature_digest(body, secret, timestamp)}"


def verify_signature(
    body: bytes,
    secret: str | bytes,
    header: str,
    *,
    now: int | None = None,
    tolerance_seconds: int = 300,
) -> int:
    match = SIGNATURE_RE.fullmatch(header.strip())
    if not match:
        raise SignatureError("invalid signature header")

    timestamp = int(match.group(1))
    current = int(time.time()) if now is None else int(now)
    if tolerance_seconds < 0 or abs(current - timestamp) > tolerance_seconds:
        raise SignatureError("signature timestamp outside allowed window")

    expected = signature_digest(body, secret, timestamp)
    if not hmac.compare_digest(expected, match.group(2)):
        raise SignatureError("signature verification failed")
    return timestamp
