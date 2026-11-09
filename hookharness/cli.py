from __future__ import annotations

import argparse
import os
import re
import sys
import time

from .receiver import create_server
from .signing import format_signature
from .transport import DeliveryError, load_json_payload, send_webhook

ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _secret(env_name: str) -> str:
    if not ENV_NAME.fullmatch(env_name):
        raise ValueError("secret environment variable name must use uppercase letters, digits, and underscores")
    value = os.environ.get(env_name, "")
    if len(value.encode("utf-8")) < 32:
        raise ValueError("secret environment variable must contain at least 32 bytes")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hookharness", description="Test webhook signatures and delivery behavior with synthetic events.")
    commands = parser.add_subparsers(dest="command", required=True)

    sign = commands.add_parser("sign", help="print a timestamped HMAC signature for a JSON fixture")
    sign.add_argument("payload")
    sign.add_argument("--secret-env", default="HOOKHARNESS_SECRET")
    sign.add_argument("--timestamp", type=int)

    send = commands.add_parser("send", help="send a signed JSON fixture to an HTTPS or loopback endpoint")
    send.add_argument("url")
    send.add_argument("--payload", required=True)
    send.add_argument("--secret-env", default="HOOKHARNESS_SECRET")
    send.add_argument("--signature-header", default="X-HookHarness-Signature")
    send.add_argument("--attempts", type=int, default=1)
    send.add_argument("--timeout", type=float, default=5.0)

    serve = commands.add_parser("serve", help="run a loopback-only HMAC verifier at /webhook")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--secret-env", default="HOOKHARNESS_SECRET")
    serve.add_argument("--tolerance-seconds", type=int, default=300)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        secret = _secret(args.secret_env)
        if args.command == "sign":
            body = load_json_payload(args.payload)
            timestamp = int(time.time()) if args.timestamp is None else args.timestamp
            print(format_signature(body, secret, timestamp))
            return 0

        if args.command == "send":
            body = load_json_payload(args.payload)
            result = send_webhook(
                args.url,
                body,
                secret,
                signature_header=args.signature_header,
                timeout_seconds=args.timeout,
                attempts=args.attempts,
            )
            request_id = f"; request_id={result.request_id}" if result.request_id else ""
            print(f"HTTP {result.status}; attempts={result.attempts}{request_id}")
            return 0 if 200 <= result.status < 300 else 1

        if args.command == "serve":
            if not 0 <= args.port <= 65535 or args.tolerance_seconds < 0:
                raise ValueError("port or timestamp tolerance is out of range")
            server = create_server(
                secret,
                port=args.port,
                tolerance_seconds=args.tolerance_seconds,
            )
            print(f"Listening on http://127.0.0.1:{server.server_port}/webhook")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
    except (ValueError, DeliveryError) as exc:
        print(f"hookharness: {exc}", file=sys.stderr)
        return 2
    return 2
