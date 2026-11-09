# HookHarness

HookHarness is a local-first command-line tool for testing webhook signatures, endpoint responses, retries, and replay handling with synthetic JSON events.

## What it does

- Signs a raw JSON body with timestamped HMAC-SHA256.
- Sends a fixture to an HTTPS endpoint, or to loopback HTTP for local testing.
- Retries network errors, HTTP 429, and HTTP 5xx with bounded exponential backoff.
- Runs a loopback-only receiver that verifies timestamps and signatures and rejects duplicate deliveries.
- Keeps secrets in environment variables and never prints secrets or raw payloads.
- Returns stable exit codes for accepted, rejected, and transport-failure outcomes.

The signature format is **t=<unix-seconds>,v1=<hex-digest>**. The signed message is the timestamp, a period, and the exact request bytes. The format is intentionally small and documented; it is not a claim of compatibility with every webhook provider.

## Install

Requires Python 3.11 or later.

~~~powershell
python -m pip install .
~~~

For development, install the pinned test tools with `python -m pip install --require-hashes -r requirements-dev.lock`, then install the checkout with `python -m pip install --no-deps --no-build-isolation -e .`.

## Local end-to-end example

Create a random secret in your shell and start the receiver:

~~~powershell
$env:HOOKHARNESS_SECRET = 'use-a-random-value-at-least-32-characters-long'
hookharness serve --port 8787
~~~

In another terminal, send a synthetic fixture:

~~~powershell
$env:HOOKHARNESS_SECRET = 'use-a-random-value-at-least-32-characters-long'
hookharness send http://127.0.0.1:8787/webhook --payload examples/order-created.json
~~~

Remote targets must use HTTPS. Redirects are not followed, to prevent silently forwarding a payload to a different destination. The receiver binds only to 127.0.0.1; it is for local development, not production hosting.

## Commands

~~~text
hookharness sign examples/order-created.json --secret-env HOOKHARNESS_SECRET
hookharness send https://example.test/hooks/orders --payload examples/order-created.json --secret-env HOOKHARNESS_SECRET --attempts 3
hookharness serve --port 8787 --secret-env HOOKHARNESS_SECRET
~~~

The sign command prints only the signature header value. The sender reports status and attempt count, not the body or secret. The receiver reports payload byte count and verification outcome, not payload contents.

## Security and limitations

- Use a synthetic payload when testing third-party endpoints.
- The secret is read only from the named environment variable and must be at least 32 bytes.
- Request bodies are limited to 1 MiB and must contain valid JSON.
- HTTPS is required for non-loopback destinations; HTTP is allowed only for loopback addresses.
- Redirects are rejected. The tool does not resolve vendor-specific signing conventions or provider account behavior.
- The local receiver is unauthenticated beyond HMAC verification and is intended only for loopback development.
- HookHarness sends requests only when the send command is explicitly run; it does not create a background service or phone home.

## Development

~~~powershell
python -m pytest -q
~~~

CI runs the test suite on Python 3.11 and 3.12.

## Project structure

- signing.py — timestamped HMAC creation and verification.
- transport.py — URL checks, bounded retries, and HTTP delivery.
- receiver.py — loopback receiver and replay cache.
- cli.py — command-line interface.

## License

MIT. See the included LICENSE file.
