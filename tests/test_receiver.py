import http.client
import json
import threading
import time

from hookharness.receiver import create_server
from hookharness.signing import format_signature


def post(server, body, signature):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    connection.request(
        "POST",
        "/webhook",
        body=body,
        headers={"Content-Type": "application/json", "X-HookHarness-Signature": signature},
    )
    response = connection.getresponse()
    result = response.status, json.loads(response.read())
    connection.close()
    return result


def test_receiver_accepts_signed_event_and_rejects_replay():
    reports = []
    server = create_server(b"x" * 32, port=0, report=reports.append)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    body = b'{"event":"demo"}'
    signature = format_signature(body, b"x" * 32, int(time.time()))
    try:
        assert post(server, body, signature)[0] == 202
        assert post(server, body, signature) == (409, {"accepted": False, "reason": "replay"})
        assert reports == [{"accepted": True, "bytes": len(body), "timestamp": int(signature.split(",")[0][2:])}]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_receiver_rejects_tampered_payload():
    server = create_server(b"x" * 32, port=0, report=lambda _event: None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    body = b'{"event":"demo"}'
    signature = format_signature(body, b"x" * 32, int(time.time()))
    try:
        assert post(server, body + b" ", signature)[0] == 401
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
