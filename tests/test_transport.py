import io
import urllib.error
from email.message import Message

import pytest

from hookharness.transport import DeliveryError, DeliveryResult, send_webhook, validate_destination


class Response:
    status = 202
    headers = Message()

    def close(self):
        pass


class Opener:
    def __init__(self, results):
        self.results = iter(results)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        result = next(self.results)
        if isinstance(result, Exception):
            raise result
        return result


def test_destination_requires_tls_except_loopback():
    validate_destination("https://example.test/hook")
    validate_destination("http://127.0.0.1:8080/hook")
    with pytest.raises(DeliveryError):
        validate_destination("http://example.test/hook")
    with pytest.raises(DeliveryError):
        validate_destination("https://user:pass@example.test/hook")


def test_sender_retries_server_failure_and_redacts_request_body_from_result():
    unavailable = urllib.error.HTTPError("https://hidden.test/path", 503, "failure", Message(), io.BytesIO())
    opener = Opener([unavailable, Response()])
    pauses = []
    result = send_webhook(
        "https://hidden.test/path",
        b'{"private":"sample"}',
        b"x" * 32,
        attempts=2,
        opener_factory=lambda: opener,
        sleep=pauses.append,
        clock=lambda: 1_700_000_000,
    )
    assert result == DeliveryResult(status=202, attempts=2)
    assert len(opener.requests) == 2
    assert pauses == [0.25]
    assert opener.requests[0][0].data == b'{"private":"sample"}'
    assert "private" not in repr(result)


def test_sender_rejects_non_json_body_size_and_bad_attempt_count():
    opener = Opener([])
    with pytest.raises(DeliveryError, match="1 MiB"):
        send_webhook("https://example.test", b"x" * (1024 * 1024 + 1), b"x" * 32, opener_factory=lambda: opener)
    with pytest.raises(DeliveryError, match="attempts"):
        send_webhook("https://example.test", b"{}", b"x" * 32, attempts=6, opener_factory=lambda: opener)
