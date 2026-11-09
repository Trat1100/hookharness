import pytest

from hookharness.signing import SignatureError, format_signature, verify_signature


def test_signature_round_trip_and_tamper_detection():
    body = b'{"event":"order.created"}'
    header = format_signature(body, "secret-material-for-tests-only", 1_700_000_000)
    assert verify_signature(body, "secret-material-for-tests-only", header, now=1_700_000_001) == 1_700_000_000
    with pytest.raises(SignatureError, match="verification failed"):
        verify_signature(body + b" ", "secret-material-for-tests-only", header, now=1_700_000_001)


def test_signature_rejects_stale_or_malformed_header():
    body = b"{}"
    header = format_signature(body, b"x" * 32, 100)
    with pytest.raises(SignatureError, match="outside"):
        verify_signature(body, b"x" * 32, header, now=500, tolerance_seconds=10)
    with pytest.raises(SignatureError, match="invalid signature header"):
        verify_signature(body, b"x" * 32, "t=100,v1=bad", now=100)
