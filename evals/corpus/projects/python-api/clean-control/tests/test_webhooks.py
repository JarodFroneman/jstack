import hashlib
import hmac
import unittest

from src.webhooks import verify_webhook


SECRET = b"fixture-secret"
NOW = 1_700_000_000


def signature_header(body: bytes, timestamp: int = NOW) -> str:
    payload = str(timestamp).encode("ascii") + b"." + body
    signature = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
    return "t=%d,v1=%s" % (timestamp, signature)


class WebhookVerifierTests(unittest.TestCase):
    def test_accepts_a_fresh_valid_signature(self) -> None:
        body = b'{"event":"invoice.paid"}'
        self.assertTrue(verify_webhook(body, signature_header(body), SECRET, NOW))

    def test_rejects_a_modified_body(self) -> None:
        original = b'{"event":"invoice.paid"}'
        modified = b'{"event":"invoice.refunded"}'
        self.assertFalse(
            verify_webhook(modified, signature_header(original), SECRET, NOW)
        )

    def test_rejects_a_stale_signature(self) -> None:
        body = b'{"event":"invoice.paid"}'
        timestamp = NOW - 301
        self.assertFalse(
            verify_webhook(body, signature_header(body, timestamp), SECRET, NOW)
        )

    def test_rejects_malformed_headers(self) -> None:
        self.assertFalse(verify_webhook(b"{}", "v1=missing-time", SECRET, NOW))

    def test_rejects_duplicate_signature_fields(self) -> None:
        body = b"{}"
        header = signature_header(body)
        self.assertFalse(verify_webhook(body, header + ",t=%d" % NOW, SECRET, NOW))


if __name__ == "__main__":
    unittest.main()
