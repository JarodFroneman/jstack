"""Public characterization tests for the legacy C token comparator."""

import ctypes
import os
import unittest


LIBRARY_PATH = os.environ["JSTACK_LEGACY_LIBRARY"]
LIBRARY = ctypes.CDLL(LIBRARY_PATH)
TOKEN_EQUAL = LIBRARY.legacy_token_equal
TOKEN_EQUAL.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
TOKEN_EQUAL.restype = ctypes.c_int


def token_equal(stored: bytes, supplied: bytes) -> int:
    return TOKEN_EQUAL(stored, len(stored), supplied, len(supplied))


class LegacyTokenTests(unittest.TestCase):
    def test_accepts_an_identical_token(self) -> None:
        self.assertEqual(token_equal(b"f6c21e99", b"f6c21e99"), 1)

    def test_rejects_prefix_suffix_and_wrong_byte_values(self) -> None:
        self.assertEqual(token_equal(b"f6c21e99", b"f6c2"), 0)
        self.assertEqual(token_equal(b"f6c21e99", b"21e99"), 0)
        self.assertEqual(token_equal(b"f6c21e99", b"f6c21e98"), 0)

    def test_rejects_an_empty_token(self) -> None:
        self.assertEqual(token_equal(b"", b""), 0)


if __name__ == "__main__":
    unittest.main()
