"""Public characterization tests for the legacy C configuration reader."""

import ctypes
import os
import unittest


LIBRARY_PATH = os.environ["JSTACK_LEGACY_LIBRARY"]
LIBRARY = ctypes.CDLL(LIBRARY_PATH)
LOOKUP = LIBRARY.legacy_config_lookup
LOOKUP.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
LOOKUP.restype = ctypes.c_int


def lookup(contents: bytes, key: bytes):
    output = ctypes.create_string_buffer(32)
    found = LOOKUP(contents, key, output, len(output))
    return found, output.value


class LegacyConfigurationTests(unittest.TestCase):
    def test_reads_an_exact_key(self) -> None:
        found, value = lookup(b"HOST=127.0.0.1\nPORT=8080\nMODE=worker\n", b"PORT")
        self.assertEqual((found, value), (1, b"8080"))

    def test_ignores_commented_entries(self) -> None:
        found, value = lookup(b"#PORT=9000\nPORT=8080\n", b"PORT")
        self.assertEqual((found, value), (1, b"8080"))

    def test_reports_a_missing_key(self) -> None:
        found, value = lookup(b"HOST=local\n", b"PORT")
        self.assertEqual((found, value), (0, b""))


if __name__ == "__main__":
    unittest.main()
