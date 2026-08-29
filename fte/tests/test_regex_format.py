"""Tests for the built-in RankedFormat regex provider."""

import os
import re
import unittest

import fte


KEY = bytes(range(32))


class Tests(unittest.TestCase):
    def test_conforms_and_roundtrips(self):
        fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=96)
        encoder = fte.FTE(format=fmt, key=KEY)

        covertext = encoder.encode(b"hello")

        self.assertIsInstance(fmt, fte.RankedFormat)
        self.assertIsInstance(covertext, bytes)
        self.assertEqual(len(covertext), 96)
        self.assertEqual(encoder.decode(covertext), b"hello")
        self.assertEqual(fmt.cardinality, 16 ** 96)

    def test_insufficient_fixed_length_is_capacity_error(self):
        encoder = fte.FTE(
            format=fte.RegexFormat(r"^[0-9a-f]+$", length=8),
            key=KEY,
        )

        with self.assertRaises(fte.FormatCapacityError):
            encoder.encode(b"hello")

    def test_multistate_dfa_roundtrips(self):
        # ``^(0|1)[a-z]+$`` compiles to a multi-state, non-dense DFA, exercising
        # the standard Goldberg-Sipser rank/unrank branches that the single
        # self-looping state of ``^[0-9a-f]+$`` never reaches.
        pattern = r"^(0|1)[a-z]+$"
        encoder = fte.FTE(format=fte.RegexFormat(pattern, length=200), key=KEY)
        matcher = re.compile(pattern.encode())

        for plaintext in (b"", b"x", b"hello world", os.urandom(40)):
            covertext = encoder.encode(plaintext)
            self.assertEqual(len(covertext), 200)
            self.assertIsNotNone(matcher.fullmatch(covertext))
            self.assertEqual(encoder.decode(covertext), plaintext)

    def test_cross_endpoint_roundtrip(self):
        sender = fte.FTE(
            format=fte.RegexFormat(r"^[0-9a-f]+$", length=96), key=KEY
        )
        receiver = fte.FTE(
            format=fte.RegexFormat(r"^[0-9a-f]+$", length=96), key=KEY
        )

        self.assertEqual(receiver.decode(sender.encode(b"hello")), b"hello")

    def test_constructor_validation(self):
        with self.assertRaises(TypeError):
            fte.RegexFormat(b"^[0-9a-f]+$", length=96)
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^[0-9a-f]+$", length=0)

    def test_empty_language_is_value_error(self):
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^(ab)+$", length=5)  # no words of odd length
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^abc$", length=2)  # literal longer than length

    def test_invalid_pattern_is_value_error(self):
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^(ab", length=4)  # unbalanced parenthesis


if __name__ == "__main__":
    unittest.main()
