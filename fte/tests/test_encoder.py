#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the regex ``fte.Encoder`` convenience wrapper."""

import os
import unittest

import fte


KEY = bytes(range(32))
REGEX = r"^[a-z]+$"
FIXED_SLICES = [128, 256, 512]
MSG_LEN = 15
CONCATS = 8


class Tests(unittest.TestCase):
    def test_single_encode_decode(self):
        for fixed_slice in FIXED_SLICES:
            encoder = fte.Encoder(REGEX, fixed_slice, key=KEY)
            plaintext = os.urandom(MSG_LEN)

            covertext = encoder.encode(plaintext)
            self.assertEqual(len(covertext), fixed_slice)

            recovered, remainder = encoder.decode(covertext)
            self.assertEqual(recovered, plaintext)
            self.assertEqual(remainder, b"")

    def test_concatenated_messages(self):
        # Each covertext is exactly fixed_slice bytes, so a concatenated stream
        # is parsed one message at a time via the returned remainder.
        for fixed_slice in FIXED_SLICES:
            encoder = fte.Encoder(REGEX, fixed_slice, key=KEY)
            plaintext = os.urandom(MSG_LEN)

            stream = b"".join(encoder.encode(plaintext) for _ in range(CONCATS))

            recovered = []
            buffer = stream
            while buffer:
                message, buffer = encoder.decode(buffer)
                recovered.append(message)

            self.assertEqual(recovered, [plaintext] * CONCATS)

    def test_empty_input_returns_empty(self):
        encoder = fte.Encoder(REGEX, 128, key=KEY)
        self.assertEqual(encoder.encode(b""), b"")

    def test_invalid_input_type(self):
        encoder = fte.Encoder(REGEX, 128, key=KEY)
        with self.assertRaises(fte.InvalidInputException):
            encoder.encode("not bytes")
        with self.assertRaises(fte.InvalidInputException):
            encoder.decode("not bytes")

    def test_covertext_too_short(self):
        encoder = fte.Encoder(REGEX, 128, key=KEY)
        with self.assertRaises(fte.DecodeFailureError):
            encoder.decode(b"too short")

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            fte.Encoder(REGEX, 128, key=b"too short")

    def test_capacity_matches_cardinality(self):
        encoder = fte.Encoder(r"^[0-9a-f]+$", 128, key=KEY)
        # 16 ** 128 == 2 ** 512, so floor(log2(N)) - 1 == 511.
        self.assertEqual(encoder.capacity, 511)

    def test_interoperable_with_fte_regexformat(self):
        # Encoder wraps the same engine, so an FTE built from the same regex,
        # length, and key decodes Encoder covertext and vice versa.
        encoder = fte.Encoder(r"^[0-9a-f]+$", 96, key=KEY)
        engine = fte.FTE(
            format=fte.RegexFormat(r"^[0-9a-f]+$", length=96), key=KEY
        )

        self.assertEqual(engine.decode(encoder.encode(b"hello")), b"hello")

        recovered, remainder = encoder.decode(engine.encode(b"hello"))
        self.assertEqual((recovered, remainder), (b"hello", b""))


if __name__ == "__main__":
    unittest.main()
