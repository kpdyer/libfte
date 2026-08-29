"""Tests for the built-in RankedFormat regex provider."""

import unittest

import fte


KEY = bytes(range(32))


class Tests(unittest.TestCase):
    def test_conforms_and_roundtrips(self):
        format = fte.RegexFormat(r"^[0-9a-f]+$", length=96)
        encoder = fte.FTE(format=format, key=KEY)

        covertext = encoder.encode(b"hello")

        self.assertIsInstance(format, fte.RankedFormat)
        self.assertIsInstance(covertext, bytes)
        self.assertEqual(len(covertext), 96)
        self.assertEqual(encoder.decode(covertext), b"hello")
        self.assertEqual(format.cardinality, 16 ** 96)

    def test_insufficient_fixed_length_is_capacity_error(self):
        encoder = fte.FTE(
            format=fte.RegexFormat(r"^[0-9a-f]+$", length=8),
            key=KEY,
        )

        with self.assertRaises(fte.FormatCapacityError):
            encoder.encode(b"hello")

    def test_constructor_validation(self):
        with self.assertRaises(TypeError):
            fte.RegexFormat(b"^[0-9a-f]+$", length=96)
        with self.assertRaises(ValueError):
            fte.RegexFormat(r"^[0-9a-f]+$", length=0)


if __name__ == "__main__":
    unittest.main()
