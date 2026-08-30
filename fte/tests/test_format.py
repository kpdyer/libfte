"""Tests for the ranked-format API."""

import os
import unittest

import fte
from fte.format import (
    _bytes_to_rank,
    _frame_rank_limit,
    _rank_offset,
    _rank_to_bytes,
)


KEY = bytes(range(32))


class HexFormat:
    """A tiny dependency-free ranked string format for unit tests."""

    def rank(self, value: str) -> int:
        return int(value, 16)

    def unrank(self, index: int) -> str:
        return format(index, "x")


class Tests(unittest.TestCase):
    def test_structural_format_conformance(self):
        self.assertIsInstance(HexFormat(), fte.RankedFormat)

        class FiniteHex(HexFormat):
            cardinality = 256

        self.assertIsInstance(FiniteHex(), fte.FiniteRankedFormat)

    def test_roundtrip(self):
        cipher = fte.FTE(format=HexFormat(), key=KEY)

        for plaintext in (b"", b"x", b"hello", b"embedded\x00zero"):
            covertext = cipher.encrypt(plaintext)
            self.assertIsInstance(covertext, str)
            self.assertEqual(cipher.decrypt(covertext), plaintext)

    def test_shortlex_byte_ranking_preserves_length_and_zeroes(self):
        values = (
            b"",
            b"\x00",
            b"\x00\x00",
            b"\x00\x01",
            b"\xff",
            bytes(range(256)),
        )

        ranks = [_bytes_to_rank(value) for value in values]

        self.assertEqual(len(set(ranks)), len(values))
        for value, rank in zip(values, ranks):
            self.assertEqual(_rank_to_bytes(rank), value)
        for rank in range(10_000):
            self.assertEqual(_bytes_to_rank(_rank_to_bytes(rank)), rank)

    def test_invalid_plaintext(self):
        cipher = fte.FTE(format=HexFormat(), key=KEY)

        with self.assertRaises(TypeError):
            cipher.encrypt("not bytes")

    def test_constructor_validates_format_and_key(self):
        class NonCallableFormat:
            rank = 1
            unrank = 2

        with self.assertRaises(TypeError):
            fte.FTE(format=object(), key=KEY)
        with self.assertRaises(TypeError):
            fte.FTE(format=NonCallableFormat(), key=KEY)
        with self.assertRaises(TypeError):
            fte.FTE(format=HexFormat, key=KEY)
        with self.assertRaises(ValueError):
            fte.FTE(format=HexFormat(), key=b"short")
        with self.assertRaises(TypeError):
            fte.FTE(format=HexFormat(), key="not bytes")
        with self.assertRaises(ValueError):
            fte.FTE(format=HexFormat(), key=KEY, max_plaintext_bytes=-1)
        with self.assertRaises(ValueError):
            fte.FTE(format=HexFormat(), key=KEY, max_plaintext_bytes=True)
        with self.assertRaises(ValueError):
            fte.FTE(
                format=HexFormat(),
                key=KEY,
                max_plaintext_bytes=1 << 32,
            )

        class InvalidCardinality(HexFormat):
            cardinality = True

        with self.assertRaises(fte.FormatContractError):
            fte.FTE(format=InvalidCardinality(), key=KEY)

    def test_plaintext_and_rank_resource_limit(self):
        cipher = fte.FTE(
            format=HexFormat(),
            key=KEY,
            max_plaintext_bytes=4,
        )

        self.assertEqual(cipher.max_plaintext_bytes, 4)
        self.assertEqual(cipher.decrypt(cipher.encrypt(b"1234")), b"1234")
        with self.assertRaises(fte.MessageTooLargeError):
            cipher.encrypt(b"12345")

        oversized_rank = _rank_offset(cipher._max_frame_bytes + 1)
        oversized = cipher.format.unrank(oversized_rank)
        with self.assertRaises(fte.InvalidCovertextError):
            cipher.decrypt(oversized)

        excessive_bits = cipher.format.unrank(
            1 << (8 * cipher._max_frame_bytes + 1)
        )
        with self.assertRaises(fte.InvalidCovertextError):
            cipher.decrypt(excessive_bits)

    def test_frame_preserves_leading_zero_bytes(self):
        framed = b"\x01\x00\x00" + b"e" * 30
        self.assertEqual(_rank_to_bytes(_bytes_to_rank(framed)), framed)

    def test_decode_rejects_unframed_rank(self):
        cipher = fte.FTE(format=HexFormat(), key=KEY)

        with self.assertRaises(fte.InvalidCovertextError):
            cipher.decrypt("02")
        with self.assertRaises(fte.InvalidCovertextError):
            cipher.decrypt("01")

        ciphertext = cipher._encrypter.encrypt(b"hello")
        wrong_version = cipher.format.unrank(
            _bytes_to_rank(b"\x02" + ciphertext)
        )
        with self.assertRaises(fte.InvalidCovertextError):
            cipher.decrypt(wrong_version)

    def test_decode_rejects_trailing_ciphertext(self):
        cipher = fte.FTE(format=HexFormat(), key=KEY)
        ciphertext = cipher._encrypter.encrypt(b"hello") + b"trailing"
        index = _bytes_to_rank(b"\x01" + ciphertext)
        covertext = cipher.format.unrank(index)

        with self.assertRaises(fte.InvalidCovertextError):
            cipher.decrypt(covertext)

    def test_decode_rejects_invalid_rank_type(self):
        class BadFormat:
            def rank(self, value):
                return True

            def unrank(self, index):
                return "unused"

        cipher = fte.FTE(format=BadFormat(), key=KEY)

        with self.assertRaises(fte.FormatContractError):
            cipher.decrypt("anything")

    def test_backend_failures_are_normalized(self):
        class FullFormat(HexFormat):
            def unrank(self, index):
                raise IndexError("full")

        class RejectingFormat(HexFormat):
            def rank(self, value):
                raise ValueError("not a member")

        with self.assertRaises(fte.FormatCapacityError) as capacity:
            fte.FTE(format=FullFormat(), key=KEY).encrypt(b"hello")
        self.assertIsInstance(capacity.exception.__cause__, IndexError)

        with self.assertRaises(fte.InvalidCovertextError) as invalid:
            fte.FTE(format=RejectingFormat(), key=KEY).decrypt("anything")
        self.assertIsInstance(invalid.exception.__cause__, ValueError)

    def test_finite_capacity_is_preflighted_at_exact_boundary(self):
        frame_length = 1 + fte.Encrypter._CTXT_EXPANSION
        required_cardinality = _frame_rank_limit(frame_length)

        class ExactFiniteHex(HexFormat):
            cardinality = required_cardinality

        class TooSmallFiniteHex(HexFormat):
            cardinality = required_cardinality - 1

        exact = fte.FTE(format=ExactFiniteHex(), key=KEY)
        self.assertEqual(exact.decrypt(exact.encrypt(b"")), b"")

        with self.assertRaises(fte.FormatCapacityError):
            fte.FTE(format=TooSmallFiniteHex(), key=KEY).encrypt(b"")

        out_of_range = ExactFiniteHex().unrank(required_cardinality)
        with self.assertRaises(fte.InvalidCovertextError):
            exact.decrypt(out_of_range)

    def test_wrong_key_is_invalid_covertext(self):
        sender = fte.FTE(format=HexFormat(), key=KEY)
        receiver = fte.FTE(format=HexFormat(), key=bytes(reversed(KEY)))

        with self.assertRaises(fte.InvalidCovertextError):
            receiver.decrypt(sender.encrypt(b"hello"))

    def test_format_property_is_read_only(self):
        cipher = fte.FTE(format=HexFormat(), key=KEY)

        with self.assertRaises(AttributeError):
            cipher.format = HexFormat()

    def test_roundtrip_over_varied_sizes(self):
        cipher = fte.FTE(format=HexFormat(), key=KEY, max_plaintext_bytes=2048)

        for length in list(range(0, 260)) + [512, 1024, 2048]:
            plaintext = os.urandom(length)
            self.assertEqual(cipher.decrypt(cipher.encrypt(plaintext)), plaintext)

    def test_cross_endpoint_roundtrip(self):
        # Two independently constructed instances must interoperate: the wire
        # format is a contract between separate sender and receiver processes.
        sender = fte.FTE(format=HexFormat(), key=KEY)
        receiver = fte.FTE(format=HexFormat(), key=KEY)

        for plaintext in (b"", b"x", b"hello", os.urandom(64)):
            self.assertEqual(receiver.decrypt(sender.encrypt(plaintext)), plaintext)

    def test_max_plaintext_bytes_zero_allows_only_empty(self):
        cipher = fte.FTE(format=HexFormat(), key=KEY, max_plaintext_bytes=0)

        self.assertEqual(cipher.max_plaintext_bytes, 0)
        self.assertEqual(cipher.decrypt(cipher.encrypt(b"")), b"")
        with self.assertRaises(fte.MessageTooLargeError):
            cipher.encrypt(b"x")

    def test_public_exports(self):
        self.assertIn("FTE", fte.__all__)
        self.assertIn("FiniteRankedFormat", fte.__all__)
        self.assertIn("RankedFormat", fte.__all__)
        self.assertIn("FormatCapacityError", fte.__all__)
        self.assertIn("FormatContractError", fte.__all__)
        self.assertIn("InvalidCovertextError", fte.__all__)
        self.assertIn("MessageTooLargeError", fte.__all__)
        self.assertIs(fte.FTE, fte.format.FTE)
        self.assertIs(fte.RankedFormat, fte.format.RankedFormat)


if __name__ == "__main__":
    unittest.main()
