"""Tests for the shortlex :class:`~fte.formats.bytes.BytesFormat`."""

import os
import unittest

from fte.formats.bytes import BytesFormat
from fte._frame import bytes_to_rank, rank_offset, rank_to_bytes


class Tests(unittest.TestCase):
    def setUp(self):
        self.fmt = BytesFormat()

    def test_empty_bytes_rank_zero(self):
        self.assertEqual(self.fmt.rank(b""), 0)
        self.assertEqual(self.fmt.unrank(0), b"")

    def test_inverse_laws_over_a_range_of_ranks(self):
        # unrank then rank is identity across a contiguous prefix of the space.
        for index in range(20_000):
            value = self.fmt.unrank(index)
            self.assertEqual(self.fmt.rank(value), index)

    def test_serialization_roundtrip_preserves_leading_zeros(self):
        values = (
            b"",
            b"\x00",
            b"\x00\x00",
            b"\x00\x01",
            b"\x00\x00\xff",
            b"\xff",
            b"\xff\xff\xff",
            bytes(range(256)),
            os.urandom(64),
        )
        for value in values:
            rank = bytes_to_rank(value)
            self.assertEqual(rank_to_bytes(rank), value)
            # Length is recoverable purely from the rank.
            self.assertEqual(len(rank_to_bytes(rank)), len(value))

    def test_shortlex_orders_by_length_then_value(self):
        # Every length-n string ranks below every length-(n+1) string.
        self.assertLess(bytes_to_rank(b"\xff"), bytes_to_rank(b"\x00\x00"))
        # Within a length, order is numeric.
        self.assertLess(
            bytes_to_rank(b"\x00\x01"), bytes_to_rank(b"\x00\x02")
        )
        # Ranks are contiguous: the whole length-1 slice is [offset(1), offset(2)).
        one_byte = sorted(bytes_to_rank(bytes([b])) for b in range(256))
        self.assertEqual(one_byte, list(range(rank_offset(1), rank_offset(2))))

    def test_rank_offset_matches_closed_form(self):
        # rank_offset(n) is 0x0101..01 (n bytes of 0x01): the sum of 256**i for
        # i in range(n), i.e. (256**n - 1) // 255. Guards the O(n) rewrite
        # against regressing to (or diverging from) the closed form.
        for length in (0, 1, 2, 5, 17, 64, 255, 256, 1000):
            self.assertEqual(rank_offset(length), (256 ** length - 1) // 255)
            self.assertEqual(
                rank_offset(length), int.from_bytes(b"\x01" * length, "big")
            )

    def test_frame_rank_limit_matches_closed_form(self):
        from fte._frame import frame_rank_limit

        for frame_length in (1, 2, 5, 33, 128, 300):
            self.assertEqual(
                frame_rank_limit(frame_length),
                rank_offset(frame_length) + 2 * 256 ** (frame_length - 1),
            )

    def test_rank_rejects_non_bytes(self):
        with self.assertRaises(TypeError):
            self.fmt.rank("not bytes")

    def test_unrank_rejects_bad_index(self):
        with self.assertRaises(ValueError):
            self.fmt.unrank(-1)
        with self.assertRaises(ValueError):
            self.fmt.unrank(True)

    def test_fingerprint_is_stable_bytes(self):
        self.assertEqual(self.fmt.fingerprint, b"fte:bytes:shortlex:1")
        self.assertEqual(BytesFormat().fingerprint, self.fmt.fingerprint)

    def test_no_cardinality_because_unbounded(self):
        self.assertIsNone(getattr(self.fmt, "cardinality", None))

    def test_bytearray_is_accepted_and_normalized(self):
        self.assertEqual(self.fmt.rank(bytearray(b"\x00\x01")), bytes_to_rank(b"\x00\x01"))


if __name__ == "__main__":
    unittest.main()
