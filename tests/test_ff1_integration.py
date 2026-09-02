"""Integration tests for the real deterministic cipher (``cipher="ff1"``).

These exercise :class:`fte.FTE` against the genuine format-preserving cipher
from libffx (``pip install 'fte[fpe]'``, which CI installs). Without it the
whole module skips via ``pytest.importorskip("ffx")``; the engine mechanics
themselves are covered without ffx in ``test_engine_matrix.py``.
"""

import unittest

import pytest

pytest.importorskip("ffx")

import fte
from fte.core import FTE, InvalidCovertextError


KEY = bytes(range(16))  # FF1 accepts 16/24/32-byte keys.


class Tests(unittest.TestCase):
    def test_fpe_digits_global_roundtrip(self):
        fmt = fte.RegexFormat(r"^[0-9]+$", length=16)
        eng = FTE(input_format=fmt, output_format=fmt, cipher="ff1", key=KEY)
        pt = b"0123456789012345"
        ct = eng.encrypt(pt)
        self.assertEqual(len(ct), 16)
        self.assertEqual(fmt.rank(ct), fmt.rank(ct))  # ct is in-format
        self.assertEqual(eng.decrypt(ct), pt)
        # Deterministic: same plaintext + tweak -> same covertext.
        self.assertEqual(eng.encrypt(pt), ct)

    def test_fpe_preserve_length_over_a_length_range(self):
        # Equal formats over a length range: length preservation is inferred,
        # and every length slice (6..9 digits) clears the one-million floor.
        fmt = fte.RegexFormat(r"^[0-9]+$", min_length=6, max_length=9)
        eng = fte.FTE(input_format=fmt, output_format=fmt, key=KEY)
        self.assertTrue(eng.preserve_length)
        for pt in (b"123456", b"1234567", b"12345678", b"123456789"):
            ct = eng.encrypt(pt)
            self.assertEqual(len(ct), len(pt))  # length preserved
            self.assertEqual(eng.decrypt(ct), pt)

    def test_cross_format_digits_to_hex(self):
        digits = fte.RegexFormat(r"^[0-9]+$", length=8)
        hex_fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=16)
        eng = FTE(input_format=digits, output_format=hex_fmt, cipher="ff1",
                  key=KEY)
        pt = b"01234567"
        ct = eng.encrypt(pt)
        self.assertEqual(len(ct), 16)  # hex output length
        self.assertEqual(hex_fmt.rank(ct), hex_fmt.rank(ct))  # in-format
        self.assertEqual(eng.decrypt(ct), pt)

    def test_wrong_tweak_rejected_when_output_dwarfs_input(self):
        # N_out / N_in > 2**60, so a wrong-tweak decryption almost surely
        # deciphers to a rank >= N_in and is rejected as never-a-covertext.
        # The input domain must clear the one-million floor, so 10**6
        # digits map into 16**24 = 2**96 hex words.
        digits = fte.RegexFormat(r"^[0-9]+$", length=6)      # 10**6
        hex_fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=24)  # 16**24 = 2**96
        self.assertGreater(hex_fmt.cardinality / digits.cardinality, 2 ** 60)
        eng = FTE(input_format=digits, output_format=hex_fmt, cipher="ff1",
                  key=KEY)
        ct = eng.encrypt(b"123456", tweak=b"per-record-A")
        self.assertEqual(eng.decrypt(ct, tweak=b"per-record-A"), b"123456")
        with self.assertRaises(InvalidCovertextError):
            eng.decrypt(ct, tweak=b"per-record-B")

    def test_fpe_convenience_roundtrip(self):
        fmt = fte.RegexFormat(r"^[0-9]+$", length=16)
        eng = fte.FTE(input_format=fmt, output_format=fmt, key=KEY)
        pt = b"4111111111111111"
        ct = eng.encrypt(pt)
        self.assertEqual(len(ct), 16)
        self.assertEqual(eng.decrypt(ct), pt)
        # FPE with a distinct tweak separates the covertext.
        self.assertNotEqual(eng.encrypt(pt, tweak=b"x"), ct)

    def test_fpe_is_injective_on_a_sample(self):
        # The domain floor forbids tiny enumerable domains, so sample a
        # 10**6-word format and confirm distinct, in-format covertexts.
        fmt = fte.RegexFormat(r"^[0-9]+$", length=6)  # exactly 1e6 words
        eng = fte.FTE(input_format=fmt, output_format=fmt, key=KEY)
        sample = [(i * 3607) % fmt.cardinality for i in range(256)]
        covertexts = {eng.encrypt(fmt.unrank(i)) for i in sample}
        self.assertEqual(len(covertexts), len(set(sample)))  # injective
        for ct in covertexts:
            self.assertEqual(len(ct), 6)  # in-format, length preserved


if __name__ == "__main__":
    unittest.main()
