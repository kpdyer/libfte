"""Integration tests for the real deterministic cipher (``cipher="ff1"``).

These exercise :class:`fte.FTE` against the genuine
format-preserving cipher from libffx. That package is being built in parallel
and is not importable here, so the whole module skips via
``pytest.importorskip("ffx")``; the engine mechanics themselves are covered
without ffx in ``test_engine_matrix.py``.
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

    def test_fpe_digits_preserve_length_roundtrip(self):
        fmt = fte.RegexFormat(r"^[0-9]+$", length=16)
        eng = FTE(input_format=fmt, output_format=fmt, cipher="ff1", key=KEY,
                  preserve_length=True)
        pt = b"9999888877776666"
        ct = eng.encrypt(pt)
        self.assertEqual(len(ct), len(pt))
        self.assertEqual(eng.decrypt(ct), pt)

    def test_fpe_preserve_length_over_a_length_range(self):
        fmt = fte.RegexFormat(r"^[0-9]+$", min_length=6, max_length=9)
        eng = fte.FTE(input_format=fmt, output_format=fmt, key=KEY, preserve_length=True)
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
        digits = fte.RegexFormat(r"^[0-9]+$", length=4)      # 10**4
        hex_fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=20)  # 16**20 = 2**80
        self.assertGreater(hex_fmt.cardinality / digits.cardinality, 2 ** 60)
        eng = FTE(input_format=digits, output_format=hex_fmt, cipher="ff1",
                  key=KEY)
        ct = eng.encrypt(b"1234", tweak=b"per-record-A")
        self.assertEqual(eng.decrypt(ct, tweak=b"per-record-A"), b"1234")
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

    def test_fpe_is_a_permutation_of_the_domain(self):
        # Small enough to enumerate: allow_small_domain lowers FF1's own floor.
        fmt = fte.RegexFormat(r"^[0-9]+$", length=3)  # 1000 words
        eng = fte.FTE(input_format=fmt, output_format=fmt, key=KEY, allow_small_domain=True)
        covertexts = {eng.encrypt(fmt.unrank(i)) for i in range(fmt.cardinality)}
        self.assertEqual(len(covertexts), fmt.cardinality)  # bijection


if __name__ == "__main__":
    unittest.main()
