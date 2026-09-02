"""The deterministic (``cipher="ff1"``) wire contract is frozen.

Two things pin it. First, every vector in ``tests/data/ff1_wire_vectors.json``
was produced by the current libfte and, because the path is deterministic,
must keep being *produced* as well as decrypted byte for byte. Second, the
composition tests recompute a covertext by hand -- rank the plaintext, call
libffx's ``FF1`` directly with the derived tweak, unrank the result -- so a
change to the tweak derivation, the length-slice arithmetic, or the cipher in
the loop fails here even if it still round-trips.

The tweak derivation is spelled out literally rather than imported from
:mod:`fte.core`, so that changing it there cannot silently pass.
"""

import hashlib
import json
import unittest
from pathlib import Path

from ffx import FF1

import fte


VECTORS_PATH = Path(__file__).resolve().parent / "data" / "ff1_wire_vectors.json"

# The frozen namespace prefix; bumping it in fte.core is a wire-format change.
TWEAK_PREFIX = b"fte:v2:ff1:1|"


def _load_vectors():
    with VECTORS_PATH.open() as handle:
        return json.load(handle)["vectors"]


def _engine(vector, key=None):
    fin = fte.RegexFormat(vector["input_pattern"], **vector["input_length_kw"])
    fout = fte.RegexFormat(
        vector["output_pattern"], **vector["output_length_kw"]
    )
    return fte.FTE(
        input_format=fin,
        output_format=fout,
        cipher=vector["cipher"],
        key=bytes.fromhex(vector["key_hex"]) if key is None else key,
    )


def _tweak_base(fp_in, fp_out, mode_tag):
    """The per-engine tweak: SHA-256 over the namespace and both fingerprints."""
    return hashlib.sha256(
        TWEAK_PREFIX
        + len(fp_in).to_bytes(4, "big")
        + fp_in
        + len(fp_out).to_bytes(4, "big")
        + fp_out
        + mode_tag
    ).digest()


class FrozenVectors(unittest.TestCase):
    def test_vectors_file_present_and_nonempty(self):
        self.assertTrue(VECTORS_PATH.exists(), VECTORS_PATH)
        self.assertGreater(len(_load_vectors()), 0)

    def test_every_vector_is_reproduced_and_decrypted(self):
        for i, vector in enumerate(_load_vectors()):
            with self.subTest(
                vector=i,
                formats=(vector["input_pattern"], vector["output_pattern"]),
            ):
                eng = _engine(vector)
                tweak = bytes.fromhex(vector["tweak_hex"])
                plaintext = bytes.fromhex(vector["plaintext_hex"])
                covertext = bytes.fromhex(vector["covertext_hex"])
                self.assertEqual(eng.preserve_length, vector["preserve_length"])
                self.assertEqual(eng.encrypt(plaintext, tweak=tweak), covertext)
                self.assertEqual(eng.decrypt(covertext, tweak=tweak), plaintext)

    def test_vectors_cover_both_length_modes(self):
        modes = {v["preserve_length"] for v in _load_vectors()}
        self.assertEqual(modes, {True, False})

    def test_wrong_key_does_not_reproduce_a_frozen_vector(self):
        vector = _load_vectors()[0]
        key = bytes.fromhex(vector["key_hex"])
        wrong = bytes(b ^ 0xFF for b in key)
        eng = _engine(vector, key=wrong)
        tweak = bytes.fromhex(vector["tweak_hex"])
        plaintext = bytes.fromhex(vector["plaintext_hex"])
        self.assertNotEqual(
            eng.encrypt(plaintext, tweak=tweak),
            bytes.fromhex(vector["covertext_hex"]),
        )


class Composition(unittest.TestCase):
    """fte's covertext is exactly libffx FF1 applied to the rank."""

    KEY = bytes(range(16))

    def test_global_path_is_ff1_over_the_whole_rank_space(self):
        digits = fte.RegexFormat(r"^[0-9]+$", length=8)
        hex_fmt = fte.RegexFormat(r"^[0-9a-f]+$", length=16)
        eng = fte.FTE(
            input_format=digits, output_format=hex_fmt, cipher="ff1",
            key=self.KEY,
        )
        self.assertFalse(eng.preserve_length)
        tweak = b"batch-2026"
        plaintext = b"01234567"

        call_tweak = (
            _tweak_base(digits.fingerprint, hex_fmt.fingerprint, b"G") + tweak
        )
        c = FF1(self.KEY).encrypt_int(
            digits.rank(plaintext), domain=hex_fmt.cardinality, tweak=call_tweak
        )
        self.assertEqual(eng.encrypt(plaintext, tweak=tweak), hex_fmt.unrank(c))

    def test_length_preserving_path_is_ff1_over_the_length_slice(self):
        fmt = fte.RegexFormat(r"^[0-9]+$", min_length=6, max_length=9)
        eng = fte.FTE(input_format=fmt, output_format=fmt, key=self.KEY)
        self.assertTrue(eng.preserve_length)
        tweak = b"orders.account"
        plaintext = b"1234567"

        offset, count = fmt.slice_bounds(len(plaintext))
        call_tweak = (
            _tweak_base(fmt.fingerprint, fmt.fingerprint, b"L")
            + len(plaintext).to_bytes(4, "big")
            + tweak
        )
        c = FF1(self.KEY).encrypt_int(
            fmt.rank(plaintext) - offset, domain=count, tweak=call_tweak
        )
        self.assertEqual(eng.encrypt(plaintext, tweak=tweak), fmt.unrank(offset + c))

    def test_default_tweak_is_the_empty_suffix(self):
        # encrypt(pt) with no tweak is encrypt(pt, tweak=b""): the derived base
        # is used bare, with nothing appended.
        fmt = fte.RegexFormat(r"^[0-9]+$", length=16)
        eng = fte.FTE(input_format=fmt, output_format=fmt, key=self.KEY)
        plaintext = b"4111111111111111"
        self.assertEqual(eng.encrypt(plaintext), eng.encrypt(plaintext, tweak=b""))
        offset, count = fmt.slice_bounds(16)
        call_tweak = (
            _tweak_base(fmt.fingerprint, fmt.fingerprint, b"L")
            + (16).to_bytes(4, "big")
        )
        c = FF1(self.KEY).encrypt_int(
            fmt.rank(plaintext) - offset, domain=count, tweak=call_tweak
        )
        self.assertEqual(eng.encrypt(plaintext), fmt.unrank(offset + c))


if __name__ == "__main__":
    unittest.main()
