"""The AE wire format is frozen: these covertexts must keep decrypting.

Every vector in ``tests/data/v1_wire_vectors.json`` was produced by the current
libfte through ``FTE(output_format=..., key=...)`` and must decrypt to the exact
same plaintext, byte for byte, so any wire-format regression fails here. A
vector carrying ``input_pattern`` uses a non-bytes ``input_format`` with the
``aes-ctr-hmac`` cipher (fixed-width rank serialization, frozen at 0.4.0).
"""

import json
import unittest
from pathlib import Path

import fte


VECTORS_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "data"
    / "v1_wire_vectors.json"
)


def _load_vectors():
    with VECTORS_PATH.open() as handle:
        return json.load(handle)["vectors"]


def _build_cipher(vector):
    fmt = fte.RegexFormat(vector["pattern"], **vector["length_kw"])
    key = bytes.fromhex(vector["key_hex"])
    if "input_pattern" not in vector:
        return fte.FTE(output_format=fmt, key=key)
    input_fmt = fte.RegexFormat(
        vector["input_pattern"], **vector["input_length_kw"]
    )
    return fte.FTE(
        input_format=input_fmt,
        output_format=fmt,
        key=key,
        cipher="aes-ctr-hmac",
    )


class Tests(unittest.TestCase):
    def test_vectors_file_present_and_nonempty(self):
        self.assertTrue(VECTORS_PATH.exists(), VECTORS_PATH)
        self.assertGreater(len(_load_vectors()), 0)

    def test_every_v1_vector_decrypts_identically(self):
        for i, vector in enumerate(_load_vectors()):
            with self.subTest(vector=i, pattern=vector["pattern"]):
                cipher = _build_cipher(vector)
                covertext = bytes.fromhex(vector["covertext_hex"])
                expected = bytes.fromhex(vector["plaintext_hex"])
                self.assertEqual(cipher.decrypt(covertext), expected)

    def test_non_bytes_input_vector_is_present(self):
        # The 0.4.0 fixed-width rank serialization is itself a wire contract.
        self.assertTrue(any("input_pattern" in v for v in _load_vectors()))

    def test_wrong_key_rejects_a_frozen_vector(self):
        vector = _load_vectors()[0]
        fmt = fte.RegexFormat(vector["pattern"], **vector["length_kw"])
        wrong = bytes.fromhex(vector["key_hex"])
        wrong = bytes(b ^ 0xFF for b in wrong)
        cipher = fte.FTE(output_format=fmt, key=wrong)
        with self.assertRaises(fte.InvalidCovertextError):
            cipher.decrypt(bytes.fromhex(vector["covertext_hex"]))


if __name__ == "__main__":
    unittest.main()
