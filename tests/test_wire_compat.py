"""The AE wire format is frozen: v1 covertexts must still decrypt in v2.

Every vector in ``tests/data/v1_wire_vectors.json`` was produced by libfte v1
through ``FTE(output_format=..., key=...)``. v2 must decrypt them to the exact same
plaintext through the same legacy signature, byte for byte.
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


class Tests(unittest.TestCase):
    def test_vectors_file_present_and_nonempty(self):
        self.assertTrue(VECTORS_PATH.exists(), VECTORS_PATH)
        self.assertGreater(len(_load_vectors()), 0)

    def test_every_v1_vector_decrypts_identically(self):
        for i, vector in enumerate(_load_vectors()):
            with self.subTest(vector=i, pattern=vector["pattern"]):
                fmt = fte.RegexFormat(vector["pattern"], **vector["length_kw"])
                cipher = fte.FTE(
                    output_format=fmt, key=bytes.fromhex(vector["key_hex"])
                )
                covertext = bytes.fromhex(vector["covertext_hex"])
                expected = bytes.fromhex(vector["plaintext_hex"])
                self.assertEqual(cipher.decrypt(covertext), expected)

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
