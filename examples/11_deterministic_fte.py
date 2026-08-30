#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Deterministic FTE across two different formats.

This is the cross-format corner of the deterministic row: the ``ff1`` cipher
with an input format that differs from the output format. A 12-digit decimal
string is re-encoded as a 16-character hex string. The transform is a
zero-expansion, deterministic bijection from the input's rank space into the
output's, so it is reversible without any authentication tag or randomness.

Because the output space (16**16) is far larger than the input space (10**12),
most hex strings are not the image of any 12-digit input; decrypting one raises
InvalidCovertextError. And because it is deterministic, use a per-record
``tweak`` to separate encryptions of the same value.

Requires the optional libffx extra::

    pip install fte[fpe]
"""

import os

import fte
from fte.core import InvalidCovertextError


def main():
    print("=== Deterministic FTE (12 digits -> 16 hex chars) ===\n")

    digits = fte.RegexFormat(r"^[0-9]+$", length=12)     # 10**12 words
    hex_out = fte.RegexFormat(r"^[0-9a-f]+$", length=16)  # 16**16 words
    key = os.urandom(16)  # FF1 key (16/24/32 bytes), never reused for AE.

    try:
        cipher = fte.FTE(
            input_format=digits,
            output_format=hex_out,
            cipher="ff1",
            key=key,
        )
    except ImportError as exc:
        print(exc)
        print("\nSkipping: install the libffx extra to run this example.")
        return

    for plaintext in (b"000000000001", b"123456789012"):
        covertext = cipher.encrypt(plaintext, tweak=b"batch-2026")

        print(f"plaintext:  {plaintext.decode()}  (12 digits)")
        print(f"covertext:  {covertext.decode()}  (16 hex chars)")

        assert len(covertext) == 16
        assert cipher.decrypt(covertext, tweak=b"batch-2026") == plaintext
        # Deterministic: same plaintext + tweak -> same covertext.
        assert cipher.encrypt(plaintext, tweak=b"batch-2026") == covertext
        print()

    # A hex string that is not the image of any 12-digit input is rejected.
    stray = hex_out.unrank(hex_out.cardinality - 1)
    try:
        cipher.decrypt(stray, tweak=b"batch-2026")
        print("unexpected: stray covertext decrypted")
    except InvalidCovertextError:
        print("A hex value outside the input's image is rejected as expected.")

    print("\nSuccess! The deterministic map round-trips every 12-digit input.")


if __name__ == "__main__":
    main()
