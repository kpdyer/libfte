#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Deterministic FTE across two different formats.

The ``ff1`` cipher maps between different input and output formats. A 12-digit
decimal string is encrypted as a 16-character hex string. The transform is
deterministic and injective: each input maps to a distinct output. It has no
nonce or authentication-tag overhead, but the output string is longer.

Because the output space (16**16) is far larger than the input space (10**12),
most hex strings are not the image of any 12-digit input; decrypting one raises
InvalidCovertextError. This rejection does not provide authentication. Use a
per-record ``tweak`` to separate deterministic encryptions of the same value.
"""

import os

import fte
from fte import InvalidCovertextError


def main():
    print("=== Deterministic FTE (12 digits -> 16 hex chars) ===\n")

    digits = fte.RegexFormat(r"^[0-9]+$", length=12)     # 10**12 words
    hex_out = fte.RegexFormat(r"^[0-9a-f]+$", length=16)  # 16**16 words
    key = os.urandom(16)  # FF1 key (16/24/32 bytes), never reused for AE.

    cipher = fte.FTE(
        input_format=digits,
        output_format=hex_out,
        cipher="ff1",
        key=key,
    )

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
