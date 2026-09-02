#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Authenticated FTE with the ``aes-ctr-hmac`` cipher.

This is the authenticated row of the 2x2: the wire-frozen AES-CTR + HMAC path.
``aes-ctr-hmac`` is randomized and authenticated -- encrypting the same
plaintext twice yields two different covertexts, and any tampering is detected
on decrypt. That safety costs a fixed 29-byte frame: a version byte, a 12-byte
random nonce, and a 16-byte HMAC-SHA256 tag (Encrypt-then-MAC over AES-128-CTR).

Here the input is a structured (non-bytes) format -- a 12-digit decimal string --
re-encrypted as hex. This uses only the built-in engine, no extra dependency.

Because ``aes-ctr-hmac`` expands by that fixed overhead, the output format must
have more capacity than the input; you cannot round-trip ``aes-ctr-hmac`` in
place through one finite format (that is the job of a deterministic cipher, such
as the ``ff1`` format-preserving cipher from the optional libffx integration).
"""

import os

import fte
from fte import FormatCapacityError, InvalidCovertextError


def main():
    print("=== Authenticated FTE (aes-ctr-hmac: randomized + authenticated) ===\n")

    digits = fte.RegexFormat(r"^[0-9]+$", length=12)      # non-bytes input
    hex_out = fte.RegexFormat(r"^[0-9a-f]+$", length=256)  # roomy output
    key = os.urandom(32)  # AE keys are exactly 32 bytes (16 enc + 16 MAC).

    cipher = fte.FTE(
        input_format=digits,
        output_format=hex_out,
        cipher="aes-ctr-hmac",
        key=key,
    )

    plaintext = b"123456789012"
    first = cipher.encrypt(plaintext)
    second = cipher.encrypt(plaintext)

    # The frame is short, so the covertext is a low-rank (leading-zero) hex
    # word; the randomized part shows up in the tail.
    print(f"plaintext:      {plaintext.decode()}")
    print(f"covertext 1 end: ...{first.decode()[-48:]}")
    print(f"covertext 2 end: ...{second.decode()[-48:]}")

    # Randomized: the same plaintext encrypts to different covertexts each call.
    assert first != second
    assert cipher.decrypt(first) == plaintext
    assert cipher.decrypt(second) == plaintext
    print("\nSame plaintext, two different covertexts -> aes-ctr-hmac is randomized.")

    # Authenticated: any altered covertext is rejected, not silently mangled.
    tampered = hex_out.unrank((hex_out.rank(first) + 1) % hex_out.cardinality)
    try:
        cipher.decrypt(tampered)
        print("unexpected: tampered covertext decrypted")
    except InvalidCovertextError:
        print("A tampered covertext is rejected -> aes-ctr-hmac is authenticated.")

    # Aside: aes-ctr-hmac expands, so the same finite format cannot serve both sides.
    try:
        fte.FTE(input_format=digits, output_format=digits, cipher="aes-ctr-hmac", key=key)
        print("unexpected: in-place aes-ctr-hmac construction succeeded")
    except FormatCapacityError:
        print(
            "In-place aes-ctr-hmac (same format both sides) is refused at construction: "
            "the 29-byte frame does not fit in 12 digits -- use ff1 for that."
        )

    print("\nSuccess! Authenticated FTE round-trips and rejects tampering.")


if __name__ == "__main__":
    main()
