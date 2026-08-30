#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Format-preserving encryption of a 9-digit identifier.

This is the FPE corner of the 2x2: the deterministic cipher (``ff1``) with the
input and output being the *same* format, length preserved in place. A 9-digit
number encrypts to another 9-digit number, so the ciphertext still fits a
fixed-width field (an SSN-style identifier, an account number, a PIN batch).

The transform is deterministic and unauthenticated: equal plaintexts map to
equal covertexts, so pass a distinct per-record ``tweak`` (a column name, a row
id) to keep encryptions of the same value in different contexts independent.

Requires the optional libffx extra::

    pip install fte[fpe]
"""

import os

import fte


def main():
    print("=== Format-Preserving Encryption (9-digit identifier) ===\n")

    # ^[0-9]+$ with a fixed length of 9 has 10**9 words, comfortably above the
    # format-preserving floor of 1e6, so allow_small_domain stays False.
    id_format = fte.RegexFormat(r"^[0-9]+$", length=9)
    key = os.urandom(16)  # FF1 keys are 16/24/32 bytes; NOT an AE key.

    try:
        cipher = fte.FTE(input_format=id_format, output_format=id_format,
                         key=key, preserve_length=True)
    except ImportError as exc:
        print(exc)
        print("\nSkipping: install the libffx extra to run this example.")
        return

    for plaintext in (b"078051120", b"000000001", b"999999999"):
        # Same value, two different record contexts -> two different covertexts.
        ssn_column = cipher.encrypt(plaintext, tweak=b"ssn")
        alt_column = cipher.encrypt(plaintext, tweak=b"tax_id")

        print(f"plaintext:        {plaintext.decode()}")
        print(f"  tweak='ssn':    {ssn_column.decode()}")
        print(f"  tweak='tax_id': {alt_column.decode()}")

        assert len(ssn_column) == 9 and ssn_column.isdigit()
        assert ssn_column != alt_column                      # tweak separation
        assert cipher.decrypt(ssn_column, tweak=b"ssn") == plaintext
        assert cipher.decrypt(alt_column, tweak=b"tax_id") == plaintext
        print()

    print("Success! Every 9-digit value round-trips to a 9-digit covertext.")


if __name__ == "__main__":
    main()
