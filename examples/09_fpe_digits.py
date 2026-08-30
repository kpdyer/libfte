#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Format-preserving encryption of a 9-digit identifier.

This is the FPE corner of the 2x2: the deterministic cipher (``ff1``) with the
input and output being the *same* format, length preserved in place. A 9-digit
number encrypts to another 9-digit number, so the ciphertext still fits a
fixed-width field (an account number, a customer id, a batch of tickets).

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
    key = os.urandom(16)  # FF1 keys are 16/24/32 bytes; NOT an AES-CTR-HMAC key.

    try:
        cipher = fte.FTE(input_format=id_format, output_format=id_format,
                         key=key, preserve_length=True)
    except ImportError as exc:
        print(exc)
        print("\nSkipping: install the libffx extra to run this example.")
        return

    # Synthetic demo identifiers (not real records).
    for account in (b"100000042", b"100000043", b"100000042"):
        # Same value, two different column contexts -> two different covertexts.
        col_a = cipher.encrypt(account, tweak=b"accounts.number")
        col_b = cipher.encrypt(account, tweak=b"orders.account")

        print(f"input:                    {account.decode()}")
        print(f"  tweak accounts.number:  {col_a.decode()}")
        print(f"  tweak orders.account:   {col_b.decode()}")

        assert len(col_a) == 9 and col_a.isdigit()
        assert col_a != col_b                                 # tweak separation
        assert cipher.decrypt(col_a, tweak=b"accounts.number") == account
        assert cipher.decrypt(col_b, tweak=b"orders.account") == account
        print()

    print("Note: the repeated input maps to the same covertext under a given")
    print("tweak (determinism), and to a different one under a different tweak.")
    print("Every 9-digit value round-trips to a 9-digit covertext.")


if __name__ == "__main__":
    main()
