#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Encrypting data into hexadecimal strings.

This example shows how to make ciphertext look like hex data,
which might blend in with log files or debugging output.
"""

import os

import fte


def main():
    # Hex covertext: every byte is a lowercase hex digit.
    cipher = fte.FTE(
        format=fte.RegexFormat('^[0-9a-f]+$', length=128),
        key=os.urandom(32),
    )

    plaintext = b'Secret message'
    ciphertext = cipher.encrypt(plaintext)

    print("=== Hex Format Encryption ===")
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"Ciphertext looks like hex:")

    # Display in typical hex dump format
    ct_str = ciphertext.decode('latin-1')
    for i in range(0, len(ct_str), 32):
        print(f"  {ct_str[i:i+32]}")

    # Verify roundtrip
    recovered = cipher.decrypt(ciphertext)
    print(f"\nRecovered: {recovered}")
    assert plaintext == recovered


if __name__ == '__main__':
    main()
