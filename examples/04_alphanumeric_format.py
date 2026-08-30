#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Encrypting data into alphanumeric strings.

This example creates ciphertext that looks like random IDs,
session tokens, or API keys.
"""

import os

import fte


def main():
    # Alphanumeric format (like base62)
    cipher = fte.FTE(
        format=fte.RegexFormat('^[A-Za-z0-9]+$', length=64),
        key=os.urandom(32),
    )

    plaintext = b'Sensitive data'
    ciphertext = cipher.encrypt(plaintext)

    print("=== Alphanumeric Format ===")
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.decode('latin-1')}")
    print(f"\nThis could pass as:")
    print(f"  - Session ID: {ciphertext[:32].decode('latin-1')}")
    print(f"  - API Key: {ciphertext[:24].decode('latin-1')}")

    # Verify roundtrip
    recovered = cipher.decrypt(ciphertext)
    print(f"\nRecovered: {recovered}")
    assert plaintext == recovered


if __name__ == '__main__':
    main()
