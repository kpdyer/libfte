#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Using convenience functions.

This example shows the simplest possible API using the
module-level encode/decode functions.
"""

import os

import fte


def main():
    print("=== Convenience Functions ===\n")

    plaintext = b'Quick and easy!'
    key = os.urandom(32)

    # One-liner encode/decode with defaults (key is always required)
    print("1. Using defaults (lowercase, length 256):")
    ciphertext = fte.encode(plaintext, key=key)
    recovered, _ = fte.decode(ciphertext, key=key)
    print(f"   Plaintext: {plaintext}")
    print(f"   Ciphertext: {ciphertext[:40].decode()}...")
    print(f"   Recovered: {recovered}")

    # Custom format
    print("\n2. Custom hex format:")
    ciphertext = fte.encode(plaintext, regex='^[0-9a-f]+$', fixed_slice=128, key=key)
    recovered, _ = fte.decode(ciphertext, regex='^[0-9a-f]+$', fixed_slice=128, key=key)
    print(f"   Ciphertext: {ciphertext.decode()}")
    print(f"   Recovered: {recovered}")
    
    # With custom key
    print("\n3. With custom key:")
    key = b'mysecretkey12345mysecretmac12345'
    ciphertext = fte.encode(plaintext, regex='^[a-z]+$', key=key)
    recovered, _ = fte.decode(ciphertext, regex='^[a-z]+$', key=key)
    print(f"   Recovered: {recovered}")
    
    print("\nAll examples completed successfully!")


if __name__ == '__main__':
    main()
