#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Encoding data as alphanumeric strings.

This example creates ciphertext that looks like random IDs,
session tokens, or API keys.
"""

import fte


def main():
    # Alphanumeric format (like base62)
    encoder = fte.Encoder(regex='^[A-Za-z0-9]+$', fixed_slice=64)
    
    plaintext = b'Sensitive data'
    ciphertext = encoder.encode(plaintext)
    
    print("=== Alphanumeric Format ===")
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.decode('latin-1')}")
    print(f"\nThis could pass as:")
    print(f"  - Session ID: {ciphertext[:32].decode('latin-1')}")
    print(f"  - API Key: {ciphertext[:24].decode('latin-1')}")
    
    # Verify roundtrip
    recovered, _ = encoder.decode(ciphertext)
    print(f"\nRecovered: {recovered}")
    assert plaintext == recovered


if __name__ == '__main__':
    main()
