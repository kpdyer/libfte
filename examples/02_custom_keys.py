#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Using custom encryption keys.

This example shows how to use your own encryption key
for deterministic, reproducible encryption.
"""

import fte


def main():
    # 32-byte key (16 bytes encryption + 16 bytes MAC)
    # In production, use secure random keys!
    key = b'0123456789abcdeffedcba9876543210'
    
    # Create cipher with custom key
    cipher = fte.Encoder(
        regex='^[a-z]+$',
        fixed_slice=256,
        key=key
    )
    
    plaintext = b'Hello, World!'
    
    # Encrypt with custom key
    ciphertext = cipher.encrypt(plaintext)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext[:50].decode()}...")
    
    # Decrypt - must use same key
    recovered, _ = cipher.decrypt(ciphertext)
    print(f"Recovered: {recovered}")
    
    # Different key produces different ciphertext
    key_alt = b'different_key!!!another_mac_key!'
    cipher_alt = fte.Encoder(regex='^[a-z]+$', fixed_slice=256, key=key_alt)
    ciphertext_alt = cipher_alt.encrypt(plaintext)
    
    print(f"\nWith different key:")
    print(f"Ciphertext: {ciphertext_alt[:50].decode()}...")
    print(f"Ciphertexts differ: {ciphertext[:50] != ciphertext_alt[:50]}")


if __name__ == '__main__':
    main()
