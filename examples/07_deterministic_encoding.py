#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Deterministic encoding with seeds.

This example shows how to use seeds to get reproducible
ciphertexts, useful for testing or when determinism is required.
"""

import fte


def main():
    # Use fixed key for reproducibility
    key = b'1234567890abcdeffedcba0987654321'
    encoder = fte.Encoder(regex='^[a-z]+$', fixed_slice=128, key=key)
    
    plaintext = b'Hello'
    
    print("=== Deterministic Encoding ===")
    print(f"Plaintext: {plaintext}")
    
    # Without seed - random each time
    print("\nWithout seed (random):")
    for i in range(3):
        ct = encoder.encode(plaintext)
        print(f"  Encoding {i+1}: {ct[:40].decode('latin-1')}...")
    
    # With seed - deterministic
    seed = b'fixedsed'  # Must be exactly 8 bytes
    
    print(f"\nWith seed={seed}:")
    for i in range(3):
        ct = encoder.encode(plaintext, seed=seed)
        print(f"  Encoding {i+1}: {ct[:40].decode('latin-1')}...")
    
    print("\nNote: With the same seed, key, and plaintext,")
    print("the ciphertext is identical every time!")
    
    # Verify decoding works
    ct_seeded = encoder.encode(plaintext, seed=seed)
    recovered, _ = encoder.decode(ct_seeded)
    print(f"\nRecovered: {recovered}")
    assert plaintext == recovered


if __name__ == '__main__':
    main()
