#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Deterministic encoding with seeds.

This example shows how to use seeds to get reproducible
ciphertexts, useful for testing or when determinism is required.
"""

import regex2dfa
import fte.encoder


def main():
    regex = '^[a-z]+$'
    fixed_slice = 128
    
    dfa = regex2dfa.regex2dfa(regex)
    
    # Use fixed keys for reproducibility
    K1 = b'1234567890abcdef'
    K2 = b'fedcba0987654321'
    encoder = fte.encoder.DfaEncoder(dfa, fixed_slice, K1=K1, K2=K2)
    
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
    
    print("\nNote: With the same seed, keys, and plaintext,")
    print("the ciphertext is identical every time!")
    
    # Verify all decode correctly
    ct_seeded = encoder.encode(plaintext, seed=seed)
    recovered, _ = encoder.decode(ct_seeded)
    print(f"\nRecovered: {recovered}")
    assert plaintext == recovered


if __name__ == '__main__':
    main()
