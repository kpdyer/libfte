#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Using custom encryption keys.

This example shows how to use your own encryption and MAC keys
for deterministic, reproducible encryption.
"""

import regex2dfa
import fte.encoder


def main():
    # Define a simple regex
    regex = '^[a-z]+$'
    fixed_slice = 256
    
    # Custom 16-byte keys (in production, use secure random keys!)
    K1 = b'0123456789abcdef'  # Encryption key
    K2 = b'fedcba9876543210'  # MAC key
    
    # Create encoder with custom keys
    dfa = regex2dfa.regex2dfa(regex)
    encoder = fte.encoder.DfaEncoder(dfa, fixed_slice, K1=K1, K2=K2)
    
    plaintext = b'Hello, World!'
    
    # Encode with custom keys
    ciphertext = encoder.encode(plaintext)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext (first 50 chars): {ciphertext[:50].decode('latin-1')}...")
    
    # Decode - must use same keys
    recovered, _ = encoder.decode(ciphertext)
    print(f"Recovered: {recovered}")
    
    # Demonstrate that different keys produce different ciphertexts
    K1_alt = b'different_key!!!'
    K2_alt = b'another_mac_key!'
    encoder_alt = fte.encoder.DfaEncoder(dfa, fixed_slice, K1=K1_alt, K2=K2_alt)
    ciphertext_alt = encoder_alt.encode(plaintext)
    
    print(f"\nWith different keys:")
    print(f"Ciphertext (first 50 chars): {ciphertext_alt[:50].decode('latin-1')}...")
    print(f"Ciphertexts are different: {ciphertext[:50] != ciphertext_alt[:50]}")


if __name__ == '__main__':
    main()
