#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Encoding data as hexadecimal strings.

This example shows how to make ciphertext look like hex data,
which might blend in with log files or debugging output.
"""

import regex2dfa
import fte.encoder


def main():
    # Regex for hexadecimal strings (lowercase)
    regex = '^[0-9a-f]+$'
    fixed_slice = 128
    
    dfa = regex2dfa.regex2dfa(regex)
    encoder = fte.encoder.DfaEncoder(dfa, fixed_slice)
    
    plaintext = b'Secret message'
    ciphertext = encoder.encode(plaintext)
    
    print("=== Hex Format Encoding ===")
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"Ciphertext looks like hex:")
    
    # Display in typical hex dump format
    ct_str = ciphertext.decode('latin-1')
    for i in range(0, len(ct_str), 32):
        print(f"  {ct_str[i:i+32]}")
    
    # Verify roundtrip
    recovered, _ = encoder.decode(ciphertext)
    print(f"\nRecovered: {recovered}")
    assert plaintext == recovered


if __name__ == '__main__':
    main()
