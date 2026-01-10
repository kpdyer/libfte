#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Encoding data as hexadecimal strings.

This example shows how to make ciphertext look like hex data,
which might blend in with log files or debugging output.
"""

import fte


def main():
    # Create encoder for hex output
    encoder = fte.Encoder(regex='^[0-9a-f]+$', fixed_slice=128)
    
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
