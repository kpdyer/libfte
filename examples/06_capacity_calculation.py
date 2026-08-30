#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Understanding language capacity.

This example explains how the capacity of a language affects
how much data can be encoded, and how to choose parameters.
"""

import math
import os

import fte


def analyze_language(name, regex, fixed_slice):
    """Analyze a language's encoding capacity."""
    encoder = fte.Encoder(regex=regex, fixed_slice=fixed_slice, key=os.urandom(32))
    
    capacity_bits = encoder.capacity
    capacity_bytes = capacity_bits // 8
    
    # Account for FTE overhead (16 bytes header + 32 bytes encryption)
    usable_bytes = max(0, capacity_bytes - 48)
    
    print(f"\n{name}:")
    print(f"  Regex: {regex}")
    print(f"  Output length: {fixed_slice} characters")
    print(f"  Capacity: {capacity_bits} bits ({capacity_bytes} bytes)")
    print(f"  Usable for plaintext: ~{usable_bytes} bytes")
    
    return capacity_bits


def main():
    print("=== Language Capacity Analysis ===")
    print("\nCapacity depends on alphabet size and output length.")
    print("More symbols = more bits per character.")
    
    # Compare different alphabets
    languages = [
        ("Binary (0-1)", "^[01]+$", 256),
        ("Hex (0-9a-f)", "^[0-9a-f]+$", 256),
        ("Lowercase (a-z)", "^[a-z]+$", 256),
        ("Alphanumeric", "^[A-Za-z0-9]+$", 256),
        ("Printable ASCII", "^[ -~]+$", 256),
    ]
    
    print("\n" + "="*60)
    for name, regex, length in languages:
        analyze_language(name, regex, length)
    
    print("\n" + "="*60)
    print("\nBits per character (theoretical):")
    print(f"  Binary (2 symbols): {math.log2(2):.2f} bits/char")
    print(f"  Hex (16 symbols): {math.log2(16):.2f} bits/char")
    print(f"  Lowercase (26 symbols): {math.log2(26):.2f} bits/char")
    print(f"  Alphanumeric (62 symbols): {math.log2(62):.2f} bits/char")
    print(f"  Printable ASCII (95 symbols): {math.log2(95):.2f} bits/char")
    
    print("\n" + "="*60)
    print("\nPractical example:")
    
    test_data = b'A' * 100
    
    for name, regex, length in [
        ("Hex format", "^[0-9a-f]+$", 512),
        ("Alphanumeric", "^[A-Za-z0-9]+$", 256),
    ]:
        encoder = fte.Encoder(regex=regex, fixed_slice=length, key=os.urandom(32))

        try:
            ciphertext = encoder.encode(test_data)
            print(f"\n{name} (length={length}):")
            print(f"  Can encode 100 bytes: YES")
            print(f"  Output size: {len(ciphertext)} bytes")
        except Exception as e:
            print(f"\n{name} (length={length}):")
            print(f"  Can encode 100 bytes: NO ({e})")


if __name__ == '__main__':
    main()
