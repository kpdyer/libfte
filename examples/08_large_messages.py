#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Handling large messages.

This example demonstrates how FTE handles messages larger than
the language capacity by using overflow.
"""

import regex2dfa
import fte.encoder


def main():
    regex = '^[a-z]+$'
    fixed_slice = 128
    
    dfa = regex2dfa.regex2dfa(regex)
    encoder = fte.encoder.DfaEncoder(dfa, fixed_slice)
    
    capacity_bytes = encoder.getCapacity() // 8
    
    print("=== Large Message Handling ===")
    print(f"Language capacity: {encoder.getCapacity()} bits ({capacity_bytes} bytes)")
    print(f"Fixed slice: {fixed_slice} characters")
    
    # Small message - fits entirely in formatted output
    small_msg = b'Hi'
    small_ct = encoder.encode(small_msg)
    print(f"\nSmall message ({len(small_msg)} bytes):")
    print(f"  Plaintext: {small_msg}")
    print(f"  Ciphertext length: {len(small_ct)} bytes")
    print(f"  All formatted: {len(small_ct) == fixed_slice}")
    
    # Medium message
    medium_msg = b'A' * 30
    medium_ct = encoder.encode(medium_msg)
    print(f"\nMedium message ({len(medium_msg)} bytes):")
    print(f"  Ciphertext length: {len(medium_ct)} bytes")
    print(f"  Formatted part: {fixed_slice} bytes")
    print(f"  Overflow: {len(medium_ct) - fixed_slice} bytes")
    
    # Large message - has overflow
    large_msg = b'X' * 100
    large_ct = encoder.encode(large_msg)
    print(f"\nLarge message ({len(large_msg)} bytes):")
    print(f"  Ciphertext length: {len(large_ct)} bytes")
    print(f"  Formatted part: {fixed_slice} bytes")
    print(f"  Overflow (raw): {len(large_ct) - fixed_slice} bytes")
    
    # Show what the ciphertext looks like
    print(f"\nCiphertext structure:")
    print(f"  Formatted (looks like regex): {large_ct[:40].decode('latin-1')}...")
    if len(large_ct) > fixed_slice:
        print(f"  Overflow (raw bytes): {large_ct[fixed_slice:fixed_slice+20]!r}...")
    
    # All decode correctly
    for name, msg, ct in [("Small", small_msg, small_ct), 
                          ("Medium", medium_msg, medium_ct),
                          ("Large", large_msg, large_ct)]:
        recovered, _ = encoder.decode(ct)
        assert msg == recovered, f"{name} message roundtrip failed!"
    
    print("\nAll messages decoded correctly!")


if __name__ == '__main__':
    main()
