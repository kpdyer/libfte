#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Handling large messages.

This example demonstrates how FTE handles messages larger than
the language capacity by using overflow.
"""

import fte


def main():
    encoder = fte.Encoder(regex='^[a-z]+$', fixed_slice=128)
    
    capacity_bytes = encoder.capacity // 8
    
    print("=== Large Message Handling ===")
    print(f"Language capacity: {encoder.capacity} bits ({capacity_bytes} bytes)")
    print(f"Fixed slice: 128 characters")
    
    # Small message - fits entirely in formatted output
    small_msg = b'Hi'
    small_ct = encoder.encode(small_msg)
    print(f"\nSmall message ({len(small_msg)} bytes):")
    print(f"  Plaintext: {small_msg}")
    print(f"  Ciphertext length: {len(small_ct)} bytes")
    print(f"  All formatted: {len(small_ct) == 128}")
    
    # Medium message
    medium_msg = b'A' * 30
    medium_ct = encoder.encode(medium_msg)
    print(f"\nMedium message ({len(medium_msg)} bytes):")
    print(f"  Ciphertext length: {len(medium_ct)} bytes")
    print(f"  Formatted part: 128 bytes")
    print(f"  Overflow: {len(medium_ct) - 128} bytes")
    
    # Large message - has overflow
    large_msg = b'X' * 100
    large_ct = encoder.encode(large_msg)
    print(f"\nLarge message ({len(large_msg)} bytes):")
    print(f"  Ciphertext length: {len(large_ct)} bytes")
    print(f"  Formatted part: 128 bytes")
    print(f"  Overflow (raw): {len(large_ct) - 128} bytes")
    
    # Show what the ciphertext looks like
    print(f"\nCiphertext structure:")
    print(f"  Formatted (matches regex): {large_ct[:40].decode('latin-1')}...")
    if len(large_ct) > 128:
        print(f"  Overflow (raw bytes): {large_ct[128:148]!r}...")
    
    # Verify all decode correctly
    for name, msg, ct in [("Small", small_msg, small_ct), 
                          ("Medium", medium_msg, medium_ct),
                          ("Large", large_msg, large_ct)]:
        recovered, _ = encoder.decode(ct)
        assert msg == recovered, f"{name} message roundtrip failed!"
    
    print("\nAll messages decoded correctly!")


if __name__ == '__main__':
    main()
