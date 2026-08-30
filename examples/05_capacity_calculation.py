#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Understanding format capacity.

This example explains how the capacity of a format (a language sliced to a
length range) determines how much data can be encrypted, and how to choose
parameters.
"""

import math
import os

import fte

KEY = bytes(range(32))  # capacity does not depend on the key value


def analyze_format(name, pattern, length):
    """Analyze a format's capacity via its cardinality."""
    fmt = fte.RegexFormat(pattern, length=length)

    # cardinality is the exact number of length-byte words in the language.
    capacity_bits = fmt.cardinality.bit_length() - 1  # floor(log2(cardinality))

    print(f"\n{name}:")
    print(f"  Pattern: {pattern}")
    print(f"  Output length: {length} bytes")
    print(f"  Capacity: {capacity_bits} bits")

    # FTE reports the exact largest plaintext this format can carry; no need to
    # approximate the framing overhead by hand. Too small a format cannot hold
    # even an empty message and is rejected at construction.
    try:
        usable_bytes = fte.FTE(output_format=fmt, key=KEY).max_plaintext_bytes
        print(f"  Usable for plaintext: {usable_bytes} bytes (exact)")
    except fte.FormatCapacityError:
        print(f"  Usable for plaintext: none (too small for the frame)")

    return capacity_bits


def main():
    print("=== Format Capacity Analysis ===")
    print("\nCapacity depends on alphabet size and output length.")
    print("More symbols = more bits per character.")

    # Compare different alphabets
    formats = [
        ("Binary (0-1)", "^[01]+$", 256),
        ("Hex (0-9a-f)", "^[0-9a-f]+$", 256),
        ("Lowercase (a-z)", "^[a-z]+$", 256),
        ("Alphanumeric", "^[A-Za-z0-9]+$", 256),
        ("Printable ASCII", "^[ -~]+$", 256),
    ]

    print("\n" + "="*60)
    for name, pattern, length in formats:
        analyze_format(name, pattern, length)

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

    for name, pattern, length in [
        ("Hex format", "^[0-9a-f]+$", 512),
        ("Alphanumeric", "^[A-Za-z0-9]+$", 256),
    ]:
        cipher = fte.FTE(
            output_format=fte.RegexFormat(pattern, length=length),
            key=os.urandom(32),
        )

        try:
            ciphertext = cipher.encrypt(test_data)
            print(f"\n{name} (length={length}):")
            print(f"  Can encrypt 100 bytes: YES")
            print(f"  Output size: {len(ciphertext)} bytes")
        except fte.FormatCapacityError as e:
            print(f"\n{name} (length={length}):")
            print(f"  Can encrypt 100 bytes: NO ({e})")


if __name__ == '__main__':
    main()
