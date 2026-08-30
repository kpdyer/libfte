#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Proper error handling.

Shows the exceptions the FTE engine and RegexFormat raise, and how to handle
each one.
"""

import os

import fte


def main():
    print("=== Error Handling ===\n")

    key = os.urandom(32)
    cipher = fte.FTE(format=fte.RegexFormat('^[a-z]+$', length=128), key=key)

    # 1. Non-bytes plaintext
    print("1. Non-bytes plaintext:")
    try:
        cipher.encrypt("not bytes")  # must be bytes, not str
    except TypeError as e:
        print(f"   Caught TypeError: {e}")

    # 2. Malformed covertext (wrong type or length)
    print("\n2. Malformed covertext:")
    try:
        cipher.decrypt(b'tooshort')
    except fte.InvalidCovertextError as e:
        print(f"   Caught InvalidCovertextError: {e}")

    # 3. Invalid key length
    print("\n3. Invalid key length:")
    try:
        fte.FTE(format=fte.RegexFormat('^[a-z]+$', length=64), key=b'tooshort')
    except ValueError as e:
        print(f"   Caught ValueError: {e}")

    # 4. Message too large for the fixed-length format
    print("\n4. Insufficient capacity:")
    try:
        tiny = fte.FTE(format=fte.RegexFormat('^[0-9a-f]+$', length=8), key=key)
        tiny.encrypt(b'x' * 100)
    except fte.FormatCapacityError as e:
        print(f"   Caught FormatCapacityError: {e}")

    # 5. Pattern with no words of the requested length
    print("\n5. Empty language for (pattern, length):")
    try:
        fte.RegexFormat('^(ab)+$', length=5)  # no words of odd length
    except ValueError as e:
        print(f"   Caught ValueError: {e}")

    # 6. Corrupted / unauthenticated covertext
    print("\n6. Tampered covertext:")
    covertext = cipher.encrypt(b'hello')
    tampered = bytes([covertext[0] ^ 0x01]) + covertext[1:]
    try:
        cipher.decrypt(tampered)
    except fte.InvalidCovertextError as e:
        print(f"   Caught InvalidCovertextError: {e}")

    # Correct usage
    print("\n" + "=" * 50)
    print("\nCorrect usage:")
    plaintext = b'Hello, World!'
    ciphertext = cipher.encrypt(plaintext)
    recovered = cipher.decrypt(ciphertext)
    print(f"   Original:  {plaintext}")
    print(f"   Recovered: {recovered}")


if __name__ == '__main__':
    main()
