#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Proper error handling.

Shows the exceptions the regex Encoder and the FTE engine raise, and how to
handle each one.
"""

import os

import fte


def main():
    print("=== Error Handling ===\n")

    key = os.urandom(32)
    cipher = fte.Encoder(regex='^[a-z]+$', fixed_slice=128, key=key)

    # 1. Invalid input type
    print("1. Invalid input type:")
    try:
        cipher.encrypt("not bytes")  # must be bytes, not str
    except fte.InvalidInputException as e:
        print(f"   Caught InvalidInputException: {e}")

    # 2. Covertext too short to decrypt
    print("\n2. Covertext too short:")
    try:
        cipher.decrypt(b'tooshort')
    except fte.DecodeFailureError as e:
        print(f"   Caught DecodeFailureError: {e}")

    # 3. Invalid ciphertext type
    print("\n3. Invalid ciphertext type:")
    try:
        cipher.decrypt("not bytes")
    except fte.InvalidInputException as e:
        print(f"   Caught InvalidInputException: {e}")

    # 4. Invalid key length
    print("\n4. Invalid key length:")
    try:
        fte.Encoder(regex='^[a-z]+$', fixed_slice=64, key=b'tooshort')
    except ValueError as e:
        print(f"   Caught ValueError: {e}")

    # 5. Message too large for the fixed-length format
    print("\n5. Insufficient capacity:")
    try:
        tiny = fte.Encoder(regex='^[0-9a-f]+$', fixed_slice=8, key=key)
        tiny.encrypt(b'x' * 100)
    except fte.FormatCapacityError as e:
        print(f"   Caught FormatCapacityError: {e}")

    # 6. Regex with no words of the requested length
    print("\n6. Empty language for (pattern, length):")
    try:
        fte.Encoder(regex='^(ab)+$', fixed_slice=5, key=key)
    except ValueError as e:
        print(f"   Caught ValueError: {e}")

    # 7. Corrupted / unauthenticated covertext
    print("\n7. Tampered covertext:")
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
    recovered, _ = cipher.decrypt(ciphertext)
    print(f"   Original:  {plaintext}")
    print(f"   Recovered: {recovered}")


if __name__ == '__main__':
    main()
