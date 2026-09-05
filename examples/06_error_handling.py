#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Proper error handling.

Handle common input, capacity, and authentication errors.
"""

import os

import fte


def main():
    key = os.urandom(32)
    cipher = fte.FTE(output_format=fte.RegexFormat('^[a-z]+$', length=128), key=key)

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
        fte.FTE(output_format=fte.RegexFormat('^[a-z]+$', length=64), key=b'tooshort')
    except ValueError as e:
        print(f"   Caught ValueError: {e}")

    # 4. A format too small for even an empty authenticated message
    print("\n4. Insufficient capacity:")
    try:
        fte.FTE(output_format=fte.RegexFormat('^[0-9a-f]+$', length=8), key=key)
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
    fmt = cipher.output_format
    tampered = fmt.unrank(fmt.rank(covertext) + 1)  # altered, still in the language
    try:
        cipher.decrypt(tampered)
    except fte.InvalidCovertextError as e:
        print(f"   Caught InvalidCovertextError: {e}")


if __name__ == '__main__':
    main()
