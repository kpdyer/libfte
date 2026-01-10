#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Proper error handling.

This example shows how to handle various error conditions
that can occur when using the FTE library.
"""

import regex2dfa
import fte.encoder
import fte.dfa


def main():
    print("=== Error Handling ===\n")
    
    regex = '^[a-z]+$'
    fixed_slice = 64
    dfa = regex2dfa.regex2dfa(regex)
    encoder = fte.encoder.DfaEncoder(dfa, fixed_slice)
    
    # 1. Invalid input type
    print("1. Invalid input type:")
    try:
        encoder.encode("not bytes")  # Should be bytes, not str
    except fte.encoder.InvalidInputException as e:
        print(f"   Caught InvalidInputException: {e}")
    
    # 2. Invalid seed length
    print("\n2. Invalid seed length:")
    try:
        encoder.encode(b'test', seed=b'short')  # Seed must be 8 bytes
    except fte.encoder.InvalidSeedLength as e:
        print(f"   Caught InvalidSeedLength: {e}")
    
    # 3. Ciphertext too short to decode
    print("\n3. Ciphertext too short:")
    try:
        encoder.decode(b'tooshort')
    except fte.encoder.DecodeFailureError as e:
        print(f"   Caught DecodeFailureError: {e}")
    
    # 4. Invalid ciphertext type
    print("\n4. Invalid ciphertext type:")
    try:
        encoder.decode("not bytes")
    except fte.encoder.InvalidInputException as e:
        print(f"   Caught InvalidInputException: {e}")
    
    # 5. Language capacity exceeded (need very small language)
    print("\n5. Insufficient capacity:")
    tiny_regex = '^(ab)+$'  # Very limited language
    tiny_dfa = regex2dfa.regex2dfa(tiny_regex)
    try:
        tiny_encoder = fte.encoder.DfaEncoder(tiny_dfa, 8)
        tiny_encoder.encode(b'x' * 100)
    except fte.encoder.InsufficientCapacityException as e:
        print(f"   Caught InsufficientCapacityException: {e}")
    except fte.dfa.LanguageIsEmptySetException as e:
        print(f"   Caught LanguageIsEmptySetException: Language too small")
    
    # Correct usage
    print("\n" + "=" * 50)
    print("\nCorrect usage:")
    
    plaintext = b'Hello, World!'
    try:
        ciphertext = encoder.encode(plaintext)
        recovered, remainder = encoder.decode(ciphertext)
        print(f"   Encoded and decoded successfully!")
        print(f"   Original: {plaintext}")
        print(f"   Recovered: {recovered}")
    except Exception as e:
        print(f"   Unexpected error: {e}")


if __name__ == '__main__':
    main()
