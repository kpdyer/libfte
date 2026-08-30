#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Basic FTE usage.

This example demonstrates the simplest way to use FTE -
encoding and decoding a message with a regex format.
"""

import os

import fte


def main():
    # Create an encoder with a regex, output length, and a 32-byte key.
    encoder = fte.Encoder(regex='^(a|b)+$', fixed_slice=512, key=os.urandom(32))
    
    # Encode a message
    plaintext = b'Hello, World!'
    ciphertext = encoder.encode(plaintext)
    
    # Decode it back
    recovered, remainder = encoder.decode(ciphertext)
    
    # Display results
    print(f'Plaintext: {plaintext}')
    print(f'Ciphertext: {ciphertext[:32].decode()}...{ciphertext[-32:].decode()}')
    print(f'Recovered: {recovered}')
    
    # Verify roundtrip
    assert plaintext == recovered, "Roundtrip failed!"
    print("\nSuccess! Message was correctly encoded and decoded.")


if __name__ == '__main__':
    main()
