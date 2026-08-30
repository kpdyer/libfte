#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Basic FTE usage.

This example demonstrates the simplest way to use FTE -
encrypting and decrypting a message with a regex format.
"""

import os

import fte


def main():
    # Create a cipher with a regex, output length, and a 32-byte key.
    cipher = fte.Encoder(regex='^(a|b)+$', fixed_slice=512, key=os.urandom(32))
    
    # Encrypt a message
    plaintext = b'Hello, World!'
    ciphertext = cipher.encrypt(plaintext)
    
    # Decrypt it back
    recovered, remainder = cipher.decrypt(ciphertext)
    
    # Display results
    print(f'Plaintext: {plaintext}')
    print(f'Ciphertext: {ciphertext[:32].decode()}...{ciphertext[-32:].decode()}')
    print(f'Recovered: {recovered}')
    
    # Verify roundtrip
    assert plaintext == recovered, "Roundtrip failed!"
    print("\nSuccess! Message was correctly encrypted and decrypted.")


if __name__ == '__main__':
    main()
