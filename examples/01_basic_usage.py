#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Basic FTE usage.

This example demonstrates the simplest way to use FTE -
encrypting and decrypting a message with a regex format.
"""

import os

import fte


def main():
    # One engine: FTE over a ranked format. RegexFormat is the built-in
    # provider; give it a pattern and the exact covertext length. FTE takes the
    # format and a 32-byte key.
    cipher = fte.FTE(
        format=fte.RegexFormat('^(a|b)+$', length=512),
        key=os.urandom(32),
    )

    # Encrypt a message
    plaintext = b'Hello, World!'
    ciphertext = cipher.encrypt(plaintext)

    # Decrypt it back
    recovered = cipher.decrypt(ciphertext)

    # Display results
    print(f'Plaintext: {plaintext}')
    print(f'Ciphertext: {ciphertext[:32].decode()}...{ciphertext[-32:].decode()}')
    print(f'Recovered: {recovered}')

    # Verify roundtrip
    assert plaintext == recovered, "Roundtrip failed!"
    print("\nSuccess! Message was correctly encrypted and decrypted.")


if __name__ == '__main__':
    main()
