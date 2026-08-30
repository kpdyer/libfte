#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Encrypting data into word-like patterns.

This example creates ciphertext that looks like pronounceable
words or names, useful for human-readable ciphertext.
"""

import os

import fte


def main():
    # Pattern: consonant-vowel alternating (pronounceable)
    consonants = 'bcdfghjklmnpqrstvwxyz'
    vowels = 'aeiou'
    regex = f'^([{consonants}][{vowels}])+$'

    cipher = fte.FTE(
        format=fte.RegexFormat(regex, length=128),
        key=os.urandom(32),
    )

    plaintext = b'Hidden'
    ciphertext = cipher.encrypt(plaintext)

    print("=== Word-Based Format ===")
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.decode('latin-1')}")
    print(f"\nThe ciphertext is pronounceable!")

    # Show it split into 'words'
    ct_str = ciphertext.decode('latin-1')
    words = [ct_str[i:i+6] for i in range(0, len(ct_str), 6)]
    print(f"As 'words': {' '.join(words)}")

    # Verify roundtrip
    recovered = cipher.decrypt(ciphertext)
    print(f"\nRecovered: {recovered}")
    assert plaintext == recovered


if __name__ == '__main__':
    main()
