#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: A gallery of regex covertext formats.

The pattern you choose denotes the covertext language. The same engine and
key produce hex strings, alphanumeric tokens, or alternating consonant/vowel
pairs by swapping the pattern. Format membership does not guarantee natural
words or a uniform distribution over the language.
"""

import os

import fte


CONSONANTS = 'bcdfghjklmnpqrstvwxyz'
VOWELS = 'aeiou'

FORMATS = [
    ("Hex (log files, debugging)", r'^[0-9a-f]+$', 128),
    ("Alphanumeric (tokens, IDs)", r'^[A-Za-z0-9]+$', 64),
    ("Consonant/vowel pairs", f'^([{CONSONANTS}][{VOWELS}])+$', 128),
]


def main():
    key = os.urandom(32)  # 32-byte key, shared by both endpoints
    plaintext = b'Secret message'

    for name, pattern, length in FORMATS:
        cipher = fte.FTE(output_format=fte.RegexFormat(pattern, length=length), key=key)
        covertext = cipher.encrypt(plaintext)

        print(f"=== {name} ===")
        print(f"  pattern:   {pattern}")
        print(f"  covertext: {covertext.decode('latin-1')}")
        assert cipher.decrypt(covertext) == plaintext
        print()

    print("All formats round-tripped.")


if __name__ == '__main__':
    main()
