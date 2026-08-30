#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: A gallery of regex covertext formats.

The covertext language is entirely the regex you choose. The same engine and
key produce hex strings, alphanumeric tokens, or pronounceable words just by
swapping the pattern.
"""

import os

import fte


CONSONANTS = 'bcdfghjklmnpqrstvwxyz'
VOWELS = 'aeiou'

FORMATS = [
    ("Hex (log files, debugging)", r'^[0-9a-f]+$', 128),
    ("Alphanumeric (tokens, IDs)", r'^[A-Za-z0-9]+$', 64),
    ("Pronounceable words", f'^([{CONSONANTS}][{VOWELS}])+$', 128),
]


def main():
    key = os.urandom(32)  # 32-byte key, shared by both endpoints
    plaintext = b'Secret message'

    for name, regex, length in FORMATS:
        cipher = fte.FTE(format=fte.RegexFormat(regex, length=length), key=key)
        covertext = cipher.encrypt(plaintext)

        print(f"=== {name} ===")
        print(f"  regex:     {regex}")
        print(f"  covertext: {covertext.decode('latin-1')}")
        assert cipher.decrypt(covertext) == plaintext
        print()

    print("All formats round-tripped.")


if __name__ == '__main__':
    main()
