#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example: Encoding data as word-like patterns.

This example creates ciphertext that looks like pronounceable
words or names, useful for human-readable encoded data.
"""

import regex2dfa
import fte.encoder


def main():
    # Pattern: consonant-vowel alternating (pronounceable)
    # Creates strings like "bababa", "kokoko", etc.
    consonants = 'bcdfghjklmnpqrstvwxyz'
    vowels = 'aeiou'
    
    # Simple CV pattern repeated
    regex = f'^([{consonants}][{vowels}])+$'
    fixed_slice = 32  # Will produce 32 characters
    
    dfa = regex2dfa.regex2dfa(regex)
    encoder = fte.encoder.DfaEncoder(dfa, fixed_slice)
    
    plaintext = b'Hidden'
    ciphertext = encoder.encode(plaintext)
    
    print("=== Word-Based Format ===")
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.decode('latin-1')}")
    print(f"\nThe ciphertext is pronounceable!")
    
    # Show it split into 'words'
    ct_str = ciphertext.decode('latin-1')
    words = [ct_str[i:i+6] for i in range(0, len(ct_str), 6)]
    print(f"As 'words': {' '.join(words)}")
    
    # Verify roundtrip
    recovered, _ = encoder.decode(ciphertext)
    print(f"\nRecovered: {recovered}")
    assert plaintext == recovered


if __name__ == '__main__':
    main()
