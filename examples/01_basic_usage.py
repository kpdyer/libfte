#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Example usage of the libfte library.

This example demonstrates encoding and decoding a message using
Format-Transforming Encryption with a simple regex that matches
strings of 'a' and 'b' characters.
"""

import regex2dfa
import fte.encoder


def main():
    # Define a regex that matches strings of 'a' and 'b' characters
    regex = '^(a|b)+$'
    fixed_slice = 512
    input_plaintext = b'test'

    # Convert regex to DFA format
    dfa = regex2dfa.regex2dfa(regex)
    
    # Create the FTE encoder
    fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)

    # Encode the plaintext
    ciphertext = fteObj.encode(input_plaintext)
    
    # Decode the ciphertext
    output_plaintext, remainder = fteObj.decode(ciphertext)

    # Display results
    print(f'input_plaintext={input_plaintext}')
    print(f'ciphertext={ciphertext[:16]}...{ciphertext[-16:]}')
    print(f'output_plaintext={output_plaintext}')
    
    # Verify the roundtrip
    assert input_plaintext == output_plaintext, "Roundtrip failed!"
    print("\nSuccess! Plaintext was correctly encoded and decoded.")


if __name__ == '__main__':
    main()
