"""FTE - Format-Transforming Encryption library.

This library implements Format-Transforming Encryption (FTE), a cryptographic
primitive that allows encoding ciphertexts as strings matching a specified
regular language.

Example usage:
    >>> import regex2dfa
    >>> import fte.encoder
    >>> 
    >>> regex = '^(a|b)+$'
    >>> fixed_slice = 512
    >>> input_plaintext = b'test'
    >>> 
    >>> dfa = regex2dfa.regex2dfa(regex)
    >>> fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)
    >>> 
    >>> ciphertext = fteObj.encode(input_plaintext)
    >>> output_plaintext, remainder = fteObj.decode(ciphertext)
    >>> 
    >>> assert input_plaintext == output_plaintext

See the paper "Protocol Misidentification Made Easy with Format-Transforming
Encryption" for details: https://kpdyer.com/publications/ccs2013-fte.pdf
"""

import sys
from pathlib import Path

# Increase the integer string conversion limit for Python 3.11+
# This is needed because the C extension converts large integers via hex strings
# when interfacing with GMP for ranking/unranking operations.
if hasattr(sys, 'set_int_max_str_digits'):
    sys.set_int_max_str_digits(0)  # Disable the limit

__version__ = (Path(__file__).parent / '_version.txt').read_text().strip()
__author__ = 'Kevin P. Dyer'
__email__ = 'kpdyer@gmail.com'
