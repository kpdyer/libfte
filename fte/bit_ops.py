#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Bit manipulation operations for FTE.

This module provides utilities for converting between integers and bytes,
as well as generating random bytes for cryptographic operations.
"""

from Crypto.Random import get_random_bytes


def random_bytes(n: int) -> bytes:
    """Return exactly n uniformly-random bytes.
    
    Args:
        n: Number of random bytes to generate.
        
    Returns:
        A bytes object of length n containing random data.
    """
    return get_random_bytes(n)


def long_to_bytes(n: int, blocksize: int = 1) -> bytes:
    """Convert an integer to its bytes representation.
    
    Args:
        n: The integer to convert.
        blocksize: If greater than 1, the output will be padded with
            leading zero bytes so its length is a multiple of blocksize.
            
    Returns:
        The bytes representation of the integer n.
        
    Examples:
        >>> long_to_bytes(255)
        b'\\xff'
        >>> long_to_bytes(256)
        b'\\x01\\x00'
        >>> long_to_bytes(1, 4)
        b'\\x00\\x00\\x00\\x01'
    """
    if n == 0:
        bytestring = b'\x00'
    else:
        # Calculate the number of bytes needed
        byte_length = (n.bit_length() + 7) // 8
        bytestring = n.to_bytes(byte_length, byteorder='big')
    
    # Pad to blocksize if needed
    if blocksize > 0 and len(bytestring) % blocksize != 0:
        padding_len = blocksize - (len(bytestring) % blocksize)
        bytestring = b'\x00' * padding_len + bytestring
    
    return bytestring


def bytes_to_long(bytestring: bytes) -> int:
    """Convert a bytes object to its integer representation.
    
    Args:
        bytestring: The bytes to convert.
        
    Returns:
        The integer representation of the bytes.
        
    Examples:
        >>> bytes_to_long(b'\\xff')
        255
        >>> bytes_to_long(b'\\x01\\x00')
        256
    """
    return int.from_bytes(bytestring, byteorder='big')
