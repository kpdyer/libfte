#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""FTE Encoder module.

This module provides the main encoding/decoding functionality for
Format-Transforming Encryption, allowing plaintext to be encoded
as strings matching a specified regular language.
"""

import math

import fte.conf
import fte.bit_ops
import fte.dfa
from fte.dfa import create_dfa
import fte.encrypter


class InvalidSeedLength(Exception):
    """Raised when the seed is not the expected length."""
    pass


class InsufficientCapacityException(Exception):
    """Raised when the language doesn't have enough capacity for the payload."""
    pass


class InvalidInputException(Exception):
    """Raised when the input to encode/decode is not bytes."""
    pass


class DecodeFailureError(Exception):
    """Raised when decode fails to properly recover a message."""
    pass


# Cache for DfaEncoder instances
_instance = {}


class DfaEncoder:
    """A caching proxy for DfaEncoderObject.
    
    If a DfaEncoder is invoked multiple times with the same parameters
    within one process, we reuse the same DfaEncoderObject instance.
    
    Args:
        dfa: The DFA specification string (AT&T FST format).
        fixed_slice: The fixed output length for encoded strings.
        K1: Optional 16-byte encryption key.
        K2: Optional 16-byte MAC key.
    """

    def __new__(cls, dfa: str, fixed_slice: int, K1: bytes = None, K2: bytes = None):
        global _instance
        key = (dfa, fixed_slice, K1, K2)
        if not _instance.get(key):
            _instance[key] = DfaEncoderObject(dfa, fixed_slice, K1, K2)
        return _instance[key]


class DfaEncoderObject:
    """The actual FTE encoder implementation.
    
    Uses a DFA (Deterministic Finite Automaton) to encode encrypted
    data as strings matching a regular language.
    """
    
    _COVERTEXT_HEADER_LEN_PLAINTEXT = 8
    _COVERTEXT_HEADER_LEN_CIPHERTEXT = 16

    def __init__(self, dfa: str, fixed_slice: int, K1: bytes = None, K2: bytes = None):
        """Construct a new encoder for the given DFA.
        
        Args:
            dfa: The DFA specification in AT&T FST format.
            fixed_slice: The length of encoded strings to produce.
                encode() outputs strings of exactly this length.
            K1: Optional 16-byte encryption key.
            K2: Optional 16-byte MAC key.
        """
        self._fixed_slice = fixed_slice
        cDFA = create_dfa(dfa, fixed_slice)
        self._dfa = fte.dfa.DFA(cDFA, self._fixed_slice)
        self._encrypter = fte.encrypter.Encrypter(K1, K2)

    def getCapacity(self) -> int:
        """Get the capacity of the language in bits.
        
        Returns:
            The floor of log2 of the cardinality of strings of length
            fixed_slice in the language.
        """
        return self._dfa._capacity

    def encode(self, X: bytes, seed: bytes = None) -> bytes:
        """Encode plaintext as a string matching the DFA's language.
        
        Args:
            X: The plaintext bytes to encode.
            seed: Optional 8-byte seed for deterministic encoding.
            
        Returns:
            The covertext: a bytes string of length fixed_slice followed
            by any overflow ciphertext.
            
        Raises:
            InvalidInputException: If X is not bytes.
            InvalidSeedLength: If seed is provided but not 8 bytes.
            InsufficientCapacityException: If the language can't hold the payload.
        """
        if not X:
            return b''

        if not isinstance(X, bytes):
            raise InvalidInputException('Input must be of type bytes.')

        if seed is not None and len(seed) != 8:
            raise InvalidSeedLength(f'The seed must be 8 bytes, got {len(seed)}')

        ciphertext = self._encrypter.encrypt(X)

        maximumBytesToRank = int(math.floor(self.getCapacity() / 8.0))
        unrank_payload_len = (
            maximumBytesToRank - DfaEncoderObject._COVERTEXT_HEADER_LEN_CIPHERTEXT
        )
        unrank_payload_len = min(len(ciphertext), unrank_payload_len)

        if unrank_payload_len <= 0:
            raise InsufficientCapacityException(
                "Language doesn't have enough capacity"
            )

        msg_len_header = fte.bit_ops.long_to_bytes(unrank_payload_len)
        msg_len_header = msg_len_header.rjust(
            DfaEncoderObject._COVERTEXT_HEADER_LEN_PLAINTEXT, b'\x00'
        )
        random_bytes = seed if seed is not None else fte.bit_ops.random_bytes(8)
        msg_len_header = random_bytes + msg_len_header
        msg_len_header = self._encrypter.encryptOneBlock(msg_len_header)

        unrank_payload = msg_len_header + ciphertext[
            :maximumBytesToRank - DfaEncoderObject._COVERTEXT_HEADER_LEN_CIPHERTEXT
        ]

        random_padding_bytes = maximumBytesToRank - len(unrank_payload)
        if random_padding_bytes > 0:
            unrank_payload += fte.bit_ops.random_bytes(random_padding_bytes)

        unrank_payload_int = fte.bit_ops.bytes_to_long(unrank_payload)

        formatted_covertext_header = self._dfa.unrank(unrank_payload_int)
        unformatted_covertext_body = ciphertext[
            maximumBytesToRank - DfaEncoderObject._COVERTEXT_HEADER_LEN_CIPHERTEXT:
        ]

        covertext = formatted_covertext_header + unformatted_covertext_body

        return covertext

    def decode(self, covertext: bytes) -> tuple:
        """Decode covertext back to plaintext.
        
        Args:
            covertext: The encoded bytes (from encode()).
            
        Returns:
            A tuple of (plaintext, remaining_buffer) where plaintext is
            the decoded message and remaining_buffer is any leftover data.
            
        Raises:
            InvalidInputException: If covertext is not bytes.
            DecodeFailureError: If covertext is too short.
        """
        if not isinstance(covertext, bytes):
            raise InvalidInputException('Input must be of type bytes.')

        if len(covertext) < self._fixed_slice:
            raise DecodeFailureError(
                "Covertext is shorter than fixed_slice, can't decode."
            )

        maximumBytesToRank = int(math.floor(self.getCapacity() / 8.0))

        rank_payload = self._dfa.rank(covertext[:self._fixed_slice])
        X = fte.bit_ops.long_to_bytes(rank_payload)
        X = X.rjust(maximumBytesToRank, b'\x00')

        msg_len_header = self._encrypter.decryptOneBlock(
            X[:DfaEncoderObject._COVERTEXT_HEADER_LEN_CIPHERTEXT]
        )
        msg_len_header = msg_len_header[8:16]
        msg_len = fte.bit_ops.bytes_to_long(
            msg_len_header[:DfaEncoderObject._COVERTEXT_HEADER_LEN_PLAINTEXT]
        )

        retval = X[16:16 + msg_len]
        retval += covertext[self._fixed_slice:]
        ctxt_len = self._encrypter.getCiphertextLen(retval)
        remaining_buffer = retval[ctxt_len:]
        retval = retval[:ctxt_len]
        retval = self._encrypter.decrypt(retval)

        return retval, remaining_buffer
