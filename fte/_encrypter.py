#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Authenticated encryption module for FTE.

This module provides authenticated encryption using AES-CTR mode
with HMAC-SHA512 for message authentication.

See https://kpdyer.com/publications/ccs2013-fte.pdf for scheme details, and
https://kpdyer.com/publications/usenix2014-fte.pdf for the libFTE toolkit.
"""

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter


class DecryptionError(Exception):
    """Raised when a ciphertext cannot be authenticated and decrypted."""
    pass


class Encrypter:
    """Authenticated encryption scheme using AES-CTR + HMAC-SHA512.

    Args:
        K1: 16-byte encryption key.
        K2: 16-byte MAC key.

    Raises:
        TypeError: If either key is not bytes.
        ValueError: If either key is not exactly 16 bytes.
    """

    _MAC_LENGTH = AES.block_size
    _IV_LENGTH = 7
    _MSG_COUNTER_LENGTH = 8
    _CTXT_EXPANSION = 1 + _IV_LENGTH + _MSG_COUNTER_LENGTH + _MAC_LENGTH
    # The header stores the plaintext length in 8 bytes but decrypt requires
    # the top 4 to be zero, so the scheme carries at most 2**32 - 1 bytes.
    _MAX_PLAINTEXT_LENGTH = (1 << 32) - 1

    def __init__(self, K1: bytes, K2: bytes):
        if not isinstance(K1, bytes) or not isinstance(K2, bytes):
            raise TypeError('Each key must be of type bytes.')
        if len(K1) != AES.block_size or len(K2) != AES.block_size:
            raise ValueError('Each key must be 16 bytes long.')

        self.K1 = K1
        self.K2 = K2
        self._ecb_enc_K1 = AES.new(K1, AES.MODE_ECB)

    def _ctr_cipher(self, iv2_bytes: bytes):
        """Return an AES-CTR cipher whose counter starts at ``iv2_bytes``."""
        counter = Counter.new(
            AES.block_size * 8,
            initial_value=int.from_bytes(iv2_bytes, 'big'),
        )
        return AES.new(key=self.K1, mode=AES.MODE_CTR, counter=counter)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using authenticated encryption.

        Args:
            plaintext: The plaintext bytes to encrypt. Can be empty.

        Returns:
            The ciphertext, which is always 32 bytes longer than the plaintext
            (16-byte W1 header + 16-byte MAC).

        Raises:
            TypeError: If plaintext is not bytes.
            ValueError: If plaintext is longer than 2**32 - 1 bytes.
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("Input plaintext must be of type bytes")
        if len(plaintext) > Encrypter._MAX_PLAINTEXT_LENGTH:
            raise ValueError("Plaintext must be at most 2**32 - 1 bytes")

        iv_bytes = get_random_bytes(Encrypter._IV_LENGTH)

        W1 = self._ecb_enc_K1.encrypt(
            b'\x01' + iv_bytes
            + len(plaintext).to_bytes(Encrypter._MSG_COUNTER_LENGTH, 'big')
        )
        W2 = self._ctr_cipher(b'\x02' + iv_bytes).encrypt(plaintext)

        mac = HMAC.new(self.K2, W1 + W2, SHA512)
        T = mac.digest()[:Encrypter._MAC_LENGTH]

        return W1 + W2 + T

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using authenticated encryption.

        Args:
            ciphertext: One complete ciphertext, exactly as returned by
                :meth:`encrypt`.

        Returns:
            The decrypted plaintext.

        Raises:
            TypeError: If ciphertext is not bytes.
            DecryptionError: If the header is malformed, the length does not
                match the header, or MAC verification fails.
        """
        if not isinstance(ciphertext, bytes):
            raise TypeError("Input ciphertext must be of type bytes")
        if len(ciphertext) < AES.block_size:
            raise DecryptionError('Incomplete ciphertext header.')

        W1 = ciphertext[:AES.block_size]
        header = self._ecb_enc_K1.decrypt(W1)

        if header[-8:-4] != b'\x00\x00\x00\x00':
            raise DecryptionError('Invalid header padding.')
        plaintext_length = int.from_bytes(header[-8:], 'big')

        expected_length = plaintext_length + Encrypter._CTXT_EXPANSION
        if len(ciphertext) != expected_length:
            raise DecryptionError(
                'Ciphertext length does not match its header.'
            )

        W2 = ciphertext[AES.block_size:AES.block_size + plaintext_length]
        T_expected = ciphertext[AES.block_size + plaintext_length:]

        mac = HMAC.new(self.K2, W1 + W2, SHA512)
        T_actual = mac.digest()[:Encrypter._MAC_LENGTH]
        if T_expected != T_actual:
            raise DecryptionError('Failed to verify MAC.')

        return self._ctr_cipher(b'\x02' + header[1:8]).decrypt(W2)
