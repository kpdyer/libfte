#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Authenticated encryption module for FTE.

This module provides authenticated encryption using AES-CTR mode
with HMAC-SHA512 for message authentication.

See https://kpdyer.com/publications/ccs2013-fte.pdf for scheme details.
"""

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA512
from Crypto.Util import Counter

import fte.bit_ops
import fte.conf


class InvalidKeyLengthError(Exception):
    """Raised when the input key length is not the correct size."""
    pass


class PlaintextTypeError(Exception):
    """Raised when the plaintext input to encrypt is not bytes."""
    pass


class CiphertextTypeError(Exception):
    """Raised when the ciphertext input to decrypt is not bytes."""
    pass


class RecoverableDecryptionError(Exception):
    """Raised when a non-fatal decryption error occurs.
    
    For example, attempting to decrypt a substring of a valid ciphertext.
    """
    pass


class UnrecoverableDecryptionError(Exception):
    """Raised when a fatal decryption error occurs, such as an invalid MAC."""
    pass


class Encrypter:
    """Authenticated encryption scheme using AES-CTR + HMAC-SHA512.
    
    Args:
        K1: Optional 16-byte encryption key. Defaults to 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF.
        K2: Optional 16-byte MAC key. Defaults to 0x00000000000000000000000000000000.
        
    Raises:
        InvalidKeyLengthError: If either key is not exactly 16 bytes.
    """

    _MAC_LENGTH = AES.block_size
    _IV_LENGTH = 7
    _MSG_COUNTER_LENGTH = 8
    _CTXT_EXPANSION = 1 + _IV_LENGTH + _MSG_COUNTER_LENGTH + _MAC_LENGTH

    def __init__(self, K1: bytes = None, K2: bytes = None):
        if K1 is None or K2 is None:
            key = fte.conf.getValue('runtime.fte.encrypter.key')
            if K1 is None:
                self.K1 = key[0:len(key) // 2]
            else:
                self.K1 = K1
            if K2 is None:
                self.K2 = key[len(key) // 2:]
            else:
                self.K2 = K2
        else:
            self.K1 = K1
            self.K2 = K2

        if len(self.K1) != AES.block_size or len(self.K2) != AES.block_size:
            raise InvalidKeyLengthError('Each key must be 16 bytes long.')

        self._ecb_enc_K1 = AES.new(self.K1, AES.MODE_ECB)
        self._ecb_enc_K2 = AES.new(self.K2, AES.MODE_ECB)

    def encrypt(self, plaintext: bytes, iv_bytes: bytes = None) -> bytes:
        """Encrypt plaintext using authenticated encryption.
        
        Args:
            plaintext: The plaintext bytes to encrypt. Can be empty.
            iv_bytes: Optional 7-byte IV. Generated randomly if not provided.
            
        Returns:
            The ciphertext, which is always 32 bytes longer than the plaintext
            (16-byte W1 header + 16-byte MAC).
            
        Raises:
            PlaintextTypeError: If plaintext is not bytes.
        """
        if not isinstance(plaintext, bytes):
            raise PlaintextTypeError("Input plaintext must be of type bytes")

        if iv_bytes is None:
            iv_bytes = fte.bit_ops.random_bytes(Encrypter._IV_LENGTH)

        iv1_bytes = b'\x01' + iv_bytes
        iv2_bytes = b'\x02' + iv_bytes

        W1 = iv1_bytes
        W1 += fte.bit_ops.long_to_bytes(len(plaintext), Encrypter._MSG_COUNTER_LENGTH)
        W1 = self._ecb_enc_K1.encrypt(W1)

        counter_length_in_bits = AES.block_size * 8
        counter_val = fte.bit_ops.bytes_to_long(iv2_bytes)
        counter = Counter.new(counter_length_in_bits, initial_value=counter_val)
        ctr_enc = AES.new(
            key=self.K1,
            mode=AES.MODE_CTR,
            counter=counter
        )
        W2 = ctr_enc.encrypt(plaintext)

        mac = HMAC.new(self.K2, W1 + W2, SHA512)
        T = mac.digest()[:Encrypter._MAC_LENGTH]

        ciphertext = W1 + W2 + T

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using authenticated encryption.
        
        Args:
            ciphertext: The ciphertext bytes to decrypt.
            
        Returns:
            The decrypted plaintext.
            
        Raises:
            CiphertextTypeError: If ciphertext is not bytes.
            RecoverableDecryptionError: If ciphertext is incomplete.
            UnrecoverableDecryptionError: If MAC verification fails or padding is invalid.
        """
        if not isinstance(ciphertext, bytes):
            raise CiphertextTypeError("Input ciphertext must be of type bytes")

        plaintext_length = self.getPlaintextLen(ciphertext)
        ciphertext_length = self.getCiphertextLen(ciphertext)
        
        if len(ciphertext) < ciphertext_length:
            raise RecoverableDecryptionError(
                f'Incomplete ciphertext: ({len(ciphertext)} of {ciphertext_length}).'
            )

        ciphertext = ciphertext[:ciphertext_length]

        W1_start = 0
        W1_end = AES.block_size
        W1 = ciphertext[W1_start:W1_end]

        W2_start = AES.block_size
        W2_end = AES.block_size + plaintext_length
        W2 = ciphertext[W2_start:W2_end]

        T_start = AES.block_size + plaintext_length
        T_end = AES.block_size + plaintext_length + Encrypter._MAC_LENGTH
        T_expected = ciphertext[T_start:T_end]

        mac = HMAC.new(self.K2, W1 + W2, SHA512)
        T_actual = mac.digest()[:Encrypter._MAC_LENGTH]
        
        if T_expected != T_actual:
            raise UnrecoverableDecryptionError('Failed to verify MAC.')

        decrypted_header = self._ecb_enc_K1.decrypt(W1)
        iv2_bytes = b'\x02' + decrypted_header[1:8]
        counter_val = fte.bit_ops.bytes_to_long(iv2_bytes)
        counter_length_in_bits = AES.block_size * 8
        counter = Counter.new(counter_length_in_bits, initial_value=counter_val)
        ctr_enc = AES.new(
            key=self.K1,
            mode=AES.MODE_CTR,
            counter=counter
        )
        plaintext = ctr_enc.decrypt(W2)

        return plaintext

    def getCiphertextLen(self, ciphertext: bytes) -> int:
        """Get the expected ciphertext length from its header.
        
        Args:
            ciphertext: A ciphertext with a valid header.
            
        Returns:
            The total ciphertext length including expansion.
        """
        plaintext_length = self.getPlaintextLen(ciphertext)
        ciphertext_length = plaintext_length + Encrypter._CTXT_EXPANSION
        return ciphertext_length

    def getPlaintextLen(self, ciphertext: bytes) -> int:
        """Get the plaintext length from the ciphertext header.
        
        Args:
            ciphertext: A ciphertext with a valid header (at least 16 bytes).
            
        Returns:
            The length of the plaintext payload.
            
        Raises:
            RecoverableDecryptionError: If ciphertext header is incomplete.
            UnrecoverableDecryptionError: If padding is invalid or length is negative.
        """
        if len(ciphertext) < 16:
            raise RecoverableDecryptionError('Incomplete ciphertext header.')

        ciphertext_header = ciphertext[:16]
        L = self._ecb_enc_K1.decrypt(ciphertext_header)

        padding_expected = b'\x00\x00\x00\x00'
        padding_actual = L[-8:-4]
        
        if padding_actual != padding_expected:
            raise UnrecoverableDecryptionError(
                f'Invalid padding: {padding_actual!r}'
            )

        message_length = fte.bit_ops.bytes_to_long(L[-8:])

        if message_length < 0:
            raise UnrecoverableDecryptionError('Negative message length.')

        return message_length

    def encryptOneBlock(self, plaintext: bytes) -> bytes:
        """Perform AES-128 ECB encryption on a 16-byte plaintext using K1.
        
        Args:
            plaintext: Exactly 16 bytes to encrypt.
            
        Returns:
            The 16-byte ciphertext.
        """
        assert len(plaintext) == 16
        return self._ecb_enc_K1.encrypt(plaintext)

    def decryptOneBlock(self, ciphertext: bytes) -> bytes:
        """Perform AES-128 ECB decryption on a 16-byte ciphertext using K1.
        
        Args:
            ciphertext: Exactly 16 bytes to decrypt.
            
        Returns:
            The 16-byte plaintext.
        """
        assert len(ciphertext) == 16
        return self._ecb_enc_K1.decrypt(ciphertext)
