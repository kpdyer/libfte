#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Authenticated encryption for FTE: AES-CTR + HMAC-SHA256 (Encrypt-then-MAC).

This is the construction from the FTE paper -- AES in counter mode, then an HMAC
over the ciphertext -- backed by OpenSSL (via ``cryptography`` for AES-CTR and
the stdlib ``hmac``/``hashlib``, both OpenSSL under the hood). It replaces an
AES-CTR + HMAC-SHA512 implementation built on pycryptodome, which was ~8x slower
for the same work.

Encrypt-then-MAC with independent keys keeps the standard IND-CPA + INT-CTXT
guarantees, and a nonce collision under a reused key costs only the
confidentiality of the colliding pair, never authenticity -- a good fit for a
static shared key used across many records.

See https://kpdyer.com/publications/ccs2013-fte.pdf for scheme details, and
https://kpdyer.com/publications/usenix2014-fte.pdf for the libFTE toolkit.
"""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class DecryptionError(Exception):
    """Raised when a ciphertext cannot be authenticated and decrypted."""
    pass


class Encrypter:
    """Encrypt-then-MAC authenticated encryption: AES-128-CTR + HMAC-SHA256.

    ``K1`` keys AES-CTR; ``K2`` keys the HMAC. The two must be independent, which
    the caller guarantees by splitting one 32-byte key into halves.

    Args:
        K1: 16-byte AES encryption key.
        K2: 16-byte HMAC key.

    Raises:
        TypeError: If either key is not bytes.
        ValueError: If either key is not exactly 16 bytes.
    """

    _KEY_LENGTH = 16
    _NONCE_LENGTH = 12
    _COUNTER_LENGTH = 16  # AES block: 12-byte nonce || 4-byte block counter
    _TAG_LENGTH = 16      # HMAC-SHA256 truncated to 128 bits
    # Ciphertext = nonce || AES-CTR(plaintext) || tag.
    _CTXT_EXPANSION = _NONCE_LENGTH + _TAG_LENGTH
    # A 4-byte block counter caps a message at 2**32 blocks; keep the historical
    # 2**32 - 1 byte bound so the engine's frame/length math is unchanged.
    _MAX_PLAINTEXT_LENGTH = (1 << 32) - 1

    def __init__(self, K1: bytes, K2: bytes):
        if not isinstance(K1, bytes) or not isinstance(K2, bytes):
            raise TypeError('Each key must be of type bytes.')
        if len(K1) != Encrypter._KEY_LENGTH or len(K2) != Encrypter._KEY_LENGTH:
            raise ValueError('Each key must be 16 bytes long.')
        self._enc_key = K1
        self._mac_key = K2

    def _counter(self, nonce: bytes) -> bytes:
        return nonce + b'\x00' * (Encrypter._COUNTER_LENGTH - Encrypter._NONCE_LENGTH)

    def _tag(self, data: bytes) -> bytes:
        return hmac.new(self._mac_key, data, hashlib.sha256).digest()[:Encrypter._TAG_LENGTH]

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt-then-MAC ``plaintext``.

        Returns ``nonce (12) || AES-CTR ciphertext || HMAC tag (16)``, i.e.
        always ``_CTXT_EXPANSION`` (28) bytes longer than the plaintext.

        Raises:
            TypeError: If plaintext is not bytes.
            ValueError: If plaintext is longer than 2**32 - 1 bytes.
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("Input plaintext must be of type bytes")
        if len(plaintext) > Encrypter._MAX_PLAINTEXT_LENGTH:
            raise ValueError("Plaintext must be at most 2**32 - 1 bytes")

        nonce = os.urandom(Encrypter._NONCE_LENGTH)
        encryptor = Cipher(
            algorithms.AES(self._enc_key), modes.CTR(self._counter(nonce))
        ).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce + ciphertext + self._tag(nonce + ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Verify the tag, then decrypt one complete ciphertext from ``encrypt``.

        Raises:
            TypeError: If ciphertext is not bytes.
            DecryptionError: If the ciphertext is too short or fails the MAC.
        """
        if not isinstance(ciphertext, bytes):
            raise TypeError("Input ciphertext must be of type bytes")
        if len(ciphertext) < Encrypter._CTXT_EXPANSION:
            raise DecryptionError('Incomplete ciphertext.')

        nonce = ciphertext[:Encrypter._NONCE_LENGTH]
        tag = ciphertext[-Encrypter._TAG_LENGTH:]
        body = ciphertext[Encrypter._NONCE_LENGTH:-Encrypter._TAG_LENGTH]

        if not hmac.compare_digest(self._tag(nonce + body), tag):
            raise DecryptionError('Failed to authenticate ciphertext.')

        decryptor = Cipher(
            algorithms.AES(self._enc_key), modes.CTR(self._counter(nonce))
        ).decryptor()
        return decryptor.update(body) + decryptor.finalize()
