#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for fte._encrypter module."""

import unittest

import fte._encrypter

TRIALS = 2 ** 8


class Tests(unittest.TestCase):
    """Test cases for the Encrypter class."""

    def setUp(self):
        """Set up test fixtures."""
        self.encrypter = fte._encrypter.Encrypter(
            K1=b'\xFF' * 16, K2=b'\x00' * 16
        )

    def test_encrypt_empty(self):
        """Test encryption of empty plaintext."""
        for _ in range(TRIALS):
            C = self.encrypter.encrypt(b'')
            for _ in range(10):
                self.assertEqual(self.encrypter.decrypt(C), b'')

    def test_encrypt_decrypt_varying_length(self):
        """Test encrypt/decrypt with varying plaintext lengths."""
        for i in range(TRIALS):
            P = b'X' * i
            C = self.encrypter.encrypt(P)
            self.assertNotEqual(C, P)
            self.assertEqual(P, self.encrypter.decrypt(C))

    def test_encrypt_decrypt_large(self):
        """Test encrypt/decrypt with large plaintext."""
        for _ in range(TRIALS):
            P = b'\x01' * (2 ** 15)
            C = self.encrypter.encrypt(P)
            self.assertNotEqual(C, P)
            self.assertEqual(P, self.encrypter.decrypt(C))

    def test_ciphertext_expansion(self):
        """Ciphertext is exactly 28 bytes longer than plaintext.

        Expansion = nonce (12 bytes) + HMAC-SHA256 tag (16 bytes) = 28 bytes.
        """
        for length in [0, 1, 10, 100, 1000]:
            P = b'A' * length
            C = self.encrypter.encrypt(P)
            self.assertEqual(len(C), len(P) + fte._encrypter.Encrypter._CTXT_EXPANSION)
            self.assertEqual(len(C), len(P) + 28)

    def test_keys_are_required(self):
        """Test that constructing without both keys fails."""
        with self.assertRaises(TypeError):
            fte._encrypter.Encrypter()
        with self.assertRaises(TypeError):
            fte._encrypter.Encrypter(K1=b'\x00' * 16)

    def test_invalid_key_length(self):
        """Test that invalid key lengths raise an exception."""
        with self.assertRaises(ValueError):
            fte._encrypter.Encrypter(K1=b'short', K2=b'\x00' * 16)
        with self.assertRaises(ValueError):
            fte._encrypter.Encrypter(K1=b'\x00' * 16, K2=b'short')

    def test_plaintext_type_error(self):
        """Test that non-bytes plaintext raises an exception."""
        with self.assertRaises(TypeError):
            self.encrypter.encrypt("string instead of bytes")

    def test_ciphertext_type_error(self):
        """Test that non-bytes ciphertext raises an exception."""
        with self.assertRaises(TypeError):
            self.encrypter.decrypt("string instead of bytes")

    def test_decrypt_rejects_wrong_length(self):
        """Test that truncated or extended ciphertexts are rejected."""
        C = self.encrypter.encrypt(b'hello')
        for bad in (C[:-1], C + b'x', C[:8]):
            with self.assertRaises(fte._encrypter.DecryptionError):
                self.encrypter.decrypt(bad)

    def test_decrypt_rejects_bad_mac(self):
        """Test that a tampered ciphertext fails MAC verification."""
        C = self.encrypter.encrypt(b'hello')
        tampered = C[:-1] + bytes([C[-1] ^ 0x01])
        with self.assertRaises(fte._encrypter.DecryptionError):
            self.encrypter.decrypt(tampered)


if __name__ == '__main__':
    unittest.main()
