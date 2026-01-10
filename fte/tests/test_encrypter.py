#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for fte.encrypter module."""

import random
import unittest

import fte.bit_ops
import fte.encrypter

TRIALS = 2 ** 8


class Tests(unittest.TestCase):
    """Test cases for the Encrypter class."""

    def setUp(self):
        """Set up test fixtures."""
        self.encrypter = fte.encrypter.Encrypter()

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

    def test_encrypt_decrypt_one_block(self):
        """Test single block encryption/decryption."""
        for _ in range(TRIALS):
            M1 = random.randint(0, (1 << 128) - 1)
            M1 = fte.bit_ops.long_to_bytes(M1, 16)
            retval = self.encrypter.encryptOneBlock(M1)
            H_out = self.encrypter.decryptOneBlock(retval)
            self.assertEqual(M1, H_out)

    def test_ciphertext_expansion(self):
        """Test that ciphertext is exactly 32 bytes longer than plaintext.
        
        Expansion = W1 (16 bytes) + MAC (16 bytes) = 32 bytes.
        """
        for length in [0, 1, 10, 100, 1000]:
            P = b'A' * length
            C = self.encrypter.encrypt(P)
            # W1=16 bytes header + plaintext + T=16 bytes MAC = plaintext + 32
            self.assertEqual(len(C), len(P) + 32)

    def test_invalid_key_length(self):
        """Test that invalid key lengths raise an exception."""
        with self.assertRaises(fte.encrypter.InvalidKeyLengthError):
            fte.encrypter.Encrypter(K1=b'short', K2=b'\x00' * 16)
        with self.assertRaises(fte.encrypter.InvalidKeyLengthError):
            fte.encrypter.Encrypter(K1=b'\x00' * 16, K2=b'short')

    def test_plaintext_type_error(self):
        """Test that non-bytes plaintext raises an exception."""
        with self.assertRaises(fte.encrypter.PlaintextTypeError):
            self.encrypter.encrypt("string instead of bytes")

    def test_ciphertext_type_error(self):
        """Test that non-bytes ciphertext raises an exception."""
        with self.assertRaises(fte.encrypter.CiphertextTypeError):
            self.encrypter.decrypt("string instead of bytes")


def suite():
    """Return the test suite."""
    loader = unittest.TestLoader()
    test_suite = unittest.TestSuite()
    test_suite.addTest(loader.loadTestsFromTestCase(Tests))
    return test_suite


if __name__ == '__main__':
    unittest.main()
