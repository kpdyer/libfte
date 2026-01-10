#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for fte.bit_ops module."""

import random
import unittest

import fte.bit_ops


class Tests(unittest.TestCase):
    """Test cases for bit operations."""

    def test_long_to_bytes_basic(self):
        """Test basic integer to bytes conversion."""
        self.assertEqual(fte.bit_ops.long_to_bytes(0xff), b'\xFF')
        self.assertEqual(fte.bit_ops.long_to_bytes(0), b'\x00')
        self.assertEqual(fte.bit_ops.long_to_bytes(256), b'\x01\x00')

    def test_bytes_to_long_basic(self):
        """Test basic bytes to integer conversion."""
        self.assertEqual(fte.bit_ops.bytes_to_long(b'\xFF'), 0xff)
        self.assertEqual(fte.bit_ops.bytes_to_long(b'\x00'), 0)
        self.assertEqual(fte.bit_ops.bytes_to_long(b'\x01\x00'), 256)

    def test_roundtrip(self):
        """Test that long_to_bytes and bytes_to_long are inverses."""
        for _ in range(2 ** 10):
            N = random.randint(0, 1 << 1024)
            M = fte.bit_ops.long_to_bytes(N)
            M = fte.bit_ops.bytes_to_long(M)
            self.assertEqual(N, M)

    def test_long_to_bytes_blocksize(self):
        """Test long_to_bytes with blocksize padding."""
        for _ in range(2 ** 10):
            N = random.randint(0, 1 << 1024)
            M = fte.bit_ops.long_to_bytes(N, 1024)
            self.assertEqual(1024, len(M))
            M = fte.bit_ops.bytes_to_long(M)
            self.assertEqual(N, M)

    def test_random_bytes_length(self):
        """Test that random_bytes returns correct length."""
        for length in [0, 1, 16, 32, 100, 1024]:
            result = fte.bit_ops.random_bytes(length)
            self.assertEqual(len(result), length)
            self.assertIsInstance(result, bytes)


def suite():
    """Return the test suite."""
    loader = unittest.TestLoader()
    test_suite = unittest.TestSuite()
    test_suite.addTest(loader.loadTestsFromTestCase(Tests))
    return test_suite


if __name__ == '__main__':
    unittest.main()
