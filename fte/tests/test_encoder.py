#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for fte.encoder module."""

import unittest

import fte.bit_ops
import fte.encoder

# DFA for .* (matches any byte sequence)
DOT_STAR_DFA = "\n".join(
    [f"0\t0\t{i}\t{i}" for i in range(256)]
) + "\n0"

DFAS = [DOT_STAR_DFA]
FIXED_SLICES = [512, 1024, 2048]
MSG_LEN = 15
CONCATS = 8


class Tests(unittest.TestCase):
    """Test cases for the DfaEncoder class."""

    def test_single_encode_decode(self):
        """Test single encode/decode roundtrip."""
        for dfa in DFAS:
            for fixed_slice in FIXED_SLICES:
                fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)

                input_plaintext = fte.bit_ops.random_bytes(MSG_LEN)
                ciphertext = fteObj.encode(input_plaintext)
                output_plaintext, buffer = fteObj.decode(ciphertext)

                self.assertEqual(input_plaintext, output_plaintext)

    def test_concatenated_messages(self):
        """Test encoding and decoding multiple concatenated messages."""
        for dfa in DFAS:
            for fixed_slice in FIXED_SLICES:
                fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)

                input_plaintext = fte.bit_ops.random_bytes(MSG_LEN)
                ciphertext = b''
                for _ in range(CONCATS):
                    ciphertext += fteObj.encode(input_plaintext)

                for _ in range(CONCATS):
                    output_plaintext, buffer = fteObj.decode(ciphertext)
                    self.assertEqual(input_plaintext, output_plaintext)
                    ciphertext = buffer

                self.assertEqual(buffer, b'')

    def test_empty_input(self):
        """Test that empty input returns empty output."""
        for dfa in DFAS:
            for fixed_slice in FIXED_SLICES:
                fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)
                result = fteObj.encode(b'')
                self.assertEqual(result, b'')

    def test_invalid_input_type(self):
        """Test that non-bytes input raises InvalidInputException."""
        dfa = DOT_STAR_DFA
        fteObj = fte.encoder.DfaEncoder(dfa, 512)
        
        with self.assertRaises(fte.encoder.InvalidInputException):
            fteObj.encode("string instead of bytes")
        
        with self.assertRaises(fte.encoder.InvalidInputException):
            fteObj.decode("string instead of bytes")

    def test_covertext_too_short(self):
        """Test that short covertext raises DecodeFailureError."""
        dfa = DOT_STAR_DFA
        fixed_slice = 512
        fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)
        
        with self.assertRaises(fte.encoder.DecodeFailureError):
            fteObj.decode(b'too short')

    def test_encoding_with_seed(self):
        """Test that encoding with seed works correctly."""
        dfa = DOT_STAR_DFA
        fteObj = fte.encoder.DfaEncoder(dfa, 512)
        plaintext = b'test message'
        seed = b'\x00' * 8
        
        # Just verify that encoding with a seed works and can be decoded
        ciphertext = fteObj.encode(plaintext, seed=seed)
        output_plaintext, buffer = fteObj.decode(ciphertext)
        
        self.assertEqual(plaintext, output_plaintext)
        self.assertEqual(buffer, b'')

    def test_invalid_seed_length(self):
        """Test that invalid seed length raises InvalidSeedLength."""
        dfa = DOT_STAR_DFA
        fteObj = fte.encoder.DfaEncoder(dfa, 512)
        
        with self.assertRaises(fte.encoder.InvalidSeedLength):
            fteObj.encode(b'test', seed=b'short')


def suite():
    """Return the test suite."""
    loader = unittest.TestLoader()
    test_suite = unittest.TestSuite()
    test_suite.addTest(loader.loadTestsFromTestCase(Tests))
    return test_suite


if __name__ == '__main__':
    unittest.main()
