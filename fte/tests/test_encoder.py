#!/usr/bin/env python
# -*- coding: utf-8 -*-



import unittest
import re

import fte.bit_ops
import fte.encoder

REGEXES = [
  '^(a|b)+$',
  '^.+$',
]

FIXED_SLICES = [
  512, 1024, 2048
]

MSG_LEN = 15
CONCATS = 8

class Tests(unittest.TestCase):

    def testSingle(self):
        for regex in REGEXES:
            for fixed_slice in FIXED_SLICES:
                fteObj = fte.encoder.RegexEncoder(regex, fixed_slice)

                input_plaintext = fte.bit_ops.random_bytes(MSG_LEN)
                ciphertext = fteObj.encode(input_plaintext)
                output_plaintext, buffer = fteObj.decode(ciphertext)
        
                self.assertEquals( input_plaintext, output_plaintext )
  
                reObj = re.compile(regex)
                self.assertTrue( reObj.match(ciphertext)>0 ) 

    def testConcat(self):
        for regex in REGEXES:
            for fixed_slice in FIXED_SLICES:
                fteObj = fte.encoder.RegexEncoder(regex, fixed_slice)

                input_plaintext = fte.bit_ops.random_bytes(MSG_LEN)
                ciphertext = ''
                for i in range(CONCATS):
                    ciphertext += fteObj.encode(input_plaintext)

                for i in range(CONCATS):
                    output_plaintext, buffer = fteObj.decode(ciphertext)
                    self.assertEquals( input_plaintext, output_plaintext )
                    ciphertext = buffer

                self.assertEquals( buffer, '' )

def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(Tests))
    return suite
