#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of libfte.
#
# libfte is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# libfte is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libfte.  If not, see <http://www.gnu.org/licenses/>.

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
