#!/usr/bin/env python
# -*- coding: utf-8 -*-



import unittest
import random
import fte.bit_ops


class Tests(unittest.TestCase):

    def _testMSB(self):
        self.assertEquals(15, fte.bit_ops.msb(0xFF, 4))
        self.assertEquals(0xFFFFFFFFFFFFFFFF,
                          fte.bit_ops.msb(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
                                          4 * 16))
        self.assertEquals(15, fte.bit_ops.msb(0xFFFFFFFFFFFFFFFFF, 4))
        self.assertEquals(15, fte.bit_ops.msb(0xF0000000000000000, 4))

    def _testLSB(self):
        self.assertEquals(15, fte.bit_ops.lsb(0xFF, 4))
        self.assertEquals(0xFFFFFFFFFFFFFFFF,
                          fte.bit_ops.lsb(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
                                          4 * 16))
        self.assertEquals(15, fte.bit_ops.lsb(0xFFFFFFFFFFFFFFFFF, 4))
        self.assertEquals(15, fte.bit_ops.lsb(15, 4))

    def testLTB(self):
        self.assertEquals(fte.bit_ops.long_to_bytes(0xff), '\xFF')
        self.assertEquals(fte.bit_ops.bytes_to_long('\xFF'), 0xff)

    def testLTB2(self):
        for i in range(2 ** 10):
            N = random.randint(0, 1 << 1024)
            M = fte.bit_ops.long_to_bytes(N)
            M = fte.bit_ops.bytes_to_long(M)
            self.assertEquals(N, M)

    def testLTB3(self):
        for i in range(2 ** 10):
            N = random.randint(0, 1 << 1024)
            M = fte.bit_ops.long_to_bytes(N, 1024)
            self.assertEquals(1024, len(M))
            M = fte.bit_ops.bytes_to_long(M)
            self.assertEquals(N, M)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(Tests))
    return suite
