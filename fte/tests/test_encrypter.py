#!/usr/bin/env python
# -*- coding: utf-8 -*-



import unittest
import random

import fte.encrypter

TRIALS = 2 ** 8


class Tests(unittest.TestCase):

    def setUp(self):
        self.encrypter = fte.encrypter.Encrypter()

    def testEncryptNoOp(self):
        for i in range(TRIALS):
            C = self.encrypter.encrypt('')
            for j in range(10):
                self.assertEquals(self.encrypter.decrypt(C), '')

    def testEncryptDecrypt_1(self):
        for i in range(TRIALS):
            P = 'X' * i
            C = self.encrypter.encrypt(P)
            self.assertNotEqual(C, P)
            for j in range(1):
                self.assertEquals(P, self.encrypter.decrypt(C))

    def testEncryptDecrypt_2(self):
        for i in range(TRIALS):
            P = '\x01' * 2 ** 15
            C = self.encrypter.encrypt(P)
            self.assertNotEqual(C, P)
            for j in range(1):
                self.assertEquals(P, self.encrypter.decrypt(C))

    def testEncryptDecryptOneBlock(self):
        for i in range(TRIALS):
            M1 = random.randint(0, (1 << 128) - 1)
            M1 = fte.bit_ops.long_to_bytes(M1, 16)
            retval = self.encrypter.encryptOneBlock(M1)
            H_out = self.encrypter.decryptOneBlock(retval)
            self.assertEquals(M1, H_out)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(Tests))
    return suite
