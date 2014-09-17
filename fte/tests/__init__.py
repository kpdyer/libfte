#!/usr/bin/env python
# -*- coding: utf-8 -*-



import unittest
import test_bit_ops
import test_encoder
import test_encrypter


def suite():
    suite = unittest.TestSuite()
    suite.addTests(test_bit_ops.suite())
    suite.addTests(test_encoder.suite())
    suite.addTests(test_encrypter.suite())
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
