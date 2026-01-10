#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test suite for the FTE library."""

import unittest

from fte.tests import test_bit_ops
from fte.tests import test_encoder
from fte.tests import test_encrypter


def suite():
    """Return the complete test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTests(test_bit_ops.suite())
    test_suite.addTests(test_encoder.suite())
    test_suite.addTests(test_encrypter.suite())
    return test_suite


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
