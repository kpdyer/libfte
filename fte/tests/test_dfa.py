#!/usr/bin/env python
# -*- coding: utf-8 -*-




import unittest
import random

import fte.dfa

NUM_TRIALS = 2 ** 8

MAX_LEN = 256
_regexs = [
    '^\C+$',
    '^(0|1)+$',
    '^(A|B)+$',
    '^(acat|adog)+$',
]


class Tests(unittest.TestCase):

    def testUnrankRank(self):
        for regex in _regexs:
            dfa = fte.dfa.from_regex(regex, MAX_LEN)
            for i in range(NUM_TRIALS):
                N = random.randint(0, (1 << dfa.getCapacity()))
                X = dfa.unrank(N)
                M = dfa.rank(X)
                self.assertEquals(N, M)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(Tests))
    return suite
