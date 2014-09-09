#!/usr/bin/env python
# -*- coding: utf-8 -*-




import os
import unittest

import fte.conf
import fte.cDFA


class Tests(unittest.TestCase):

    def testMakeDFA(self):
        base_dir = fte.conf.getValue('general.base_dir')
        for i in range(1, 6):
            regex_file = os.path.join(
                base_dir, 'fte/tests/dfas/test' + str(i) + '.regex')
            with open(regex_file) as fh:
                regex = fh.read()

            dfa_file = os.path.join(
                base_dir, 'fte/tests/dfas/test' + str(i) + '.dfa')
            with open(dfa_file) as fh:
                expected_fst = fh.read()

            actual_fst = fte.dfa._attFstFromRegex(regex)
            actual_fst = fte.dfa._attFstMinimize(actual_fst)

            self.assertEquals(actual_fst, expected_fst)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(Tests))
    return suite
