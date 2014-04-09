#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of fteproxy.
#
# fteproxy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# fteproxy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with fteproxy.  If not, see <http://www.gnu.org/licenses/>.

import unittest
import test_bit_ops
import test_cDFA
import test_dfa
import test_encoder
import test_encrypter


def suite():
    suite = unittest.TestSuite()
    suite.addTests(test_bit_ops.suite())
    suite.addTests(test_cDFA.suite())
    suite.addTests(test_dfa.suite())
    suite.addTests(test_encoder.suite())
    suite.addTests(test_encrypter.suite())
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
