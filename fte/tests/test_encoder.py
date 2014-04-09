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

import fte.encoder


class Tests(unittest.TestCase):

    def testRegexEncoderRequest(self):
        self.assertTrue(True)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(Tests))
    return suite
