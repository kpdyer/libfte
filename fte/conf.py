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

import os
import sys


def getValue(key):
    return conf[key]


def setValue(key, value):
    conf[key] = value


def we_are_frozen():
    # All of the modules are built-in to the interpreter, e.g., by py2exe
    return hasattr(sys, "frozen")


def module_path():
    if we_are_frozen():
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(__file__)


conf = {}


"""The base path for the location of the fte.* modules."""
if we_are_frozen():
    conf['general.base_dir'] = module_path()
else:
    conf['general.base_dir'] = os.path.join(module_path(), '..')


"""The path for fte *.json definition files."""
if we_are_frozen():
    conf['general.defs_dir'] = os.path.join(module_path(), 'fte', 'defs')
else:
    conf['general.defs_dir'] = os.path.join(module_path(), '..', 'fte', 'defs')


"""Our loglevel = 0|1|2"""
conf['runtime.loglevel'] = 1


"""The default AE scheme key."""
conf['runtime.fte.encrypter.key'] = 'FF' * 16 + '00' * 16
