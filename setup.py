#!/usr/bin/env python

# This file is part of libfte.
#
# libfte is free software: you can resetuptools it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# libfte is setuptoolsd in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libfte.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup
from setuptools import Extension
from setuptools.command.build_py import build_py as DistutilsBuild
from setuptools.command.install import install as DistutilsInstall

import glob
import sys
import os

def do_pre_build_py_stuff():
    os.system('make libre2.a')

def do_post_build_py_stuff():
    pass

def do_pre_install_stuff():
    os.system('make libre2.a')

def do_post_install_stuff():
    pass

class FTEBuild(DistutilsBuild):
    def run(self):
        do_pre_install_stuff()
        DistutilsBuild.run(self)
        do_post_install_stuff()

class FTEInstall(DistutilsInstall):
    def run(self):
        do_pre_install_stuff()
        DistutilsInstall.run(self)
        do_post_install_stuff()

if os.name == 'nt':
    libraries = ['gmp.dll', 'gmpxx.dll']
else:
    libraries = ['gmp', 'gmpxx']

fte_cDFA = Extension('fte.cDFA',
                     include_dirs=['fte',
                                   'thirdparty/re2',
                                   'thirdparty/gmp/include',
                                   ],
                     library_dirs=['thirdparty/re2/obj',
                                   'thirdparty/gmp/lib',
                                   ],
                     extra_compile_args=['-O3',
                                         '-fPIE',
                                         ],
                     extra_link_args=['thirdparty/re2/obj/libre2.a',
                                      '-Wl,-undefined,dynamic_lookup',
                                      ],
                     libraries=libraries,
                     sources=['fte/rank_unrank.cc', 'fte/cDFA.cc'])

with open('fte/VERSION') as fh:
    LIBFTE_RELEASE = fh.read().strip()

with open('README') as fh:
    long_description = fh.read()

setup(name='fte',
      data_files=[('fte',['fte/VERSION'])],
      test_suite = 'fte.tests.suite',
      version=LIBFTE_RELEASE,
      description='Format-Transforming Encryption',
      long_description=long_description,
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/kpdyer/libfte',
      ext_modules=[fte_cDFA],
      packages=['fte'],
      cmdclass={'build_py': FTEBuild,
                'install': FTEInstall},
      )
