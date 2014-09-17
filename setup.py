#!/usr/bin/env python

from setuptools import setup
from setuptools import Extension
from setuptools.command.build_py import build_py as DistutilsBuild
from setuptools.command.install import install as DistutilsInstall

import glob
import sys
import os

if os.name == 'nt':
    libraries = ['gmp.dll']
else:
    libraries = ['gmp']

fte_cDFA = Extension('fte.cDFA',
                     include_dirs=['fte',
                                   ],
                     extra_compile_args=['-O3',
                                         '-fPIC',
                                         ],
                     libraries=libraries,
                     sources=['fte/rank_unrank.cc', 'fte/cDFA.cc'])

with open('fte/VERSION') as fh:
    LIBFTE_RELEASE = fh.read().strip()

with open('README') as fh:
    long_description = fh.read()

setup(name='fte',
      install_requires=['pycrypto'],
      package_data = {'fte': ['VERSION']},
      test_suite = 'fte.tests.suite',
      version=LIBFTE_RELEASE,
      description='Format-Transforming Encryption',
      long_description=long_description,
      author='Kevin P. Dyer',
      author_email='kpdyer@gmail.com',
      url='https://github.com/kpdyer/libfte',
      ext_modules=[fte_cDFA],
      packages=['fte'],
      )
