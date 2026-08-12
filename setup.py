#!/usr/bin/env python
"""Setup script for libfte - Format-Transforming Encryption library.

libfte is a pure Python package; no compilation or system libraries are
required.
"""

from setuptools import setup


with open('fte/_version.txt') as fh:
    LIBFTE_RELEASE = fh.read().strip()

with open('README_PYPI.md', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='fte',
    version=LIBFTE_RELEASE,
    description='Format-Transforming Encryption',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Kevin P. Dyer',
    author_email='kpdyer@gmail.com',
    url='https://github.com/kpdyer/libfte',
    license='MIT',
    python_requires='>=3.10',
    install_requires=[
        'pycryptodome>=3.9.0',
        'regex2dfa>=0.2.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0',
            'pytest-cov',
        ],
    },
    package_data={'fte': ['_version.txt']},
    test_suite='fte.tests',
    packages=['fte', 'fte.tests'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.14',
        'Topic :: Security :: Cryptography',
    ],
)
