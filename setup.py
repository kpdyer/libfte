#!/usr/bin/env python
"""Setup script for libfte - Format-Transforming Encryption library."""

from setuptools import setup, Extension
import os
import subprocess
import sys


def get_gmp_paths():
    """Find GMP include and library directories."""
    include_dirs = ['fte']
    library_dirs = []
    
    # Check for Homebrew on macOS
    if sys.platform == 'darwin':
        try:
            # Try to get Homebrew prefix
            result = subprocess.run(
                ['brew', '--prefix', 'gmp'],
                capture_output=True, text=True, check=True
            )
            gmp_prefix = result.stdout.strip()
            include_dirs.append(os.path.join(gmp_prefix, 'include'))
            library_dirs.append(os.path.join(gmp_prefix, 'lib'))
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to common Homebrew locations
            for prefix in ['/opt/homebrew', '/usr/local']:
                inc = os.path.join(prefix, 'include')
                lib = os.path.join(prefix, 'lib')
                if os.path.exists(os.path.join(inc, 'gmp.h')):
                    include_dirs.append(inc)
                    library_dirs.append(lib)
                    break
    
    # Also check thirdparty directory (for bundled GMP)
    if os.path.exists('thirdparty/gmp/include'):
        include_dirs.append('thirdparty/gmp/include')
        library_dirs.extend(['thirdparty/gmp/bin', 'thirdparty/gmp/lib'])
    
    # Check standard system paths
    for inc_path in ['/usr/include', '/usr/local/include']:
        if os.path.exists(os.path.join(inc_path, 'gmp.h')):
            if inc_path not in include_dirs:
                include_dirs.append(inc_path)
    
    return include_dirs, library_dirs


if os.name == 'nt':
    libraries = ['gmp.dll']
else:
    libraries = ['gmp', 'gmpxx']

# Platform-specific compiler flags
extra_compile_args = ['-O3', '-fPIC', '-std=c++11']
extra_link_args = []

if sys.platform == 'darwin':
    extra_link_args = ['-Wl,-undefined,dynamic_lookup']

include_dirs, library_dirs = get_gmp_paths()

fte_cDFA = Extension(
    'fte.cDFA',
    include_dirs=include_dirs,
    extra_compile_args=extra_compile_args,
    library_dirs=library_dirs,
    extra_link_args=extra_link_args,
    libraries=libraries,
    sources=['fte/rank_unrank.cc', 'fte/cDFA.cc']
)

with open('fte/_version.txt') as fh:
    LIBFTE_RELEASE = fh.read().strip()

with open('README.md', encoding='utf-8') as fh:
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
    python_requires='>=3.8',
    install_requires=[
        'pycryptodome>=3.9.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0',
            'pytest-cov',
        ],
    },
    package_data={'fte': ['_version.txt']},
    test_suite='fte.tests',
    ext_modules=[fte_cDFA],
    packages=['fte', 'fte.tests'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: C++',
        'Topic :: Security :: Cryptography',
    ],
)
