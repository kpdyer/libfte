#!/usr/bin/env python
"""Setup script for libfte - Format-Transforming Encryption library.

The C++ extension is optional and requires GMP library. If GMP is not
available, the package will still install with a pure Python implementation.

To force building the native extension, set FTE_BUILD_NATIVE=1.
To skip the native extension, set FTE_BUILD_NATIVE=0.
"""

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import os
import subprocess
import sys


class BuildExtOptional(build_ext):
    """Custom build_ext that makes C++ extension optional."""
    
    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception as e:
            print(f"\n*** WARNING: Failed to build C++ extension: {e}")
            print("*** The package will use pure Python implementation instead.")
            print("*** For better performance, install GMP library and rebuild.\n")


def get_gmp_paths():
    """Find GMP include and library directories."""
    include_dirs = ['fte']
    library_dirs = []
    gmp_found = False
    
    # Check for Homebrew on macOS
    if sys.platform == 'darwin':
        try:
            result = subprocess.run(
                ['brew', '--prefix', 'gmp'],
                capture_output=True, text=True, check=True
            )
            gmp_prefix = result.stdout.strip()
            gmp_header = os.path.join(gmp_prefix, 'include', 'gmp.h')
            if os.path.exists(gmp_header):
                include_dirs.append(os.path.join(gmp_prefix, 'include'))
                library_dirs.append(os.path.join(gmp_prefix, 'lib'))
                gmp_found = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Try common Homebrew locations
            for prefix in ['/opt/homebrew', '/usr/local']:
                gmp_header = os.path.join(prefix, 'include', 'gmp.h')
                if os.path.exists(gmp_header):
                    include_dirs.append(os.path.join(prefix, 'include'))
                    library_dirs.append(os.path.join(prefix, 'lib'))
                    gmp_found = True
                    break
    
    # Check standard system paths (Linux)
    for inc_path in ['/usr/include', '/usr/local/include']:
        gmp_header = os.path.join(inc_path, 'gmp.h')
        if os.path.exists(gmp_header):
            if inc_path not in include_dirs:
                include_dirs.append(inc_path)
            gmp_found = True
            break
    
    return include_dirs, library_dirs, gmp_found


def get_ext_modules():
    """Get extension modules list, empty if GMP not found or disabled."""
    # Check environment variable
    build_native = os.environ.get('FTE_BUILD_NATIVE', '').lower()
    
    if build_native == '0':
        print("*** Skipping C++ extension (FTE_BUILD_NATIVE=0)")
        return []
    
    include_dirs, library_dirs, gmp_found = get_gmp_paths()
    
    if not gmp_found and build_native != '1':
        print("*** GMP library not found, skipping C++ extension.")
        print("*** Install GMP and set FTE_BUILD_NATIVE=1 to build native extension.")
        return []
    
    if os.name == 'nt':
        libraries = ['gmp.dll']
    else:
        libraries = ['gmp', 'gmpxx']
    
    extra_compile_args = ['-O3', '-fPIC', '-std=c++11']
    extra_link_args = []
    
    if sys.platform == 'darwin':
        extra_link_args = ['-Wl,-undefined,dynamic_lookup']
    
    fte_cDFA = Extension(
        'fte.cDFA',
        include_dirs=include_dirs,
        extra_compile_args=extra_compile_args,
        library_dirs=library_dirs,
        extra_link_args=extra_link_args,
        libraries=libraries,
        sources=['fte/rank_unrank.cc', 'fte/cDFA.cc'],
        optional=True,
    )
    
    return [fte_cDFA]


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
    python_requires='>=3.8',
    install_requires=[
        'pycryptodome>=3.9.0',
        'regex2dfa>=0.2.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0',
            'pytest-cov',
        ],
        'native': [],  # Native extension (requires GMP)
    },
    package_data={'fte': ['_version.txt']},
    test_suite='fte.tests',
    ext_modules=get_ext_modules(),
    cmdclass={'build_ext': BuildExtOptional},
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
        'Topic :: Security :: Cryptography',
    ],
)
