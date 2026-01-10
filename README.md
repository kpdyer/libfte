# libfte

[![Tests](https://github.com/kpdyer/libfte/actions/workflows/test.yml/badge.svg)](https://github.com/kpdyer/libfte/actions/workflows/test.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Format-Transforming Encryption (FTE) is a cryptographic primitive explored in the paper *Protocol Misidentification Made Easy with Format-Transforming Encryption* [1]. FTE allows a user to specify the format of their output ciphertexts using regular expressions. The libfte library implements the primitive presented in [1].

If you are interested in the *proxy system* that uses FTE to bypass DPI systems, please see [fteproxy](https://github.com/kpdyer/fteproxy).

## Installation

```bash
pip install fte
```

The library works out of the box with pure Python. No external dependencies required beyond `pycryptodome`.

### Optional: Native Extension for Performance

For better performance, install the GMP library and set `FTE_USE_NATIVE=1`:

```bash
# Install GMP (Ubuntu/Debian)
sudo apt-get install libgmp-dev

# Install GMP (macOS)
brew install gmp

# Rebuild with native extension
FTE_BUILD_NATIVE=1 pip install --force-reinstall fte

# Use native extension at runtime
export FTE_USE_NATIVE=1
```

## Example Usage

```python
import regex2dfa
import fte.encoder

regex = '^(a|b)+$'
fixed_slice = 512
input_plaintext = b'test'

dfa = regex2dfa.regex2dfa(regex)
fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)

ciphertext = fteObj.encode(input_plaintext)
output_plaintext, remainder = fteObj.decode(ciphertext)

print(f'input_plaintext={input_plaintext}')
print(f'ciphertext={ciphertext[:16]}...{ciphertext[-16:]}')
print(f'output_plaintext={output_plaintext}')
```

Output:
```
input_plaintext=b'test'
ciphertext=b'aaaaaaaabaaaaaba'...b'aabbbbbbbbaababb'
output_plaintext=b'test'
```

## Configuration

| Environment Variable | Description |
|---------------------|-------------|
| `FTE_USE_NATIVE=1` | Use C++ extension (requires GMP) |
| `FTE_BUILD_NATIVE=1` | Build C++ extension during install |
| `FTE_BUILD_NATIVE=0` | Skip C++ extension during install |

Check which implementation is active:

```python
from fte.dfa import using_native
print(f"Using native extension: {using_native()}")
```

## API Reference

### `fte.encoder.DfaEncoder`

The main class for FTE encoding/decoding.

```python
DfaEncoder(dfa: str, fixed_slice: int, K1: bytes = None, K2: bytes = None)
```

- `dfa`: DFA specification in AT&T FST format
- `fixed_slice`: Length of encoded output strings
- `K1`: Optional 16-byte encryption key
- `K2`: Optional 16-byte MAC key

Methods:
- `encode(plaintext: bytes, seed: bytes = None) -> bytes`: Encode plaintext
- `decode(ciphertext: bytes) -> tuple[bytes, bytes]`: Decode to (plaintext, remainder)
- `getCapacity() -> int`: Get the capacity in bits

### `fte.encrypter.Encrypter`

Authenticated encryption using AES-CTR + HMAC-SHA512.

```python
Encrypter(K1: bytes = None, K2: bytes = None)
```

Methods:
- `encrypt(plaintext: bytes) -> bytes`: Encrypt with 32-byte expansion
- `decrypt(ciphertext: bytes) -> bytes`: Decrypt and verify MAC

## Changelog

### v0.2.0 (2025)
- **Breaking**: Now requires Python 3.8+
- **Breaking**: All string inputs/outputs are now `bytes` instead of `str`
- **New**: Pure Python implementation (no GMP required by default)
- **New**: Optional C++ extension for performance (`FTE_USE_NATIVE=1`)
- Updated to use pycryptodome instead of deprecated pycrypto
- Optimized GMP bindings with binary integer conversion
- Added type hints throughout
- Added pyproject.toml for modern packaging

### v0.1.x
- Original Python 2.7 implementation (required GMP)

## References

[1] [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf)
    Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart and Thomas Shrimpton
    CCS 2013

## License

MIT License - see [LICENSE](LICENSE) for details.
