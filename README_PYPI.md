# libfte

[![Tests](https://github.com/kpdyer/libfte/actions/workflows/test.yml/badge.svg)](https://github.com/kpdyer/libfte/actions/workflows/test.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Format-Transforming Encryption (FTE) library for Python.

FTE allows you to encrypt data such that the ciphertext matches a specified regular expression format. This is useful for protocol obfuscation and bypassing Deep Packet Inspection (DPI) systems.

## Requirements

- Python 3.8+
- GMP library

### System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install libgmp-dev

# macOS
brew install gmp
```

## Installation

```bash
pip install fte
```

## Quick Start

```python
import regex2dfa
import fte.encoder

# Define a regex that matches strings of 'a' and 'b' characters
regex = '^(a|b)+$'
fixed_slice = 512

# Convert regex to DFA format
dfa = regex2dfa.regex2dfa(regex)

# Create encoder and encrypt
fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)
ciphertext = fteObj.encode(b'secret message')

# Decrypt
plaintext, remainder = fteObj.decode(ciphertext)
```

The ciphertext will be a 512-character string of only `a` and `b` characters, indistinguishable from valid strings in the regex language.

## Features

- **Format-Transforming Encryption**: Encrypt data to match any regular expression
- **Authenticated Encryption**: AES-CTR + HMAC-SHA512
- **High Performance**: Optimized C++ extension with GMP for arbitrary precision arithmetic
- **Python 3.8+**: Modern Python with type hints

## Documentation

Full documentation and API reference: [GitHub](https://github.com/kpdyer/libfte)

## References

Based on the paper [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf) (CCS 2013).

## License

MIT License
