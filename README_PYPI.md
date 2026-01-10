# libfte

[![Tests](https://github.com/kpdyer/libfte/actions/workflows/test.yml/badge.svg)](https://github.com/kpdyer/libfte/actions/workflows/test.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Format-Transforming Encryption (FTE) library for Python.

FTE allows you to encrypt data such that the ciphertext matches a specified regular expression format. This is useful for protocol obfuscation and bypassing Deep Packet Inspection (DPI) systems.

## Installation

```bash
pip install fte
```

Works out of the box with pure Python. No external dependencies required!

### Optional: Native Extension

For better performance, install GMP and enable native mode:

```bash
# Install GMP
sudo apt-get install libgmp-dev  # Ubuntu/Debian
brew install gmp                  # macOS

# Rebuild with native extension
FTE_BUILD_NATIVE=1 pip install --force-reinstall fte

# Enable at runtime
export FTE_USE_NATIVE=1
```

## Quick Start

```python
import regex2dfa
import fte.encoder

# Define format as regex
regex = '^(a|b)+$'
fixed_slice = 512

# Convert regex to DFA
dfa = regex2dfa.regex2dfa(regex)

# Create encoder and encrypt
fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)
ciphertext = fteObj.encode(b'secret message')

# Decrypt
plaintext, remainder = fteObj.decode(ciphertext)
```

The ciphertext will be a 512-character string of only `a` and `b` characters.

## Features

- **Pure Python**: Works without any C dependencies
- **Optional Native Extension**: C++/GMP for better performance
- **Format-Transforming Encryption**: Encrypt data to match any regular expression
- **Authenticated Encryption**: AES-CTR + HMAC-SHA512
- **Python 3.8+**: Modern Python with type hints

## Documentation

Full documentation: [GitHub](https://github.com/kpdyer/libfte)

## References

Based on [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf) (CCS 2013).

## License

MIT License
