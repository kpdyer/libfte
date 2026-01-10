# libfte

[![PyPI version](https://img.shields.io/pypi/v/fte.svg)](https://pypi.org/project/fte/)
[![Tests](https://github.com/kpdyer/libfte/actions/workflows/test.yml/badge.svg)](https://github.com/kpdyer/libfte/actions/workflows/test.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Format-Transforming Encryption (FTE) transforms ciphertext to match arbitrary formats specified by regular expressions. Unlike standard encryption that produces random-looking output, FTE produces ciphertext that looks like whatever format you specify—hexadecimal strings, alphanumeric tokens, or any pattern expressible as a regex.

This is useful for:
- **Protocol obfuscation**: Make encrypted traffic look like benign data
- **Bypassing filters**: Evade systems that block encrypted-looking content
- **Steganography**: Hide data in plain sight within expected formats

Based on the paper [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf) (CCS 2013).

## Installation

```bash
pip install fte
```

Works out of the box with pure Python—no compilation required.

## Quick Example

Encrypt a secret message so the ciphertext looks like words:

```python
import fte

# Create encoder: output will be lowercase "words" with spaces
encoder = fte.Encoder(regex=r'^([a-z]+ )+[a-z]+$', fixed_slice=80)

# Encrypt
ciphertext = encoder.encode(b'Attack at dawn')
print(ciphertext.decode())
# → "kqpvx mzbjw tnrdc fyhls wqaem xocgi znvub pdkry lfstj bhwce"

# Decrypt
plaintext, _ = encoder.decode(ciphertext)
# → b'Attack at dawn'
```

The ciphertext looks like random text, but contains your encrypted message.

## More Examples

### URL Paths
Make ciphertext look like website URLs:

```python
encoder = fte.Encoder(regex=r'^/[a-z]+/[a-z]+\.html$', fixed_slice=64)
ciphertext = encoder.encode(b'secret')
# → "/hsdxanghqvdhb/pvzvdsrpnjktdhnewdfhehaftajibecrluewdyrbekwh.html"
```

### URL Slugs
Make ciphertext look like hyphenated slugs:

```python
encoder = fte.Encoder(regex=r'^[a-z]+-[a-z]+-[a-z]+$', fixed_slice=48)
ciphertext = encoder.encode(b'secret')
# → "dxosmywnpyjuarsfvcado-o-smdsyvovfnnsgzhzelpujnya"
```

### Alphanumeric Tokens
Make ciphertext look like API keys or session tokens:

```python
encoder = fte.Encoder(regex='^[A-Za-z0-9]+$', fixed_slice=64)
ciphertext = encoder.encode(b'secret')
# → "Kj8mNp2xQw4yLr9vBn3cHt6sFg0dAe5iUo7lMz1bXk..."
```

### One-liner Convenience Functions

```python
ciphertext = fte.encode(b'secret', regex='^[a-z]+$', fixed_slice=128)
plaintext, _ = fte.decode(ciphertext, regex='^[a-z]+$', fixed_slice=128)
```

See the [`examples/`](examples/) directory for more use cases.

## Optional: Native Extension

For ~3x better performance, install GMP and enable the native extension:

```bash
# Install GMP
sudo apt-get install libgmp-dev  # Ubuntu/Debian
brew install gmp                  # macOS

# Rebuild with native extension
FTE_BUILD_NATIVE=1 pip install --force-reinstall fte

# Enable at runtime
export FTE_USE_NATIVE=1
```

## API Reference

### `fte.Encoder`

The main class for FTE encoding/decoding.

```python
fte.Encoder(regex: str, fixed_slice: int, key: bytes = None)
```

| Parameter | Description |
|-----------|-------------|
| `regex` | Regular expression defining output format |
| `fixed_slice` | Length of formatted output |
| `key` | Optional 32-byte key (random if not provided) |

**Methods:**

| Method | Description |
|--------|-------------|
| `encode(plaintext: bytes) -> bytes` | Encrypt and format plaintext |
| `decode(ciphertext: bytes) -> (bytes, bytes)` | Decrypt, returns (plaintext, remainder) |
| `capacity` | Property: bits of data that fit in `fixed_slice` |

### Convenience Functions

```python
fte.encode(plaintext, regex='^[a-z]+$', fixed_slice=256, key=None)
fte.decode(ciphertext, regex='^[a-z]+$', fixed_slice=256, key=None)
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `FTE_USE_NATIVE=1` | Use C++ extension at runtime |
| `FTE_BUILD_NATIVE=1` | Build C++ extension during install |

## How It Works

1. **Encryption**: Your plaintext is encrypted with AES-CTR and authenticated with HMAC-SHA512
2. **Ranking**: The ciphertext (an integer) is converted to a string in the regular language using a DFA ranking algorithm
3. **Output**: The result is a string matching your regex that encodes your encrypted data

The capacity depends on your regex—more symbols means more bits per character:

| Format | Regex | Bits/char |
|--------|-------|-----------|
| Binary | `^[01]+$` | 1.0 |
| Hex | `^[0-9a-f]+$` | 4.0 |
| Alphanumeric | `^[A-Za-z0-9]+$` | 5.95 |

## References

[1] [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf)
    Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart and Thomas Shrimpton
    ACM CCS 2013

## License

MIT License - see [LICENSE](LICENSE) for details.
