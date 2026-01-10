# libfte

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
pip install fte regex2dfa
```

Works out of the box with pure Python—no compilation required.

## Quick Example

Encrypt a secret message so the ciphertext looks like a hex string:

```python
import regex2dfa
import fte.encoder

# Define the output format: only hex characters (0-9, a-f)
regex = '^[0-9a-f]+$'
output_length = 128

# Create encoder
dfa = regex2dfa.regex2dfa(regex)
encoder = fte.encoder.DfaEncoder(dfa, output_length)

# Encrypt
secret = b'Attack at dawn'
ciphertext = encoder.encode(secret)

print(f"Secret: {secret}")
print(f"Ciphertext: {ciphertext.decode()}")
# Output: Ciphertext: 8a3f2b1c9e7d4a6b0f5c8e2a1d9b7f3c4e6a8d0b2f5c9e1a3d7b4f6c8e0a2d5b...

# Decrypt
plaintext, _ = encoder.decode(ciphertext)
print(f"Decrypted: {plaintext}")
# Output: Decrypted: b'Attack at dawn'
```

The ciphertext is indistinguishable from random hex data, but contains your encrypted message.

## More Examples

### Alphanumeric Tokens
Make ciphertext look like API keys or session tokens:

```python
regex = '^[A-Za-z0-9]+$'
dfa = regex2dfa.regex2dfa(regex)
encoder = fte.encoder.DfaEncoder(dfa, 64)

ciphertext = encoder.encode(b'secret')
# Output: "Kj8mNp2xQw4yLr9vBn3cHt6sFg0dAe5iUo7lMz1bXk..."
```

### Binary Strings
For systems that only accept 0s and 1s:

```python
regex = '^[01]+$'
dfa = regex2dfa.regex2dfa(regex)
encoder = fte.encoder.DfaEncoder(dfa, 512)

ciphertext = encoder.encode(b'secret')
# Output: "0110100101011010110010110100101101..."
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

### `fte.encoder.DfaEncoder`

```python
DfaEncoder(dfa: str, fixed_slice: int, K1: bytes = None, K2: bytes = None)
```

| Parameter | Description |
|-----------|-------------|
| `dfa` | DFA specification (from `regex2dfa.regex2dfa()`) |
| `fixed_slice` | Length of formatted output |
| `K1` | 16-byte encryption key (random if not provided) |
| `K2` | 16-byte MAC key (random if not provided) |

**Methods:**

| Method | Description |
|--------|-------------|
| `encode(plaintext: bytes) -> bytes` | Encrypt and format plaintext |
| `decode(ciphertext: bytes) -> (bytes, bytes)` | Decrypt, returns (plaintext, remainder) |
| `getCapacity() -> int` | Bits of data that fit in `fixed_slice` |

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
