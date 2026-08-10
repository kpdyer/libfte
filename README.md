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

## Benchmarks

The repository ships with [`benchmark.py`](benchmark.py), a self-contained script
that measures the two costs that matter in practice:

- **Encoder construction** — the one-time cost of compiling a regex into a DFA.
- **`encode()` / `decode()`** — the per-message cost, dominated by the DFA
  rank/unrank over large integers. This scales with `fixed_slice` (the output
  length), *not* with the plaintext size.

It runs across the built-in formats (binary, hex, alphanumeric, words, URLs) and
sweeps `fixed_slice` to show how per-message cost scales. It also records the
**CPU / OS / Python** it ran on (absolute numbers only mean something next to
the hardware), and when the C++ extension is built it runs **both backends** and
reports the speed-up. Every timed round-trip is verified, so a clean run also
serves as a correctness check.

```bash
# Auto: compares Python vs. native C++ when the extension is built,
# otherwise runs pure Python only
python benchmark.py

# Faster run: fewer iterations, skip the fixed_slice sweep
python benchmark.py --quick

# Force a single backend
python benchmark.py --backend python
python benchmark.py --backend native
```

To enable the Python-vs-C++ comparison, build the native extension first (see
[Optional: Native Extension](#optional-native-extension)):

```bash
FTE_BUILD_NATIVE=1 pip install --force-reinstall -e .
```

Example output (Apple M3 Pro, both backends):

```
CPU     : Apple M3 Pro
Cores   : 12 physical / 12 logical
Arch    : arm64
OS      : macOS-26.6.1-arm64-arm-64bit-Mach-O
Python  : 3.14.6 (CPython)
libfte  : 0.2.1

Per-format encode/decode
Format         slice bits/ch   py-enc   na-enc  enc x   py-dec   na-dec  dec x   ok
-----------------------------------------------------------------------------------
Binary           512    1.00    0.097    0.040   2.4x    0.089    0.036   2.5x  yes
Hex              256    4.00    0.087    0.032   2.7x    0.063    0.033   1.9x  yes
URL path         128    4.48    0.151    0.035   4.3x    0.113    0.032   3.5x  yes

Per-message scaling vs. fixed_slice (regex ^[a-z]+$)
fixed_slice    cap(b)   py-enc   na-enc  enc x   py-dec   na-dec  dec x
-----------------------------------------------------------------------
256              1202    0.095    0.038   2.5x    0.065    0.032   2.0x
1024             4812    0.838    0.106   7.9x    0.388    0.076   5.1x
2048             9625    2.922    0.242  12.1x    1.159    0.169   6.9x
```

The native advantage grows with `fixed_slice`, since larger outputs mean larger
integers where GMP's arithmetic dominates. Use `python benchmark.py --help` for
all options.

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
