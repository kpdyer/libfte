# libfte Examples

This directory contains examples demonstrating various features of the libfte library.

## Prerequisites

```bash
pip install fte
```

## Examples

| File | Description |
|------|-------------|
| `01_basic_usage.py` | Simple encrypt/decrypt roundtrip |
| `02_custom_keys.py` | Using custom encryption keys |
| `03_hex_format.py` | Encrypting data into hexadecimal strings |
| `04_alphanumeric_format.py` | Creating token-like ciphertexts |
| `05_word_based_format.py` | Pronounceable word patterns |
| `06_capacity_calculation.py` | Understanding language capacity |
| `10_error_handling.py` | Proper exception handling |
| `11_multiple_messages.py` | Parsing a stream of fixed-length covertexts |
| `12_custom_format.py` | Writing your own `RankedFormat` provider |

## Running Examples

```bash
python examples/01_basic_usage.py
```

## Quick Start

One engine, `fte.FTE`, encrypts through a ranked-format provider. `fte.RegexFormat`
is the built-in one:

```python
import os
import fte

key = os.urandom(32)  # 32-byte key, shared by both endpoints
cipher = fte.FTE(format=fte.RegexFormat('^[0-9a-f]+$', length=128), key=key)

ciphertext = cipher.encrypt(b'secret message')
plaintext = cipher.decrypt(ciphertext)
```

To target a covertext language regex can't describe, supply your own
`RankedFormat` (see `12_custom_format.py`).

## Choosing a Format

| Format | Regex | Bits/char | Use case |
|--------|-------|-----------|----------|
| Binary | `^[01]+$` | 1.0 | Minimal alphabet |
| Hex | `^[0-9a-f]+$` | 4.0 | Log files, debugging |
| Alphanumeric | `^[A-Za-z0-9]+$` | 5.95 | Tokens, IDs |
| Lowercase | `^[a-z]+$` | 4.7 | Simple text |

## Tips

1. **Larger `length`** = more capacity but longer covertext
2. **More symbols in regex** = more bits per character
3. **Each `RegexFormat` covertext is exactly `length` bytes**: slice a stream into fixed-size chunks
4. **Pass an explicit `key`** so both endpoints share the same one
