# libfte Examples

This directory contains examples demonstrating various features of the libfte library.

## Prerequisites

```bash
pip install fte
```

## Examples

| File | Description |
|------|-------------|
| `01_basic_usage.py` | Simple encode/decode roundtrip |
| `02_custom_keys.py` | Using custom encryption keys |
| `03_hex_format.py` | Encoding data as hexadecimal strings |
| `04_alphanumeric_format.py` | Creating token-like ciphertexts |
| `05_word_based_format.py` | Pronounceable word patterns |
| `06_capacity_calculation.py` | Understanding language capacity |
| `10_error_handling.py` | Proper exception handling |
| `11_multiple_messages.py` | Encoding/decoding message streams |
| `12_convenience_functions.py` | One-liner encode/decode |

## Running Examples

```bash
python examples/01_basic_usage.py
```

## Quick Start

```python
import os
import fte

key = os.urandom(32)  # 32-byte key, shared by both endpoints
encoder = fte.Encoder(regex='^[0-9a-f]+$', fixed_slice=128, key=key)

ciphertext = encoder.encode(b'secret message')
plaintext, _ = encoder.decode(ciphertext)
```

Or use convenience functions:

```python
import os
import fte

key = os.urandom(32)
ciphertext = fte.encode(b'secret', regex='^[0-9a-f]+$', key=key)
plaintext, _ = fte.decode(ciphertext, regex='^[0-9a-f]+$', key=key)
```

## Choosing a Format

| Format | Regex | Bits/char | Use case |
|--------|-------|-----------|----------|
| Binary | `^[01]+$` | 1.0 | Minimal alphabet |
| Hex | `^[0-9a-f]+$` | 4.0 | Log files, debugging |
| Alphanumeric | `^[A-Za-z0-9]+$` | 5.95 | Tokens, IDs |
| Lowercase | `^[a-z]+$` | 4.7 | Simple text |

## Tips

1. **Larger `fixed_slice`** = more capacity but longer output
2. **More symbols in regex** = more efficient encoding
3. **Handle remainder** when decoding streams of concatenated covertexts
4. **Pass an explicit `key`** so both endpoints share the same one
