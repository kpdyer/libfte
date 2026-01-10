# libfte Examples

This directory contains examples demonstrating various features of the libfte library.

## Prerequisites

```bash
pip install fte regex2dfa
```

## Examples

| File | Description |
|------|-------------|
| `01_basic_usage.py` | Simple encode/decode roundtrip |
| `02_custom_keys.py` | Using custom encryption and MAC keys |
| `03_hex_format.py` | Encoding data as hexadecimal strings |
| `04_alphanumeric_format.py` | Creating token-like ciphertexts |
| `05_word_based_format.py` | Pronounceable word patterns |
| `06_capacity_calculation.py` | Understanding language capacity |
| `07_deterministic_encoding.py` | Reproducible encoding with seeds |
| `08_large_messages.py` | Handling overflow for large data |
| `09_performance_comparison.py` | Benchmarking pure Python vs native |
| `10_error_handling.py` | Proper exception handling |
| `11_multiple_messages.py` | Encoding/decoding message streams |

## Running Examples

```bash
# Run a specific example
python examples/01_basic_usage.py

# Run with native extension (if GMP installed)
FTE_USE_NATIVE=1 python examples/09_performance_comparison.py
```

## Choosing a Format

The regex you choose affects:

1. **Capacity**: More symbols = more data per character
2. **Appearance**: What the ciphertext looks like
3. **Compatibility**: What systems will accept it

Common choices:

| Format | Regex | Bits/char | Use case |
|--------|-------|-----------|----------|
| Binary | `^[01]+$` | 1.0 | Minimal alphabet |
| Hex | `^[0-9a-f]+$` | 4.0 | Log files, debugging |
| Base64-like | `^[A-Za-z0-9+/]+$` | 6.0 | Data transfer |
| Alphanumeric | `^[A-Za-z0-9]+$` | 5.95 | Tokens, IDs |
| Lowercase | `^[a-z]+$` | 4.7 | Simple text |

## Tips

1. **Larger `fixed_slice`** = more capacity but longer output
2. **More symbols in regex** = more efficient encoding
3. **Use seeds** for deterministic/testable output
4. **Handle remainder** when decoding streams
