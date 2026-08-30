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
| `03_regex_formats.py` | A gallery of regex covertext formats |
| `04_variable_length.py` | Variable-length covertext via `min_length`/`max_length` |
| `05_capacity_calculation.py` | Understanding format capacity |
| `06_error_handling.py` | Proper exception handling |
| `07_multiple_messages.py` | Parsing a stream of fixed-length covertexts |
| `08_custom_format.py` | Writing your own `RankedFormat` provider |
| `09_authenticated_fte.py` | Authenticated FTE (`aes-ctr-hmac`) over a non-bytes input format |

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
cipher = fte.FTE(output_format=fte.RegexFormat('^[0-9a-f]+$', length=128), key=key)

ciphertext = cipher.encrypt(b'secret message')
plaintext = cipher.decrypt(ciphertext)
```

To target a covertext language no regex denotes, supply your own
`RankedFormat` (see `08_custom_format.py`).

## Choosing a Format

See the [bits-per-character table](../README.md#how-it-works) in the main
README for how alphabet size drives capacity.

## Tips

1. **Larger `length`** = more capacity but longer covertext
2. **A larger alphabet in the pattern** = more bits per character
3. **A fixed-`length` covertext is exactly `length` bytes**, so a stream of
   them slices into fixed-size chunks; a `min_length`/`max_length` covertext
   varies in length with the message (see `04_variable_length.py`)
4. **Pass an explicit `key`** so both endpoints share the same one
