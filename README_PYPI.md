# libfte

[![PyPI version](https://img.shields.io/pypi/v/fte.svg)](https://pypi.org/project/fte/)
[![Tests](https://github.com/kpdyer/libfte/actions/workflows/test.yml/badge.svg)](https://github.com/kpdyer/libfte/actions/workflows/test.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Format-Transforming Encryption**: encrypt data so the ciphertext matches any format you specify.

## What is FTE?

Unlike standard encryption that produces random-looking output, FTE produces ciphertext that looks like whatever format you specify (via a regular expression, or any `RankedFormat` provider you supply), so it can look like hex strings, alphanumeric tokens, any language a regex can denote, or a custom format of your own.

> **One engine.** libfte encrypts through a single path: `fte.FTE` over a
> `RankedFormat` provider. Pass a `format` and a 32-byte `key`, then call
> `encrypt` / `decrypt`. `fte.RegexFormat` is the built-in provider; supply your
> own `RankedFormat` for any other covertext language. The wire format changed
> in 0.4.0 and is not compatible with libfte 0.3.x and earlier.

## Installation

```bash
pip install fte
```

Works out of the box with pure Python, no compilation required.

## Quick Example

Encrypt a secret so the ciphertext looks like words:

```python
import os
import fte

key = os.urandom(32)  # 32 bytes, shared by both endpoints

# Pick a covertext format, then build a cipher over it and the key.
word_format = fte.RegexFormat(r'^([a-z]+ )+[a-z]+$', length=80)
cipher = fte.FTE(output_format=word_format, key=key)

ciphertext = cipher.encrypt(b'Attack at dawn')
print(ciphertext.decode())
# → "a kgxbpxy vpgdigzczzkwlgmapocgjzspnqzilpyhezdbtxalonocvhlpc bbtflzgxhjjjpvmmnvvu"

plaintext = cipher.decrypt(ciphertext)
# → b'Attack at dawn'
```

`RegexFormat` also takes a `min_length`/`max_length` range for variable-length
covertext; a fixed `length` is the special case where they are equal.

### Ranked-Format Providers

`FTE` accepts any object implementing the structural `RankedFormat` protocol:
reversible `rank()` and `unrank()` methods. Providers need no inheritance,
registration, or runtime dependency on libfte:

```python
import secrets

import fte


class DecimalText:
    def rank(self, value: str, /) -> int:
        if not value.isascii() or not value.isdigit():
            raise ValueError("not canonical decimal text")
        if value != "0" and value.startswith("0"):
            raise ValueError("not canonical decimal text")
        return int(value)

    def unrank(self, index: int, /) -> str:
        if type(index) is not int or index < 0:
            raise ValueError("invalid rank")
        return str(index)

shared_32_byte_key = secrets.token_bytes(32)
cipher = fte.FTE(output_format=DecimalText(), key=shared_32_byte_key)
covertext: str = cipher.encrypt(b"secret")
assert cipher.decrypt(covertext) == b"secret"
```

The key and exact ranked-format ordering must match at both endpoints. Generic
FTE framing exposes plaintext length through the rank and guarantees membership
in the format's language, not a uniform distribution over unused format
capacity.

## Use Cases

- **Protocol obfuscation**: Make encrypted traffic look like benign data
- **Bypassing filters**: Evade systems that block encrypted-looking content
- **Constrained fields**: Confine ciphertext to a required character set or field shape, such as an alphanumeric account token or a fixed-width record field

## Documentation

Full docs and examples: [github.com/kpdyer/libfte](https://github.com/kpdyer/libfte)

## Reference

Based on [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf) (ACM CCS 2013).

## License

MIT
