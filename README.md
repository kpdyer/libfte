# libfte

[![PyPI version](https://img.shields.io/pypi/v/fte.svg)](https://pypi.org/project/fte/)
[![Tests](https://github.com/kpdyer/libfte/actions/workflows/test.yml/badge.svg)](https://github.com/kpdyer/libfte/actions/workflows/test.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Format-transforming encryption (FTE) encrypts data into a chosen format, such
as hexadecimal strings, alphanumeric tokens, or a language defined by a regular
expression. Custom providers can target other formats through reversible
`rank()` and `unrank()` methods.

One engine, `fte.FTE`, supports randomized authenticated encryption and
FF1 format-preserving encryption (FPE).

## Installation

Requires Python 3.10 or later:

```bash
python -m pip install fte
```

libfte is pure Python. Its dependencies are `cryptography` for AES-CTR,
`regex2dfa` for regex compilation, and `libffx` for FF1. No compiler is needed
on platforms with prebuilt `cryptography` wheels.

## Authenticated encryption

Choose an output format and share a 32-byte key between endpoints:

```python
import os
import fte

key = os.urandom(32)
words = fte.RegexFormat(r"^([a-z]+ )+[a-z]+$", length=73)
cipher = fte.FTE(output_format=words, key=key)

covertext = cipher.encrypt(b"Attack at dawn")
print(covertext.decode())  # 73 lowercase letters and spaces; varies per call
assert cipher.decrypt(covertext) == b"Attack at dawn"
```

The default cipher, `aes-ctr-hmac`, authenticates each message and adds 29 bytes
before formatting. This format holds up to 15 plaintext bytes, reported by
`cipher.max_plaintext_bytes`. Oversized messages and invalid covertexts are
rejected.

For variable-length covertext, use `min_length` and `max_length` instead of
`length`. For example, `fte.RegexFormat(r"^[a-z]+$", min_length=40,
max_length=400)` produces matching strings within that range.

## Format-preserving encryption

Use the same finite format on both sides and select `cipher="ff1"` explicitly:

```python
import os
import fte

digits = fte.RegexFormat(r"^[0-9]+$", length=9)
cipher = fte.FTE(
    input_format=digits, output_format=digits, key=os.urandom(16), cipher="ff1"
)

token = cipher.encrypt(b"100000042", tweak=b"account:42")
assert len(token) == 9 and token.isdigit()
assert cipher.decrypt(token, tweak=b"account:42") == b"100000042"
```

FF1 is deterministic and unauthenticated: repeated plaintext under the same
key and tweak gives the same ciphertext. Use distinct per-record tweaks to
separate records, and never reuse an authenticated-encryption key for FF1.
Deterministic formats must contain at least one million values per domain.
Both endpoints must use the same regex text and length bounds: equivalent
patterns can have different fingerprints and therefore different FF1 tweaks.

Two different finite formats can also be connected with explicit `cipher="ff1"`;
see the [deterministic FTE example](https://github.com/kpdyer/libfte/blob/master/examples/11_deterministic_fte.py).

## Limits and compatibility

- For bytes input, the default plaintext limit is 1 MiB, reduced further by a
  finite output's capacity. An explicit `max_plaintext_bytes` can adjust the
  resource limit; see the [API reference](https://github.com/kpdyer/libfte/blob/master/docs/api.md#plaintext-limits).
- Authenticated FTE reveals plaintext byte length through the covertext's rank.
  It guarantees format membership, not a uniform distribution over the format.
  Excess capacity can produce long runs of leading zeros or other low-ranked
  symbols; choose a length close to what the message needs.
- Treat patterns and length bounds as trusted configuration. Keep each
  covertext intact: normalization, editing, or concatenation changes its rank.
- Version 0.4.x uses a different wire format from 0.3.x and earlier. Both
  endpoints must use compatible versions and ranked-format orderings.

See the [security model and reporting policy](https://github.com/kpdyer/libfte/blob/master/SECURITY.md)
for key usage, nonce limits, and decryption behavior.

## Documentation

- [API reference](https://github.com/kpdyer/libfte/blob/master/docs/api.md)
- [Regex syntax and choosing a length](https://github.com/kpdyer/libfte/blob/master/fte/formats/regex/README.md)
- [Writing a format provider](https://github.com/kpdyer/libfte/blob/master/docs/formats.md)
- [Runnable examples](https://github.com/kpdyer/libfte/tree/master/examples)
- [Benchmarks](https://github.com/kpdyer/libfte/blob/master/docs/performance.md)
- [Development and building](https://github.com/kpdyer/libfte/blob/master/BUILDING.md)

## References

Based on [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf)
(CCS 2013) and [LibFTE: A Toolkit for Constructing Practical, Format-Abiding Encryption Schemes](https://kpdyer.com/publications/usenix2014-fte.pdf)
(USENIX Security 2014).

[MIT License](https://github.com/kpdyer/libfte/blob/master/LICENSE).
