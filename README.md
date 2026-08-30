# libfte

[![PyPI version](https://img.shields.io/pypi/v/fte.svg)](https://pypi.org/project/fte/)
[![Tests](https://github.com/kpdyer/libfte/actions/workflows/test.yml/badge.svg)](https://github.com/kpdyer/libfte/actions/workflows/test.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Format-Transforming Encryption (FTE) transforms ciphertext to match a target format: one given by a regular expression, or by any *ranked-format* provider you supply. Unlike standard encryption that produces random-looking output, FTE produces ciphertext that looks like whatever format you specify: hexadecimal strings, alphanumeric tokens, any pattern expressible as a regex, or a custom format such as decimal text or a domain-specific grammar.

This is useful for:
- **Protocol obfuscation**: Make encrypted traffic look like benign data
- **Bypassing filters**: Evade systems that block encrypted-looking content
- **Constrained fields**: Confine ciphertext to a required character set or field shape, such as an alphanumeric account token or a fixed-width record field

Based on the paper [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf) (CCS 2013).

### One engine, two axes

There is a single engine, `fte.FTE`, that maps `rank_in -> transform ->
unrank_out`: it ranks a value of the input format to an integer, transforms
that integer, and unranks the result into the output format. Two independent
choices shape it:

- the **format pair**: `input_format` and `output_format` (the input defaults
  to raw bytes, `BytesFormat`); and
- the **cipher** on the integer in between: `"ae"` (randomized, authenticated,
  expanding: the classic AES-CTR + HMAC path) or `"ff1"` (deterministic,
  zero-expansion, format-preserving, via the optional
  [libffx](https://github.com/kpdyer/libffx) extra).

That gives a 2x2 of behaviors:

| cipher \ formats | `input == output` | `input != output` |
|---|---|---|
| **`ff1`** (deterministic, zero-expansion, unauthenticated) | **FPE**: re-encrypt a value in place, optionally length-preserving | **deterministic FTE**: a reversible rank map between two formats |
| **`ae`** (randomized, authenticated, expanding) | authenticated encryption over bytes | **classic FTE**: bytes hidden as a chosen covertext format |

**FPE is simply the equal-formats case**: pass the same format as
`input_format` and `output_format` and the deterministic cipher is inferred.

> The wire format changed in 0.4.0 and is **not** compatible with libfte 0.3.x
> and earlier. The `ff1` cipher is deterministic and **unauthenticated**: it
> leaks plaintext equality and is only as strong as the input space is large,
> so use per-record `tweak` values. Never reuse a key across the two ciphers.

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

The ciphertext looks like random text but contains your encrypted message.

For **format-preserving encryption**, use the same format on both sides. Equal
formats infer the deterministic `ff1` cipher (needs `pip install fte[fpe]`):

```python
digits = fte.RegexFormat(r'^[0-9]+$', length=9)   # a 9-digit language
fpe = fte.FTE(input_format=digits, output_format=digits,
              key=os.urandom(16), preserve_length=True)

token = fpe.encrypt(b'078051120', tweak=b'ssn')   # another 9-digit string
assert fpe.decrypt(token, tweak=b'ssn') == b'078051120'
```

## More Examples

The snippets below reuse a shared 32-byte `key = os.urandom(32)`.

### URL paths
```python
cipher = fte.FTE(output_format=fte.RegexFormat(r'^/[a-z]+/[a-z]+\.html$', length=96), key=key)
cipher.encrypt(b'secret')
# → "/hsdxanghqvdhb/pvzvdsrpnjktdhnewdfhehaftajibecrluewdyrbe...html"
```

### URL slugs
```python
cipher = fte.FTE(output_format=fte.RegexFormat(r'^[a-z]+-[a-z]+-[a-z]+$', length=80), key=key)
cipher.encrypt(b'secret')
# → "dxosmywnpyjuarsfvcado-osmdsyvovfnnsgzhzelpujnya-qfwbekwh..."
```

### Alphanumeric tokens
```python
cipher = fte.FTE(output_format=fte.RegexFormat('^[A-Za-z0-9]+$', length=64), key=key)
cipher.encrypt(b'secret')
# → "Kj8mNp2xQw4yLr9vBn3cHt6sFg0dAe5iUo7lMz1bXk..."
```

### Variable-length covertext
Give a `min_length`/`max_length` range instead of a fixed `length`, and the
covertext length varies with the message (`min_length == max_length` is the
fixed case):
```python
lowercase = fte.RegexFormat('^[a-z]+$', min_length=40, max_length=400)
cipher = fte.FTE(output_format=lowercase, key=key)
cipher.encrypt(b'secret')       # a lowercase string somewhere in 40..400 bytes
```

### Custom ranked-format providers

The `format` can be any structural `RankedFormat`: an object with reversible
`rank()` and `unrank()` methods. No inheritance, registration, or dependency
between libfte and the provider is required. `fte.RegexFormat` is just the
built-in one (see [`fte/formats/`](fte/formats/)):

```python
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

key = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
# Demonstration key only; load a securely shared secret in production.
cipher = fte.FTE(output_format=DecimalText(), key=key)

covertext: str = cipher.encrypt(b"secret")
plaintext = cipher.decrypt(covertext)

assert plaintext == b"secret"
```

`FTE` consumes and returns one complete covertext value per message. The two
endpoints must use the same key and a compatible ranked-format ordering. Treat
returned covertext as a canonical, atomic value: normalization or other edits
alter its rank.

See the [ranked-format provider API](docs/formats.md) for the complete provider
contract and a conformance checklist, and the [`examples/`](examples/) directory
for more use cases.

## API Reference

### `fte.FTE`

The engine. Maps a value of `input_format` to a value of `output_format` via
the chosen cipher.

```python
fte.FTE(
    *,
    input_format: RankedFormat = BytesFormat(),
    output_format: RankedFormat,
    key: bytes,
    cipher: str | object | None = None,   # "ae" | "ff1" | object | inferred
    preserve_length: bool = False,        # ff1, equal formats only
    max_plaintext_bytes: int | None = None,   # ae, bytes input only
    allow_small_domain: bool = False,     # ff1 domain floor 1e6 -> 100
)
```

| Member | Description |
|--------|-------------|
| `encrypt(plaintext, *, tweak=b"") -> T` | Rank the input, transform, unrank into a covertext (tweak: ff1 only) |
| `decrypt(covertext, *, tweak=b"") -> P` | Rank the covertext, invert the transform, unrank the plaintext |
| `input_format` / `output_format` | The two formats |
| `cipher` | Resolved mode: `"ae"` or `"deterministic"` |
| `preserve_length` | Whether ff1 permutes each length slice in place |
| `max_plaintext_bytes` | Largest plaintext accepted, ae only (see below) |

Key sizes: `"ae"` needs exactly 32 bytes (16 encryption + 16 MAC); `"ff1"`
needs 16/24/32. The `ff1` cipher requires the extra: `pip install fte[fpe]`.

`max_plaintext_bytes` is chosen for you when left unset: a finite format (one
with a `cardinality`, like `RegexFormat`) uses the exact size its capacity
allows, and an unbounded format falls back to a 1 MiB default. It is also the
guard that lets `decrypt` reject an oversized covertext cheaply, so set it
explicitly only to tighten that bound or to cap an unbounded format. When
messages may exceed the default, both endpoints should use the same value.

### `fte.RegexFormat`

The built-in `RankedFormat`: a byte language compiled from a regular expression.
Choose a fixed covertext length, or a `[min_length, max_length]` range for
variable-length covertext (`min_length == max_length` is the fixed case).

```python
fte.RegexFormat(pattern: str, *, length: int)                       # fixed
fte.RegexFormat(pattern: str, *, min_length: int, max_length: int)  # range
```

| Member | Description |
|--------|-------------|
| `pattern` | The regular expression |
| `min_length`, `max_length` | Covertext length bounds (equal for a fixed length) |
| `cardinality` | Number of matching words in the length range |
| `rank(value: bytes) -> int` | Rank of a canonical covertext value |
| `unrank(index: int) -> bytes` | The covertext value at `index` |

`length=N` is shorthand for `min_length=max_length=N`; pass either `length` or
the `min_length`/`max_length` pair, not both. Construction raises `ValueError`
if the language has no words in the requested length range.

### `fte.RankedFormat`

The extension protocol every provider implements:

```python
class RankedFormat(Protocol[T]):
    def rank(self, value: T, /) -> int: ...
    def unrank(self, index: int, /) -> T: ...
```

Formats must use contiguous non-negative ranks and satisfy
`rank(unrank(i)) == i` and `unrank(rank(value)) == value`. A finite provider may
additionally expose an exact positive `cardinality` attribute; libfte then
performs capacity checks before encryption.

## How It Works

1. **Encryption**: Your plaintext is encrypted with AES-CTR and authenticated with HMAC-SHA512
2. **Framing**: The ciphertext is mapped reversibly to a non-negative integer
3. **Formatting**: A built-in or custom ranked format maps that integer to covertext

The framing is variable-length. Anyone who can rank a covertext can infer its
exact plaintext byte length, even without the key. FTE guarantees membership in
the selected format, not a uniform distribution over every rank when the
provider offers more capacity than the message needs.

The capacity depends on your regex: more symbols means more bits per character:

| Format | Regex | Bits/char |
|--------|-------|-----------|
| Binary | `^[01]+$` | 1.0 |
| Hex | `^[0-9a-f]+$` | 4.0 |
| Alphanumeric | `^[A-Za-z0-9]+$` | 5.95 |

## Benchmarks

The repository ships with [`benchmark.py`](benchmark.py), a self-contained
script that measures the two costs that matter in practice:

- **Cipher construction**: the one-time cost of compiling a regex into a DFA
  and pre-computing the ranking tables.
- **`encrypt()` / `decrypt()`**: the per-message cost, dominated by the DFA
  rank/unrank over large integers. This scales with the covertext `length`,
  *not* with the plaintext size.

It runs across the built-in formats (binary, hex, alphanumeric, words, URLs),
sweeps `length` to show how per-message cost scales, and records the CPU /
OS / Python it ran on. Every timed round-trip is verified, so a clean run also
serves as a correctness check.

```bash
python benchmark.py            # full run
python benchmark.py --quick    # fewer iterations, skip the length sweep
```

Example output (Apple M3 Pro):

```
Per-format performance
Format          length  cap(bits)  bits/char   build(ms)  encrypt(ms)  decrypt(ms)
----------------------------------------------------------------------------------
Binary             512        512       1.00       0.24         0.098        0.087
Hex                256       1024       4.00       0.68         0.087        0.061
Alphanumeric       192       1143       5.95       1.79         0.076        0.053

Per-message scaling vs. length (regex ^[a-z]+$)
length   cap(bits)  encrypt(ms)  decrypt(ms)
--------------------------------------------
256           1203        0.095        0.059
2048          9626        3.076        1.198
```

Per-message cost grows super-linearly with `length`, since larger outputs
mean larger integers in the rank/unrank arithmetic. Use
`python benchmark.py --help` for all options.

## References

[1] [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf)
    Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart and Thomas Shrimpton
    ACM CCS 2013

## License

MIT License - see [LICENSE](LICENSE) for details.
