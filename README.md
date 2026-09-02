# libfte

[![PyPI version](https://img.shields.io/pypi/v/fte.svg)](https://pypi.org/project/fte/)
[![Tests](https://github.com/kpdyer/libfte/actions/workflows/test.yml/badge.svg)](https://github.com/kpdyer/libfte/actions/workflows/test.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Format-Transforming Encryption (FTE) transforms ciphertext to match a target format: one given by a regular expression, or by any *ranked-format* provider you supply. Unlike standard encryption that produces random-looking output, FTE produces ciphertext that looks like whatever format you specify: hexadecimal strings, alphanumeric tokens, any language a regex can denote, or a custom format such as decimal text or a domain-specific grammar.

This is useful for:
- **Protocol obfuscation**: Make encrypted traffic look like benign data
- **Bypassing filters**: Evade systems that block encrypted-looking content
- **Constrained fields**: Confine ciphertext to a required character set or field shape, such as an alphanumeric account token or a fixed-width record field

Based on the papers [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf) (CCS 2013), which introduced the FTE scheme, and [LibFTE: A Toolkit for Constructing Practical, Format-Abiding Encryption Schemes](https://kpdyer.com/publications/usenix2014-fte.pdf) (USENIX Security 2014), which described the FPE/FTE toolkit this library is named for. See [References](#references).

### Ciphers and Formats

There is a single engine, `fte.FTE`, that maps `rank_in -> transform ->
unrank_out`: it ranks a value of the input format to an integer, transforms
that integer, and unranks the result into the output format. Two independent
choices shape it:

- the **format pair**: `input_format` and `output_format` (the input defaults
  to raw bytes, `BytesFormat`); and
- the **cipher** on the integer in between: `"aes-ctr-hmac"` (randomized,
  authenticated, expanding: the classic AES-CTR + HMAC path) or a deterministic,
  zero-expansion cipher **object** exposing `encrypt_int` / `decrypt_int`.

That gives a 2x2 of behaviors:

| cipher \ formats | `input == output` | `input != output` |
|---|---|---|
| **`ff1`** (deterministic, zero-expansion) | **FPE**: re-encrypt a value in place | **deterministic FTE**: a reversible rank map between two formats |
| **`aes-ctr-hmac`** (randomized, authenticated, expanding) | authenticated encryption over bytes | **classic FTE**: bytes hidden as a chosen covertext format |

`cipher="ff1"` is the built-in format-preserving cipher (NIST SP 800-38G FF1,
via [libffx](https://github.com/kpdyer/libffx)). The deterministic column also
takes any object with `encrypt_int(x, *, domain, tweak)` /
`decrypt_int(y, *, domain, tweak)` forming a permutation of `range(domain)`, so
you can supply your own cipher.

**FPE is the equal-formats case**: pass the same format as `input_format` and
`output_format` and the deterministic cipher is inferred.

> The wire format changed in 0.4.0 and is **not** compatible with libfte 0.3.x
> and earlier. A deterministic cipher is unauthenticated and leaks plaintext
> equality; pass per-record `tweak` values and never reuse a key across the two
> ciphers.

## Installation

```bash
pip install fte
```

## Quick Example

Encrypt a secret so the ciphertext looks like words:

```python
import os
import fte

key = os.urandom(32)  # 32 bytes, shared by both endpoints

# Pick a covertext format, then build a cipher over it and the key.
# 73 characters of words hold up to 15 plaintext bytes (cipher.max_plaintext_bytes).
word_format = fte.RegexFormat(r'^([a-z]+ )+[a-z]+$', length=73)
cipher = fte.FTE(output_format=word_format, key=key)

ciphertext = cipher.encrypt(b'Attack at dawn')
print(ciphertext.decode())
# One real run; the exact text varies per call, because the cipher is randomized:
# aa migbcjfbkvhczkjjwogvkpr m hnczwlthnujcutvnxqtrfhfnvnjhowaax mg nazfkrf

plaintext = cipher.decrypt(ciphertext)
# → b'Attack at dawn'
```

The covertext is a string of the chosen format that carries your encrypted
message. Because the format holds one byte more than the message needs, the
covertext can begin with a short run of the format's lowest-ranked symbols
(`a` and space); a much larger `length` would make that run long (see
[How It Works](#how-it-works)).

For **format-preserving encryption**, use the same format on both sides. Equal
formats infer the deterministic `ff1` cipher, and length is preserved
automatically:

```python
digits = fte.RegexFormat(r'^[0-9]+$', length=9)   # a 9-digit language
fpe = fte.FTE(input_format=digits, output_format=digits, key=os.urandom(16))

token = fpe.encrypt(b'100000042', tweak=b'accounts')  # another 9-digit string
assert fpe.decrypt(token, tweak=b'accounts') == b'100000042'
```

## More Examples

The snippets below reuse a shared 32-byte `key = os.urandom(32)`. Each
`length` is the smallest that holds one byte more than the 6-byte message; the
outputs shown are from one real run, and yours will differ (the cipher is
randomized).

### URL paths
```python
cipher = fte.FTE(output_format=fte.RegexFormat(r'^/[a-z]+/[a-z]+\.html$', length=66), key=key)
cipher.encrypt(b'secret')
# → b'/aagkbylrumwypuvsxjwymsedkpqvcfnspezlgoivwgjjzruert/vtgmhuzfl.html'
```

### URL slugs
```python
cipher = fte.FTE(output_format=fte.RegexFormat(r'^[a-z]+-[a-z]+-[a-z]+$', length=60), key=key)
cipher.encrypt(b'secret')
# → b'a-qogwiyjqkhmakfxo-jhszhdlrpqeskjmolsfnmnskmzsixfjiilmimwkhb'
```

### Alphanumeric tokens
```python
cipher = fte.FTE(output_format=fte.RegexFormat('^[A-Za-z0-9]+$', length=48), key=key)
cipher.encrypt(b'secret')
# → b'00ZO60lS5n5KAI37NT9baatQ2mSvF3zKOZaDOGwzYHuTz1yF'
```

### Variable-length covertext
Give a `min_length`/`max_length` range instead of a fixed `length`, and the
covertext length varies with the message (`min_length == max_length` is the
fixed case):
```python
lowercase = fte.RegexFormat('^[a-z]+$', min_length=40, max_length=400)
cipher = fte.FTE(output_format=lowercase, key=key)
cipher.encrypt(b'secret')       # a lowercase string in 40..400 bytes (59 for this message)
```

### Custom ranked-format providers

The `output_format` can be any structural `RankedFormat`: an object with reversible
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
    cipher: str | object | None = None,   # "aes-ctr-hmac" | "ff1" | object | inferred
    max_plaintext_bytes: int | None = None,   # aes-ctr-hmac, bytes input only
)
```

| Member | Description |
|--------|-------------|
| `encrypt(plaintext, *, tweak=b"") -> T` | Rank the input, transform, unrank into a covertext (tweak: deterministic cipher only; a non-empty tweak with `aes-ctr-hmac` raises `ValueError`) |
| `decrypt(covertext, *, tweak=b"") -> P` | Rank the covertext, invert the transform, unrank the plaintext |
| `input_format` / `output_format` | The two formats |
| `cipher` | Resolved mode: `"aes-ctr-hmac"` or `"deterministic"` |
| `preserve_length` | Read-only: whether a deterministic cipher preserves length in place (inferred) |
| `max_plaintext_bytes` | Largest plaintext accepted, aes-ctr-hmac only (see below) |

The `cipher` is `"aes-ctr-hmac"`, `"ff1"`, a deterministic cipher **object**
(any object with `encrypt_int` / `decrypt_int`), or `None` to infer it: a bytes
input picks `"aes-ctr-hmac"`; two formats with equal fingerprints pick `"ff1"`;
any other pair must name the cipher. `"aes-ctr-hmac"` needs a 32-byte key (16
encryption + 16 MAC); `"ff1"` needs 16/24/32; a cipher object carries its own
key.

A deterministic cipher infers **length preservation** from the formats: when
input and output are the same format and it can name its per-length slices, a
value keeps its length; otherwise the whole language is permuted. It also
enforces a **one-million domain floor** (Draft SP 800-38G Rev 1) on the
*input* domain, raising `SmallDomainError` with no opt-out: every non-empty
length slice must clear it when length is preserved, and the input format's whole
cardinality must clear it for a cross-format map (the output is at least as
large, so it clears it too).

`max_plaintext_bytes` (the `aes-ctr-hmac` cipher, bytes input) is chosen for
you when left unset: a finite output format uses the exact size its capacity
allows, and an unbounded one falls back to a 1 MiB default. It also lets
`decrypt` reject an oversized covertext cheaply. Passing it is rejected for a
non-bytes input: there the property reports the fixed width at which every
input rank is serialized before encryption (the smallest `W` with
`256**W >= cardinality`), so the covertext length never depends on the
plaintext value.

### `fte.RegexFormat`

The built-in `RankedFormat`: a format over the byte language a regular
expression denotes. Choose a fixed covertext length, or a
`[min_length, max_length]` range for variable-length covertext
(`min_length == max_length` is the fixed case).

```python
fte.RegexFormat(pattern: str, *, length: int)                       # fixed
fte.RegexFormat(pattern: str, *, min_length: int, max_length: int)  # range
```

| Member | Description |
|--------|-------------|
| `pattern` | The regular expression denoting the covertext language |
| `min_length`, `max_length` | Covertext length bounds (equal for a fixed length) |
| `cardinality` | Number of matching words in the length range |
| `rank(value: bytes) -> int` | Rank of a canonical covertext value |
| `unrank(index: int) -> bytes` | The covertext value at `index` |
| `fingerprint` | `bytes`: SHA-256 over the pattern text and length bounds. Equal fingerprints guarantee identical ranking and infer the `ff1` cipher; two spellings of one language (`^[ab]+$` and an equivalent pattern written differently) rank identically but get different fingerprints, so use the same pattern string at both endpoints of a deterministic cipher |
| `slice_bounds(length: int, /) -> tuple[int, int]` | `(offset, count)` of the words of exactly `length` bytes within the rank space (`ValueError` outside `[min_length, max_length]`); what lets FPE preserve length |

`length=N` is shorthand for `min_length=max_length=N`; pass either `length` or
the `min_length`/`max_length` pair, not both. Construction raises `ValueError`
if the language has no words in the requested length range, if the pattern is
not a valid regular expression, or if it uses syntax that regex2dfa would
silently misread. The pattern always matches the whole covertext, and the
dialect is smaller than Python's `re` (literals, `*` `+` `?`, `|`, `(...)`,
classes with ranges and `^` negation, `.` for any of the 256 bytes, the escapes
`\n` `\t` `\r` `\0` `\xHH` `\d` `\s` `\w`, and a backslash before any
punctuation character). Rejected up front: brace quantifiers (`{3}`, `{2,4}`:
any unescaped `{` outside a class; write `\{` or `[{]` for a literal brace);
every other backslash-letter or backslash-digit escape (`\D` `\S` `\W` `\b`
`\B` `\A` `\Z` `\z` `\f` `\v` `\a` `\e` `\u...` `\p{...}` `\Q...\E`,
backreferences `\1`..`\9`, and so on); octal escapes (`\012`) and `\x` without
exactly two hex digits; a backslash anywhere inside `[...]` (`[\d]`, `[\n]`,
`[\]]`, `[\\]`); an empty class `[]` or `[^]`; POSIX classes (`[[:alpha:]]`);
`^` or `$` anywhere but the start or end of the pattern or of an alternative;
empty alternatives (`(a|)`; write `(a)?`) and empty groups `()`; and a pattern
ending in a bare backslash or in `\$` (write `\$$` or `[$]`). See
[`fte/formats/regex/README.md`](fte/formats/regex/README.md) for the full list.

### `fte.BytesFormat`

The default `input_format`: the shortlex ranked format over every finite byte
string, ordered by length and then numerically (`b''` ranks 0, the 256
single bytes rank 1..256, two-byte strings follow, and so on), so length and
leading zero bytes survive `rank`/`unrank`. The language is unbounded, so it
exposes no `cardinality`; it is the same ordering the wire frame uses.

```python
fte.BytesFormat()
```

| Member | Description |
|--------|-------------|
| `rank(value: bytes) -> int` | Shortlex rank of `value` |
| `unrank(index: int) -> bytes` | The byte string at `index`, for any `index >= 0` |
| `fingerprint` | `b"fte:bytes:shortlex:1"`: names the ordering as part of the wire contract |

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

### Exceptions

Every engine error derives from `fte.FTEError`; bad arguments (a wrong key
size, an unknown `cipher`, an invalid pattern) raise `TypeError` or
`ValueError` instead.

| Exception | Raised when |
|-----------|-------------|
| `FTEError` | Base class of the errors below |
| `FormatCapacityError` | A format cannot hold an encrypted frame: at construction when the output format is too small for even an empty message (or, with a non-bytes input, for every input rank), or when a deterministic cipher's input cardinality exceeds its output's (or either format is unbounded); at `encrypt` when a plaintext exceeds a finite output's capacity |
| `FormatContractError` | A format breaks the `RankedFormat` contract: a `cardinality` that is not a positive integer, or a covertext `rank()` that returns something other than a non-negative integer |
| `InvalidCovertextError` | `decrypt` cannot recover a plaintext: the covertext is not in the output language, is oversized, has the wrong frame version, fails authentication, or (deterministic cipher) deciphers outside the input format's rank space |
| `InvalidPlaintextError` | `encrypt` is given a value that is not a member of a non-bytes `input_format` (its `rank()` fails or falls outside the rank space); a non-bytes plaintext for the bytes input is a `TypeError` |
| `MessageTooLargeError` | A bytes plaintext exceeds the configured ceiling (the `max_plaintext_bytes` argument, or the 1 MiB default); exceeding a finite format's capacity is `FormatCapacityError` instead |
| `SmallDomainError` | A deterministic cipher's domain is below the one-million floor: a non-empty length slice with fewer than a million words when length is preserved, or an input format with fewer than a million values for a cross-format map |

## How It Works

1. **Encryption**: Your plaintext is encrypted with AES-128-CTR under a fresh
   12-byte random nonce, then authenticated with HMAC-SHA256 over the nonce
   and ciphertext (Encrypt-then-MAC; the tag is truncated to 16 bytes). The
   32-byte key is split into a 16-byte AES key and a 16-byte MAC key. Both
   primitives run on OpenSSL: AES-CTR through the `cryptography` package, HMAC
   through the standard library's `hmac`/`hashlib`.
2. **Framing**: A one-byte wire-format version is prepended, so an `n`-byte
   plaintext becomes an `n + 29`-byte frame (`1 + 12 + n + 16`), and the frame
   is mapped reversibly to a non-negative integer: its shortlex rank (length
   first, then value; the `BytesFormat` ordering).
3. **Formatting**: A built-in or custom ranked format maps that integer to a
   covertext with `unrank()`; `decrypt()` runs the steps in reverse and
   rejects a covertext whose tag does not verify with `InvalidCovertextError`.

With a non-bytes `input_format`, step 1 encrypts the input's rank serialized at
a fixed width set by the input's cardinality, so the covertext length never
depends on the plaintext value.

The framing is variable-length. Anyone who can rank a covertext can infer its
exact plaintext byte length, even without the key. FTE guarantees membership in
the format's language, not a uniform distribution over every rank when the
format offers more capacity than the message needs. Concretely, the frame's
rank is only about `8 * (n + 29)` bits long, so when the format's cardinality
is much larger a fixed-length covertext begins with a run of the format's
lowest-ranked symbols (leading `0`s for hex, `a a a` for the word format) that
grows with the unused capacity. Keep `length` close to what the message needs
(`cipher.max_plaintext_bytes` reports the fit) to keep that run short.

The vocabulary here is deliberate: a **pattern** (a regex) denotes a
**language** (the set of matching words), a **format** ranks a finite slice of
a language and is the wire contract endpoints must share, and a **provider**
(such as `fte.formats.regex`, or your own `RankedFormat`) implements formats.
See [Terminology](docs/formats.md#terminology) for the full glossary.

The capacity depends on the language: a larger alphabet means more bits per
character:

| Format | Pattern | Bits/char |
|--------|---------|-----------|
| Binary | `^[01]+$` | 1.0 |
| Hex | `^[0-9a-f]+$` | 4.0 |
| Alphanumeric | `^[A-Za-z0-9]+$` | 5.95 |

## Benchmarks

The repository ships with [`benchmark.py`](benchmark.py), a self-contained
script that measures the two costs that matter in practice:

- **Cipher construction**: the one-time cost of compiling a regex into a DFA
  and pre-computing the ranking tables.
- **`encrypt()` / `decrypt()`**: the per-message cost, dominated by the DFA
  rank/unrank over large integers. It grows with the covertext `length` (the
  DFA walk) and with the plaintext size (the magnitude of the integer being
  ranked), so every format is timed twice: with a short 18-byte payload and
  with a payload that fills the format's capacity (`max_plaintext_bytes`).

It runs across six formats (binary, hex, lowercase, alphanumeric, URL paths,
words), sweeps `length` for `^[a-z]+$` to show how per-message cost scales,
and records the CPU / OS / Python it ran on. Every timed round-trip is
verified, so a clean run also serves as a correctness check.

```bash
python benchmark.py            # full run: 100 iterations, with the length sweep
python benchmark.py --quick    # 20 iterations, skip the length sweep
```

Numbers are machine-dependent. One full run on an Apple M3 Pro (Python 3.14;
times in ms, median of 100 iterations):

```
Per-format performance (per-message times in ms)
Format          length  cap(bits)  bits/char   build(ms)  enc/small  dec/small  max(B)   enc/max   dec/max
----------------------------------------------------------------------------------------------------------
Binary             512        512       1.00       0.110      0.051      0.043      35     0.060     0.050
Hex                256       1024       4.00       0.076      0.026      0.020      99     0.046     0.037
Lowercase          256       1203       4.70       0.082      0.026      0.021     122     0.047     0.040
Alphanumeric       192       1143       5.95       0.097      0.021      0.017     114     0.039     0.031
URL path           128        575       4.49       0.186      0.031      0.030      43     0.038     0.037
Words              120        570       4.75       0.120      0.031      0.028      43     0.037     0.035

Per-message scaling vs. length (regex ^[a-z]+$)
length    cap(bits)  enc/small  dec/small  max(B)   enc/max   dec/max
---------------------------------------------------------------------
128             601      0.019      0.016      47     0.023     0.020
256            1203      0.028      0.021     122     0.047     0.039
512            2406      0.046      0.034     272     0.132     0.098
1024           4813      0.082      0.059     573     0.436     0.293
2048           9626      0.152      0.111    1175     1.612     0.943
```

For a short payload the per-message cost grows more slowly than `length` does
(about 8x from 128 to 2048); a payload that fills the capacity grows
super-linearly (about 70x over the same range), since the integer being ranked
grows with the covertext too. Use `python benchmark.py --help` for all options.

## References

[1] [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf)
    Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart and Thomas Shrimpton
    ACM CCS 2013

[2] [LibFTE: A Toolkit for Constructing Practical, Format-Abiding Encryption Schemes](https://kpdyer.com/publications/usenix2014-fte.pdf)
    Daniel Luchaup, Kevin P. Dyer, Somesh Jha, Thomas Ristenpart and Thomas Shrimpton
    USENIX Security 2014

## License

MIT License - see [LICENSE](LICENSE) for details.
