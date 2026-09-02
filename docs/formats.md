# Ranked-format providers

`fte.FTE` separates cryptography from covertext generation at one narrow
boundary: a non-negative integer rank. libfte owns encryption, authentication,
versioned byte framing, and bytes-to-integer conversion. A format provider owns
only the reversible mapping between ranks and canonical values.

A format can sit on either side of the engine: as the `output_format` (the
covertext language) or as the `input_format` (the plaintext language, which
defaults to `fte.BytesFormat`, raw bytes). The engine is
`rank_in -> transform -> unrank_out`, so one provider serves both roles.

## Terminology

libfte's code and docs use four terms precisely:

| Term | What it is | Example |
|------|-----------|---------|
| **pattern** (a regex) | Syntax: the string you write | `^[0-9a-f]+$` |
| **language** | Semantics: the set of words a pattern denotes | all nonempty lowercase hex strings |
| **format** | A finite slice of a language plus its canonical ordering (`rank`/`unrank`). The wire contract. | `RegexFormat(r'^[0-9a-f]+$', length=128)` |
| **provider** | The mechanism that implements formats | `fte.formats.regex`, or your own `RankedFormat` class |

In one line: a pattern denotes a language; a format ranks a finite slice of a
language; a provider implements formats. Two different patterns can denote the
same language, and one language yields many formats (different length bounds or
orderings). Endpoints must agree on the format, not the pattern.

## Interface

```python
from typing import Protocol, TypeVar

T = TypeVar("T")

class RankedFormat(Protocol[T]):
    def rank(self, value: T, /) -> int: ...
    def unrank(self, index: int, /) -> T: ...
```

This is a structural protocol. Providers do not inherit from libfte, register
plugins, or import libfte at runtime. An existing object with compatible methods
already conforms. Three optional conventions extend it:

- `cardinality`: the exact positive size of the contiguous rank space
  `range(cardinality)`. It is optional for the output of the `aes-ctr-hmac`
  cipher, where libfte uses it to reject messages that cannot always fit before
  performing encryption. The deterministic cipher requires it on both formats
  and refuses a format without one at construction with
  `FormatCapacityError: the deterministic cipher requires both formats to be
  finite (expose a positive cardinality)`.
- `fingerprint`: a stable `bytes` identifier for the exact ordering. The
  deterministic cipher requires it on both formats (`ValueError: the
  deterministic cipher requires both formats to expose a bytes fingerprint`),
  binds it into every tweak, and infers FPE from equal fingerprints. Equal
  fingerprints must guarantee identical ranking; the converse is not required
  (`RegexFormat` hashes the pattern text, so two spellings of one language get
  different fingerprints), so use the same spelling at both endpoints.
- `slice_bounds(length) -> (offset, count)`, together with integer
  `min_length` and `max_length` attributes: the first rank of the words of
  `length` bytes and how many there are (possibly zero). When an equal-format
  pair provides these, the deterministic cipher permutes each length slice in
  place so a value keeps its length; `FTE.preserve_length` is inferred from
  them, never requested.

## Required behavior

A provider must satisfy all of these rules:

1. Ranks are exact Python `int` values, never `bool`, and are non-negative.
2. Supported ranks are contiguous and start at zero.
3. `rank(unrank(index)) == index` for every supported index.
4. `unrank(rank(value)) == value` for every canonical covertext value.
5. Both operations are deterministic and perform no randomness, encryption,
   key handling, network I/O, or text normalization.
6. Values outside the format's language and unsupported indexes are rejected.
7. The ordering is a wire-level compatibility contract. Both endpoints must
   use implementations with identical ranking behavior.

With the `aes-ctr-hmac` cipher, `unrank()` failures during encryption become
`fte.FormatCapacityError`. On the deterministic path the cipher's output is
always inside the output domain, so an `unrank()` failure there is a contract
violation and propagates as raised. Invalid values or failures while ranking a
covertext become `fte.InvalidCovertextError`; a plaintext the input format
cannot rank, or whose rank falls outside `range(cardinality)`, becomes
`fte.InvalidPlaintextError`. Returning a non-integer or negative rank for a
covertext is a provider bug and raises `fte.FormatContractError` (on the input
side the same defect is reported as `fte.InvalidPlaintextError`), as does a
`cardinality` that is not a positive integer. Original provider exceptions are
retained as causes.

## Example provider

```python
class LowerHex:
    def rank(self, value: str, /) -> int:
        if not value:
            raise ValueError("not canonical lowercase hex")
        index = int(value, 16)
        if index < 0 or format(index, "x") != value:
            raise ValueError("not canonical lowercase hex")
        return index

    def unrank(self, index: int, /) -> str:
        if type(index) is not int or index < 0:
            raise ValueError("invalid rank")
        return format(index, "x")
```

Use it without an adapter:

```python
from fte import FTE

shared_32_byte_key = bytes(range(32))  # demo only; use a real shared secret
cipher = FTE(output_format=LowerHex(), key=shared_32_byte_key)
covertext = cipher.encrypt(b"hello")   # lowercase hex; differs per run (nonce)
assert cipher.decrypt(covertext) == b"hello"
```

`max_plaintext_bytes` is the largest plaintext an `FTE` will accept, and left
unset it is derived: a finite provider (one exposing `cardinality`) uses the
exact size its capacity allows, and an unbounded provider falls back to a 1 MiB
default. That same limit is the guard that lets decryption reject an oversized
rank before converting it back into a potentially large byte string, so set it
explicitly only to tighten that bound or to cap an unbounded provider. It is a
bytes-input knob: with a non-bytes `input_format` the argument is rejected
(`ValueError`), and the property reports the fixed serialization width
described below (or `None` for the deterministic cipher).

The version-one frame is variable length for a bytes input. Anyone who can rank
a covertext can therefore infer its exact plaintext byte length without knowing
the key. (With a non-bytes `input_format` the input rank is serialized at a
fixed width, so every frame has the same length and the covertext reveals
nothing about the plaintext value; see below.) The mapping guarantees
membership in the format's language, but it is not uniform over unused rank
capacity when a finite provider is much larger than the message requires.
Applications needing length hiding or a target distribution must add an
appropriate fixed-size record/padding layer before `FTE.encrypt`.

`FTE.decrypt` is not constant-time: it rejects a covertext outside the format,
an impossible rank or length, or a wrong version byte before verifying the
authentication tag (the version-one frame has no padding), so rejection latency
depends on why a value was rejected. Every check made before the tag uses only
information available without the key. This is safe under FTE's threat model,
where an on-path observer sees covertext but has no decryption oracle. Do not
expose `decrypt` directly as a remote timing oracle to untrusted callers.

## Input formats and the deterministic cipher

Any provider can also be the `input_format`. With the `aes-ctr-hmac` cipher
(which must be spelled out for a non-bytes input; the engine only infers it for
raw bytes) the plaintext is ranked, the rank is serialized at a fixed width
`W`, the smallest `W` with `256**W >= cardinality`, and that byte string goes
through the same randomized, authenticated frame as a bytes plaintext. Because
the width is fixed by the input's `cardinality`, the frame length never depends
on the plaintext value. `max_plaintext_bytes` reports `W`, and a finite output
must have room for a `W + 29` byte frame or construction raises
`FormatCapacityError`. Decryption rejects an authentic frame whose payload is
not exactly `W` bytes.

```python
from fte import FTE, RegexFormat

digits = RegexFormat(r"^[0-9]+$", length=12)      # 10**12 values: W = 5
hex128 = RegexFormat(r"^[0-9a-f]+$", length=128)
shared_32_byte_key = bytes(range(32))             # demo only; use a real secret

cipher = FTE(input_format=digits, output_format=hex128,
             key=shared_32_byte_key, cipher="aes-ctr-hmac")
assert cipher.max_plaintext_bytes == 5            # 256**4 < 10**12 <= 256**5
covertext = cipher.encrypt(b"123456789012")       # 128 hex bytes; random nonce
assert cipher.decrypt(covertext) == b"123456789012"
```

The deterministic cipher (`cipher="ff1"`, or any object with
`encrypt_int(x, *, domain, tweak)` / `decrypt_int(y, *, domain, tweak)`) maps
an input rank straight to an output rank with no framing and no expansion. It
needs both formats to be finite and fingerprinted, the input cardinality must
not exceed the output cardinality (a permutation cannot be injective
otherwise), and the input domain must clear the one-million format-preserving
floor or construction raises `SmallDomainError`; with inferred length
preservation every non-empty length slice must clear it. The floor applies to
the input domain because the strength of a deterministic map is bounded by the
input space, not by the key. Passing the same fingerprinted format on both
sides infers `cipher="ff1"`. A bare provider such as `LowerHex`, which exposes
no cardinality, is refused at construction:

```python
import fte

try:
    fte.FTE(input_format=LowerHex(), output_format=LowerHex(),
            key=bytes(16), cipher="ff1")
except fte.FormatCapacityError as exc:
    print(exc)
# the deterministic cipher requires both formats to be finite (expose a
# positive cardinality)
```

## Built-in regex provider

`fte.RegexFormat` lives in [`fte/formats/regex/`](../fte/formats/regex/) and
is the reference implementation to copy when writing your own provider. It uses
exactly the same extension point:

```python
from fte import FTE, RegexFormat

fmt = RegexFormat(r"^[0-9a-f]+$", length=96)          # fixed 96-byte covertext
shared_32_byte_key = bytes(range(32))                 # demo only; use a secret
cipher = FTE(output_format=fmt, key=shared_32_byte_key)

covertext: bytes = cipher.encrypt(b"hello")           # differs per run (nonce)
assert cipher.decrypt(covertext) == b"hello"
```

Pass a `min_length`/`max_length` range instead of `length` for variable-length
covertext; the words are ordered by length, then lexicographically within a
length, and `min_length == max_length` recovers the fixed case with an identical
wire format.

`RegexFormat.cardinality` is the exact number of matching words across the length
range. Encryption raises `FormatCapacityError` when that finite rank space cannot
contain the complete encrypted message. Construction raises `ValueError` if the
length arguments are missing, mixed, or not positive integers with
`min_length <= max_length`; if `pattern` is not a valid regular expression; or if
the language has no words in the requested length range.

Construction also raises `ValueError`, before `regex2dfa` runs, for syntax that
`regex2dfa` would silently misread rather than reject: brace quantifiers such
as `{3}` or `{2,4}` (write `\{` or `[{]` for a literal brace), escapes it does
not implement (`\D`, `\S`, `\W`, `\b`, backreferences, octal escapes, `\x`
without exactly two hex digits), a backslash anywhere inside `[...]`, an empty
or POSIX class, empty alternatives and empty groups, and `^` or `$` away from
the start or end of the pattern or of an alternative. [`fte/formats/regex/README.md`](../fte/formats/regex/README.md)
lists the supported dialect in full.

`regex2dfa` compiles the pattern to a minimized DFA, so two patterns that denote
the same language produce byte-identical ranking: `^[ab]+$` and `^(a|b)+$`
interoperate. The wire contract is the format (the language, the length bounds,
and the ordering version), never the pattern's spelling. `RegexFormat` also
exposes `fingerprint`, `slice_bounds`, `min_length`, and `max_length`, so it
works on either side of the engine and, used on both, infers the deterministic
cipher with in-place length preservation.

## Provider checklist

- Test both inverse laws at representative and boundary ranks.
- Test rejection of noncanonical values and unsupported ranks.
- Document the native covertext type and ordering compatibility version.
- Expose `cardinality` and a stable bytes `fingerprint` if the format will be
  used with the deterministic cipher; add `slice_bounds` plus `min_length` /
  `max_length` for in-place length preservation.
- Document practical size, time, memory, and concurrency limits.
- Bound work performed while ranking attacker-controlled values.
- Keep transport framing and streaming outside the ranked-format object.
