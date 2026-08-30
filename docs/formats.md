# Ranked-format providers

`fte.FTE` separates cryptography from covertext generation at one narrow
boundary: a non-negative integer rank. libfte owns encryption, authentication,
versioned byte framing, and bytes-to-integer conversion. A format provider owns
only the reversible mapping between ranks and canonical covertext values.

## Interface

```python
from typing import Protocol, TypeVar

T = TypeVar("T")

class RankedFormat(Protocol[T]):
    def rank(self, value: T, /) -> int: ...
    def unrank(self, index: int, /) -> T: ...

class FiniteRankedFormat(RankedFormat[T], Protocol[T]):
    @property
    def cardinality(self) -> int: ...
```

This is a structural protocol. Providers do not inherit from libfte, register
plugins, or import libfte at runtime. An existing object with compatible methods
already conforms. `cardinality` is optional; when supplied, it must be the exact
positive size of the contiguous rank space `range(cardinality)`. libfte uses it
to reject messages that cannot always fit before performing encryption.

## Required behavior

A provider must satisfy all of these rules:

1. Ranks are exact Python `int` values, never `bool`, and are non-negative.
2. Supported ranks are contiguous and start at zero.
3. `rank(unrank(index)) == index` for every supported index.
4. `unrank(rank(value)) == value` for every canonical covertext value.
5. Both operations are deterministic and perform no randomness, encryption,
   key handling, network I/O, or text normalization.
6. Values outside the canonical format and unsupported indexes are rejected.
7. The ordering is a wire-level compatibility contract. Both endpoints must
   use implementations with identical ranking behavior.

`unrank()` failures during encryption become `fte.FormatCapacityError`. Invalid
values or failures during ranking become `fte.InvalidCovertextError`. Returning
a non-integer or negative rank is a provider bug and raises
`fte.FormatContractError`. Original provider exceptions are retained as causes.

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

cipher = FTE(format=LowerHex(), key=shared_32_byte_key)
covertext = cipher.encrypt(b"hello")
assert cipher.decrypt(covertext) == b"hello"
```

`max_plaintext_bytes` is the largest plaintext an `FTE` will accept, and left
unset it is derived: a finite provider (one exposing `cardinality`) uses the
exact size its capacity allows, and an unbounded provider falls back to a 1 MiB
default. That same limit is the guard that lets decryption reject an oversized
rank before converting it back into a potentially large byte string, so set it
explicitly only to tighten that bound or to cap an unbounded provider.

The version-one frame is variable length. Anyone who can rank a covertext can
therefore infer its exact plaintext byte length without knowing the key. The
mapping guarantees membership in the provider's language, but it is not uniform
over unused rank capacity when a finite provider is much larger than the
message requires. Applications needing length hiding or a target distribution
must add an appropriate fixed-size record/padding layer before `FTE.encrypt`.

`FTE.decrypt` is not constant-time: it rejects malformed framing, length, and
padding before verifying the authentication tag, so rejection latency depends on
why a value was rejected. This is safe under FTE's threat model, where an
on-path observer sees covertext but has no decryption oracle. Do not expose
`decrypt` directly as a remote timing oracle to untrusted callers.

## Built-in regex provider

`fte.RegexFormat` lives in [`fte/formats/regex/`](../fte/formats/regex/) and
is the reference implementation to copy when writing your own provider. It uses
exactly the same extension point:

```python
from fte import FTE, RegexFormat

fmt = RegexFormat(r"^[0-9a-f]+$", length=96)          # fixed 96-byte covertext
cipher = FTE(format=fmt, key=shared_32_byte_key)

covertext: bytes = cipher.encrypt(b"hello")
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

## Provider checklist

- Test both inverse laws at representative and boundary ranks.
- Test rejection of noncanonical values and unsupported ranks.
- Document the native covertext type and ordering compatibility version.
- Document practical size, time, memory, and concurrency limits.
- Bound work performed while ranking attacker-controlled values.
- Keep transport framing and streaming outside the ranked-format object.
