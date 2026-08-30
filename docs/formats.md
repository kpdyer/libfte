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

`unrank()` failures during encoding become `fte.FormatCapacityError`. Invalid
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

encoder = FTE(format=LowerHex(), key=shared_32_byte_key)
covertext = encoder.encode(b"hello")
assert encoder.decode(covertext) == b"hello"
```

`FTE` defaults to a 1 MiB plaintext resource limit. Set
`max_plaintext_bytes` lower for expensive formats or explicitly raise it for a
trusted high-capacity provider. This is a resource ceiling, not a promise that
the selected provider can represent every message up to that size. Decode
rejects ranks beyond the corresponding bound before converting them back into
a potentially large byte string.

The version-one frame is variable length. Anyone who can rank a covertext can
therefore infer its exact plaintext byte length without knowing the key. The
mapping guarantees membership in the provider's language, but it is not uniform
over unused rank capacity when a finite provider is much larger than the
message requires. Applications needing length hiding or a target distribution
must add an appropriate fixed-size record/padding layer before `FTE.encode`.

`FTE.decode` is not constant-time: it rejects malformed framing, length, and
padding before verifying the authentication tag, so rejection latency depends on
why a value was rejected. This is safe under FTE's threat model, where an
on-path observer sees covertext but has no decode oracle. Do not expose `decode`
directly as a remote timing oracle to untrusted callers.

## Provider checklist

- Test both inverse laws at representative and boundary ranks.
- Test rejection of noncanonical values and unsupported ranks.
- Document the native covertext type and ordering compatibility version.
- Document practical size, time, memory, and concurrency limits.
- Bound work performed while ranking attacker-controlled values.
- Keep transport framing and streaming outside the ranked-format object.
