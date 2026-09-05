# Writing a format provider

A provider maps canonical values to non-negative integer ranks and back.
`fte.FTE` handles encryption and framing; providers determine the plaintext or
covertext language. They can serve as `input_format`, `output_format`, or both.

## Terminology

| Term | Meaning | Example |
|------|---------|---------|
| Pattern | Regex syntax describing a language | `^[0-9a-f]+$` |
| Language | The set of matching values | Nonempty lowercase hex strings |
| Format | Canonical values and their reversible ordering; may be finite or unbounded | `RegexFormat(pattern, length=128)` or `BytesFormat()` |
| Provider | The implementation of a format | `RegexFormat` or a custom class |

## Interface

```python
from typing import Protocol, TypeVar

T = TypeVar("T")

class RankedFormat(Protocol[T]):
    def rank(self, value: T, /) -> int: ...
    def unrank(self, index: int, /) -> T: ...
```

The protocol is structural: providers need no inheritance, registration, or
runtime dependency on libfte. See [08_custom_format.py](../examples/08_custom_format.py)
for a complete provider over decimal strings and its use with `FTE`.

### Metadata

- `cardinality`: the exact positive integer size of `range(cardinality)`.
  Omit it for an unbounded format. Authenticated encryption permits an unbounded
  output, but requires cardinality for a non-bytes input. Deterministic
  encryption requires finite formats on both sides.
- `fingerprint`: a stable bytes identifier for the ordering. Required on both
  sides of a deterministic cipher, which binds the identifiers into its tweak.
  Equal fingerprints must guarantee identical ranking; the converse is not
  required.
- `slice_bounds(length) -> (offset, count)`: the first rank and number of values
  of that length, possibly zero. Together with integer `min_length` and
  `max_length`, this enables a deterministic cipher to preserve length when
  both formats have equal fingerprints.

See the [API reference](api.md#choosing-a-cipher) for cipher selection, domain
requirements, and [plaintext limits](api.md#plaintext-limits).

## Required behavior

1. Ranks are exact Python `int` values, never `bool`, and are non-negative.
2. Supported ranks are contiguous and start at zero.
3. `rank(unrank(index)) == index` for every supported index.
4. `unrank(rank(value)) == value` for every canonical value.
5. Both operations are deterministic and perform no randomness, encryption,
   key handling, network I/O, or text normalization.
6. Reject noncanonical values and unsupported indexes.

`FTE` consumes and returns one complete value per message. Keep transport
framing and streaming outside the provider, and preserve each returned value
intact: editing or normalizing it changes its rank.

### Errors

A failure to rank a plaintext becomes `InvalidPlaintextError`; a failure to
rank covertext becomes `InvalidCovertextError`. A non-integer or negative
covertext rank raises `FormatContractError` (the corresponding plaintext defect
raises `InvalidPlaintextError`). Invalid cardinality metadata also raises
`FormatContractError`.

With authenticated encryption, an output `unrank()` failure becomes
`FormatCapacityError`. On the deterministic path it propagates unchanged,
because a conforming cipher already returns an in-domain rank. Wrapped provider
exceptions are retained as causes. See the [exception reference](api.md#exceptions).

## Compatibility

The ordering is part of the wire contract. Endpoints must agree on the formats,
key, cipher, and any tweak. Equal ranking alone is insufficient for deterministic
encryption, which also binds the format fingerprints and length mode.

Equivalent regexes, such as `^[ab]+$` and `^(a|b)+$`, have identical rankings for
the same length bounds. However, `RegexFormat` hashes the **pattern text** into
its fingerprint. Use the same pattern text and bounds at both endpoints of a
deterministic cipher; substituting an equivalent pattern can silently change
the decrypted plaintext. Authenticated encryption does not bind fingerprints
and can interoperate across equivalent rankings.

`BytesFormat` names its ordering with `b"fte:bytes:shortlex:1"`.
`RegexFormat` uses SHA-256 of `b"fte:regex:1|" + pattern + b"|" + min_length +
b"|" + max_length`, encoding the pattern and decimal length bounds as UTF-8.
Changing these identifiers or the ranking changes compatibility.

The built-in regex provider lives in [fte/formats/regex](../fte/formats/regex/).
Its [guide](../fte/formats/regex/README.md) documents length selection and the
supported regex dialect.

## Provider checklist

- Test both inverse laws at representative and boundary ranks.
- Test rejection of noncanonical values and unsupported ranks.
- Document the native value type, ordering version, and metadata.
- Document practical size, time, memory, and concurrency limits.
- Bound work performed while ranking untrusted values.
- Preserve ordering and fingerprints across compatible releases.

See [SECURITY.md](../SECURITY.md) for the encryption threat model, plaintext
length disclosure, and decryption timing.
