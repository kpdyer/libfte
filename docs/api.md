# API reference

## Public API and compatibility

Use the names exported by `fte`: `FTE`, `RegexFormat`, `BytesFormat`,
`RankedFormat`, and the [engine exceptions](#exceptions), including `FTEError`.
Their documented constructors, methods, and properties form the stable public
API. `fte.__version__` reports the installed version. The provider aliases in
`fte.formats` and `fte.formats.regex.RegexFormat` remain supported.

Direct imports from `fte.frame` and `fte.formats.regex.dfa` are deprecated.
Both modules retain their existing exported functions, classes, and exceptions
during migration and emit `DeprecationWarning` when first imported. They will
be removed in a future breaking release; ordinary public API use does not
import them or emit these warnings. To show deprecation warnings while testing,
run Python with `-W default::DeprecationWarning`.

| Deprecated use | Migration |
|----------------|-----------|
| `fte.frame.bytes_to_rank()` / `rank_to_bytes()` | `fte.BytesFormat().rank()` / `.unrank()` |
| Frame capacity calculations for a configured cipher | Construct `fte.FTE(...)` and read `max_plaintext_bytes`; construction rejects an insufficient format |
| Raw DFA construction and per-length ranking | Use `fte.RegexFormat` for regex languages, or implement the `fte.RankedFormat` [provider contract](formats.md) |

There is no stable replacement for raw DFA/FST parsing or the remaining frame
internals. Applications that need these interfaces should pin a release that
still provides them while moving that functionality into their own provider
or another maintained dependency. Modules and names beginning with `_` are
private implementation details, not migration targets. The deprecation does
not change ranking, fingerprints, or encrypted-frame bytes.

## `fte.FTE`

The engine maps `input_format.rank(plaintext)` through a cipher, then calls
`output_format.unrank()` to produce one complete covertext value.

```python
fte.FTE(
    *,
    input_format=None,               # defaults to BytesFormat()
    output_format=None,              # required; None raises ValueError
    key: bytes,
    cipher: str | object | None = None,
    max_plaintext_bytes: int | None = None,
)
```

| Member | Description |
|--------|-------------|
| `encrypt(plaintext, /, *, tweak=b"")` | Encrypt one input-format value into an output-format value |
| `decrypt(covertext, /, *, tweak=b"")` | Decrypt one output-format value into an input-format value |
| `input_format`, `output_format` | The configured formats; read-only |
| `cipher` | Resolved mode: `"aes-ctr-hmac"` or `"deterministic"` |
| `preserve_length` | Whether the deterministic cipher permutes each length slice in place |
| `max_plaintext_bytes` | Effective bytes-input limit, fixed input-rank width, or `None`; see below |

### Choosing a cipher

| `cipher` argument | Behavior | Key |
|-------------------|----------|-----|
| `"aes-ctr-hmac"` | Randomized, authenticated encryption with a 29-byte frame overhead | 32 bytes: 16 for AES, 16 for HMAC |
| `"ff1"` | Deterministic rank permutation using `libffx.FF1`, with no nonce or authentication tag | 16, 24, or 32 bytes |
| Cipher object **(deprecated)** | A custom permutation with `encrypt_int(x, *, domain, tweak)` and `decrypt_int(y, *, domain, tweak)`; construction emits `DeprecationWarning` | The object owns its key; the required bytes `FTE` key argument is unused |

With `cipher=None`, a `BytesFormat` input selects `"aes-ctr-hmac"`. Select
`cipher="ff1"` explicitly for deterministic, unauthenticated encryption.
For compatibility, equal bytes fingerprints still infer `"ff1"`, but successful
construction emits `DeprecationWarning`; this inference will be removed in a
future breaking release. Adding `cipher="ff1"` preserves existing ciphertexts,
keys, tweaks, and length behavior. Other format pairs already require an explicit
cipher. See the [provider contract](formats.md) for custom formats.

The deterministic cipher requires finite, fingerprinted formats with input
cardinality no greater than output cardinality. Its input domain must contain
at least one million values, or construction raises `SmallDomainError`.

Equal fingerprints infer length preservation when the input provides
`slice_bounds()` and integer `min_length`/`max_length` attributes. Each nonempty
length slice must then contain at least one million values. Otherwise the cipher
permutes the output's whole rank space; decrypting a value that maps outside the
input space raises `InvalidCovertextError`.

`tweak` accepts bytes or bytearray and defaults to empty bytes. A deterministic
cipher binds it to the formats and length mode. Authenticated encryption has no
associated-data support and rejects a nonempty tweak. Never reuse keys across
the two ciphers; see [SECURITY.md](../SECURITY.md).

### Migrating custom cipher objects

Passing a cipher object is deprecated. It remains accepted during the migration
period and produces the same covertexts as before. The deprecation does not
affect custom [format providers](formats.md).

For new data, choose `cipher="ff1"` for deterministic encryption or
`cipher="aes-ctr-hmac"` for authenticated encryption, and pass the encryption
key directly to `FTE`. Authenticated encryption also requires enough output
capacity for its frame; it cannot replace every deterministic configuration.

A custom object can implement a different permutation, own a different key, or
interpret tweaks differently from a built-in cipher. Changing its `cipher`
argument to `"ff1"` is therefore **not generally ciphertext compatible**.
Retain the original implementation, its key, format definitions, and tweaks to
decrypt existing data. Migrate by decrypting with that configuration and
encrypting with a separately configured named cipher. Keep track of which
configuration produced each stored value; do not try to identify it by whether
unauthenticated decryption returns a value in the format. No public replacement
for arbitrary cipher injection is introduced.

### Plaintext limits

For a bytes input, the resource ceiling defaults to **1 MiB**. A finite output
can lower it further: `max_plaintext_bytes` reports the smaller of that ceiling
and the output's plaintext capacity. An unbounded output uses the ceiling alone.

Pass `max_plaintext_bytes` to raise or lower the resource ceiling; it must be an
integer from `0` through `2**32 - 1`. The output's capacity still applies. Zero
allows only an empty plaintext. A format too small for even an empty encrypted
message is rejected at construction.

Exceeding the resource ceiling raises `MessageTooLargeError`; a message within
that ceiling but beyond the finite output's capacity raises
`FormatCapacityError`. The effective limit also bounds accepted encrypted-frame
lengths during decryption.

For an authenticated non-bytes input, the input must be finite. Every rank is
serialized at the same width `W`, the smallest integer with
`256**W >= input_format.cardinality`. The property reports `W`; the constructor
rejects an explicit `max_plaintext_bytes`. The output must fit every `W + 29`
byte frame, and decryption rejects payloads of any other width. See the
[structured-input example](../examples/09_authenticated_fte.py).

For the deterministic cipher, `max_plaintext_bytes` is `None`; format cardinality
and any length slices define the domain.

### Framing

Authenticated encryption uses AES-128-CTR with a fresh 12-byte nonce and a
16-byte HMAC-SHA256 tag over the nonce and ciphertext. The complete frame is
`version (1) || nonce (12) || ciphertext || tag (16)`. Its version byte is `0x01`.
The frame's shortlex rank (length first, then numeric value) becomes the output
format's rank. Decryption reverses this mapping and verifies the tag before
recovering the plaintext.

For bytes input, the frame reveals the exact plaintext length to anyone who can
rank the covertext. Fixed-width input-rank serialization avoids that dependency
for non-bytes input. The mapping guarantees membership in the output language,
not a uniform distribution over unused rank capacity. See the
[security model](../SECURITY.md#security-model) for nonce limits and rejection
timing, and the [regex guide](../fte/formats/regex/README.md#choosing-a-length)
for capacity examples.

## `fte.RegexFormat`

A finite byte language compiled from a regex, ordered by length and then
lexicographically within a length:

```python
fte.RegexFormat(pattern: str, *, length: int)
fte.RegexFormat(pattern: str, *, min_length: int, max_length: int)
```

Pass a positive fixed `length` or both positive bounds with
`min_length <= max_length`. `length=N` is identical to
`min_length=max_length=N`. Invalid patterns, unsupported syntax, and length
ranges containing no matching words raise `ValueError`.

| Member | Description |
|--------|-------------|
| `pattern` | Original regex text |
| `min_length`, `max_length` | Inclusive covertext length bounds |
| `cardinality` | Exact number of matching words in the range |
| `rank(value, /) -> int` | Rank of a matching bytes or bytearray value |
| `unrank(index, /) -> bytes` | Word at an integer rank in `range(cardinality)` |
| `fingerprint` | SHA-256 identifier derived from pattern text and length bounds |
| `slice_bounds(length, /) -> tuple[int, int]` | Starting rank and word count for one length; `ValueError` outside the bounds |

`pattern`, `min_length`, `max_length`, `cardinality`, and `fingerprint` are
read-only. Create a new `RegexFormat` to use a different pattern or length
range; assigning or deleting these properties raises `AttributeError`.

When upgrading from writable metadata, reconstruct formats from their pattern
and length arguments instead of loading previously pickled instances. Python
pickle state is not a cross-version format; rankings and fingerprints are
unchanged by this change.

The pattern matches the whole covertext. The dialect is smaller than Python's
`re`; see the [supported syntax](../fte/formats/regex/README.md#supported-syntax)
and [compatibility rules](formats.md#compatibility).

## `fte.BytesFormat`

`fte.BytesFormat()` ranks every finite byte string in shortlex order. The empty
string ranks 0, one-byte strings rank 1–256, two-byte strings follow, and so on.
Length and leading zero bytes survive a round trip. This is the default input
format, and its language is unbounded: it has no `cardinality`.

| Member | Description |
|--------|-------------|
| `rank(value, /) -> int` | Shortlex rank of a bytes or bytearray value |
| `unrank(index, /) -> bytes` | Byte string at any non-negative integer rank |
| `fingerprint` | `b"fte:bytes:shortlex:1"`, the stable ordering identifier |

## `fte.RankedFormat`

The structural protocol requires reversible `rank(value)` and `unrank(index)`
methods. See [Writing a format provider](formats.md) for metadata, inverse laws,
error handling, and a conformance checklist.

## Exceptions

All engine errors below derive from `fte.FTEError`. Bad arguments, including
invalid key sizes and regex syntax, raise `TypeError` or `ValueError` instead.

| Exception | Meaning |
|-----------|---------|
| `FormatCapacityError` | Insufficient output capacity, or incompatible cardinalities for the chosen cipher |
| `FormatContractError` | Invalid cardinality metadata or a covertext rank that is not a non-negative integer |
| `InvalidCovertextError` | Invalid output value, oversized or malformed frame, failed authentication, or deterministic decryption outside the input domain |
| `InvalidPlaintextError` | A non-bytes input format cannot rank the plaintext within its domain; non-bytes plaintext given to `BytesFormat` input instead raises `TypeError` |
| `MessageTooLargeError` | A bytes plaintext exceeds the resource ceiling |
| `SmallDomainError` | A deterministic input domain or nonempty length slice contains fewer than one million values |
