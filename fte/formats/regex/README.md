# `fte.formats.regex`

The built-in ranked-format provider, and the reference implementation to copy
when you write your own. `RegexFormat` compiles a regular expression into a
ranked byte language, so `fte.FTE` ciphertext comes out looking like the pattern
you chose: hex, alphanumeric tokens, URL paths, lowercase words, and so on.

## Example

```python
import fte

# Every covertext is exactly 128 bytes of lowercase hex.
cipher = fte.FTE(
    format=fte.RegexFormat(r'^[0-9a-f]+$', length=128),
    key=bytes(range(32)),               # demo key; share a real secret
)

covertext = cipher.encrypt(b'secret')   # e.g. '9f3c...'  (128 hex chars)
assert cipher.decrypt(covertext) == b'secret'
```

## Fixed vs variable length

A regular expression like `^[0-9a-f]+$` describes an infinite language, so you
bound it to make it rankable. There are two ways:

- **Fixed length.** `RegexFormat(pattern, length=N)` ranks the words of exactly
  `N` bytes, so every covertext is `N` bytes. This is the classic fixed-slice
  behavior, and it makes a stream trivial to parse (fixed-size chunks).
- **Variable length.** `RegexFormat(pattern, min_length=a, max_length=b)` ranks
  all matching words whose length is in `[a, b]`, ordered by length and then
  lexicographically within a length, so covertext length varies with the
  message. `min_length == max_length` is the fixed case, identical to `length=`.

```python
# Covertext is a lowercase string somewhere in 40..400 bytes.
fmt = fte.RegexFormat(r'^[a-z]+$', min_length=40, max_length=400)
```

Pass either `length`, or the `min_length`/`max_length` pair, not both.

## Choosing a length

The covertext has to be big enough to hold FTE's authenticated frame (a fixed
33-byte overhead plus the message). If the language is too small for even an
empty message, `fte.FTE(...)` raises `FormatCapacityError` at construction. As a
rule of thumb, capacity grows with the alphabet size and the length: for the hex
format above, `length=128` holds up to 31 plaintext bytes
(`cipher.max_plaintext_bytes`). Construction also raises `ValueError` if the
language has no words in the requested length range.

## What's in here

- [`format.py`](format.py): `RegexFormat`, the provider. Its whole job is the two
  inverse methods every ranked format owes the engine, `rank` and `unrank`, plus
  a `cardinality`. There is no cryptography here.
- [`dfa.py`](dfa.py): the Goldberg-Sipser DFA ranker that `RegexFormat` is built
  on. It counts and ranks the words of the language by length.

The engine (`fte.FTE`) owns encryption, authentication, and framing; this
subpackage owns only the covertext language. That separation is exactly what
makes a new format easy to add.

## Writing your own format

`RegexFormat` is just one implementation of the structural `RankedFormat`
contract (any object with reversible `rank`/`unrank`). To target a covertext
language a regex cannot describe, write your own provider. See the
[ranked-format provider guide](../../../docs/formats.md) for the contract and a
conformance checklist, and `examples/12_custom_format.py` for a small worked
provider.
