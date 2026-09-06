# `fte.formats.regex`

`RegexFormat` ranks the byte strings matching a regex within a chosen length
range. See the [API reference](../../../docs/api.md#fteregexformat) for its
methods and metadata.

## Example

```python
import fte

# Every covertext is exactly 72 bytes of lowercase hex.
cipher = fte.FTE(
    output_format=fte.RegexFormat(r'^[0-9a-f]+$', length=72),
    key=bytes(range(32)),               # demo key; share a real secret
)

covertext = cipher.encrypt(b'secret')
# 72 hex characters, randomized per call
assert cipher.decrypt(covertext) == b'secret'
```

The leading zeros are the format's spare capacity: the frame for a 6-byte
message is a little smaller than the largest 72-digit hex number, so the top
digits come out zero. A message closer to `cipher.max_plaintext_bytes` fills
them.

## Fixed vs variable length

Bound the language to the byte lengths this provider will rank:

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

With `aes-ctr-hmac`, the covertext must hold the message plus a 29-byte
authenticated frame overhead. If the format is too small for even an empty
message, `fte.FTE(...)` raises `FormatCapacityError` at construction. As a rule
of thumb, capacity grows with the alphabet size and the length: the hex format
above holds up to 7 plaintext bytes at `length=72` and 35 at `length=128`
(`cipher.max_plaintext_bytes`). The [resource limit](../../../docs/api.md#plaintext-limits)
can reduce usable capacity. `RegexFormat` itself raises `ValueError` if the
language has no words in the requested length range.

For a simple alphabet, capacity grows with its bits per character:

| Alphabet | Pattern | Bits/character |
|----------|---------|----------------|
| Binary | `^[01]+$` | 1 |
| Hex | `^[0-9a-f]+$` | 4 |
| Alphanumeric | `^[A-Za-z0-9]+$` | about 5.95 |

## Supported syntax

`RegexFormat` hands the pattern to `regex2dfa`, whose dialect is smaller than
Python's `re`. The pattern always describes the whole covertext (there is no
unanchored search), and the alphabet is bytes: `.` means any of the 256 byte
values, newline included. Everything below was verified against the DFAs
regex2dfa emits.

Supported:

- Literal characters. A character in U+0080..U+00FF stands for the byte of the
  same value; anything above raises `ValueError` (patterns denote byte
  languages).
- The quantifiers `*`, `+`, `?`; alternation `|`; groups `(...)`, nested and
  quantified (`(ab)+`).
- Character classes `[abc]`, ranges `[a-z]`, several ranges `[a-cx-z]`, negated
  classes `[^a]`, and a literal `-` at either end (`[-a]`, `[a-]`). Punctuation
  is literal inside a class, `[{}$.*|(]` included.
- The escapes `\n`, `\t`, `\r`, `\0` (NUL), `\xHH` (exactly two hex digits),
  `\d` (`[0-9]`), `\w` (`[0-9A-Za-z_]`), and `\s` (tab, newline, carriage
  return, space; not `\v` or `\f`), plus a backslash before any punctuation
  character for that literal character (`\.`, `\\`, `\{`, `\$`, ...).
- `^` at the start and `$` at the end of a whole-value alternative
  (`^a$|^b$`). Nested groups are allowed when their surrounding alternative
  also starts or ends there (`^(^a|^b)$`, `a(b$|c$)`). Anchors cannot occur
  inside quantified groups. They are optional: `a`, `^a`, `a$`, and `^a$`
  denote the same language.

Rejected by `RegexFormat` with `ValueError` before compilation, because
regex2dfa would silently misread them (as literal text, or by dropping or
rebinding them):

- Brace quantifiers `{n}`, `{n,m}`, `{n,}`, `{,m}`: any unescaped `{` outside a
  class. Write `\{` or `[{]` for a literal brace; `}` on its own is fine.
- Every other backslash-letter or backslash-digit escape: `\D`, `\S`, `\W`,
  `\b`, `\B`, `\A`, `\Z`, `\f`, `\v`, `\a`, `\e`, `\u...`, `\p{...}`,
  `\Q...\E`, backreferences `\1`..`\9`, and so on. regex2dfa does not support
  them (it compiles most to the bare letter or digit, and `\C` to any byte).
  Spell the class out instead (`[^0-9]` for `\D`).
- Octal escapes (`\012`) and `\x` with fewer than two hex digits.
- A backslash inside a character class (`[\d]`, `[\n]`, `[\]]`, `[\\]`):
  regex2dfa has no escapes inside `[...]`, so the backslash is a literal
  backslash and the first `]` still closes the class. Write the escape outside
  the class, or put the actual character in the string (`'[\t ]'` in a non-raw
  Python string).
- An empty class `[]` or `[^]` (the first `]` always closes the class), and
  POSIX classes like `[[:alpha:]]`.
- `^` or `$` away from the start or end of a whole-value alternative
  (`^a$b$`, `a(^b)$`, `^(a$)b$`, `^(a$|b)c$`): regex2dfa drops them. A group
  boundary does not make an anchor valid when an enclosing alternative has
  preceding or following atoms. Optional atoms count too: `a?(^b)` and
  `(a$)b?` are rejected. Write `\^` or `[$]` for the literal
  character. A `\$` at the very end of the pattern is rejected too: regex2dfa
  strips the final `$` before parsing, and the dangling backslash would become
  a NUL byte. Write `\$$` or `[$]` instead. A pattern ending in a bare
  backslash is rejected for the same reason.
- Quantified anchors (`^+a`) and any group containing an anchor that is
  quantified with `*`, `+`, or `?` (`(^a)+`, `((a$)|b)*`, `(^a)?`). This is a
  conservative syntax rule: regex2dfa discards assertions rather than enforcing
  them on each repetition. Optional whole-value anchors belong outside the
  quantified group, as in `^(a)+$`.
- Empty alternatives (`a|`, `|a`, `a||b`, `(|a)`, `(a|)`): regex2dfa rejects
  most of them, but one right before `)` silently folds the atom before the
  group into the alternation (`x(b|)y` becomes `(x|b)y`). Write `?` after a
  group for an optional group (`x(b)?y`).
- An empty group `()`: regex2dfa applies a quantifier after it to the
  preceding atom instead (`a()*` becomes `a*`).

regex2dfa rejects the rest itself, and `RegexFormat` reports that as
`ValueError` too: lazy and possessive quantifiers (`a+?`, `a*+`), every `(?...)`
form (non-capturing groups, flags, lookaround, named groups), unclosed classes,
reversed ranges, and patterns matching only the empty string (`^$`).

## Compatibility

Equivalent patterns rank identically for the same length bounds, but their
fingerprints depend on the pattern text. Deterministic encryption requires the
same pattern text and bounds at both endpoints. See the
[provider compatibility rules](../../../docs/formats.md#compatibility).

Older releases accepted some internal and quantified anchors that regex2dfa
ignored. These patterns now raise `ValueError`; the library does not reinterpret
them. For new data, choose a supported pattern that describes the intended
whole-value language. For existing ciphertext, retain the original library
version, pattern text, and length bounds in a legacy reader, then decrypt and
re-encrypt into the new format. Do not simply rewrite the pattern used to read
existing FF1 ciphertext: even a language-equivalent rewrite changes the format
fingerprint and therefore the encryption mapping.

## Implementation

[format.py](format.py) implements the provider using the Goldberg-Sipser ranker
in [_dfa.py](_dfa.py). The DFA implementation is private. To implement another
format, see the
[provider contract](../../../docs/formats.md) and
[custom provider example](../../../examples/08_custom_format.py).
