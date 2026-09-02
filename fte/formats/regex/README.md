# `fte.formats.regex`

The built-in ranked-format provider, and the reference implementation to copy
when you write your own. `RegexFormat` compiles a pattern into a format, a
ranked slice of the byte language the pattern denotes, so `fte.FTE` ciphertext
comes out looking like the pattern you chose: hex, alphanumeric tokens, URL
paths, lowercase words, and so on.

## Example

```python
import fte

# Every covertext is exactly 72 bytes of lowercase hex.
cipher = fte.FTE(
    output_format=fte.RegexFormat(r'^[0-9a-f]+$', length=72),
    key=bytes(range(32)),               # demo key; share a real secret
)

covertext = cipher.encrypt(b'secret')
# 72 hex chars, different on every run (the frame carries a random nonce), e.g.
# b'00029c3526a6938e1c4d94eaa379c2f5380e9aa1ec1a82e114df39e9bbe953862b57b18b'
assert cipher.decrypt(covertext) == b'secret'
```

The leading zeros are the format's spare capacity: the frame for a 6-byte
message is a little smaller than the largest 72-digit hex number, so the top
digits come out zero. A message closer to `cipher.max_plaintext_bytes` fills
them.

## Fixed vs variable length

A pattern like `^[0-9a-f]+$` denotes an infinite language, so you bound it to
make it rankable. There are two ways:

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

The covertext has to be big enough to hold FTE's authenticated frame: a fixed
29-byte overhead (1 version byte, a 12-byte random nonce, and a 16-byte
HMAC-SHA256 tag) plus the message. If the format is too small for even an empty
message, `fte.FTE(...)` raises `FormatCapacityError` at construction. As a rule
of thumb, capacity grows with the alphabet size and the length: the hex format
above holds up to 7 plaintext bytes at `length=72` and 35 at `length=128`
(`cipher.max_plaintext_bytes`). Construction also raises `ValueError` if the
language has no words in the requested length range.

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
- `^` at the start and `$` at the end of the pattern or of an alternative
  (`^a$|^b$`). They are optional: `a`, `^a`, `a$`, and `^a$` denote the same
  language.

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
- `^` or `$` anywhere but the start or end of the pattern or of an alternative
  (`^a$b$`): regex2dfa drops them. Write `\^` or `[$]` for the literal
  character. A `\$` at the very end of the pattern is rejected too: regex2dfa
  strips the final `$` before parsing, and the dangling backslash would become
  a NUL byte. Write `\$$` or `[$]` instead. A pattern ending in a bare
  backslash is rejected for the same reason.
- Empty alternatives (`a|`, `|a`, `a||b`, `(|a)`, `(a|)`): regex2dfa rejects
  most of them, but one right before `)` silently folds the atom before the
  group into the alternation (`x(b|)y` becomes `(x|b)y`). Write `?` after a
  group for an optional group (`x(b)?y`).
- An empty group `()`: regex2dfa applies a quantifier after it to the
  preceding atom instead (`a()*` becomes `a*`).

regex2dfa rejects the rest itself, and `RegexFormat` reports that as
`ValueError` too: lazy and possessive quantifiers (`a+?`, `a*+`), every `(?...)`
form (non-capturing groups, flags, lookaround, named groups), unclosed classes,
reversed ranges, and patterns denoting the empty language (`^$`).

## What's in here

- [`format.py`](format.py): `RegexFormat`, the provider. Its whole job is the two
  inverse methods every ranked format owes the engine, `rank` and `unrank`, plus
  a `cardinality`. There is no cryptography here.
- [`dfa.py`](dfa.py): the Goldberg-Sipser DFA ranker that `RegexFormat` is built
  on. It counts and ranks the words of the language by length.

The engine (`fte.FTE`) owns encryption, authentication, and framing; this
subpackage owns only the ranking of the covertext language. That separation is
exactly what makes a new provider easy to add.

Because `regex2dfa` produces a minimized DFA, two patterns denoting the same
language rank identically: the format depends on the language and length
bounds, not on the pattern's spelling.

## Writing your own provider

`RegexFormat` is just one implementation of the structural `RankedFormat`
contract (any object with reversible `rank`/`unrank`). To target a covertext
language no regex denotes, write your own provider. See the
[ranked-format provider guide](../../../docs/formats.md) for the contract and a
conformance checklist, and `examples/08_custom_format.py` for a small worked
provider.
