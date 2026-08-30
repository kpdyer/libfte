"""The 2x2 engine matrix: {ff1/object, ae} x {input==output, input!=output}.

These tests exercise :class:`fte.FTE` end to end without the real ``ffx``
package. The deterministic cells use a duck-typed *toy* cipher object -- any
object exposing ``encrypt_int(x, *, domain, tweak) -> int`` and
``decrypt_int(y, *, domain, tweak) -> int`` forming a permutation of
``range(domain)`` is a valid cipher, which is both the test seam and the public
extension point. The AE cells use the real, wire-frozen authenticated path over
:class:`~fte.formats.regex.RegexFormat`.

Formats here are tiny, hand-built list formats so every domain can be brute
forced. Their cardinalities sit below the format-preserving floor on purpose, so
the deterministic cells pass ``allow_small_domain=True`` (floor 100); the
``SmallDomainError`` behavior is checked directly.
"""

import hashlib
import itertools
import random
import unittest

import fte
from fte.core import (
    FTE,
    FormatCapacityError,
    InvalidCovertextError,
    InvalidPlaintextError,
    SmallDomainError,
)


class ToyCipher:
    """A deterministic, tweakable permutation of ``range(domain)`` for tests.

    For each ``(domain, tweak)`` it derives a fixed shuffle of ``range(domain)``
    from a seeded PRNG and looks values up in that permutation (and its inverse).
    It is a genuine bijection, deterministic in its inputs, and separated by
    tweak -- everything the engine asks of a cipher object and nothing more. The
    ``key`` argument the engine passes to ``FTE`` is ignored: an object cipher
    carries its own key.
    """

    def __init__(self, key=b"toy-key"):
        self._key = key
        self._cache = {}

    def _perm(self, domain, tweak):
        cache_key = (domain, tweak)
        perm = self._cache.get(cache_key)
        if perm is None:
            seed = hashlib.sha256(
                self._key + b"|" + tweak + b"|" + str(domain).encode()
            ).digest()
            rng = random.Random(seed)
            forward = list(range(domain))
            rng.shuffle(forward)
            inverse = [0] * domain
            for i, v in enumerate(forward):
                inverse[v] = i
            perm = (forward, inverse)
            self._cache[cache_key] = perm
        return perm

    def encrypt_int(self, x, *, domain, tweak):
        forward, _ = self._perm(domain, tweak)
        return forward[x]

    def decrypt_int(self, y, *, domain, tweak):
        _, inverse = self._perm(domain, tweak)
        return inverse[y]


class ListFormat:
    """A finite ``RankedFormat`` over an explicit list of distinct values."""

    def __init__(self, values, *, fingerprint):
        self._values = list(values)
        self._index = {v: i for i, v in enumerate(self._values)}
        if len(self._index) != len(self._values):
            raise ValueError("values must be distinct")
        self.cardinality = len(self._values)
        self.fingerprint = fingerprint

    def rank(self, value, /):
        try:
            return self._index[value]
        except (KeyError, TypeError):
            raise ValueError(f"{value!r} is not a member of this format")

    def unrank(self, index, /):
        if type(index) is not int or not 0 <= index < self.cardinality:
            raise ValueError(f"index {index!r} out of range")
        return self._values[index]


class SlicedListFormat:
    """A finite ``SlicedRankedFormat``: values grouped into length slices.

    ``per_length`` maps each length to the (distinct, that-length) values in it.
    Values are laid out length-first, so a value's global rank falls inside its
    length slice, which is exactly what ``preserve_length`` needs.
    """

    def __init__(self, per_length, *, fingerprint):
        self.min_length = min(per_length)
        self.max_length = max(per_length)
        self.fingerprint = fingerprint
        self._values = []
        self._offsets = {}
        self._counts = {}
        cumulative = 0
        for length in range(self.min_length, self.max_length + 1):
            values = list(per_length.get(length, []))
            for v in values:
                if len(v) != length:
                    raise ValueError("value length must match its slice")
            self._offsets[length] = cumulative
            self._counts[length] = len(values)
            self._values.extend(values)
            cumulative += len(values)
        self.cardinality = cumulative
        self._index = {v: i for i, v in enumerate(self._values)}

    def slice_bounds(self, length, /):
        if length < self.min_length or length > self.max_length:
            raise ValueError(
                f"length {length} outside "
                f"[{self.min_length}, {self.max_length}]"
            )
        return self._offsets[length], self._counts[length]

    def rank(self, value, /):
        try:
            return self._index[value]
        except (KeyError, TypeError):
            raise ValueError(f"{value!r} is not a member of this format")

    def unrank(self, index, /):
        if type(index) is not int or not 0 <= index < self.cardinality:
            raise ValueError(f"index {index!r} out of range")
        return self._values[index]


def _list_format(prefix, n, fingerprint):
    return ListFormat(
        [f"{prefix}{i:04d}" for i in range(n)], fingerprint=fingerprint
    )


def _sliced_format(alphabet, lengths, fingerprint):
    per_length = {
        length: ["".join(p) for p in itertools.product(alphabet, repeat=length)]
        for length in lengths
    }
    return SlicedListFormat(per_length, fingerprint=fingerprint)


KEY_AE = bytes(range(32))
KEY_UNUSED = b"ignored-for-object-cipher"
# A regex output roomy enough to hold any AE frame in these tests.
BIG_HEX = fte.RegexFormat(r"^[0-9a-f]+$", length=256)


class Tests(unittest.TestCase):
    # ---- deterministic, input == output (FPE cell) --------------------- #
    def test_deterministic_fpe_roundtrip_and_membership(self):
        fmt = _list_format("v", 200, b"fp:v200")
        eng = FTE(
            input_format=fmt,
            output_format=fmt,
            cipher=ToyCipher(),
            key=KEY_UNUSED,
            allow_small_domain=True,
        )
        self.assertEqual(eng.cipher, "deterministic")
        for i in range(fmt.cardinality):
            pt = fmt.unrank(i)
            ct = eng.encrypt(pt)
            self.assertIn(ct, fmt._values)  # covertext stays in the format
            self.assertEqual(eng.decrypt(ct), pt)

    def test_deterministic_is_deterministic_and_a_permutation(self):
        fmt = _list_format("v", 200, b"fp:v200")
        eng = FTE(
            input_format=fmt,
            output_format=fmt,
            cipher=ToyCipher(),
            key=KEY_UNUSED,
            allow_small_domain=True,
        )
        first = [eng.encrypt(fmt.unrank(i)) for i in range(fmt.cardinality)]
        second = [eng.encrypt(fmt.unrank(i)) for i in range(fmt.cardinality)]
        self.assertEqual(first, second)  # deterministic
        self.assertEqual(set(first), set(fmt._values))  # a permutation

    def test_deterministic_tweak_separation(self):
        fmt = _list_format("v", 200, b"fp:v200")
        eng = FTE(
            input_format=fmt,
            output_format=fmt,
            cipher=ToyCipher(),
            key=KEY_UNUSED,
            allow_small_domain=True,
        )
        by_tweak_a = [
            eng.encrypt(fmt.unrank(i), tweak=b"record-A")
            for i in range(fmt.cardinality)
        ]
        by_tweak_b = [
            eng.encrypt(fmt.unrank(i), tweak=b"record-B")
            for i in range(fmt.cardinality)
        ]
        self.assertNotEqual(by_tweak_a, by_tweak_b)
        # Each tweak still round-trips under its own tweak.
        for i in range(fmt.cardinality):
            self.assertEqual(
                eng.decrypt(by_tweak_a[i], tweak=b"record-A"), fmt.unrank(i)
            )

    # ---- deterministic, input != output (rank-map FTE cell) ------------ #
    def test_deterministic_cross_format_roundtrip(self):
        fin = _list_format("i", 120, b"fp:in120")
        fout = _list_format("o", 200, b"fp:out200")
        eng = FTE(
            input_format=fin,
            output_format=fout,
            cipher=ToyCipher(),
            key=KEY_UNUSED,
            allow_small_domain=True,
        )
        for i in range(fin.cardinality):
            pt = fin.unrank(i)
            ct = eng.encrypt(pt)
            self.assertIn(ct, fout._values)
            self.assertEqual(eng.decrypt(ct), pt)

    def test_deterministic_cross_format_injectivity_rejection(self):
        # Covertexts whose deciphered rank is >= N_in were never valid inputs.
        fin = _list_format("i", 120, b"fp:in120")
        fout = _list_format("o", 200, b"fp:out200")
        eng = FTE(
            input_format=fin,
            output_format=fout,
            cipher=ToyCipher(),
            key=KEY_UNUSED,
            allow_small_domain=True,
        )
        valid = {eng.encrypt(fin.unrank(i)) for i in range(fin.cardinality)}
        rejected = 0
        for value in fout._values:
            if value in valid:
                continue
            with self.assertRaises(InvalidCovertextError):
                eng.decrypt(value)
            rejected += 1
        # Exactly the surplus covertexts are unreachable.
        self.assertEqual(rejected, fout.cardinality - fin.cardinality)

    def test_deterministic_equal_cardinality_cross_format(self):
        # Different fingerprints but equal size: still a clean bijection.
        fin = _list_format("i", 200, b"fp:eqA")
        fout = _list_format("o", 200, b"fp:eqB")
        eng = FTE(
            input_format=fin,
            output_format=fout,
            cipher=ToyCipher(),
            key=KEY_UNUSED,
            allow_small_domain=True,
        )
        covertexts = {eng.encrypt(fin.unrank(i)) for i in range(200)}
        self.assertEqual(covertexts, set(fout._values))

    # ---- deterministic, preserve_length -------------------------------- #
    def test_preserve_length_across_multiple_lengths(self):
        fmt = _sliced_format("abcde", (3, 4), b"fp:sliced-abcde-3-4")
        eng = FTE(
            input_format=fmt,
            output_format=fmt,
            cipher=ToyCipher(),
            key=KEY_UNUSED,
            preserve_length=True,
            allow_small_domain=True,
        )
        self.assertTrue(eng.preserve_length)
        for pt in fmt._values:
            ct = eng.encrypt(pt)
            self.assertEqual(len(ct), len(pt))  # length preserved in place
            self.assertIn(ct, fmt._values)
            self.assertEqual(eng.decrypt(ct), pt)

    def test_preserve_length_permutes_each_slice_independently(self):
        fmt = _sliced_format("abcde", (3, 4), b"fp:sliced-abcde-3-4")
        eng = FTE(
            input_format=fmt,
            output_format=fmt,
            cipher=ToyCipher(),
            key=KEY_UNUSED,
            preserve_length=True,
            allow_small_domain=True,
        )
        for length in (3, 4):
            slice_values = [v for v in fmt._values if len(v) == length]
            covertexts = {eng.encrypt(v) for v in slice_values}
            # A permutation of exactly that length's slice.
            self.assertEqual(covertexts, set(slice_values))

    def test_preserve_length_tweak_carries_length(self):
        # Distinct tweaks separate outputs even within one length slice.
        fmt = _sliced_format("abcde", (3, 4), b"fp:sliced-abcde-3-4")
        eng = FTE(
            input_format=fmt,
            output_format=fmt,
            cipher=ToyCipher(),
            key=KEY_UNUSED,
            preserve_length=True,
            allow_small_domain=True,
        )
        a = eng.encrypt("abc", tweak=b"one")
        b = eng.encrypt("abc", tweak=b"two")
        self.assertNotEqual(a, b)
        self.assertEqual(eng.decrypt(a, tweak=b"one"), "abc")
        self.assertEqual(eng.decrypt(b, tweak=b"two"), "abc")

    # ---- AE cell, bytes input (classic FTE) ---------------------------- #
    def test_ae_bytes_roundtrip_is_randomized_and_authenticated(self):
        eng = FTE(output_format=BIG_HEX, key=KEY_AE)
        self.assertEqual(eng.cipher, "aes-ctr-hmac")
        ct1 = eng.encrypt(b"attack at dawn")
        ct2 = eng.encrypt(b"attack at dawn")
        self.assertNotEqual(ct1, ct2)  # re-drawn per call
        self.assertEqual(eng.decrypt(ct1), b"attack at dawn")
        self.assertEqual(eng.decrypt(ct2), b"attack at dawn")

    def test_ae_bytes_wrong_key_and_tamper_rejected(self):
        eng = FTE(output_format=BIG_HEX, key=KEY_AE)
        ct = eng.encrypt(b"secret")
        other = FTE(output_format=BIG_HEX, key=bytes(range(32, 64)))
        with self.assertRaises(InvalidCovertextError):
            other.decrypt(ct)
        # Any other in-format value fails authentication.
        forged = BIG_HEX.unrank((BIG_HEX.rank(ct) + 1) % BIG_HEX.cardinality)
        with self.assertRaises(InvalidCovertextError):
            eng.decrypt(forged)

    # ---- AE cell, non-bytes input -------------------------------------- #
    def test_ae_non_bytes_roundtrip_via_rank_serialization(self):
        digits = fte.RegexFormat(r"^[0-9]+$", length=6)
        eng = FTE(input_format=digits, output_format=BIG_HEX, cipher="aes-ctr-hmac",
                  key=KEY_AE)
        ct1 = eng.encrypt(b"012345")
        ct2 = eng.encrypt(b"012345")
        self.assertNotEqual(ct1, ct2)  # randomized for non-bytes too
        self.assertEqual(eng.decrypt(ct1), b"012345")
        self.assertEqual(eng.decrypt(ct2), b"012345")

    def test_ae_non_bytes_capacity_checked_at_init(self):
        # A finite input whose largest frame the tiny output cannot hold.
        digits = fte.RegexFormat(r"^[0-9]+$", length=6)
        tiny = fte.RegexFormat(r"^[0-9a-f]+$", length=8)  # only 4 payload bytes
        with self.assertRaises(FormatCapacityError):
            FTE(input_format=digits, output_format=tiny, cipher="aes-ctr-hmac",
                key=KEY_AE)

    # ---- ValueError / error matrix for bad configs --------------------- #
    def test_tweak_with_ae_is_rejected(self):
        eng = FTE(output_format=BIG_HEX, key=KEY_AE)
        with self.assertRaises(ValueError):
            eng.encrypt(b"x", tweak=b"nope")
        with self.assertRaises(ValueError):
            eng.decrypt(eng.encrypt(b"x"), tweak=b"nope")

    def test_preserve_length_cross_format_is_rejected(self):
        fin = _list_format("i", 200, b"fp:pA")
        fout = _list_format("o", 200, b"fp:pB")
        with self.assertRaises(ValueError):
            FTE(input_format=fin, output_format=fout, cipher=ToyCipher(),
                key=KEY_UNUSED, preserve_length=True, allow_small_domain=True)

    def test_preserve_length_requires_slice_bounds(self):
        fmt = _list_format("v", 200, b"fp:noslice")  # no slice_bounds()
        with self.assertRaises(ValueError):
            FTE(input_format=fmt, output_format=fmt, cipher=ToyCipher(),
                key=KEY_UNUSED, preserve_length=True, allow_small_domain=True)

    def test_preserve_length_with_ae_is_rejected(self):
        with self.assertRaises(ValueError):
            FTE(output_format=BIG_HEX, key=KEY_AE, preserve_length=True)

    def test_missing_cipher_for_cross_format_is_rejected(self):
        fin = _list_format("i", 200, b"fp:mA")
        fout = _list_format("o", 200, b"fp:mB")
        with self.assertRaises(ValueError):
            FTE(input_format=fin, output_format=fout, key=KEY_UNUSED,
                allow_small_domain=True)

    def test_ae_key_must_be_32_bytes(self):
        with self.assertRaises(ValueError):
            FTE(output_format=BIG_HEX, key=b"too-short")
        with self.assertRaises(ValueError):
            FTE(output_format=BIG_HEX, key=bytes(31))

    def test_max_plaintext_bytes_rejected_for_non_bytes_input(self):
        digits = fte.RegexFormat(r"^[0-9]+$", length=6)
        with self.assertRaises(ValueError):
            FTE(input_format=digits, output_format=BIG_HEX, cipher="aes-ctr-hmac",
                key=KEY_AE, max_plaintext_bytes=8)

    def test_legacy_format_alias_removed(self):
        with self.assertRaises(TypeError):
            FTE(format=BIG_HEX, key=KEY_AE)

    def test_exactly_one_output_format_required(self):
        with self.assertRaises(ValueError):
            FTE(key=KEY_AE)

    # ---- SmallDomainError and allow_small_domain ----------------------- #
    def test_small_domain_without_flag_raises(self):
        fmt = _list_format("v", 200, b"fp:small")
        with self.assertRaises(SmallDomainError):
            FTE(input_format=fmt, output_format=fmt, cipher=ToyCipher(),
                key=KEY_UNUSED)

    def test_small_domain_flag_lowers_floor_to_100(self):
        ok = _list_format("v", 100, b"fp:exactly100")
        # 100 meets the lowered floor; construction succeeds and round-trips.
        eng = FTE(input_format=ok, output_format=ok, cipher=ToyCipher(),
                  key=KEY_UNUSED, allow_small_domain=True)
        self.assertEqual(eng.decrypt(eng.encrypt("v0005")), "v0005")

        too_small = _list_format("v", 99, b"fp:below100")
        with self.assertRaises(SmallDomainError):
            FTE(input_format=too_small, output_format=too_small,
                cipher=ToyCipher(), key=KEY_UNUSED, allow_small_domain=True)

    def test_small_domain_preserve_length_names_offending_lengths(self):
        # Length-2 slice (25 words) is below the floor of 100; length-3 (125) is
        # above it. The error should name only the offending length.
        fmt = _sliced_format("abcde", (2, 3), b"fp:mixed-slices")
        with self.assertRaises(SmallDomainError) as caught:
            FTE(input_format=fmt, output_format=fmt, cipher=ToyCipher(),
                key=KEY_UNUSED, preserve_length=True, allow_small_domain=True)
        self.assertIn("2", str(caught.exception))

    # ---- capacity and injectivity at init ------------------------------ #
    def test_input_larger_than_output_rejected_at_init(self):
        fin = _list_format("i", 300, b"fp:big")
        fout = _list_format("o", 200, b"fp:small")
        with self.assertRaises(FormatCapacityError):
            FTE(input_format=fin, output_format=fout, cipher=ToyCipher(),
                key=KEY_UNUSED, allow_small_domain=True)

    def test_deterministic_requires_finite_formats(self):
        # BytesFormat is unbounded (no cardinality): invalid for deterministic.
        fmt = _list_format("v", 200, b"fp:v200")
        with self.assertRaises(FormatCapacityError):
            FTE(input_format=fte.BytesFormat(), output_format=fmt,
                cipher=ToyCipher(), key=KEY_UNUSED, allow_small_domain=True)

    def test_invalid_plaintext_rejected(self):
        fmt = _list_format("v", 200, b"fp:v200")
        eng = FTE(input_format=fmt, output_format=fmt, cipher=ToyCipher(),
                  key=KEY_UNUSED, allow_small_domain=True)
        with self.assertRaises(InvalidPlaintextError):
            eng.encrypt("not-a-member")


if __name__ == "__main__":
    unittest.main()
