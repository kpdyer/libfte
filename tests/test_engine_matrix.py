"""The 2x2 engine matrix: {ff1/object, aes-ctr-hmac} x {input==output, input!=output}.

The matrix exercises :class:`fte.FTE` end to end without the real ``ffx``
package. The deterministic cells use a duck-typed *toy* cipher object -- any
object exposing ``encrypt_int(x, *, domain, tweak) -> int`` and
``decrypt_int(y, *, domain, tweak) -> int`` forming a permutation of
``range(domain)`` is accepted by the deprecated object-cipher path. These tests
retain coverage of that behavior during migration. The AE cells use the real,
wire-frozen authenticated path over :class:`~fte.formats.regex.RegexFormat`.
The focused deprecation checks also construct the real named ciphers.

The deterministic domain floor (one million) is always enforced, so the formats
here are *computed* decimal-string languages large enough to clear it, and the
deterministic assertions sample rather than enumerate.
"""

import hashlib
import inspect
import math
import unittest
import warnings

import fte
from fte import frame
from fte.core import (
    FTE,
    FormatCapacityError,
    InvalidCovertextError,
    InvalidPlaintextError,
    SmallDomainError,
)


class ToyCipher:
    """A deterministic, tweakable permutation of ``range(domain)`` for tests.

    For each ``(domain, tweak)`` it derives an affine map ``x -> (a*x + b) mod
    domain`` with ``a`` coprime to ``domain`` (so it is a genuine bijection),
    seeded from the key, the tweak, and the domain. It is deterministic in its
    inputs and separated by tweak -- everything the engine asks of a cipher
    object and nothing more, in O(1) per call so million-element domains stay
    cheap. The ``key`` the engine passes to ``FTE`` is ignored: an object cipher
    carries its own key.
    """

    def __init__(self, key=b"toy-key"):
        self._key = key
        self._cache = {}

    def _params(self, domain, tweak):
        cache_key = (domain, tweak)
        params = self._cache.get(cache_key)
        if params is None:
            seed = int.from_bytes(
                hashlib.sha256(
                    self._key + b"|" + tweak + b"|" + str(domain).encode()
                ).digest(),
                "big",
            )
            a = (seed % domain) or 1
            while math.gcd(a, domain) != 1:
                a += 1
                if a >= domain:
                    a = 1
            b = (seed // domain) % domain
            a_inv = pow(a, -1, domain)
            params = (a, b, a_inv)
            self._cache[cache_key] = params
        return params

    def encrypt_int(self, x, *, domain, tweak):
        a, b, _ = self._params(domain, tweak)
        return (a * x + b) % domain

    def decrypt_int(self, y, *, domain, tweak):
        a, b, a_inv = self._params(domain, tweak)
        return (a_inv * (y - b)) % domain


class DigitsFormat:
    """Fixed-length decimal strings: a computed ``SlicedRankedFormat``.

    Cardinality is ``10 ** length`` (one length slice), so length 6 sits exactly
    on the one-million floor and longer lengths clear it comfortably.
    """

    def __init__(self, length, *, fingerprint):
        self.min_length = length
        self.max_length = length
        self._length = length
        self.cardinality = 10 ** length
        self.fingerprint = fingerprint

    def slice_bounds(self, length, /):
        if length != self._length:
            raise ValueError(f"length {length} outside [{self._length}]")
        return 0, self.cardinality

    def rank(self, value, /):
        if (
            type(value) is not str
            or len(value) != self._length
            or not value.isascii()
            or not value.isdigit()
        ):
            raise ValueError(f"{value!r} is not a member of this format")
        return int(value)

    def unrank(self, index, /):
        if type(index) is not int or not 0 <= index < self.cardinality:
            raise ValueError(f"index {index!r} out of range")
        return str(index).zfill(self._length)


class RangeDigitsFormat:
    """Variable-length decimal strings over ``[lo, hi]``, computed.

    Length ``L`` holds ``10 ** L`` words; the rank space is laid out length-first
    so a value's global rank falls inside its own length slice.
    """

    def __init__(self, lo, hi, *, fingerprint):
        self.min_length = lo
        self.max_length = hi
        self.fingerprint = fingerprint
        offset = 0
        self._offsets = {}
        self._counts = {}
        for length in range(lo, hi + 1):
            count = 10 ** length
            self._offsets[length] = offset
            self._counts[length] = count
            offset += count
        self.cardinality = offset

    def slice_bounds(self, length, /):
        if length < self.min_length or length > self.max_length:
            raise ValueError(
                f"length {length} outside [{self.min_length}, {self.max_length}]"
            )
        return self._offsets[length], self._counts[length]

    def rank(self, value, /):
        if type(value) is not str or not value.isascii() or not value.isdigit():
            raise ValueError(f"{value!r} is not a member of this format")
        length = len(value)
        if length < self.min_length or length > self.max_length:
            raise ValueError(f"{value!r} has an unsupported length")
        return self._offsets[length] + int(value)

    def unrank(self, index, /):
        if type(index) is not int or not 0 <= index < self.cardinality:
            raise ValueError(f"index {index!r} out of range")
        for length in range(self.min_length, self.max_length + 1):
            count = self._counts[length]
            if index < count:
                return str(index).zfill(length)
            index -= count
        raise AssertionError("unreachable")


class NoSliceDigitsFormat:
    """Fixed-length decimal strings with **no** ``slice_bounds`` (no length API).

    An equal-fingerprint pair of these exercises the global fallback: the engine
    cannot preserve length, so it permutes the whole cardinality instead.
    """

    def __init__(self, length, *, fingerprint):
        self._length = length
        self.cardinality = 10 ** length
        self.fingerprint = fingerprint

    def rank(self, value, /):
        if (
            type(value) is not str
            or len(value) != self._length
            or not value.isascii()
            or not value.isdigit()
        ):
            raise ValueError(f"{value!r} is not a member of this format")
        return int(value)

    def unrank(self, index, /):
        if type(index) is not int or not 0 <= index < self.cardinality:
            raise ValueError(f"index {index!r} out of range")
        return str(index).zfill(self._length)


class CountFormat:
    """The integers ``range(n)`` as their own ranks: a minimal finite format."""

    def __init__(self, n):
        self.cardinality = n

    def rank(self, value, /):
        if type(value) is not int or not 0 <= value < self.cardinality:
            raise ValueError(f"{value!r} is not a member of this format")
        return value

    def unrank(self, index, /):
        if type(index) is not int or not 0 <= index < self.cardinality:
            raise ValueError(f"index {index!r} out of range")
        return index


# A deterministic spread of distinct ranks to sample from a large domain.
def _sample_ranks(n, count=64):
    if n <= count:
        return list(range(n))
    step = max(1, n // count)
    seen = {}
    for i in range(count):
        seen[(i * step) % n] = None
    seen[0] = None
    seen[n - 1] = None
    return list(seen)


KEY_AE = bytes(range(32))
KEY_UNUSED = b"ignored-for-object-cipher"
# A regex output roomy enough to hold any AE frame in these tests.
BIG_HEX = fte.RegexFormat(r"^[0-9a-f]+$", length=256)


class CustomCipherDeprecation(unittest.TestCase):
    def test_warning_points_to_constructor_caller_and_occurs_once(self):
        fmt = DigitsFormat(6, fingerprint=b"fp:legacy-custom")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            call_line = inspect.currentframe().f_lineno + 1
            eng = FTE(input_format=fmt, output_format=fmt,
                      cipher=ToyCipher(), key=b"")
            self.assertEqual(eng.decrypt(eng.encrypt("123456")), "123456")
        self.assertEqual(len(caught), 1)
        self.assertIs(caught[0].category, DeprecationWarning)
        self.assertIn(
            "Passing a cipher object to FTE is deprecated", str(caught[0].message)
        )
        self.assertIn("existing", str(caught[0].message))
        self.assertEqual(caught[0].filename, __file__)
        self.assertEqual(caught[0].lineno, call_line)

    def test_existing_custom_cipher_covertexts_and_key_ownership_are_preserved(self):
        fmt = DigitsFormat(6, fingerprint=b"fp:legacy-custom")
        # Frozen before deprecation, using ToyCipher's own default key.
        vectors = [
            ("000000", b"", "214186"),
            ("123456", b"record-A", "889261"),
            ("999999", b"", "164859"),
        ]
        for key in (b"", bytes(range(32))):
            with self.subTest(key=key):
                with self.assertWarns(DeprecationWarning):
                    eng = FTE(input_format=fmt, output_format=fmt,
                              cipher=ToyCipher(), key=key)
                for plaintext, tweak, covertext in vectors:
                    self.assertEqual(eng.encrypt(plaintext, tweak=tweak), covertext)
                    self.assertEqual(eng.decrypt(covertext, tweak=tweak), plaintext)

    def test_named_ciphers_and_default_bytes_input_do_not_warn(self):
        fmt = DigitsFormat(6, fingerprint=b"fp:d6")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            eng = FTE(input_format=fmt, output_format=fmt,
                      cipher="ff1", key=bytes(range(16)))
            self.assertEqual(eng.decrypt(eng.encrypt("123456")), "123456")
            for cipher in ("aes-ctr-hmac", None):
                eng = FTE(output_format=BIG_HEX, cipher=cipher, key=KEY_AE)
                self.assertEqual(eng.decrypt(eng.encrypt(b"hello")), b"hello")
        self.assertEqual(caught, [])

    def test_invalid_objects_are_rejected_without_deprecation_warning(self):
        fmt = DigitsFormat(6, fingerprint=b"fp:d6")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertRaisesRegex(TypeError, "callable encrypt_int"):
                FTE(input_format=fmt, output_format=fmt, cipher=object(), key=b"")
            small = DigitsFormat(5, fingerprint=b"fp:d5")
            with self.assertRaises(SmallDomainError):
                FTE(input_format=small, output_format=small,
                    cipher=ToyCipher(), key=b"")
        self.assertEqual(caught, [])


class Tests(unittest.TestCase):
    def setUp(self):
        # The matrix keeps exercising legacy object behavior. Warning behavior
        # is asserted separately above; do not hide any other deprecation.
        context = warnings.catch_warnings()
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        warnings.filterwarnings(
            "ignore", message="Passing a cipher object to FTE is deprecated;",
            category=DeprecationWarning,
        )

    # ---- deterministic, input == output (FPE cell) --------------------- #
    def test_deterministic_fpe_roundtrip_and_membership(self):
        fmt = DigitsFormat(6, fingerprint=b"fp:d6")
        eng = FTE(input_format=fmt, output_format=fmt,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        self.assertEqual(eng.cipher, "deterministic")
        self.assertTrue(eng.preserve_length)  # equal format + slice_bounds
        for i in _sample_ranks(fmt.cardinality):
            pt = fmt.unrank(i)
            ct = eng.encrypt(pt)
            self.assertEqual(len(ct), len(pt))
            self.assertEqual(fmt.rank(ct), fmt.rank(ct))  # ct is in the format
            self.assertEqual(eng.decrypt(ct), pt)

    def test_deterministic_is_deterministic_and_injective(self):
        fmt = DigitsFormat(6, fingerprint=b"fp:d6")
        eng = FTE(input_format=fmt, output_format=fmt,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        sample = _sample_ranks(fmt.cardinality)
        first = [eng.encrypt(fmt.unrank(i)) for i in sample]
        second = [eng.encrypt(fmt.unrank(i)) for i in sample]
        self.assertEqual(first, second)              # deterministic
        self.assertEqual(len(set(first)), len(first))  # injective on the sample

    def test_deterministic_tweak_separation(self):
        fmt = DigitsFormat(6, fingerprint=b"fp:d6")
        eng = FTE(input_format=fmt, output_format=fmt,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        a = [eng.encrypt(fmt.unrank(i), tweak=b"record-A")
             for i in _sample_ranks(fmt.cardinality)]
        b = [eng.encrypt(fmt.unrank(i), tweak=b"record-B")
             for i in _sample_ranks(fmt.cardinality)]
        self.assertNotEqual(a, b)
        for i, rank in enumerate(_sample_ranks(fmt.cardinality)):
            self.assertEqual(
                eng.decrypt(a[i], tweak=b"record-A"), fmt.unrank(rank)
            )

    def test_equal_format_without_slice_bounds_uses_global(self):
        # Equal fingerprints but no slice_bounds -> global permutation, and
        # preserve_length is inferred False. Still a clean round-trip.
        fmt = NoSliceDigitsFormat(6, fingerprint=b"fp:noslice6")
        eng = FTE(input_format=fmt, output_format=fmt,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        self.assertFalse(eng.preserve_length)
        for i in _sample_ranks(fmt.cardinality):
            pt = fmt.unrank(i)
            self.assertEqual(eng.decrypt(eng.encrypt(pt)), pt)

    # ---- deterministic, input != output (rank-map FTE cell) ------------ #
    def test_deterministic_cross_format_roundtrip(self):
        fin = DigitsFormat(6, fingerprint=b"fp:in6")
        fout = DigitsFormat(7, fingerprint=b"fp:out7")
        eng = FTE(input_format=fin, output_format=fout,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        self.assertFalse(eng.preserve_length)  # cross-format never preserves
        for i in _sample_ranks(fin.cardinality):
            pt = fin.unrank(i)
            ct = eng.encrypt(pt)
            self.assertEqual(len(ct), 7)          # in the output format
            self.assertEqual(eng.decrypt(ct), pt)

    def test_deterministic_cross_format_injectivity_rejection(self):
        # Covertexts whose deciphered rank is >= N_in were never valid inputs.
        fin = DigitsFormat(6, fingerprint=b"fp:in6")     # 1e6
        fout = DigitsFormat(7, fingerprint=b"fp:out7")   # 1e7
        eng = FTE(input_format=fin, output_format=fout,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        accepted = rejected = 0
        for y in _sample_ranks(fout.cardinality, count=200):
            covertext = fout.unrank(y)
            try:
                pt = eng.decrypt(covertext)
            except InvalidCovertextError:
                rejected += 1
            else:
                accepted += 1
                self.assertEqual(eng.encrypt(pt), covertext)  # round-trips
        # With N_out = 10 * N_in, most sampled covertexts are unreachable, and
        # both paths must be exercised.
        self.assertGreater(rejected, 0)
        self.assertGreater(accepted, 0)

    def test_deterministic_equal_cardinality_cross_format(self):
        # Different fingerprints, equal size: global bijection, no length rule.
        fin = DigitsFormat(6, fingerprint=b"fp:eqA")
        fout = DigitsFormat(6, fingerprint=b"fp:eqB")
        eng = FTE(input_format=fin, output_format=fout,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        self.assertFalse(eng.preserve_length)
        for i in _sample_ranks(fin.cardinality):
            pt = fin.unrank(i)
            self.assertEqual(eng.decrypt(eng.encrypt(pt)), pt)

    # ---- deterministic, inferred length preservation ------------------- #
    def test_preserve_length_across_multiple_lengths(self):
        fmt = RangeDigitsFormat(6, 7, fingerprint=b"fp:range6-7")
        eng = FTE(input_format=fmt, output_format=fmt,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        self.assertTrue(eng.preserve_length)
        for length in (6, 7):
            offset, count = fmt.slice_bounds(length)
            for r in _sample_ranks(count, count=16):
                pt = fmt.unrank(offset + r)
                ct = eng.encrypt(pt)
                self.assertEqual(len(ct), length)  # length preserved in place
                self.assertEqual(eng.decrypt(ct), pt)

    def test_preserve_length_permutes_each_slice_independently(self):
        fmt = RangeDigitsFormat(6, 7, fingerprint=b"fp:range6-7")
        eng = FTE(input_format=fmt, output_format=fmt,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        for length in (6, 7):
            offset, count = fmt.slice_bounds(length)
            outs = {eng.encrypt(fmt.unrank(offset + r))
                    for r in _sample_ranks(count, count=32)}
            # Every covertext keeps the slice's length; injective on the sample.
            self.assertTrue(all(len(o) == length for o in outs))
            self.assertEqual(len(outs), len(_sample_ranks(count, count=32)))

    def test_preserve_length_tweak_carries_length(self):
        fmt = RangeDigitsFormat(6, 7, fingerprint=b"fp:range6-7")
        eng = FTE(input_format=fmt, output_format=fmt,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        a = eng.encrypt("000123", tweak=b"one")
        b = eng.encrypt("000123", tweak=b"two")
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), 6)
        self.assertEqual(eng.decrypt(a, tweak=b"one"), "000123")
        self.assertEqual(eng.decrypt(b, tweak=b"two"), "000123")

    # ---- AE cell, bytes input (classic FTE) ---------------------------- #
    def test_ae_bytes_roundtrip_is_randomized_and_authenticated(self):
        eng = FTE(output_format=BIG_HEX, key=KEY_AE)
        self.assertEqual(eng.cipher, "aes-ctr-hmac")
        self.assertFalse(eng.preserve_length)
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
        eng = FTE(input_format=digits, output_format=BIG_HEX,
                  cipher="aes-ctr-hmac", key=KEY_AE)
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
            FTE(input_format=digits, output_format=tiny,
                cipher="aes-ctr-hmac", key=KEY_AE)

    def test_ae_non_bytes_requires_finite_input(self):
        # A non-bytes input with no cardinality has no fixed rank width, so
        # the AE path refuses it up front instead of failing mid-arithmetic.
        class UnboundedDigits:
            def rank(self, value, /):
                return int(value)

            def unrank(self, index, /):
                return str(index)

        with self.assertRaises(FormatCapacityError) as caught:
            FTE(input_format=UnboundedDigits(), output_format=BIG_HEX,
                cipher="aes-ctr-hmac", key=KEY_AE)
        self.assertIn("finite cardinality", str(caught.exception))

    def test_ae_non_bytes_covertext_length_is_plaintext_independent(self):
        # The rank is serialized at a fixed width, so a variable-length output
        # gets the same frame length for the smallest, a middle, and the
        # largest input value: the covertext length reveals nothing about it.
        digits = fte.RegexFormat(r"^[0-9]+$", length=12)
        var_hex = fte.RegexFormat(r"^[0-9a-f]+$", min_length=1, max_length=400)
        eng = FTE(input_format=digits, output_format=var_hex,
                  cipher="aes-ctr-hmac", key=KEY_AE)
        lengths = set()
        for pt in (b"000000000000", b"000000065536", b"999999999999"):
            for _ in range(8):
                ct = eng.encrypt(pt)
                lengths.add(len(ct))
                self.assertEqual(eng.decrypt(ct), pt)
        self.assertEqual(len(lengths), 1, lengths)

    def test_ae_non_bytes_rejects_wrong_width_plaintext(self):
        # An authentic frame whose plaintext is not exactly the fixed width
        # was never produced by encrypt(): shorter (a shortlex-style encoding)
        # and longer (padded) serializations are both rejected.
        digits = fte.RegexFormat(r"^[0-9]+$", length=6)
        eng = FTE(input_format=digits, output_format=BIG_HEX,
                  cipher="aes-ctr-hmac", key=KEY_AE)
        width = eng.max_plaintext_bytes
        self.assertEqual(width, 3)  # 10**6 - 1 needs 20 bits
        for pt_bytes in (b"\x00" * (width - 1), b"\x00" * (width + 1)):
            framed = frame.FRAME_VERSION + eng._encrypter.encrypt(pt_bytes)
            forged = BIG_HEX.unrank(frame.bytes_to_rank(framed))
            with self.assertRaises(InvalidCovertextError):
                eng.decrypt(forged)
        # The genuine width still round-trips (rank 0 is all-zero bytes).
        framed = frame.FRAME_VERSION + eng._encrypter.encrypt(b"\x00" * width)
        self.assertEqual(
            eng.decrypt(BIG_HEX.unrank(frame.bytes_to_rank(framed))), b"000000"
        )

    def test_ae_non_bytes_rejects_empty_plaintext_frame(self):
        # An authentic frame carrying a 0-byte plaintext is rejected when the
        # fixed width is positive: it is not a shortlex spelling of rank 0.
        digits = fte.RegexFormat(r"^[0-9]+$", length=6)
        eng = FTE(input_format=digits, output_format=BIG_HEX,
                  cipher="aes-ctr-hmac", key=KEY_AE)
        self.assertGreater(eng.max_plaintext_bytes, 0)
        framed = frame.FRAME_VERSION + eng._encrypter.encrypt(b"")
        forged = BIG_HEX.unrank(frame.bytes_to_rank(framed))
        with self.assertRaises(InvalidCovertextError):
            eng.decrypt(forged)

    def test_ae_non_bytes_zero_width_rejects_one_byte_frame(self):
        # A cardinality-1 input serializes its only rank at width 0, so the
        # empty plaintext is the sole authentic frame; a 1-byte frame (rank 0
        # written at width 1) was never produced by encrypt().
        one_word = fte.RegexFormat(r"^a+$", length=5)
        eng = FTE(input_format=one_word, output_format=BIG_HEX,
                  cipher="aes-ctr-hmac", key=KEY_AE)
        self.assertEqual(eng.max_plaintext_bytes, 0)
        framed = frame.FRAME_VERSION + eng._encrypter.encrypt(b"\x00")
        forged = BIG_HEX.unrank(frame.bytes_to_rank(framed))
        with self.assertRaises(InvalidCovertextError):
            eng.decrypt(forged)
        # The genuine empty frame still decrypts to the one word.
        framed = frame.FRAME_VERSION + eng._encrypter.encrypt(b"")
        self.assertEqual(
            eng.decrypt(BIG_HEX.unrank(frame.bytes_to_rank(framed))), b"aaaaa"
        )

    def test_ae_non_bytes_width_is_fixed_by_input_cardinality(self):
        # W is the smallest width with 256**W >= n_in (W == 0 for n_in == 1),
        # not the shortlex length of n_in - 1 (which is 1 for n_in == 257).
        expected = {1: 0, 2: 1, 255: 1, 256: 1, 257: 2, 65536: 2, 65537: 3}
        for n, width in expected.items():
            with self.subTest(n=n):
                eng = FTE(input_format=CountFormat(n), output_format=BIG_HEX,
                          cipher="aes-ctr-hmac", key=KEY_AE)
                self.assertEqual(eng.max_plaintext_bytes, width)
                for value in {0, n // 2, n - 1}:
                    self.assertEqual(eng.decrypt(eng.encrypt(value)), value)

    # ---- ValueError / error matrix for bad configs --------------------- #
    def test_tweak_with_ae_is_rejected(self):
        eng = FTE(output_format=BIG_HEX, key=KEY_AE)
        with self.assertRaises(ValueError):
            eng.encrypt(b"x", tweak=b"nope")
        with self.assertRaises(ValueError):
            eng.decrypt(eng.encrypt(b"x"), tweak=b"nope")

    def test_missing_cipher_for_cross_format_is_rejected(self):
        fin = DigitsFormat(6, fingerprint=b"fp:mA")
        fout = DigitsFormat(7, fingerprint=b"fp:mB")
        with self.assertRaises(ValueError):
            FTE(input_format=fin, output_format=fout, key=KEY_UNUSED)

    def test_ae_key_must_be_32_bytes(self):
        with self.assertRaises(ValueError):
            FTE(output_format=BIG_HEX, key=b"too-short")
        with self.assertRaises(ValueError):
            FTE(output_format=BIG_HEX, key=bytes(31))

    def test_max_plaintext_bytes_rejected_for_non_bytes_input(self):
        digits = fte.RegexFormat(r"^[0-9]+$", length=6)
        with self.assertRaises(ValueError):
            FTE(input_format=digits, output_format=BIG_HEX,
                cipher="aes-ctr-hmac", key=KEY_AE, max_plaintext_bytes=8)

    def test_legacy_format_alias_removed(self):
        with self.assertRaises(TypeError):
            FTE(format=BIG_HEX, key=KEY_AE)

    def test_removed_flags_are_rejected(self):
        # preserve_length and allow_small_domain are no longer parameters.
        fmt = DigitsFormat(6, fingerprint=b"fp:d6")
        with self.assertRaises(TypeError):
            FTE(input_format=fmt, output_format=fmt, cipher=ToyCipher(),
                key=KEY_UNUSED, preserve_length=True)
        with self.assertRaises(TypeError):
            FTE(input_format=fmt, output_format=fmt, cipher=ToyCipher(),
                key=KEY_UNUSED, allow_small_domain=True)

    def test_exactly_one_output_format_required(self):
        with self.assertRaises(ValueError):
            FTE(key=KEY_AE)

    # ---- SmallDomainError (always enforced, no opt-out) ---------------- #
    def test_small_domain_raises(self):
        fmt = DigitsFormat(5, fingerprint=b"fp:d5")  # 1e5 < 1e6
        with self.assertRaises(SmallDomainError):
            FTE(input_format=fmt, output_format=fmt,
                cipher=ToyCipher(), key=KEY_UNUSED)

    def test_small_domain_at_exactly_one_million_is_allowed(self):
        fmt = DigitsFormat(6, fingerprint=b"fp:d6")  # 1e6, on the floor
        eng = FTE(input_format=fmt, output_format=fmt,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        self.assertEqual(eng.decrypt(eng.encrypt("000042")), "000042")

    def test_small_domain_cross_format_is_judged_on_the_input(self):
        # A deterministic map's strength is bounded by the input space, so the
        # floor applies to n_in even when the output clears it.
        fout = DigitsFormat(7, fingerprint=b"fp:out7")  # 1e7, above the floor
        with self.assertRaises(SmallDomainError) as caught:
            FTE(input_format=DigitsFormat(5, fingerprint=b"fp:in5"),
                output_format=fout, cipher=ToyCipher(), key=KEY_UNUSED)
        self.assertIn("input domain", str(caught.exception))
        eng = FTE(input_format=DigitsFormat(6, fingerprint=b"fp:in6"),
                  output_format=fout, cipher=ToyCipher(), key=KEY_UNUSED)
        self.assertEqual(eng.decrypt(eng.encrypt("000042")), "000042")

    def test_small_domain_slice_names_offending_lengths(self):
        # Length-5 slice (1e5) is below the floor; length-6 (1e6) meets it. The
        # error should name only the offending length.
        fmt = RangeDigitsFormat(5, 6, fingerprint=b"fp:range5-6")
        with self.assertRaises(SmallDomainError) as caught:
            FTE(input_format=fmt, output_format=fmt,
                cipher=ToyCipher(), key=KEY_UNUSED)
        self.assertIn("5", str(caught.exception))

    # ---- capacity and injectivity at init ------------------------------ #
    def test_input_larger_than_output_rejected_at_init(self):
        fin = DigitsFormat(7, fingerprint=b"fp:big7")    # 1e7
        fout = DigitsFormat(6, fingerprint=b"fp:small6")  # 1e6
        with self.assertRaises(FormatCapacityError):
            FTE(input_format=fin, output_format=fout,
                cipher=ToyCipher(), key=KEY_UNUSED)

    def test_deterministic_requires_finite_formats(self):
        # BytesFormat is unbounded (no cardinality): invalid for deterministic.
        fmt = DigitsFormat(6, fingerprint=b"fp:d6")
        with self.assertRaises(FormatCapacityError):
            FTE(input_format=fte.BytesFormat(), output_format=fmt,
                cipher=ToyCipher(), key=KEY_UNUSED)

    def test_invalid_plaintext_rejected(self):
        fmt = DigitsFormat(6, fingerprint=b"fp:d6")
        eng = FTE(input_format=fmt, output_format=fmt,
                  cipher=ToyCipher(), key=KEY_UNUSED)
        with self.assertRaises(InvalidPlaintextError):
            eng.encrypt("not-a-member")


if __name__ == "__main__":
    unittest.main()
