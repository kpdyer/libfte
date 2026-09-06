"""Tests for the optional format metadata: ``fingerprint`` and ``slice_bounds``.

Both are additive conventions on the ranked-format contract. ``fingerprint``
names the exact ordering; ``slice_bounds`` exposes a format's per-length rank
slices. :class:`~fte.formats.regex.RegexFormat` and
:class:`~fte.formats.bytes.BytesFormat` provide them.
"""

import copy
import pickle
import unittest

import fte
from fte.formats.bytes import BytesFormat


class MetadataImmutabilityTests(unittest.TestCase):
    def test_mutation_cannot_desynchronize_metadata_from_ranking(self):
        fmt = fte.RegexFormat(r"^[ab]+$", min_length=1, max_length=2)
        words = [fmt.unrank(i) for i in range(fmt.cardinality)]
        fingerprint = fmt.fingerprint

        for name, value in (
            ("pattern", r"^[0-9]+$"),
            ("min_length", 2),
            ("max_length", 3),
            ("cardinality", 100),
            ("fingerprint", b"changed"),
        ):
            with self.subTest(attribute=name):
                with self.assertRaises(AttributeError):
                    setattr(fmt, name, value)
                with self.assertRaises(AttributeError):
                    delattr(fmt, name)

        self.assertEqual(fmt.pattern, r"^[ab]+$")
        self.assertEqual((fmt.min_length, fmt.max_length), (1, 2))
        self.assertEqual(fmt.fingerprint, fingerprint)
        self.assertEqual(fmt.slice_bounds(2), (2, 4))
        self.assertEqual([fmt.unrank(i) for i in range(fmt.cardinality)], words)
        self.assertEqual([fmt.rank(word) for word in words], list(range(6)))

    def test_copy_and_pickle_preserve_metadata_and_ranking(self):
        fmt = fte.RegexFormat(r"^[ab]+$", min_length=1, max_length=2)
        for method, restored in (
            ("copy", copy.copy(fmt)),
            ("deepcopy", copy.deepcopy(fmt)),
            ("pickle", pickle.loads(pickle.dumps(fmt))),
        ):
            with self.subTest(method=method):
                self.assertIsNot(restored, fmt)
                self.assertEqual(restored.pattern, fmt.pattern)
                self.assertEqual(restored.fingerprint, fmt.fingerprint)
                self.assertEqual(restored.cardinality, fmt.cardinality)
                for length in range(fmt.min_length, fmt.max_length + 1):
                    self.assertEqual(
                        restored.slice_bounds(length), fmt.slice_bounds(length)
                    )
                for rank in range(fmt.cardinality):
                    self.assertEqual(restored.unrank(rank), fmt.unrank(rank))
                    self.assertEqual(restored.rank(fmt.unrank(rank)), rank)
                with self.assertRaises(AttributeError):
                    restored.cardinality = 100

    def test_subclasses_can_add_metadata_but_not_replace_configuration(self):
        class LabeledFormat(fte.RegexFormat):
            pass

        fmt = LabeledFormat(r"^[ab]+$", length=2)
        fmt.label = "example"
        self.assertEqual(fmt.label, "example")
        with self.assertRaises(AttributeError):
            fmt.pattern = r"^[0-9]+$"
        self.assertEqual(fmt.unrank(0), b"aa")


class FingerprintTests(unittest.TestCase):
    def test_regex_fingerprint_is_stable_bytes(self):
        a = fte.RegexFormat(r"^[0-9]+$", length=9)
        b = fte.RegexFormat(r"^[0-9]+$", length=9)
        self.assertIsInstance(a.fingerprint, bytes)
        self.assertEqual(a.fingerprint, b.fingerprint)  # same params -> same fp

    def test_regex_fingerprint_separates_pattern_and_lengths(self):
        base = fte.RegexFormat(r"^[0-9]+$", length=9)
        other_pattern = fte.RegexFormat(r"^[0-9a-f]+$", length=9)
        other_length = fte.RegexFormat(r"^[0-9]+$", length=10)
        other_range = fte.RegexFormat(r"^[0-9]+$", min_length=9, max_length=10)
        self.assertNotEqual(base.fingerprint, other_pattern.fingerprint)
        self.assertNotEqual(base.fingerprint, other_length.fingerprint)
        self.assertNotEqual(base.fingerprint, other_range.fingerprint)

    def test_bytes_fingerprint_is_stable_bytes(self):
        self.assertIsInstance(BytesFormat().fingerprint, bytes)
        self.assertEqual(BytesFormat().fingerprint, BytesFormat().fingerprint)
        self.assertNotEqual(
            BytesFormat().fingerprint, fte.RegexFormat(r"^[0-9]+$", length=9).fingerprint
        )


class SliceBoundsTests(unittest.TestCase):
    def test_fixed_length_single_slice(self):
        fmt = fte.RegexFormat(r"^[0-9]+$", length=4)
        offset, count = fmt.slice_bounds(4)
        self.assertEqual(offset, 0)
        self.assertEqual(count, fmt.cardinality)
        self.assertEqual(count, 10 ** 4)

    def test_range_slices_partition_the_rank_space(self):
        fmt = fte.RegexFormat(r"^[0-9]+$", min_length=1, max_length=3)
        total = 0
        for length in range(1, 4):
            offset, count = fmt.slice_bounds(length)
            self.assertEqual(offset, total)   # contiguous, length-first
            total += count
        self.assertEqual(total, fmt.cardinality)

    def test_slice_bounds_agrees_with_rank_layout(self):
        fmt = fte.RegexFormat(r"^[0-9]+$", min_length=1, max_length=3)
        for length in range(1, 4):
            offset, count = fmt.slice_bounds(length)
            # Every rank in the slice unranks to a value of that length.
            for r in (offset, offset + count - 1):
                self.assertEqual(len(fmt.unrank(r)), length)

    def test_slice_bounds_rejects_out_of_range_length(self):
        fmt = fte.RegexFormat(r"^[0-9]+$", length=4)
        with self.assertRaises(ValueError):
            fmt.slice_bounds(3)
        with self.assertRaises(ValueError):
            fmt.slice_bounds(5)


if __name__ == "__main__":
    unittest.main()
