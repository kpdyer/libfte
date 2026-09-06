"""Compatibility imports warn without affecting normal public API use."""

import os
from pathlib import Path
import subprocess
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    def run_child(self, script):
        # A fresh interpreter observes the first import warning and keeps the
        # legacy modules out of the parent process's module cache.
        result = subprocess.run(
            [sys.executable, "-c", script],
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_api_does_not_load_legacy_modules_or_warn(self):
        self.run_child("""
import sys
import warnings

warnings.simplefilter("error", DeprecationWarning)
import fte

assert "regex2dfa" not in sys.modules
assert "fte.frame" not in sys.modules
assert "fte.formats.regex.dfa" not in sys.modules

for output in (fte.BytesFormat(), fte.RegexFormat("^[a-z]+$", length=128)):
    cipher = fte.FTE(output_format=output, key=bytes(32))
    assert cipher.decrypt(cipher.encrypt(b"hello")) == b"hello"

assert "fte.frame" not in sys.modules
assert "fte.formats.regex.dfa" not in sys.modules
""")

    def test_frame_import_warns_and_preserves_functions_and_cache(self):
        self.run_child("""
import warnings
from fte import _frame

with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always", DeprecationWarning)
    from fte import frame
    from fte.frame import rank_offset

assert len(caught) == 1, caught
assert caught[0].category is DeprecationWarning
assert "fte.frame is deprecated" in str(caught[0].message)
assert caught[0].filename == "<string>", caught[0].filename
assert frame.__all__ == _frame.__all__
for name in frame.__all__:
    assert getattr(frame, name) is getattr(_frame, name), name

_frame.rank_offset.cache_clear()
offset = _frame.rank_offset(3)
assert rank_offset(3) == offset
assert _frame.rank_offset.cache_info().hits == 1
assert frame.rank_to_bytes(frame.bytes_to_rank(b"\\x00hi")) == b"\\x00hi"
""")

    def test_dfa_import_warns_and_preserves_classes_and_exceptions(self):
        self.run_child("""
import warnings
from fte.formats.regex import _dfa

with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always", DeprecationWarning)
    import fte.formats.regex.dfa as legacy
    from fte.formats.regex.dfa import DFA, InvalidRankInput, InvalidUnrankInput

assert len(caught) == 1, caught
assert caught[0].category is DeprecationWarning
assert "fte.formats.regex.dfa is deprecated" in str(caught[0].message)
assert caught[0].filename == "<string>", caught[0].filename
assert legacy.__all__ == _dfa.__all__
for name in legacy.__all__:
    assert getattr(legacy, name) is getattr(_dfa, name), name

dfa = DFA("0\\t0\\t97\\t97\\n0\\n", 2)
assert dfa.unrank(dfa.rank(b"aa"), 2) == b"aa"
for action, args, error in (
    (dfa.rank, (b"b",), InvalidRankInput),
    (dfa.unrank, (-1, 2), InvalidUnrankInput),
    (DFA, ("0\\n", 1), legacy.InvalidFSTFormat),
):
    try:
        action(*args)
    except error:
        pass
    else:
        raise AssertionError(f"expected {error}")
""")


if __name__ == "__main__":
    unittest.main()
