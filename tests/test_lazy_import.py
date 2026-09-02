"""Tests for the lazy import of the regex2dfa-backed RegexFormat."""

import os
import subprocess
import sys
import unittest
from pathlib import Path


# tests/ sits directly under the checkout, so the project root is one level
# up. It goes on the child's PYTHONPATH so the child imports *this* fte
# rather than whichever one happens to be installed.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Runs in a child interpreter with regex2dfa blocked: sys.modules[name] = None
# makes any "import regex2dfa" raise ImportError, simulating an environment
# where regex2dfa is not installed.
CHILD_SCRIPT = """
import os
import sys

sys.modules['regex2dfa'] = None

import fte

# sys.argv[1] is PROJECT_ROOT: the checkout's own package must be the one
# imported, not an installed copy (and not a sibling of the checkout).
assert fte.__file__.startswith(os.path.join(sys.argv[1], 'fte', '')), fte.__file__
assert issubclass(fte.FTE, object)
assert isinstance(fte.RankedFormat, type)


class HexFormat:
    def rank(self, value: str) -> int:
        return int(value, 16)

    def unrank(self, index: int) -> str:
        return format(index, "x")


cipher = fte.FTE(output_format=HexFormat(), key=bytes(range(32)))
assert cipher.decrypt(cipher.encrypt(b"hello")) == b"hello"

try:
    fte.RegexFormat
except ImportError:
    pass
else:
    raise AssertionError("accessing fte.RegexFormat should raise ImportError")
"""


class Tests(unittest.TestCase):
    def test_import_fte_without_regex2dfa(self):
        result = subprocess.run(
            [sys.executable, "-c", CHILD_SCRIPT, str(PROJECT_ROOT)],
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_regex_format_still_importable(self):
        import fte
        from fte.formats import RegexFormat

        self.assertIs(fte.RegexFormat, RegexFormat)

    def test_dir_lists_regex_format(self):
        import fte
        import fte.formats

        self.assertIn("RegexFormat", dir(fte))
        self.assertIn("RegexFormat", dir(fte.formats))


if __name__ == "__main__":
    unittest.main()
