"""The built-in regular-expression ranked format.

This subpackage holds everything regex-specific: :class:`RegexFormat`, the
provider you hand to :class:`fte.FTE`, and the DFA ranker it is built on. Every
other format lives in its own sibling subpackage under :mod:`fte.formats`.
"""

from fte.formats.regex.format import RegexFormat


__all__ = ["RegexFormat"]
