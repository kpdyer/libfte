"""The built-in regular-expression ranked-format provider.

This subpackage holds everything regex-specific: :class:`RegexFormat`, whose
instances are the formats you hand to :class:`fte.FTE`, and the DFA ranker it
is built on. Every other provider lives in its own sibling subpackage under
:mod:`fte.formats`.
"""

from fte.formats.regex.format import RegexFormat


__all__ = ["RegexFormat"]
