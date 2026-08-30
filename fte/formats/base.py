"""The ranked-format contract that every :mod:`fte.formats` provider implements.

A *ranked format* is the one extension point of :class:`fte.FTE`. It owns nothing
cryptographic: it is only a deterministic, reversible ordering of the canonical
values in some covertext language. The engine turns an encrypted message into a
non-negative integer rank and asks the format to name the value at that rank;
decryption ranks the value back. See :mod:`fte.formats.regex` for the reference
implementation.
"""

from __future__ import annotations

from typing import Protocol, TypeVar, runtime_checkable


__all__ = ["RankedFormat"]


Covertext = TypeVar("Covertext")


@runtime_checkable
class RankedFormat(Protocol[Covertext]):
    """A deterministic, reversible ordering of canonical covertext values.

    A conforming format must provide a contiguous zero-based rank space and
    satisfy both inverse laws for every supported rank and canonical value::

        format.rank(format.unrank(index)) == index
        format.unrank(format.rank(value)) == value

    The ordering is part of the wire format. Sender and receiver must therefore
    use compatible implementations and versions. Implementations should reject
    values outside the format's language and indexes outside their capacity.

    The protocol is structural: any object with callable ``rank`` and ``unrank``
    methods conforms, with no need to subclass or import this module at runtime.

    A format may additionally expose a ``cardinality`` attribute, the exact
    positive size of its contiguous rank space ``range(cardinality)``.
    Declaring one lets :class:`fte.FTE` reject a message that can never fit
    *before* it performs any encryption, and the deterministic (FPE) cipher
    requires it on both formats.

    Two further optional conventions serve the deterministic cipher:

    * ``fingerprint``: a stable ``bytes`` identifier for the exact ordering
      (pattern, length range, version). The engine binds it into its tweaks
      and uses it to decide when two formats are interchangeable, so equal
      fingerprints must mean identical ranking.
    * ``slice_bounds(length) -> (offset, count)``: the first rank of the
      slice holding all values of that length, and the number of values in
      it. When an equal-format (FPE) pair provides this method (plus integer
      ``min_length`` / ``max_length`` attributes), the deterministic cipher
      permutes each slice in place so a value keeps its length.

    :class:`~fte.formats.bytes.BytesFormat` and
    :class:`~fte.formats.regex.RegexFormat` provide fingerprints;
    ``RegexFormat`` also provides ``slice_bounds``.
    """

    def rank(self, value: Covertext, /) -> int:
        """Return the non-negative integer assigned to ``value``."""

        ...

    def unrank(self, index: int, /) -> Covertext:
        """Return the canonical value assigned to non-negative ``index``."""

        ...
