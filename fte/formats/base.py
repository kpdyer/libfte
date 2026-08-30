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
    values outside their canonical format and indexes outside their capacity.

    The protocol is structural: any object with callable ``rank`` and ``unrank``
    methods conforms, with no need to subclass or import this module at runtime.

    A format may additionally expose a ``cardinality`` attribute, the exact
    positive size of its contiguous rank space ``range(cardinality)``.
    Declaring one lets :class:`fte.FTE` reject a message that can never fit
    *before* it performs any encryption.
    """

    def rank(self, value: Covertext, /) -> int:
        """Return the non-negative integer assigned to ``value``."""

        ...

    def unrank(self, index: int, /) -> Covertext:
        """Return the canonical value assigned to non-negative ``index``."""

        ...
