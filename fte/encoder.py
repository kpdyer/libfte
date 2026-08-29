#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Exception types for the regex :class:`fte.Encoder` API.

The regex encoder now delegates to :class:`fte.FTE` with
:class:`fte.RegexFormat`; there is a single encoding engine. These exception
classes remain for the input-validation errors ``Encoder`` raises directly and
for backward-compatible imports.
"""


class InvalidInputException(Exception):
    """Raised when the input to encode/decode is not bytes."""


class DecodeFailureError(Exception):
    """Raised when a covertext is too short to decode."""
