"""Regression suite over the edge-case regex corpus.

The corpus (``regex_corpus_data.py``) plus its frozen goldens
(``regex_corpus_golden.json``) pin the exact ranking bijection of every
edge-case regex. Any change that alters a cardinality, an ``unrank`` output, or
the ``rank`` inverse fails here, so a performance optimization cannot silently
change the wire format. Regenerate the goldens with
``gen_regex_corpus_golden.py`` only when such a change is intentional.

Coverage per regex: cardinality, sampled ``unrank`` outputs and their ``rank``
inverses (all frozen), length bounds, an independent language check via Python
``re``, out-of-range boundaries, and an end-to-end FTE round-trip where the
format is large enough to hold an encrypted frame.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

import pytest

from fte import FTE
from fte import _frame as frame
from fte.core import FormatCapacityError
from regex_corpus_data import CORPUS
from fte.formats.regex.format import RegexFormat
from gen_regex_corpus_golden import build_format

_GOLDEN = json.loads(Path(__file__).with_name("regex_corpus_golden.json").read_text())
_KEY = bytes(range(32))

# ids parametrize every test so failures name the exact regex.
_IDS = [label for label, _, _ in CORPUS]
_BY_ID = {label: (pattern, spec) for label, pattern, spec in CORPUS}


@lru_cache(maxsize=None)
def _format_for(label: str) -> RegexFormat:
    # Cached so a large-DFA entry is compiled once across the whole test module,
    # not rebuilt per test function. Tests only read the format, so sharing it
    # is safe.
    return build_format(*_BY_ID[label])


def test_corpus_ids_are_unique_and_match_the_goldens():
    # The corpus and frozen goldens must describe the same set of regexes;
    # editing one without regenerating the other is a mistake, not a silent pass.
    assert len(_IDS) == len(set(_IDS))
    assert set(_GOLDEN) == set(_IDS)


@pytest.mark.parametrize("label", _IDS)
def test_ranking_matches_golden(label):
    pattern, _ = _BY_ID[label]
    fmt = _format_for(label)
    golden = _GOLDEN[label]
    assert fmt.cardinality == int(golden["cardinality"])
    for index_str, word_hex in golden["probes"]:
        index, word = int(index_str), bytes.fromhex(word_hex)
        assert fmt.unrank(index) == word
        assert fmt.rank(word) == index
        assert fmt.min_length <= len(word) <= fmt.max_length
        # independent language oracle: Python re must accept the same word.
        assert re.fullmatch(pattern, word.decode("latin-1"), re.DOTALL) is not None
    with pytest.raises(ValueError):
        fmt.unrank(fmt.cardinality)
    with pytest.raises(ValueError):
        fmt.unrank(-1)


@pytest.mark.parametrize("label", _IDS)
def test_fte_end_to_end_or_capacity_rejection(label):
    # Every corpus format either carries an authenticated frame end to end or
    # is refused at construction. The frame math decides which, so both
    # branches are checked against it rather than skipping the small ones.
    fmt = _format_for(label)
    fits = frame.capacity_plaintext_limit(
        fmt.cardinality, FTE._CIPHERTEXT_EXPANSION
    ) >= 0
    if not fits:
        with pytest.raises(FormatCapacityError):
            FTE(output_format=fmt, key=_KEY)
        return
    cipher = FTE(output_format=fmt, key=_KEY)
    limit = cipher.max_plaintext_bytes
    payloads = {b""}
    if limit >= 1:
        payloads.add(b"x" * min(limit, 8))
    for payload in payloads:
        assert cipher.decrypt(cipher.encrypt(payload)) == payload
