"""Regression suite over the 149-regex edge-case corpus.

The corpus (``regex_corpus_data.py``) plus its frozen goldens
(``regex_corpus_golden.json``) pin the exact ranking bijection of every
edge-case regex. Any change that alters a cardinality, an ``unrank`` output, or
the ``rank`` inverse fails here, so a performance optimization cannot silently
change the wire format. Regenerate the goldens with
``gen_regex_corpus_golden.py`` only when such a change is intentional.

Coverage per regex: cardinality, sampled ``unrank`` outputs and their ``rank``
inverses (all frozen), out-of-range boundaries, length bounds, an independent
language check via Python ``re``, and an end-to-end FTE round-trip where the
format is large enough to hold an encrypted frame.

The corpus also spans a wide range of DFA shapes (the ``dfa_*`` entries: state
counts up to a few thousand, transition counts up to several thousand, and
alphabets from 2 to 256 symbols), so the general ranking walk is exercised, not
just flat single-alphabet languages. Each entry's DFA size is recorded in the
goldens and asserted for spread.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

import pytest

from fte import FTE
from fte.core import FormatCapacityError
from regex_corpus_data import CORPUS
from fte.formats.regex.format import RegexFormat
from gen_regex_corpus_golden import dfa_stats

_GOLDEN = json.loads(Path(__file__).with_name("regex_corpus_golden.json").read_text())
_KEY = bytes(range(32))

# ids parametrize every test so failures name the exact regex.
_IDS = [entry[0] for entry in CORPUS]
_BY_ID = {entry[0]: entry for entry in CORPUS}


def _build(pattern: str, spec) -> RegexFormat:
    if isinstance(spec, (tuple, list)):
        return RegexFormat(pattern, min_length=spec[0], max_length=spec[1])
    return RegexFormat(pattern, length=spec)


@lru_cache(maxsize=None)
def _format_for(label: str) -> RegexFormat:
    # Cached so a large-DFA entry is compiled once across the whole test module,
    # not rebuilt per test function. Tests only read the format, so sharing it
    # is safe.
    _, pattern, spec, _ = _BY_ID[label]
    return _build(pattern, spec)


def test_corpus_size_and_unique_ids():
    assert len(CORPUS) == 149
    assert len(_IDS) == len(set(_IDS))


def test_golden_matches_corpus_ids():
    # corpus.py and the frozen goldens must describe the same set of regexes;
    # editing one without regenerating the other is a mistake, not a silent pass.
    assert set(_GOLDEN) == set(_IDS)


@pytest.mark.parametrize("label", _IDS)
def test_golden_metadata_matches_corpus(label):
    _, pattern, spec, _ = _BY_ID[label]
    lo, hi = (spec if isinstance(spec, (tuple, list)) else (spec, spec))
    g = _GOLDEN[label]
    assert g["pattern"] == pattern
    assert (g["min_length"], g["max_length"]) == (lo, hi)


@pytest.mark.parametrize("label", _IDS)
def test_cardinality_matches_golden(label):
    fmt = _format_for(label)
    assert fmt.cardinality == int(_GOLDEN[label]["cardinality"])
    assert fmt.cardinality > 0


@pytest.mark.parametrize("label", _IDS)
def test_unrank_matches_golden(label):
    fmt = _format_for(label)
    for index_str, word_hex in _GOLDEN[label]["probes"]:
        assert fmt.unrank(int(index_str)).hex() == word_hex


@pytest.mark.parametrize("label", _IDS)
def test_rank_inverts_unrank(label):
    fmt = _format_for(label)
    for index_str, word_hex in _GOLDEN[label]["probes"]:
        index = int(index_str)
        assert fmt.rank(bytes.fromhex(word_hex)) == index
        # full inverse law in both directions
        assert fmt.unrank(fmt.rank(fmt.unrank(index))) == fmt.unrank(index)


@pytest.mark.parametrize("label", _IDS)
def test_probe_words_match_pattern_and_length(label):
    _, pattern, _, _ = _BY_ID[label]
    fmt = _format_for(label)
    for index_str, word_hex in _GOLDEN[label]["probes"]:
        word = bytes.fromhex(word_hex)
        assert fmt.min_length <= len(word) <= fmt.max_length
        # independent language oracle: Python re must accept the same word.
        assert re.fullmatch(pattern, word.decode("latin-1"), re.DOTALL) is not None


@pytest.mark.parametrize("label", _IDS)
def test_out_of_range_ranks_rejected(label):
    fmt = _format_for(label)
    with pytest.raises(ValueError):
        fmt.unrank(fmt.cardinality)
    with pytest.raises(ValueError):
        fmt.unrank(-1)


@pytest.mark.parametrize("label", _IDS)
def test_fte_end_to_end_where_capacity_allows(label):
    fmt = _format_for(label)
    try:
        cipher = FTE(output_format=fmt, key=_KEY)
    except FormatCapacityError:
        pytest.skip("format too small to hold an encrypted frame")
    limit = cipher.max_plaintext_bytes
    payloads = {b""}
    if limit >= 1:
        payloads.add(b"x" * min(limit, 8))
    for payload in payloads:
        assert cipher.decrypt(cipher.encrypt(payload)) == payload


@pytest.mark.parametrize("label", _IDS)
def test_frozen_dfa_stats_are_accurate(label):
    # The recorded DFA shape (states / transitions / alphabet) must match what
    # regex2dfa produces now, so the corpus documents real sizes. Computed from
    # the public FST output, independent of libfte's DFA internals.
    _, pattern, _, _ = _BY_ID[label]
    assert dfa_stats(pattern) == _GOLDEN[label]["dfa"]


def test_corpus_spans_dfa_shapes():
    # Guard the point of the dfa_* entries: the corpus must keep exercising the
    # general ranking walk across a wide range of DFA sizes, not only small
    # flat languages. Thresholds are loose so ordinary edits do not trip them,
    # but removing the large-DFA entries would.
    stats = [g["dfa"] for g in _GOLDEN.values()]
    states = [s["states"] for s in stats]
    transitions = [s["transitions"] for s in stats]
    alphabets = [s["alphabet"] for s in stats]

    assert max(states) >= 1000, "no large-state DFA in the corpus"
    assert sum(1 for s in states if s >= 256) >= 3, "too few many-state DFAs"
    assert max(transitions) >= 2000, "no high-transition DFA in the corpus"
    assert sum(1 for t in transitions if t > 1000) >= 5, "too few dense DFAs"
    assert max(alphabets) >= 256, "no full-byte-alphabet DFA in the corpus"
    assert min(alphabets) <= 2, "no tiny-alphabet DFA in the corpus"
