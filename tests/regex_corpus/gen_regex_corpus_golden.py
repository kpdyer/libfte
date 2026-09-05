#!/usr/bin/env python
"""Regenerate ``regex_corpus_golden.json`` from ``regex_corpus_data.py``.

The golden file freezes the exact ranking bijection (cardinality + sampled
``unrank`` outputs) for every corpus regex. ``test_regex_corpus.py`` compares the
live implementation against it, so a performance change that alters any output
fails the suite.

Run this ONLY when a ranking change is intentional. Changing the bijection
changes the wire format: sender and receiver must both upgrade. Regenerating
silently defeats the regression guard, so review the JSON diff before committing.

    python tests/regex_corpus/gen_regex_corpus_golden.py
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import regex2dfa

from regex_corpus_data import CORPUS
from fte.formats.regex.format import RegexFormat

GOLDEN_PATH = Path(__file__).with_name("regex_corpus_golden.json")


def probe_indices(n: int) -> list[int]:
    """Deterministic probe ranks for a format of cardinality ``n``.

    Small formats are enumerated exhaustively; larger ones sample the
    boundaries plus a few PRNG-selected interior points. The choice is a pure
    function of ``n`` so the goldens are reproducible.
    """
    if n <= 10:
        return list(range(n))
    idx = {0, 1, 2, n - 1, n - 2, n // 2, n // 3, (2 * n) // 3}
    r = int(hashlib.sha256(str(n).encode()).hexdigest(), 16)
    for _ in range(4):
        r = (r * 6364136223846793005 + 1442695040888963407) & ((1 << 128) - 1)
        idx.add(r % n)
    return sorted(i for i in idx if 0 <= i < n)


def build_format(pattern: str, spec) -> RegexFormat:
    if isinstance(spec, (tuple, list)):
        return RegexFormat(pattern, min_length=spec[0], max_length=spec[1])
    return RegexFormat(pattern, length=spec)


def dfa_stats(pattern: str) -> dict:
    """Size of the minimized DFA for ``pattern``: distinct states, transitions,
    and alphabet symbols. Computed from ``regex2dfa``'s AT&T FST output (public
    and stable) rather than any libfte DFA internals, so it documents the
    corpus's coverage of DFA shapes independently of how the ranker stores them.
    """
    fst = regex2dfa.regex2dfa(pattern)
    states: set[str] = set()
    symbols: set[str] = set()
    transitions = 0
    for line in fst.split("\n"):
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 4:  # src dst input output
            states.add(parts[0])
            states.add(parts[1])
            symbols.add(parts[2])
            transitions += 1
        elif len(parts) == 1:  # final state
            states.add(parts[0])
    return {"states": len(states), "transitions": transitions,
            "alphabet": len(symbols)}


def build_golden() -> dict:
    golden: dict = {}
    for label, pattern, spec, _tags in CORPUS:
        fmt = build_format(pattern, spec)
        n = fmt.cardinality
        if n <= 0:
            raise ValueError(f"{label}: empty format")
        probes = []
        for i in probe_indices(n):
            word = fmt.unrank(i)
            if fmt.rank(word) != i:
                raise ValueError(f"{label}: rank/unrank not inverse at {i}")
            probes.append([str(i), word.hex()])
        lo, hi = (spec if isinstance(spec, (tuple, list)) else (spec, spec))
        golden[label] = {
            "pattern": pattern,
            "min_length": lo,
            "max_length": hi,
            "cardinality": str(n),
            "dfa": dfa_stats(pattern),
            "probes": probes,
        }
    return golden


def main() -> None:
    golden = build_golden()
    with open(GOLDEN_PATH, "w") as fh:
        json.dump(golden, fh, indent=1, sort_keys=True)
        fh.write("\n")
    n_probes = sum(len(g["probes"]) for g in golden.values())
    print(f"wrote {GOLDEN_PATH.name}: {len(golden)} regexes, {n_probes} probe pairs")


if __name__ == "__main__":
    main()
