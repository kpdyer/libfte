"""Run every script in examples/ so the documented usage keeps working."""

import runpy
from pathlib import Path

import pytest


EXAMPLES = sorted((Path(__file__).resolve().parents[1] / "examples").glob("*.py"))


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_example_runs(path):
    runpy.run_path(str(path), run_name="__main__")
