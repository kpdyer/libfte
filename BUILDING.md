# libfte Build Instructions

libfte itself is pure Python; there is nothing in this repository to compile.
It depends on three packages:

- `cryptography` (AES-CTR): a compiled extension that bundles OpenSSL. PyPI
  ships prebuilt wheels for supported platforms, so no compiler is normally
  needed.
- `regex2dfa` (pattern compilation): pure Python.
- `libffx` (the `ff1` format-preserving cipher): pure Python.

## Requirements

- Python 3.10 or later
- Network access to PyPI (or a mirror) for the dependencies above

## Install

```bash
git clone https://github.com/kpdyer/libfte.git
cd libfte
pip install .
```

For development (tests and coverage):

```bash
pip install -e ".[dev]"
```

## Verification

Run the test suite:

```bash
pytest -v
```

Or try an example:

```bash
python examples/01_basic_usage.py
```

## Development

```bash
# Run tests with coverage
pytest -v --cov=fte
```

## Building distributions

```bash
pip install build
python -m build
```

This produces a source distribution and a `py3-none-any` wheel in `dist/`.
`python -m build` creates an isolated build environment and installs
`setuptools>=77` (the floor declared in `pyproject.toml`) into it, so it needs
network access; with `setuptools>=77` already installed,
`python -m build --no-isolation` builds offline.
