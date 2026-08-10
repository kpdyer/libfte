# libfte Build Instructions

libfte is a pure Python package. There is nothing to compile and no system
libraries are required.

## Requirements

- Python 3.8 or later

## Install

```bash
git clone https://github.com/kpdyer/libfte.git
cd libfte
pip install .
```

For development (tests, coverage, linting):

```bash
pip install -e ".[dev]"
```

## Verification

Run the test suite:

```bash
pytest fte/tests/ -v
```

Or try an example:

```bash
python examples/01_basic_usage.py
```

## Development

```bash
# Run tests with coverage
pytest fte/tests/ -v --cov=fte

# Run linting
flake8 fte/
```

## Building distributions

```bash
pip install build
python -m build
```

This produces a source distribution and a pure Python wheel in `dist/`.
