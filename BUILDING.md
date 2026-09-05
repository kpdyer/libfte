# Development and building

Requires Python 3.10 or later. libfte is pure Python; `cryptography` supplies
prebuilt wheels on supported platforms. Dependency installation needs access to
PyPI or a mirror.

## Development setup

```bash
git clone https://github.com/kpdyer/libfte.git
cd libfte
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

Run tests with coverage:

```bash
python -m pytest --cov=fte
```

See [examples](examples/) for runnable usage examples and
[performance](docs/performance.md) for benchmarks.

## Building distributions

```bash
python -m pip install build
python -m build
```

This produces a source distribution and a `py3-none-any` wheel in `dist/`.
Build isolation installs `setuptools>=77`; with that requirement already
installed, `python -m build --no-isolation` builds offline.
