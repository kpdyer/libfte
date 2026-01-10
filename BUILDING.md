# libfte Build Instructions

## Requirements

- Python 3.8 or later
- GMP library (for arbitrary precision arithmetic)
- C++ compiler (g++ or clang++)

## Ubuntu/Debian

Install the required system packages:

```bash
sudo apt-get update
sudo apt-get install python3-dev python3-pip libgmp-dev git build-essential
```

Clone and install libfte:

```bash
git clone https://github.com/kpdyer/libfte.git
cd libfte
pip install .
```

For development:

```bash
pip install -e ".[dev]"
```

## macOS

Install Homebrew if you don't have it:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install dependencies:

```bash
brew install python gmp git
```

Clone and install libfte:

```bash
git clone https://github.com/kpdyer/libfte.git
cd libfte
pip3 install .
```

For development:

```bash
pip3 install -e ".[dev]"
```

## Windows

Building on Windows requires:

1. Python 3.8+ from python.org
2. Visual Studio Build Tools (C++ workload)
3. MPIR library (Windows-compatible GMP alternative)

See the [libfte-builder](https://github.com/kpdyer/libfte-builder) repository for detailed Windows build instructions.

## Verification

After installation, verify the build:

```bash
python -m pytest fte/tests/ -v
```

Or run the example:

```bash
python examples/example1.py
```

## Development

For development work:

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests with coverage
pytest fte/tests/ -v --cov=fte

# Run linting
flake8 fte/
```
