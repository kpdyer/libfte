#!/usr/bin/env python
"""Handle common input, capacity, and authentication errors."""

import os

import fte


def expect(error, action):
    try:
        action()
    except error as exc:
        print(f"   {error.__name__}: {exc}")
    else:
        raise AssertionError(f"expected {error.__name__}")


def main():
    key = os.urandom(32)
    cipher = fte.FTE(output_format=fte.RegexFormat('^[a-z]+$', length=128), key=key)

    print("1. Non-bytes plaintext:")
    expect(TypeError, lambda: cipher.encrypt("not bytes"))

    print("2. Malformed covertext (wrong length for the format):")
    expect(fte.InvalidCovertextError, lambda: cipher.decrypt(b'tooshort'))

    print("3. Invalid key length:")
    expect(ValueError, lambda: fte.FTE(
        output_format=fte.RegexFormat('^[a-z]+$', length=64), key=b'tooshort'))

    print("4. A format too small for even an empty authenticated message:")
    expect(fte.FormatCapacityError, lambda: fte.FTE(
        output_format=fte.RegexFormat('^[0-9a-f]+$', length=8), key=key))

    print("5. A pattern with no words of the requested length:")
    expect(ValueError, lambda: fte.RegexFormat('^(ab)+$', length=5))

    print("6. Tampered covertext, still in the format:")
    covertext = cipher.encrypt(b'hello')
    fmt = cipher.output_format
    tampered = fmt.unrank(fmt.rank(covertext) + 1)
    expect(fte.InvalidCovertextError, lambda: cipher.decrypt(tampered))


if __name__ == '__main__':
    main()
