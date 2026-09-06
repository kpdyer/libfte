"""The FTE engine: ``rank_in -> transform -> unrank_out``.

The engine owns encryption and framing; :mod:`fte.formats` providers own the
reversible ordering of plaintext and covertext values.
"""

from __future__ import annotations

import hashlib
import warnings
from typing import Generic, TypeVar

from fte import frame
from fte._encrypter import DecryptionError, Encrypter
from fte.formats.base import RankedFormat
from fte.formats.bytes import BytesFormat


__all__ = [
    "FTE",
    "FTEError",
    "FormatCapacityError",
    "FormatContractError",
    "InvalidCovertextError",
    "InvalidPlaintextError",
    "MessageTooLargeError",
    "SmallDomainError",
]


Covertext = TypeVar("Covertext")
Plaintext = TypeVar("Plaintext")


class FTEError(Exception):
    """Base class for errors raised by the FTE engine."""


class FormatContractError(FTEError):
    """Raised when a format violates the :class:`RankedFormat` contract."""


class FormatCapacityError(FTEError):
    """Raised when a format cannot represent an encrypted payload rank."""


class MessageTooLargeError(FTEError):
    """Raised when plaintext exceeds the configured resource limit."""


class InvalidCovertextError(FTEError):
    """Raised when a covertext cannot be decrypted back to a plaintext."""


class InvalidPlaintextError(FTEError):
    """Raised when a plaintext is not a member of the input format."""


class SmallDomainError(FTEError):
    """Raised when a deterministic domain is below the format-preserving floor."""


# Domain floors for the deterministic (format-preserving) cipher, mirroring
# FF1's own refusal to permute a domain that is too small to hide anything
# (Draft SP 800-38G Rev 1). Always enforced; there is no opt-out.
_FF1_DOMAIN_FLOOR = 1_000_000

# Namespace prefix for the deterministic effective tweak. Bumping it changes the
# tweak of every deterministic covertext, so it is part of the wire contract.
_DETERMINISTIC_TWEAK_PREFIX = b"fte:v2:ff1:1|"


def _load_ff1():
    """Import ``ffx.FF1`` lazily so ``import fte`` does not pay for libffx."""

    from ffx import FF1

    return FF1


class FTE(Generic[Plaintext, Covertext]):
    """Encrypt a value of the input format into one of the output format.

    Construct with keyword-only arguments::

        FTE(input_format=..., output_format=..., key=..., cipher=...)

    * ``input_format`` defaults to :class:`~fte.formats.bytes.BytesFormat`, so
      ``FTE(output_format=fmt, key=key)`` is the classic pipeline: bytes in,
      the AE cipher, ``fmt`` out.
    * **FPE is the equal-formats case**: passing the same format as
      ``input_format`` and ``output_format`` with ``cipher="ff1"`` re-encrypts
      a value in place. Length is preserved automatically when the
      format can name its per-length slices (a ``slice_bounds`` method plus
      integer ``min_length`` / ``max_length``), so a value keeps its length;
      otherwise the whole language is permuted. See :attr:`preserve_length`.
    * ``cipher`` is ``"aes-ctr-hmac"``, ``"ff1"``, a duck-typed object exposing
      ``encrypt_int(x, *, domain, tweak) -> int`` /
      ``decrypt_int(y, *, domain, tweak) -> int``, or ``None`` to infer it:
      a bytes input picks ``"aes-ctr-hmac"``; otherwise two formats with equal
      fingerprints still pick ``"ff1"`` with a :class:`DeprecationWarning`.
      Pass ``cipher="ff1"`` explicitly to select unauthenticated encryption;
      anything else must be spelled out.

    The deterministic cipher refuses a domain below one million (Draft
    SP 800-38G Rev 1), raising :class:`SmallDomainError`, because FF1 is
    insecure over a domain small enough to brute-force. There is no opt-out.

    ``key`` is 32 bytes for ``"aes-ctr-hmac"`` (16 encryption + 16 MAC) and
    16/24/32 bytes for ``"ff1"``. **Never reuse a key across the two ciphers**:
    the AE and format-preserving constructions are unrelated and share no
    security proof.

    ``tweak`` (a per-call keyword on :meth:`encrypt` / :meth:`decrypt`) is only
    meaningful with the deterministic cipher; the AE path has no
    associated-data support and rejects a non-empty tweak.

    ``max_plaintext_bytes`` keeps its classic meaning for a bytes input (a
    resource ceiling and decrypt-side size guard; see the property) and is
    rejected for a non-bytes input, whose size the format's cardinality
    already fixes.

    With the ``aes-ctr-hmac`` cipher the covertext is randomized and authenticated, so
    encrypting the same plaintext twice yields two different covertexts: they
    are re-drawn per call. This holds for a non-bytes input too, whose rank is
    serialized at a fixed width (set by the input format's cardinality, so the
    frame length never depends on the plaintext) and then run through the same
    randomized AE frame.

    The deterministic (``ff1`` / object) cipher is, by contrast,
    *deterministic* and *unauthenticated*: equal plaintexts map to equal
    covertexts, so it leaks plaintext equality, and its effective strength is
    bounded by the size of the input space rather than by the key, so the
    one-million floor is enforced on the input domain. Pass a distinct
    per-record ``tweak`` to separate encryptions.

    Passing an object with ``encrypt_int()`` / ``decrypt_int()`` is deprecated
    and emits :class:`DeprecationWarning`. Existing objects retain their behavior
    and own their key; the ``FTE`` key argument is unused for them. Keep the
    original object when decrypting old data: switching to a named cipher is
    not generally ciphertext compatible.
    """

    _FRAME_VERSION = frame.FRAME_VERSION
    _CIPHERTEXT_EXPANSION = Encrypter._CTXT_EXPANSION

    _DEFAULT_MAX_PLAINTEXT_BYTES = 1 << 20
    _ENCRYPTER_MAX_PLAINTEXT_BYTES = Encrypter._MAX_PLAINTEXT_LENGTH

    __slots__ = (
        "_input_format",
        "_output_format",
        "_input_is_bytes",
        "_cipher_mode",  # "aes-ctr-hmac" | "deterministic"
        "_cipher",       # the deterministic cipher object, else None
        "_encrypter",    # the AE encrypter, else None
        "_preserve_length",
        "_tweak_base",   # deterministic effective-tweak stem, else None
        "_n_in",         # finite input cardinality, else None
        "_n_out",        # finite output cardinality, else None
        # AE-path resource / capacity machinery:
        "_resource_max",
        "_capacity_limit",
        "_max_plaintext_bytes",
        "_max_frame_bytes",
    )

    def __init__(
        self,
        *,
        input_format: RankedFormat[Plaintext] | None = None,
        output_format: RankedFormat[Covertext] | None = None,
        key: bytes,
        cipher: str | object | None = None,
        max_plaintext_bytes: int | None = None,
    ) -> None:
        # ---- resolve the format pair -----------------------------------
        if output_format is None:
            raise ValueError("output_format is required")
        if input_format is None:
            input_format = BytesFormat()

        self._validate_format(input_format, "input_format")
        self._validate_format(output_format, "output_format")

        input_is_bytes = isinstance(input_format, BytesFormat)

        n_in = self._finite_cardinality(input_format, "input_format")
        n_out = self._finite_cardinality(output_format, "output_format")

        fp_in = getattr(input_format, "fingerprint", None)
        fp_out = getattr(output_format, "fingerprint", None)

        # ---- resolve the cipher ----------------------------------------
        inferred_ff1 = False
        if cipher is None:
            if input_is_bytes:
                cipher = "aes-ctr-hmac"
            elif (
                isinstance(fp_in, bytes)
                and isinstance(fp_out, bytes)
                and fp_in == fp_out
            ):
                cipher = "ff1"
                inferred_ff1 = True
            else:
                raise ValueError(
                    "cannot infer cipher for this format pair; pass "
                    "cipher='ff1' for a deterministic transform, "
                    "cipher='aes-ctr-hmac' "
                    "for authenticated encryption"
                )

        if isinstance(cipher, str):
            if cipher == "aes-ctr-hmac":
                cipher_mode = "aes-ctr-hmac"
            elif cipher == "ff1":
                cipher_mode = "deterministic"
            else:
                raise ValueError(
                    f"unknown cipher {cipher!r}; expected 'aes-ctr-hmac' "
                    "or 'ff1'"
                )
        else:
            if not callable(getattr(cipher, "encrypt_int", None)) or not callable(
                getattr(cipher, "decrypt_int", None)
            ):
                raise TypeError(
                    "cipher object must provide callable encrypt_int() and "
                    "decrypt_int() methods"
                )
            cipher_mode = "deterministic"

        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")

        # max_plaintext_bytes is a bytes-input resource knob; it has no meaning
        # for a non-bytes input, whose size the format cardinality already
        # fixes.
        if not input_is_bytes and max_plaintext_bytes is not None:
            raise ValueError(
                "max_plaintext_bytes is only valid with a bytes input_format"
            )
        if max_plaintext_bytes is not None and (
            type(max_plaintext_bytes) is not int
            or not 0 <= max_plaintext_bytes <= self._ENCRYPTER_MAX_PLAINTEXT_BYTES
        ):
            raise ValueError(
                "max_plaintext_bytes must be an integer between 0 and 2**32 - 1"
            )

        self._input_format = input_format
        self._output_format = output_format
        self._input_is_bytes = input_is_bytes
        self._cipher_mode = cipher_mode
        self._preserve_length = False  # set by _init_deterministic if inferred
        self._n_in = n_in
        self._n_out = n_out
        self._cipher = None
        self._encrypter = None
        self._tweak_base = None
        self._resource_max = None
        self._capacity_limit = None
        self._max_plaintext_bytes = None
        self._max_frame_bytes = None

        if cipher_mode == "deterministic":
            self._init_deterministic(cipher, key, fp_in, fp_out)
            if inferred_ff1:
                warnings.warn(
                    "Implicit FF1 selection is deprecated and will be removed "
                    "in a future breaking release; pass cipher='ff1' explicitly "
                    "to select deterministic, unauthenticated encryption. "
                    "Explicit selection preserves existing ciphertexts.",
                    DeprecationWarning,
                    stacklevel=2,
                )
        else:
            if len(key) != 32:
                raise ValueError(
                    "Key must be exactly 32 bytes "
                    "(16 for encryption + 16 for MAC)"
                )
            self._encrypter = Encrypter(key[:16], key[16:])
            self._init_ae_capacity(max_plaintext_bytes)

        if not isinstance(cipher, str):
            warnings.warn(
                "Passing a cipher object to FTE is deprecated; use "
                "cipher='ff1' or cipher='aes-ctr-hmac' for new data. "
                "Keep the original cipher to decrypt existing "
                "custom-cipher covertexts until migrated.",
                DeprecationWarning,
                stacklevel=2,
            )

    # ------------------------------------------------------------------ #
    # Construction helpers                                               #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_format(fmt: object, name: str) -> None:
        if isinstance(fmt, type):
            raise TypeError(f"{name} must be an instance, not a class")
        if not callable(getattr(fmt, "rank", None)) or not callable(
            getattr(fmt, "unrank", None)
        ):
            raise TypeError(
                f"{name} must provide callable rank() and unrank() methods"
            )

    @staticmethod
    def _finite_cardinality(fmt: object, name: str) -> int | None:
        cardinality = getattr(fmt, "cardinality", None)
        if cardinality is not None and (
            type(cardinality) is not int or cardinality <= 0
        ):
            raise FormatContractError(
                f"{name}.cardinality must be a positive integer when provided"
            )
        return cardinality

    def _init_deterministic(
        self,
        cipher: str | object,
        key: bytes,
        fp_in: object,
        fp_out: object,
    ) -> None:
        if self._n_in is None or self._n_out is None:
            raise FormatCapacityError(
                "the deterministic cipher requires both formats to be finite "
                "(expose a positive cardinality)"
            )
        if self._n_in > self._n_out:
            raise FormatCapacityError(
                f"input cardinality {self._n_in} exceeds output cardinality "
                f"{self._n_out}; a permutation cannot be injective"
            )
        if not isinstance(fp_in, bytes) or not isinstance(fp_out, bytes):
            raise ValueError(
                "the deterministic cipher requires both formats to expose a "
                "bytes fingerprint"
            )

        # Length preservation is inferred, not requested: when the input and
        # output are the same format and it can name its per-length slices,
        # permute each length in place so a value keeps its length. Otherwise
        # (cross-format, or a format with no slice_bounds) permute over the
        # whole cardinality.
        preserve_length = (
            fp_in == fp_out
            and callable(getattr(self._input_format, "slice_bounds", None))
            and type(getattr(self._input_format, "min_length", None)) is int
            and type(getattr(self._input_format, "max_length", None)) is int
        )
        self._preserve_length = preserve_length

        # The format-preserving floor is always enforced: FF1 is insecure over a
        # domain small enough to brute-force, so a too-small domain is refused
        # rather than made opt-outable.
        # The strength of a deterministic map is bounded by the input space,
        # so the floor applies to n_in (n_in <= n_out, so n_out clears it too).
        if preserve_length:
            self._check_slice_domains(_FF1_DOMAIN_FLOOR)
        elif self._n_in < _FF1_DOMAIN_FLOOR:
            raise SmallDomainError(
                f"input domain {self._n_in} is below the format-preserving "
                f"floor {_FF1_DOMAIN_FLOOR}; enlarge the input format"
            )

        # Resolve the concrete cipher object.
        if isinstance(cipher, str):  # cipher == "ff1"
            FF1 = _load_ff1()
            if len(key) not in (16, 24, 32):
                raise ValueError(
                    "cipher='ff1' requires a 16, 24, or 32 byte key"
                )
            self._cipher = FF1(key)
        else:
            self._cipher = cipher

        # Length-prefix the fingerprints so the digest input is injective in
        # (fp_in, fp_out, mode) even for fingerprints containing separator
        # bytes or of unusual lengths.
        mode_tag = b"L" if preserve_length else b"G"
        self._tweak_base = hashlib.sha256(
            _DETERMINISTIC_TWEAK_PREFIX
            + len(fp_in).to_bytes(4, "big")
            + fp_in
            + len(fp_out).to_bytes(4, "big")
            + fp_out
            + mode_tag
        ).digest()

    def _check_slice_domains(self, floor: int) -> None:
        fmt = self._input_format
        lo = fmt.min_length
        hi = fmt.max_length
        offending = []
        for length in range(lo, hi + 1):
            _, count = fmt.slice_bounds(length)
            if 0 < count < floor:
                offending.append(length)
        if offending:
            raise SmallDomainError(
                f"length slices {offending} are below the format-preserving "
                f"floor {floor}; widen the alphabet or raise the minimum length"
            )

    def _init_ae_capacity(self, max_plaintext_bytes: int | None) -> None:
        if self._input_is_bytes:
            # Classic behavior: the resource ceiling and capacity limit are
            # driven by the output format alone; the bytes input is unbounded.
            cardinality = self._n_out
            resource_max = (
                self._DEFAULT_MAX_PLAINTEXT_BYTES
                if max_plaintext_bytes is None
                else max_plaintext_bytes
            )
            if cardinality is None:
                capacity_limit = None
                effective = resource_max
            else:
                capacity_limit = min(
                    frame.capacity_plaintext_limit(
                        cardinality, self._CIPHERTEXT_EXPANSION
                    ),
                    self._ENCRYPTER_MAX_PLAINTEXT_BYTES,
                )
                if capacity_limit < 0:
                    raise FormatCapacityError(
                        "format is too small to hold even an empty encrypted "
                        "message"
                    )
                effective = min(resource_max, capacity_limit)

            self._resource_max = resource_max
            self._capacity_limit = capacity_limit
            self._max_plaintext_bytes = effective
            self._max_frame_bytes = effective + 1 + self._CIPHERTEXT_EXPANSION
            return

        # AE over a finite non-bytes input: the plaintext is the fixed-width
        # big-endian serialization of an input rank in [0, n_in), padded to the
        # smallest W with 256**W >= n_in, so every frame has the same length
        # and the covertext reveals nothing about the rank. (The shortlex
        # length of n_in - 1 would be one byte short for e.g. n_in = 257.)
        # There is no separate resource knob (max_plaintext_bytes was rejected
        # earlier).
        if self._n_in is None:
            raise FormatCapacityError(
                "a non-bytes input_format must expose a finite cardinality "
                "for the 'aes-ctr-hmac' cipher"
            )
        max_pt_bytes = ((self._n_in - 1).bit_length() + 7) // 8
        self._resource_max = max_pt_bytes
        self._capacity_limit = max_pt_bytes
        self._max_plaintext_bytes = max_pt_bytes
        self._max_frame_bytes = max_pt_bytes + 1 + self._CIPHERTEXT_EXPANSION

        if self._n_out is not None:
            output_capacity = frame.capacity_plaintext_limit(
                self._n_out, self._CIPHERTEXT_EXPANSION
            )
            if output_capacity < max_pt_bytes:
                raise FormatCapacityError(
                    "output format cannot represent every authenticated frame "
                    f"for this input (needs room for {max_pt_bytes} plaintext "
                    f"bytes, holds {max(output_capacity, 0)})"
                )

    # ------------------------------------------------------------------ #
    # Public properties                                                  #
    # ------------------------------------------------------------------ #
    @property
    def input_format(self) -> RankedFormat[Plaintext]:
        """The input (plaintext) format."""

        return self._input_format

    @property
    def output_format(self) -> RankedFormat[Covertext]:
        """The output (covertext) format."""

        return self._output_format

    @property
    def cipher(self) -> str:
        """The resolved cipher mode: ``"aes-ctr-hmac"`` or ``"deterministic"``."""

        return self._cipher_mode

    @property
    def preserve_length(self) -> bool:
        """Whether the deterministic transform permutes each length in place.

        Inferred, not configured: true when the input and output are the same
        format and it can name its per-length slices, so a value keeps its
        length; false otherwise (a cross-format map, or a format without
        ``slice_bounds``). Always false for the ``aes-ctr-hmac`` cipher.
        """

        return self._preserve_length

    @property
    def max_plaintext_bytes(self) -> int | None:
        """Largest plaintext this instance accepts (AE cipher only).

        For bytes input, this is the smaller of the resource ceiling (1 MiB
        by default) and any finite output capacity. An explicit constructor
        limit can raise or lower the ceiling, up to 2**32 - 1 bytes. The same
        limit bounds accepted frame lengths during decryption. For a finite
        non-bytes input it is the fixed serialization width of every input
        rank; for the deterministic cipher it is ``None``.
        """

        return self._max_plaintext_bytes

    # ------------------------------------------------------------------ #
    # Encrypt / decrypt                                                  #
    # ------------------------------------------------------------------ #
    def encrypt(self, plaintext: Plaintext, /, *, tweak: bytes = b"") -> Covertext:
        """Encrypt ``plaintext`` into a value of the output format."""

        tweak = self._validate_tweak(tweak)
        if self._cipher_mode == "aes-ctr-hmac":
            return self._encrypt_ae(plaintext)
        return self._encrypt_deterministic(plaintext, tweak)

    def decrypt(self, covertext: Covertext, /, *, tweak: bytes = b"") -> Plaintext:
        """Decrypt one output-format value back to a plaintext."""

        tweak = self._validate_tweak(tweak)
        if self._cipher_mode == "aes-ctr-hmac":
            return self._decrypt_ae(covertext)
        return self._decrypt_deterministic(covertext, tweak)

    def _validate_tweak(self, tweak: bytes) -> bytes:
        if not isinstance(tweak, (bytes, bytearray)):
            raise TypeError("tweak must be bytes")
        tweak = bytes(tweak)
        if self._cipher_mode == "aes-ctr-hmac" and tweak:
            raise ValueError(
                "the 'aes-ctr-hmac' cipher has no associated-data support; a "
                "non-empty tweak is only valid with a deterministic cipher"
            )
        return tweak

    def _rank_plaintext(self, plaintext: Plaintext) -> int:
        try:
            r = self._input_format.rank(plaintext)
        except Exception as exc:
            raise InvalidPlaintextError("invalid plaintext") from exc
        if type(r) is not int or not 0 <= r < self._n_in:
            raise InvalidPlaintextError(
                "plaintext rank is outside the input format's rank space"
            )
        return r

    # ---- deterministic path ------------------------------------------ #
    def _encrypt_deterministic(self, plaintext: Plaintext, tweak: bytes):
        if self._preserve_length:
            return self._encrypt_preserve_length(plaintext, tweak)

        r = self._rank_plaintext(plaintext)
        c = self._cipher.encrypt_int(
            r, domain=self._n_out, tweak=self._tweak_base + tweak
        )
        return self._output_format.unrank(c)

    def _decrypt_deterministic(self, covertext: Covertext, tweak: bytes):
        if self._preserve_length:
            # The preserve-length path re-derives the rank inside its own
            # slice; ranking the whole covertext here first would be wasted.
            return self._decrypt_preserve_length(covertext, tweak)
        try:
            r = self._output_format.rank(covertext)
        except Exception as exc:
            raise InvalidCovertextError("invalid covertext") from exc
        if type(r) is not int or r < 0:
            raise FormatContractError(
                "format.rank() must return a non-negative integer"
            )
        if r >= self._n_out:
            raise InvalidCovertextError("invalid covertext")
        x = self._cipher.decrypt_int(
            r, domain=self._n_out, tweak=self._tweak_base + tweak
        )
        if x >= self._n_in:
            # The output space is larger than the input space; this ciphertext
            # deciphers outside the valid inputs, so it was never a covertext.
            raise InvalidCovertextError("invalid covertext")
        return self._input_format.unrank(x)

    def _encrypt_preserve_length(self, plaintext: Plaintext, tweak: bytes):
        fmt = self._input_format
        try:
            length = len(plaintext)
        except TypeError as exc:
            raise InvalidPlaintextError("plaintext has no length") from exc
        try:
            offset, count = fmt.slice_bounds(length)
            r = fmt.rank(plaintext) - offset
        except Exception as exc:
            raise InvalidPlaintextError("invalid plaintext") from exc
        if count <= 0 or not 0 <= r < count:
            raise InvalidPlaintextError(
                "plaintext is not in the length slice it claims"
            )
        call_tweak = self._tweak_base + length.to_bytes(4, "big") + tweak
        c = self._cipher.encrypt_int(r, domain=count, tweak=call_tweak)
        return fmt.unrank(offset + c)

    def _decrypt_preserve_length(self, covertext: Covertext, tweak: bytes):
        fmt = self._input_format
        try:
            length = len(covertext)
        except TypeError as exc:
            raise InvalidCovertextError("invalid covertext") from exc
        try:
            offset, count = fmt.slice_bounds(length)
        except Exception as exc:
            raise InvalidCovertextError("invalid covertext") from exc
        if count <= 0:
            raise InvalidCovertextError("invalid covertext")
        try:
            r = fmt.rank(covertext) - offset
        except Exception as exc:
            raise InvalidCovertextError("invalid covertext") from exc
        if not 0 <= r < count:
            raise InvalidCovertextError("invalid covertext")
        call_tweak = self._tweak_base + length.to_bytes(4, "big") + tweak
        x = self._cipher.decrypt_int(r, domain=count, tweak=call_tweak)
        return fmt.unrank(offset + x)

    # ---- AE path ------------------------------------------------------ #
    def _encrypt_ae(self, plaintext: Plaintext) -> Covertext:
        if self._input_is_bytes:
            if not isinstance(plaintext, bytes):
                raise TypeError("plaintext must be bytes")
            pt_bytes = plaintext
            # Exceeding the resource ceiling is the caller's own limit;
            # exceeding a finite format's capacity is the format being too
            # small. The capacity check is the exact inverse of
            # frame.capacity_plaintext_limit.
            if len(pt_bytes) > self._resource_max:
                raise MessageTooLargeError(
                    "plaintext exceeds the configured max_plaintext_bytes"
                )
            if (
                self._capacity_limit is not None
                and len(pt_bytes) > self._capacity_limit
            ):
                raise FormatCapacityError(
                    "format cannot represent every encrypted payload at this "
                    "length"
                )
        else:
            r = self._rank_plaintext(plaintext)
            pt_bytes = r.to_bytes(self._max_plaintext_bytes, "big")

        ciphertext = self._encrypter.encrypt(pt_bytes)
        framed = self._FRAME_VERSION + ciphertext
        index = frame.bytes_to_rank(framed)
        try:
            return self._output_format.unrank(index)
        except Exception as exc:
            raise FormatCapacityError(
                "format cannot represent the encrypted payload rank"
            ) from exc

    def _decrypt_ae(self, covertext: Covertext) -> Plaintext:
        # A bytes covertext longer than the largest frame can never decrypt;
        # reject it before rank() materializes a huge integer from junk.
        if (
            isinstance(self._output_format, BytesFormat)
            and isinstance(covertext, (bytes, bytearray))
            and len(covertext) > self._max_frame_bytes
        ):
            raise InvalidCovertextError("invalid covertext")
        try:
            index = self._output_format.rank(covertext)
        except Exception as exc:
            raise InvalidCovertextError("invalid covertext") from exc

        if type(index) is not int or index < 0:
            raise FormatContractError(
                "format.rank() must return a non-negative integer"
            )
        # These size guards stay lazy per call: a precomputed 256**N rank bound
        # would make __init__ cost and retained memory linear in
        # max_plaintext_bytes, while these checks are cheap on every decrypt.
        if self._n_out is not None and index >= self._n_out:
            raise InvalidCovertextError("invalid covertext")
        if index.bit_length() > 8 * self._max_frame_bytes + 1:
            raise InvalidCovertextError("invalid covertext")
        if frame.rank_byte_length(index) > self._max_frame_bytes:
            raise InvalidCovertextError("invalid covertext")

        framed = frame.rank_to_bytes(index)
        if not framed.startswith(self._FRAME_VERSION) or len(framed) < (
            len(self._FRAME_VERSION) + self._CIPHERTEXT_EXPANSION
        ):
            raise InvalidCovertextError("invalid covertext")

        ciphertext = framed[len(self._FRAME_VERSION):]
        try:
            pt_bytes = self._encrypter.decrypt(ciphertext)
        except DecryptionError:
            pt_bytes = None
        if pt_bytes is None:
            # Raised outside the handler: pre-MAC header detail must not chain
            # into public errors, so neither __cause__ nor __context__ is set.
            raise InvalidCovertextError("invalid covertext") from None

        if self._input_is_bytes:
            return pt_bytes
        if len(pt_bytes) != self._max_plaintext_bytes:
            raise InvalidCovertextError("invalid covertext")
        r = int.from_bytes(pt_bytes, "big")
        if r >= self._n_in:
            raise InvalidCovertextError("invalid covertext")
        return self._input_format.unrank(r)
