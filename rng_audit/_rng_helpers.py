"""Shared test doubles for the PyCryptodome entropy audit.

These doubles are intentionally *only* imported by the audit scripts in this
directory. Nothing here is imported by application code.
"""
from __future__ import annotations

import hashlib
import os


class CountingDeterministicRNG:
    """Deterministic, call-counting stand-in for ``get_random_bytes(n)``.

    Output is fully reproducible (a seeded hash keystream, never OS entropy)
    and every (n, cumulative_count) request is recorded so tests can assert
    how many random draws a code path makes and with what sizes.

    The keystream is SHA-256 over a monotonic block counter rather than raw
    counter bytes: prime/key-generation tests assume uniformly distributed
    input, and structured byte fills pathologically slow down primality
    testing while still being deterministic.
    """

    def __init__(self) -> None:
        self.calls: list[int] = []
        self.total_bytes = 0
        self._block = 0
        self._buf = b""

    def __call__(self, n: int) -> bytes:
        if not isinstance(n, int) or n < 0:
            raise ValueError("bad length %r" % (n,))
        self.calls.append(n)
        self.total_bytes += n
        out = bytearray()
        while len(out) < n:
            if not self._buf:
                self._block += 1
                self._buf = hashlib.sha256(
                    b"audit-rng/%d" % self._block
                ).digest()
            take = min(n - len(out), len(self._buf))
            out += self._buf[:take]
            self._buf = self._buf[take:]
        return bytes(out)


class FailingRNG:
    """RNG that always raises, mimicking a broken/blocked entropy source."""

    def __init__(self, exc: BaseException = RuntimeError("injected RNG failure")) -> None:
        self.exc = exc
        self.calls: list[int] = []

    def __call__(self, n: int) -> bytes:
        self.calls.append(n)
        raise self.exc


class OsUrandomSentinel:
    """Wraps ``os.urandom`` and records every call.

    A failing injected RNG must either propagate the error or stop; if code
    silently falls back to the OS RNG, this sentinel records the fallback so
    the audit can detect it instead of guessing.
    """

    def __init__(self) -> None:
        self.calls: list[int] = []
        self._real = os.urandom

    def __call__(self, n: int) -> bytes:
        self.calls.append(n)
        return self._real(n)


def fresh_state():
    """Return fresh doubles for one isolated experiment."""
    return CountingDeterministicRNG(), FailingRNG(), OsUrandomSentinel()
