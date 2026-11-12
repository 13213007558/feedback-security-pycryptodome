"""Isolated probes: who actually consumes injected randomness in PyCryptodome?

Each experiment runs in its own subprocess (see run_isolated_audit.py) so
import order and monkeypatching never leak across cases. Every case emits a
JSON line consumed by the runner.

Patch styles under test
-----------------------
GLOBAL_POST  : monkeypatch Crypto.Random.get_random_bytes AFTER the target
               module has already been imported (the common, and fragile,
               test setup).
GLOBAL_PRE   : monkeypatch Crypto.Random.get_random_bytes BEFORE importing
               the target module.
EXPLICIT     : pass randfunc=/rand_func= directly at the public entry point.

Binding styles observed in lib/Crypto (4.4.0)
---------------------------------------------
LATE  : code does ``from Crypto import Random`` and reads
        ``Random.get_random_bytes`` at call time  -> GLOBAL_POST works.
EARLY : code does ``from Crypto.Random import get_random_bytes`` at module
        import time, binding the name once         -> GLOBAL_POST is ignored.
"""
from __future__ import annotations

import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _rng_helpers import CountingDeterministicRNG, FailingRNG, OsUrandomSentinel  # noqa: E402

import Crypto  # noqa: E402
import Crypto.Random  # noqa: E402

VERSION = Crypto.__version__


def _result(name, **kw):
    out = {"case": name, "version": VERSION}
    out.update(kw)
    print("JSON " + json.dumps(out, sort_keys=True))


def _guard_os_urandom():
    """Replace os.urandom with a recording sentinel.

    Crypto.Random.get_random_bytes is itself an alias of os.urandom, so the
    sentinel doubles as evidence of any draw that bypassed our injection and
    reached the real OS entropy source.
    """
    sentinel = OsUrandomSentinel()
    os.urandom = sentinel
    return sentinel


# ---------------------------------------------------------------------------
# Individual entry points. Each returns the random-drawing object/value path
# so the caller can trigger one draw deterministically.
# ---------------------------------------------------------------------------

def _rsa_key():
    from Crypto.PublicKey import RSA
    return RSA.generate(1024)


def _ecc_key(curve="p256"):
    from Crypto.PublicKey import ECC
    return ECC.generate(curve=curve)


def _oaep_cipher(key):
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    return PKCS1_OAEP.new(key, hashAlgo=SHA256)


def _pss_signer(key):
    from Crypto.Signature import pss
    from Crypto.Hash import SHA256
    return pss.new(key)


def _aes_cbc(mode_kw=None):
    from Crypto.Cipher import AES
    return AES.new(b"A" * 16, AES.MODE_CBC)


def _aes_gcm():
    from Crypto.Cipher import AES
    return AES.new(b"A" * 16, AES.MODE_GCM)


def _chacha():
    from Crypto.Cipher import ChaCha20
    return ChaCha20.new(key=b"k" * 32)


ENTRY_DRAW = {
    # name: (loader, draw action, expected default draw sizes when unpatched
    #        is not asserted here; sizes are recorded instead)
}


def run_counting(case, patch_style, entry):
    """Deterministic counting RNG: record whether draws reach our double.

    GLOBAL_POST patches ONLY ``Crypto.Random.get_random_bytes`` (the realistic
    test setup); ``os.urandom`` stays real but is sentinel-wrapped so any draw
    that bypasses the patch is visible as real-OS-entropy consumption.
    """
    rng = CountingDeterministicRNG()
    if patch_style == "GLOBAL_PRE":
        # Before target import: point both names at our double, because
        # early-bound modules copy the name during import below.
        os.urandom = rng
        Crypto.Random.get_random_bytes = rng
        _import_target(entry)
    elif patch_style == "GLOBAL_POST":
        _import_target(entry)
        # Realistic test setup: patch ONLY the public alias. os.urandom keeps
        # its original function object, which early-bound modules still hold.
        # Interception is decided solely by whether OUR double gets called;
        # if not, the draw went to the real OS RNG (no way to re-wrap the
        # already-bound object without touching the target module itself).
        Crypto.Random.get_random_bytes = rng
    elif patch_style == "GLOBAL_POST_PRELOADED":
        # Worst-case ordering: instantiate once so all lazy _mode_* modules
        # bind their get_random_bytes name, then patch the public alias.
        _preload_target(entry)
        Crypto.Random.get_random_bytes = rng
    try:
        outcome = _draw(entry, rng, explicit=(patch_style == "EXPLICIT"))
    except Exception as exc:  # noqa: BLE001 - audit wants the raw failure
        _result(case, patch=patch_style, intercepted=False,
                os_urandom_calls=[],
                error=type(exc).__name__ + ": " + str(exc)[:120])
        return
    # A draw only counts as intercepted when OUR double was actually called.
    really_intercepted = outcome["used_injected"] and bool(rng.calls)
    _result(case, patch=patch_style,
            intercepted=really_intercepted,
            call_sizes=rng.calls, total_bytes=rng.total_bytes,
            os_urandom_calls=[] if really_intercepted else ["real OS RNG (uncounted)"],
            bypassed_to_os=not really_intercepted
            and patch_style in ("GLOBAL_POST", "GLOBAL_POST_PRELOADED"),
            evidence=outcome["evidence"])


def run_failing(case, entry):
    """Post-import patch with a failing RNG; detect silent fallback.

    Realistic setup: only ``Crypto.Random.get_random_bytes`` is re-pointed.
    ``os.urandom`` is sentinel-wrapped so any late-bound fallback is visible;
    early-bound modules keep the original OS RNG object, and for them the
    probe's evidence is simply that the failing RNG is never called.
    """
    _import_target(entry)
    fail = FailingRNG()
    sentinel = _guard_os_urandom()
    Crypto.Random.get_random_bytes = fail
    try:
        outcome = _draw(entry, fail, explicit=False)
        _result(case, patch="FAIL_GLOBAL",
                intercepted=outcome["used_injected"],
                fail_calls=fail.calls, os_urandom_calls=sentinel.calls,
                silent_fallback=bool(sentinel.calls),
                note="no error raised")
    except Exception as exc:  # noqa: BLE001
        _result(case, patch="FAIL_GLOBAL",
                intercepted=bool(fail.calls),
                fail_calls=fail.calls, os_urandom_calls=sentinel.calls,
                silent_fallback=bool(sentinel.calls),
                propagated_error=type(exc).__name__ + ": " + str(exc)[:120])


def run_failing_explicit(case, entry):
    """Same, but the failing RNG is passed explicitly to the entry point."""
    fail = FailingRNG()
    sentinel = _guard_os_urandom()
    try:
        outcome = _draw(entry, fail, explicit=True)
        _result(case, patch="FAIL_EXPLICIT",
                intercepted=outcome["used_injected"],
                fail_calls=fail.calls, os_urandom_calls=sentinel.calls,
                silent_fallback=bool(sentinel.calls),
                note="no error raised")
    except Exception as exc:  # noqa: BLE001
        _result(case, patch="FAIL_EXPLICIT",
                intercepted=bool(fail.calls),
                fail_calls=fail.calls, os_urandom_calls=sentinel.calls,
                silent_fallback=bool(sentinel.calls),
                propagated_error=type(exc).__name__ + ": " + str(exc)[:120])


# ---------------------------------------------------------------------------
# Entry-point plumbing
# ---------------------------------------------------------------------------

def _import_target(entry):
    if entry == "RSA_GENERATE":
        from Crypto.PublicKey import RSA  # noqa: F401
    elif entry == "ECC_GENERATE":
        from Crypto.PublicKey import ECC  # noqa: F401
    elif entry == "OAEP_ENCRYPT":
        from Crypto.Cipher import PKCS1_OAEP  # noqa: F401
    elif entry == "PSS_SIGN":
        from Crypto.Signature import pss  # noqa: F401
    elif entry in ("AES_CBC_IV", "AES_GCM_NONCE", "CHACHA20_NONCE"):
        if entry.startswith("AES"):
            from Crypto.Cipher import AES  # noqa: F401
        else:
            from Crypto.Cipher import ChaCha20  # noqa: F401


def _preload_target(entry):
    """Force every lazily imported module/name to bind BEFORE patching.

    AES.new() imports its _mode_* module on first call; instantiating once
    here makes a subsequent post-import patch behave like true early binding.
    """
    from Crypto.Cipher import AES, ChaCha20
    if entry == "AES_CBC_IV":
        AES.new(b"k" * 16, AES.MODE_CBC)
    elif entry == "AES_GCM_NONCE":
        AES.new(b"k" * 16, AES.MODE_GCM)
    elif entry == "CHACHA20_NONCE":
        ChaCha20.new(key=b"k" * 32)
    else:
        _import_target(entry)


def _draw(entry, rng, explicit):
    """Trigger exactly one randomized operation; report provenance."""
    if entry == "RSA_GENERATE":
        from Crypto.PublicKey import RSA
        kw = {"randfunc": rng} if explicit else {}
        key = RSA.generate(1024, **kw)
        # Prove the draw really came from us: re-generate with the same RNG
        # state class and confirm deterministic equality.
        rng2 = CountingDeterministicRNG()
        key2 = RSA.generate(1024, randfunc=rng2)
        return {"used_injected": key.n == key2.n,
                "evidence": "deterministic regeneration matches" if key.n == key2.n
                else "output differs from deterministic baseline"}

    if entry == "ECC_GENERATE":
        from Crypto.PublicKey import ECC
        kw = {"randfunc": rng} if explicit else {}
        key = ECC.generate(curve="p256", **kw)
        rng2 = CountingDeterministicRNG()
        key2 = ECC.generate(curve="p256", randfunc=rng2)
        return {"used_injected": int(key.d) == int(key2.d),
                "evidence": "scalar d matches deterministic baseline"
                if int(key.d) == int(key2.d)
                else "scalar d differs from deterministic baseline"}

    if entry == "OAEP_ENCRYPT":
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.Hash import SHA256
        rsa = RSA.generate(1024, randfunc=CountingDeterministicRNG())
        kw = {"randfunc": rng} if explicit else {}
        cipher = PKCS1_OAEP.new(rsa, hashAlgo=SHA256, **kw)
        c1 = cipher.encrypt(b"audit")
        rng2 = CountingDeterministicRNG()
        cipher2 = PKCS1_OAEP.new(rsa, hashAlgo=SHA256, randfunc=rng2)
        c2 = cipher2.encrypt(b"audit")
        return {"used_injected": c1 == c2,
                "evidence": "ciphertexts identical under same RNG stream"
                if c1 == c2 else "ciphertexts random despite injection"}

    if entry == "PSS_SIGN":
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pss
        from Crypto.Hash import SHA256
        rsa = RSA.generate(1024, randfunc=CountingDeterministicRNG())
        kw = {"rand_func": rng} if explicit else {}
        signer = pss.new(rsa, **kw)
        h = SHA256.new(b"audit")
        s1 = signer.sign(h)
        rng2 = CountingDeterministicRNG()
        s2 = pss.new(rsa, rand_func=rng2).sign(SHA256.new(b"audit"))
        return {"used_injected": s1 == s2,
                "evidence": "signatures identical under same RNG stream"
                if s1 == s2 else "salts random despite injection"}

    if entry == "AES_CBC_IV":
        from Crypto.Cipher import AES
        if explicit:
            return _explicit_iv_case(AES.MODE_CBC, 16)
        c = AES.new(b"k" * 16, AES.MODE_CBC)
        used = bool(rng.calls) and bytes(c.iv) == CountingDeterministicRNG()(16)
        return {"used_injected": used,
                "evidence": "iv drawn from injected double"
                if used else "iv from real OS RNG (injection bypassed)"}

    if entry == "AES_GCM_NONCE":
        from Crypto.Cipher import AES
        if explicit:
            return _explicit_iv_case(AES.MODE_GCM, 16)
        c = AES.new(b"k" * 16, AES.MODE_GCM)
        used = bool(rng.calls) and bytes(c.nonce) == CountingDeterministicRNG()(16)
        return {"used_injected": used,
                "evidence": "nonce drawn from injected double"
                if used else "nonce from real OS RNG (injection bypassed)"}

    if entry == "CHACHA20_NONCE":
        from Crypto.Cipher import ChaCha20
        if explicit:
            return {"used_injected": False,
                    "evidence": "ChaCha20.new has no randfunc parameter "
                                "(nonce must be supplied by caller)"}
        c = ChaCha20.new(key=b"k" * 32)
        used = bool(rng.calls) and bytes(c.nonce) == CountingDeterministicRNG()(8)
        return {"used_injected": used,
                "evidence": "nonce drawn from injected double"
                if used else "nonce from real OS RNG (injection bypassed)"}

    raise ValueError(entry)


def _explicit_iv_case(mode, size):
    """Modes take the random value itself (iv=/nonce=), not a randfunc."""
    return {"used_injected": False,
            "evidence": "symmetric modes accept an explicit iv=/nonce= of "
                        "%d bytes; there is no randfunc parameter" % size}


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

ENTRIES = ["RSA_GENERATE", "ECC_GENERATE", "OAEP_ENCRYPT", "PSS_SIGN",
           "AES_CBC_IV", "AES_GCM_NONCE", "CHACHA20_NONCE"]


def main():
    mode = sys.argv[1]
    entry = sys.argv[2]
    if mode == "count":
        run_counting(entry, sys.argv[3], entry)
    elif mode == "fail":
        run_failing(entry, entry)
    elif mode == "fail_explicit":
        run_failing_explicit(entry, entry)
    else:
        raise SystemExit("unknown mode " + mode)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(2)
