"""Subprocess failure-injection tests: prove errors propagate and no silent
fallback to os.urandom occurs, without ever leaving a broken RNG in the
parent interpreter or in production code.

Each test spawns a fresh python process that installs a failing RNG, exercises
one entry point, and prints a JSON verdict. The parent only reads the verdict.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

CHILD = r"""
import json, os, sys
sys.path.insert(0, %r)
from _rng_helpers import FailingRNG, OsUrandomSentinel, CountingDeterministicRNG

entry = sys.argv[1]

# Import target modules FIRST so early-bound names copy the real RNG, mirroring
# a real post-import monkeypatch setup.
if entry in ("RSA", "OAEP", "PSS"):
    from Crypto.PublicKey import RSA
    if entry == "OAEP":
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.Hash import SHA256
    if entry == "PSS":
        from Crypto.Signature import pss
        from Crypto.Hash import SHA256
elif entry == "ECC":
    from Crypto.PublicKey import ECC
elif entry == "CHACHA20":
    from Crypto.Cipher import ChaCha20

fail = FailingRNG()
sentinel = OsUrandomSentinel()
os.urandom = sentinel                      # watch late-bound fallback
import Crypto.Random
Crypto.Random.get_random_bytes = fail      # post-import global patch

verdict = {"entry": entry}
try:
    if entry == "RSA":
        RSA.generate(1024)
    elif entry == "ECC":
        ECC.generate(curve="p256")
    elif entry == "OAEP":
        rsa = RSA.generate(1024, randfunc=CountingDeterministicRNG())
        PKCS1_OAEP.new(rsa, SHA256).encrypt(b"m")
    elif entry == "PSS":
        rsa = RSA.generate(1024, randfunc=CountingDeterministicRNG())
        pss.new(rsa).sign(SHA256.new(b"m"))
    elif entry == "CHACHA20":
        ChaCha20.new(key=b"k" * 32)
    verdict.update(raised=False, fail_calls=list(fail.calls),
                   os_urandom_calls=list(sentinel.calls))
except RuntimeError as exc:
    verdict.update(raised=True, error=str(exc),
                   fail_calls=list(fail.calls),
                   os_urandom_calls=list(sentinel.calls))
print("JSON " + json.dumps(verdict))
""" % HERE


def _run(entry):
    proc = subprocess.run(
        [sys.executable, "-c", CHILD, entry],
        capture_output=True, text=True, timeout=120,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("JSON "):
            return json.loads(line[5:])
    raise AssertionError("no verdict: " + proc.stderr[-300:])


def test_late_bound_entries_propagate_and_never_fall_back():
    for entry in ("RSA", "OAEP", "PSS"):
        v = _run(entry)
        assert v["raised"] is True, v
        assert v["fail_calls"], "failing RNG was never reached: %s" % v
        assert v["os_urandom_calls"] == [], "silent os.urandom fallback: %s" % v


def test_early_bound_entries_bypass_post_import_patch():
    # ECC and ChaCha20 copy get_random_bytes at import time. A post-import
    # global patch is ignored: the failing RNG is never reached, no error is
    # raised, and the original os.urandom object (not even the sentinel, which
    # was installed after binding) supplies real entropy.
    for entry in ("ECC", "CHACHA20"):
        v = _run(entry)
        assert v["raised"] is False, v
        assert v["fail_calls"] == [], "patch should be ignored: %s" % v
        assert v["os_urandom_calls"] == [], \
            "bound name predates the sentinel; real RNG is used: %s" % v


def test_explicit_failing_randfunc_never_touches_os_urandom():
    code = (
        "import sys, json; sys.path.insert(0, %r);"
        "from _rng_helpers import FailingRNG, OsUrandomSentinel;"
        "import os; s=OsUrandomSentinel(); os.urandom=s;"
        "from Crypto.PublicKey import RSA;"
        "r={'os_urandom_calls': list(s.calls)};"
        "\ntry:\n RSA.generate(1024, randfunc=FailingRNG()); r['raised']=False\n"
        "except RuntimeError: r['raised']=True; r['os_urandom_calls']=list(s.calls)\n"
        "print('JSON '+json.dumps(r))"
    ) % HERE
    proc = subprocess.run([sys.executable, "-c", code],
                          capture_output=True, text=True, timeout=120)
    verdict = json.loads(
        [ln for ln in proc.stdout.splitlines() if ln.startswith("JSON ")][0][5:])
    assert verdict["raised"] is True
    assert verdict["os_urandom_calls"] == []
