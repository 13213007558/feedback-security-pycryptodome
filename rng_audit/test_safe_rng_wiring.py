"""Recommended, production-safe test wiring for controlled PyCryptodome RNG.

Design rules (these are what keep test randomness out of production):

1. NEVER monkeypatch ``os.urandom`` or reassign ``Crypto.Random.get_random_bytes``
   at import time / session scope. Half the library binds the name early, so a
   global patch is order-dependent and a leak poisons every later test.
2. Prefer the explicit ``randfunc=`` / ``rand_func=`` parameter supported by the
   public entry points. It is local to one call and needs no global mutation.
3. For symmetric modes, which have NO randfunc parameter, pass an explicit
   ``iv=`` / ``nonce=`` drawn from the test double instead of patching.
4. If a global patch is unavoidable, scope it to a fixture with teardown that
   restores the original binding, and patch BOTH the public alias and the
   already-imported module-level names (early-bound modules keep their own copy).
5. Run failure-injection in a subprocess so the broken RNG cannot outlive the
   test (see run_isolated_audit.py); assert the error propagates and that no
   silent fallback to os.urandom occurred.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _rng_helpers import CountingDeterministicRNG, FailingRNG  # noqa: E402


# ---------------------------------------------------------------------------
# Rule 2: explicit randfunc is the safe default for key generation / OAEP / PSS
# ---------------------------------------------------------------------------

def test_rsa_generate_uses_explicit_randfunc_locally():
    from Crypto.PublicKey import RSA
    rng = CountingDeterministicRNG()
    key = RSA.generate(1024, randfunc=rng)
    assert rng.total_bytes > 0
    # Same deterministic stream -> identical key, proving provenance.
    assert RSA.generate(1024, randfunc=CountingDeterministicRNG()).n == key.n


def test_ecc_generate_uses_explicit_randfunc():
    from Crypto.PublicKey import ECC
    rng = CountingDeterministicRNG()
    key = ECC.generate(curve="p256", randfunc=rng)
    assert rng.calls  # ECC p256 draws scalar bytes through randfunc
    assert int(ECC.generate(curve="p256",
                            randfunc=CountingDeterministicRNG()).d) == int(key.d)


def test_oaep_encrypt_uses_explicit_randfunc():
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    rsa = RSA.generate(1024, randfunc=CountingDeterministicRNG())
    rng = CountingDeterministicRNG()
    c1 = PKCS1_OAEP.new(rsa, SHA256, randfunc=rng).encrypt(b"x")
    c2 = PKCS1_OAEP.new(rsa, SHA256,
                        randfunc=CountingDeterministicRNG()).encrypt(b"x")
    assert rng.calls == [32]  # one seed draw, SHA-256 hLen
    assert c1 == c2


def test_pss_sign_uses_explicit_randfunc():
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pss
    from Crypto.Hash import SHA256
    rsa = RSA.generate(1024, randfunc=CountingDeterministicRNG())
    rng = CountingDeterministicRNG()
    s1 = pss.new(rsa, rand_func=rng).sign(SHA256.new(b"m"))
    s2 = pss.new(rsa, rand_func=CountingDeterministicRNG()).sign(
        SHA256.new(b"m"))
    assert rng.calls == [32]  # salt draw only; MGF1 is deterministic
    assert s1 == s2


# ---------------------------------------------------------------------------
# Rule 3: symmetric modes take an explicit iv/nonce VALUE, not a randfunc
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode,kw,length", [
    ("MODE_CBC", {}, 16),
    ("MODE_GCM", {}, 16),
    ("MODE_EAX", {}, 16),
    ("MODE_CCM", {}, 11),
    ("MODE_OCB", {}, 15),
])
def test_symmetric_modes_controlled_via_explicit_iv_nonce(mode, kw, length):
    from Crypto.Cipher import AES
    rng = CountingDeterministicRNG()
    iv_nonce = rng(length)
    cipher = AES.new(b"k" * 16, getattr(AES, mode),
                     nonce=iv_nonce, **kw) if mode != "MODE_CBC" else \
        AES.new(b"k" * 16, getattr(AES, mode), iv=iv_nonce)
    blob = getattr(cipher, "nonce", getattr(cipher, "iv", None))
    assert bytes(blob) == iv_nonce


def test_chacha20_controlled_via_explicit_nonce():
    from Crypto.Cipher import ChaCha20
    nonce = CountingDeterministicRNG()(8)
    c = ChaCha20.new(key=b"k" * 32, nonce=nonce)
    assert bytes(c.nonce) == nonce


# ---------------------------------------------------------------------------
# Rule 4: if a global patch is required, restore it AND cover early-bound names
# ---------------------------------------------------------------------------

@pytest.fixture
def controlled_global_rng():
    """Patch every binding PyCryptodome 4.4.0 uses, then restore all of them.

    Late-bound modules read ``Crypto.Random.get_random_bytes`` at call time;
    early-bound modules hold their own ``get_random_bytes`` name copied at
    import. A safe global patch must re-point both, and snapshot/restore each.
    """
    import Crypto.Random
    from Crypto.Cipher import (  # noqa: F401 - ensure names exist to patch
        AES, ChaCha20, Salsa20, _mode_cbc, _mode_gcm, _mode_eax)
    from Crypto.PublicKey import ECC

    rng = CountingDeterministicRNG()
    snapshots = {
        Crypto.Random: ("get_random_bytes",
                        Crypto.Random.get_random_bytes),
        _mode_cbc: ("get_random_bytes", _mode_cbc.get_random_bytes),
        _mode_gcm: ("get_random_bytes", _mode_gcm.get_random_bytes),
        _mode_eax: ("get_random_bytes", _mode_eax.get_random_bytes),
        ChaCha20: ("get_random_bytes", ChaCha20.get_random_bytes),
        Salsa20: ("get_random_bytes", Salsa20.get_random_bytes),
        AES: ("get_random_bytes", AES.get_random_bytes),
        ECC: ("get_random_bytes", ECC.get_random_bytes),
    }
    for module, (attr, _original) in snapshots.items():
        setattr(module, attr, rng)
    yield rng
    for module, (attr, original) in snapshots.items():
        setattr(module, attr, original)


def test_global_patch_fixture_touches_and_restores_cbc(controlled_global_rng):
    from Crypto.Cipher import AES
    cipher = AES.new(b"k" * 16, AES.MODE_CBC)
    assert controlled_global_rng.calls  # CBC draw reached the double
    assert bytes(cipher.iv) == CountingDeterministicRNG()(16)


def test_binding_restored_to_real_os_urandom_after_fixture():
    # Runs after the fixture's teardown in the test above: the public alias
    # must once again be the genuine os.urandom object, not a test double.
    import os
    from Crypto import Random
    assert Random.get_random_bytes is os.urandom


# ---------------------------------------------------------------------------
# Rule 5: failure must propagate, never silently fall back to another RNG
# ---------------------------------------------------------------------------

def test_explicit_failing_randfunc_propagates():
    from Crypto.PublicKey import RSA
    with pytest.raises(RuntimeError, match="injected RNG failure"):
        RSA.generate(1024, randfunc=FailingRNG())


def test_explicit_failing_randfunc_pss_propagates():
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pss
    from Crypto.Hash import SHA256
    rsa = RSA.generate(1024, randfunc=CountingDeterministicRNG())
    with pytest.raises(RuntimeError, match="injected RNG failure"):
        pss.new(rsa, rand_func=FailingRNG()).sign(SHA256.new(b"m"))
