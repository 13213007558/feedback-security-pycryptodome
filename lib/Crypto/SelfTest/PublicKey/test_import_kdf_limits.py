#
#  SelfTest/PublicKey/test_import_kdf_limits.py: end-to-end verification that
#  the max_iteration_count, threads and max_memory limits of the private key
#  import API reach the actual KDF and reject crafted blobs before any
#  expensive key derivation runs.
#
# SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""Self-tests for the propagation of the KDF resource limits from the public
``import_key`` API (RSA and ECC) down to the PBKDF1/PBKDF2/scrypt/bcrypt KDFs.

The expensive parameters are never actually computed: the KDF is replaced by an
observable stub that records the call (and fails if reached), so that a limit
violation is proven to be rejected *before* the costly derivation. Only small,
real parameters are used for the successful round-trips.
"""

import base64
import struct

import pytest

from Crypto import (
    IncorrectPassphraseError,
    KdfIterationLimitError,
    KdfMemoryLimitError,
    PassphraseRequiredError,
)
from Crypto.Cipher import AES, DES
from Crypto.Hash import SHA1
from Crypto.IO import _PBES
from Crypto.IO._PBES import (
    _DEFAULT_MAX_BCRYPT_ROUNDS,
    _DEFAULT_MAX_ITERATION_COUNT,
    _DEFAULT_MAX_MEMORY,
    _DEFAULT_MAX_SCRYPT_COST,
    _OID_PBES2,
    _OID_PBKDF2,
    _OID_SCRYPT,
    PBES1,
    PBES2,
)
from Crypto.Protocol import KDF
from Crypto.PublicKey import ECC, RSA
from Crypto.PublicKey import _openssh
from Crypto.Util.Padding import pad
from Crypto.Util.asn1 import DerInteger, DerObjectId, DerOctetString, DerSequence

PASSWORD = "pw"
SCRYPT = "scryptAndAES256-CBC"
PBKDF2_CBC = "PBKDF2WithHMAC-SHA256AndAES128-CBC"
PBKDF2_GCM = "PBKDF2WithHMAC-SHA256AndAES256-GCM"

# Small, real parameters: cheap enough to run for real in the round-trip tests.
FAST_PBKDF2 = {"iteration_count": 4}
FAST_SCRYPT = {"iteration_count": 1024, "block_size": 8, "parallelization": 1}
# A value so large that actually deriving a key would take hours / exhaust RAM.
HUGE_PBKDF2_COUNT = _DEFAULT_MAX_ITERATION_COUNT + 1
HUGE_SCRYPT_N = 2**40
HUGE_BCRYPT_ROUNDS = _DEFAULT_MAX_BCRYPT_ROUNDS + 1


# ---------------------------------------------------------------------------
# Observability helpers
# ---------------------------------------------------------------------------


class KdfNotExpected(Exception):
    """Raised by the stubs when a limit should have stopped the import first."""


class RecordingKdf:
    """Patch one of the KDF entry points actually used by the import path.

    The replacement records every call (and the keyword arguments), then either
    delegates to the real KDF or raises :class:`KdfNotExpected`. The point is
    that a limit rejection must happen with zero recorded calls.
    """

    def __init__(self, module, name, delegate=False, real=None):
        self.module = module
        self.name = name
        self.delegate = delegate
        self.real = real
        self.calls = 0
        self.kwargs = []
        self._original = getattr(module, name)

    def __call__(self, *args, **kwargs):
        self.calls += 1
        self.kwargs.append(kwargs)
        if self.delegate:
            return self.real(*args, **kwargs)
        raise KdfNotExpected("the %s KDF must not run for an over-limit blob" % self.name)

    def install(self):
        setattr(self.module, self.name, self)
        return self

    def restore(self):
        setattr(self.module, self.name, self._original)


@pytest.fixture
def blocked_pbkdf2(monkeypatch):
    stub = RecordingKdf(_PBES, "PBKDF2")
    monkeypatch.setattr(_PBES, "PBKDF2", stub)
    return stub


@pytest.fixture
def blocked_scrypt(monkeypatch):
    stub = RecordingKdf(_PBES, "scrypt")
    monkeypatch.setattr(_PBES, "scrypt", stub)
    return stub


@pytest.fixture
def blocked_pbkdf1(monkeypatch):
    stub = RecordingKdf(_PBES, "PBKDF1")
    monkeypatch.setattr(_PBES, "PBKDF1", stub)
    return stub


@pytest.fixture
def blocked_bcrypt(monkeypatch):
    stub = RecordingKdf(_openssh, "_bcrypt_pbkdf")
    monkeypatch.setattr(_openssh, "_bcrypt_pbkdf", stub)
    return stub


@pytest.fixture
def recording_scrypt(monkeypatch):
    """scrypt spy that still returns the real derived key (for threads)."""
    real = _PBES.scrypt
    stub = RecordingKdf(_PBES, "scrypt", delegate=True, real=real)
    monkeypatch.setattr(_PBES, "scrypt", stub)
    return stub


# ---------------------------------------------------------------------------
# Blob builders / mutators
# ---------------------------------------------------------------------------


def _decode_pbes2(blob):
    epi = DerSequence().decode(blob, nr_elements=2)
    alg = DerSequence().decode(epi[0])
    assert DerObjectId().decode(alg[0]).value == _OID_PBES2
    pbes2 = DerSequence().decode(alg[1], nr_elements=2)
    kdf = DerSequence().decode(pbes2[0], nr_elements=2)
    encrypted = DerOctetString().decode(epi[1]).payload
    return alg, pbes2, kdf, encrypted


def _encode_pbes2(alg, pbes2, kdf, kdf_params_der, encrypted):
    new_kdf = DerSequence([kdf[0], kdf_params_der]).encode()
    new_pbes2 = DerSequence([new_kdf, pbes2[1]]).encode()
    new_alg = DerSequence([alg[0], new_pbes2]).encode()
    return DerSequence([DerSequence().decode(new_alg), DerOctetString(encrypted)]).encode()


def _to_der(blob):
    """Decode a PEM PKCS#8 blob to DER; pass DER through unchanged."""
    if blob[:1] == b"-":
        from Crypto.IO import PEM

        der, _marker, _enc_flag = PEM.decode(blob.decode("latin-1"), PASSWORD.encode())
        return der
    return blob


def _reencode(original, der):
    """Re-wrap mutated DER in PEM if the input was PEM, so that the import
    still goes through the PEM parsing branch."""
    if original[:1] != b"-":
        return der
    body = base64.encodebytes(der).strip()
    return (b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + body
            + b"\n-----END ENCRYPTED PRIVATE KEY-----\n")


def mutate_pbkdf2_count(blob, new_count):
    original = blob
    blob = _to_der(blob)
    alg, pbes2, kdf, encrypted = _decode_pbes2(blob)
    assert DerObjectId().decode(kdf[0]).value == _OID_PBKDF2
    params = DerSequence().decode(kdf[1], nr_elements=(2, 3, 4))
    items = [params[0], DerInteger(new_count).encode()]
    items += [params[i] for i in range(2, len(params))]
    return _reencode(original, _encode_pbes2(alg, pbes2, kdf, DerSequence(items).encode(), encrypted))


def mutate_scrypt(blob, N=None, r=None, p=None):
    original = blob
    blob = _to_der(blob)
    alg, pbes2, kdf, encrypted = _decode_pbes2(blob)
    assert DerObjectId().decode(kdf[0]).value == _OID_SCRYPT
    params = DerSequence().decode(kdf[1], nr_elements=(4, 5))
    N = params[1] if N is None else N
    r = params[2] if r is None else r
    p = params[3] if p is None else p
    items = [params[0], DerInteger(N).encode(), DerInteger(r).encode(), DerInteger(p).encode()]
    if len(params) > 4:
        items.append(params[4])
    return _reencode(original, _encode_pbes2(alg, pbes2, kdf, DerSequence(items).encode(), encrypted))


def make_pbes1_blob(inner_pkcs8, password, iterations, salt=b"\x01\x02\x03\x04\x05\x06\x07\x08"):
    """A hand-crafted EncryptedPrivateKeyInfo with PBES1 (pbeWithSHA1AndDES)."""
    key_iv = KDF.PBKDF1(password, salt, 16, iterations, SHA1)
    ciphertext = DES.new(key_iv[:8], DES.MODE_CBC, key_iv[8:]).encrypt(pad(inner_pkcs8, 8))
    pbe_params = DerSequence([DerOctetString(salt), DerInteger(iterations)]).encode()
    algorithm = DerSequence([DerObjectId("1.2.840.113549.1.5.10"), pbe_params]).encode()
    return DerSequence([DerSequence().decode(algorithm), DerOctetString(ciphertext)]).encode()


def _u32(value):
    return struct.pack(">I", value)


def _ssh_string(value):
    if isinstance(value, str):
        value = value.encode()
    return _u32(len(value)) + value


def _mpint(number):
    raw = number.to_bytes((number.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _ssh_string(raw)


def _openssh_wrap(public_blob, private_section, kdfoptions, ciphername, kdfname):
    body = b"openssh-key-v1\x00"
    body += _ssh_string(ciphername) + _ssh_string(kdfname) + _ssh_string(kdfoptions)
    body += _u32(1) + _ssh_string(public_blob) + _ssh_string(private_section)
    return (
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + base64.encodebytes(body)
        + b"-----END OPENSSH PRIVATE KEY-----\n"
    )


def make_openssh_rsa(key, password, rounds):
    e = key.e.to_bytes((key.e.bit_length() + 7) // 8, "big")
    n = key.n.to_bytes((key.n.bit_length() + 7) // 8, "big")
    e = b"\x00" + e if e[0] & 0x80 else e
    n = b"\x00" + n if n[0] & 0x80 else n
    public_blob = _ssh_string("ssh-rsa") + _ssh_string(e) + _ssh_string(n)

    check = 0x11223344
    section = _u32(check) + _u32(check)
    section += _ssh_string("ssh-rsa")
    section += b"".join(_mpint(x) for x in (key.n, key.e, key.d, key.invq, key.p, key.q))
    section += _ssh_string("comment")
    section += bytes(range(1, (8 - len(section) % 8) % 8 + 1))[: (8 - len(section) % 8) % 8]

    salt = b"\xaa" * 16
    kdfoptions = _ssh_string(salt) + _u32(rounds)
    derived = _openssh._bcrypt_pbkdf(password, salt, rounds)
    cipher = AES.new(derived[:32], AES.MODE_CTR, nonce=b"", initial_value=derived[32:48])
    return _openssh_wrap(public_blob, cipher.encrypt(section), kdfoptions, "aes256-ctr", "bcrypt")


def make_openssh_ed25519(key, password, rounds):
    public_raw = key.public_key().export_key(format="raw")
    public_blob = _ssh_string("ssh-ed25519") + _ssh_string(public_raw)

    check = 0x11223344
    section = _u32(check) + _u32(check)
    section += _ssh_string("ssh-ed25519") + _ssh_string(public_raw)
    section += _ssh_string(key.seed + public_raw) + _ssh_string("comment")
    section += bytes(range(1, (8 - len(section) % 8) % 8 + 1))[: (8 - len(section) % 8) % 8]

    salt = b"\xbb" * 16
    kdfoptions = _ssh_string(salt) + _u32(rounds)
    derived = _openssh._bcrypt_pbkdf(password, salt, rounds)
    cipher = AES.new(derived[:32], AES.MODE_CTR, nonce=b"", initial_value=derived[32:48])
    return _openssh_wrap(public_blob, cipher.encrypt(section), kdfoptions, "aes256-ctr", "bcrypt")


def bump_openssh_rounds(pem, old_rounds, new_rounds):
    """Rewrite the bcrypt rounds field without re-running the expensive KDF."""
    lines = pem.splitlines()
    body = base64.b64decode(b"".join(lines[1:-1]))
    needle = _u32(old_rounds)
    # The rounds INTEGER is the last four bytes of the 20-byte kdfoptions blob.
    assert needle in body
    body = body.replace(needle, _u32(new_rounds), 1)
    lines[1:-1] = [base64.encodebytes(body).strip()]
    return b"\n".join(lines) + b"\n"


# ---------------------------------------------------------------------------
# Fixtures: real keys and protected blobs built with small, real parameters
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_key():
    return RSA.generate(1024)


@pytest.fixture(scope="module")
def ecc_key():
    return ECC.generate(curve="p256")


@pytest.fixture(scope="module")
def ed25519_key():
    return ECC.generate(curve="Ed25519")


@pytest.fixture
def rsa_pbkdf2_der(rsa_key):
    return rsa_key.export_key("DER", passphrase=PASSWORD, pkcs=8,
                              protection=PBKDF2_CBC, prot_params=FAST_PBKDF2)


@pytest.fixture
def rsa_pbkdf2_pem(rsa_key):
    return rsa_key.export_key("PEM", passphrase=PASSWORD, pkcs=8,
                              protection=PBKDF2_GCM, prot_params=FAST_PBKDF2)


@pytest.fixture
def ecc_pbkdf2_der(ecc_key):
    return ecc_key.export_key(format="DER", passphrase=PASSWORD,
                              protection=PBKDF2_CBC, prot_params=FAST_PBKDF2)


@pytest.fixture
def ecc_pbkdf2_pem(ecc_key):
    return ecc_key.export_key(format="PEM", passphrase=PASSWORD,
                              protection=PBKDF2_CBC, prot_params=FAST_PBKDF2)


@pytest.fixture
def rsa_scrypt_der(rsa_key):
    return rsa_key.export_key("DER", passphrase=PASSWORD, pkcs=8,
                              protection=SCRYPT, prot_params=FAST_SCRYPT)


@pytest.fixture
def rsa_scrypt_pem(rsa_key):
    return rsa_key.export_key("PEM", passphrase=PASSWORD, pkcs=8,
                              protection=SCRYPT, prot_params=FAST_SCRYPT)


@pytest.fixture
def ecc_scrypt_der(ecc_key):
    return ecc_key.export_key(format="DER", passphrase=PASSWORD,
                              protection=SCRYPT, prot_params=FAST_SCRYPT)


@pytest.fixture
def ecc_scrypt_parallel_der(ecc_key):
    return ecc_key.export_key(
        format="DER", passphrase=PASSWORD, protection="scryptAndAES128-CBC",
        prot_params={"iteration_count": 1024, "block_size": 8, "parallelization": 4},
    )


@pytest.fixture
def rsa_pbes1_der(rsa_key):
    return make_pbes1_blob(rsa_key.export_key("DER", pkcs=8), PASSWORD.encode(), 4)


@pytest.fixture
def rsa_openssh_pem(rsa_key):
    return make_openssh_rsa(rsa_key, PASSWORD.encode(), 3)


@pytest.fixture
def ed25519_openssh_pem(ed25519_key):
    return make_openssh_ed25519(ed25519_key, PASSWORD.encode(), 3)


# ---------------------------------------------------------------------------
# 1. Successful round-trips with real, small parameters (boundary included)
# ---------------------------------------------------------------------------


class TestRealRoundTrips:
    """The limits must not get in the way of legitimate, cheap blobs."""

    @pytest.mark.parametrize(
        "blob_name, importer",
        [
            ("rsa_pbkdf2_der", RSA),
            ("rsa_pbkdf2_pem", RSA),
            ("ecc_pbkdf2_der", ECC),
            ("ecc_pbkdf2_pem", ECC),
            ("rsa_scrypt_der", RSA),
            ("rsa_scrypt_pem", RSA),
            ("ecc_scrypt_der", ECC),
            ("rsa_pbes1_der", RSA),
            ("rsa_openssh_pem", RSA),
            ("ed25519_openssh_pem", ECC),
        ],
    )
    def test_decrypt_with_default_limits(self, request, blob_name, importer):
        blob = request.getfixturevalue(blob_name)
        assert importer.import_key(blob, passphrase=PASSWORD).has_private()

    def test_pbkdf2_boundary_count_allowed(self, rsa_pbkdf2_der):
        # count == limit is allowed (the check is strictly greater-than)
        key = RSA.import_key(rsa_pbkdf2_der, passphrase=PASSWORD, max_iteration_count=4)
        assert key.has_private()

    def test_scrypt_boundary_cost_allowed(self, rsa_scrypt_der):
        # N=1024, r=8, p=1 -> cost N*r*p/8 = 1024
        key = RSA.import_key(rsa_scrypt_der, passphrase=PASSWORD, max_iteration_count=1024)
        assert key.has_private()

    def test_bcrypt_boundary_rounds_allowed(self, rsa_openssh_pem):
        key = RSA.import_key(rsa_openssh_pem, passphrase=PASSWORD, max_iteration_count=3)
        assert key.has_private()

    def test_limit_zero_disables_check_and_still_decrypts(self, rsa_pbkdf2_der):
        key = RSA.import_key(rsa_pbkdf2_der, passphrase=PASSWORD, max_iteration_count=0)
        assert key.has_private()

    def test_max_memory_zero_disables_memory_check(self, rsa_scrypt_der):
        key = RSA.import_key(rsa_scrypt_der, passphrase=PASSWORD, max_memory=0)
        assert key.has_private()


# ---------------------------------------------------------------------------
# 2. PBKDF2 (PBES2): max_iteration_count reaches the KDF, checked first
# ---------------------------------------------------------------------------


class TestPbkdf2IterationLimit:
    def test_explicit_limit_rejected_before_kdf(self, rsa_pbkdf2_der, blocked_pbkdf2):
        crafted = mutate_pbkdf2_count(rsa_pbkdf2_der, 1_000_000)
        with pytest.raises(KdfIterationLimitError):
            RSA.import_key(crafted, passphrase=PASSWORD, max_iteration_count=4)
        assert blocked_pbkdf2.calls == 0

    def test_default_limit_rejected_before_kdf(self, rsa_pbkdf2_der, blocked_pbkdf2):
        crafted = mutate_pbkdf2_count(rsa_pbkdf2_der, HUGE_PBKDF2_COUNT)
        with pytest.raises(KdfIterationLimitError) as excinfo:
            RSA.import_key(crafted, passphrase=PASSWORD)
        assert blocked_pbkdf2.calls == 0
        assert "the default" in str(excinfo.value)
        assert str(_DEFAULT_MAX_ITERATION_COUNT) in str(excinfo.value)

    def test_pem_path_equally_guarded(self, rsa_pbkdf2_pem, blocked_pbkdf2):
        crafted = mutate_pbkdf2_count(rsa_pbkdf2_pem, 1_000_000)
        with pytest.raises(KdfIterationLimitError):
            RSA.import_key(crafted, passphrase=PASSWORD, max_iteration_count=4)
        assert blocked_pbkdf2.calls == 0

    def test_ecc_path_guarded(self, ecc_pbkdf2_der, blocked_pbkdf2):
        crafted = mutate_pbkdf2_count(ecc_pbkdf2_der, 1_000_000)
        with pytest.raises(KdfIterationLimitError):
            ECC.import_key(crafted, passphrase=PASSWORD, max_iteration_count=4)
        assert blocked_pbkdf2.calls == 0

    def test_limit_checked_even_with_wrong_passphrase(self, rsa_pbkdf2_der, blocked_pbkdf2):
        crafted = mutate_pbkdf2_count(rsa_pbkdf2_der, 1_000_000)
        # A KDF limit error must not be masked as an incorrect-passphrase error
        with pytest.raises(KdfIterationLimitError):
            RSA.import_key(crafted, passphrase="definitely-wrong", max_iteration_count=4)
        assert blocked_pbkdf2.calls == 0

    def test_zero_disables_limit_then_wrong_passphrase_surfaces(self, rsa_pbkdf2_der):
        crafted = mutate_pbkdf2_count(rsa_pbkdf2_der, 1_000_000)
        # With the check disabled, the KDF really runs and a wrong password is
        # reported as IncorrectPassphraseError, not as a limit error.
        with pytest.raises(IncorrectPassphraseError):
            RSA.import_key(crafted, passphrase="definitely-wrong", max_iteration_count=0)


# ---------------------------------------------------------------------------
# 3. scrypt: both the work (cost) limit and the memory limit
# ---------------------------------------------------------------------------


class TestScryptCostLimit:
    def test_explicit_cost_limit_before_kdf(self, rsa_scrypt_der, blocked_scrypt):
        crafted = mutate_scrypt(rsa_scrypt_der, N=2**20)  # cost = N (r=8,p=1)
        with pytest.raises(KdfIterationLimitError):
            RSA.import_key(crafted, passphrase=PASSWORD, max_iteration_count=1024)
        assert blocked_scrypt.calls == 0

    def test_default_cost_limit_before_kdf(self, rsa_scrypt_der, blocked_scrypt):
        crafted = mutate_scrypt(rsa_scrypt_der, N=HUGE_SCRYPT_N)
        with pytest.raises(KdfIterationLimitError) as excinfo:
            RSA.import_key(crafted, passphrase=PASSWORD)
        assert blocked_scrypt.calls == 0
        assert isinstance(excinfo.value, KdfIterationLimitError)
        assert str(_DEFAULT_MAX_SCRYPT_COST) in str(excinfo.value)

    def test_high_r_p_inflates_cost_before_kdf(self, rsa_scrypt_der, blocked_scrypt):
        # N=1024 but r*p huge: cost N*r*p/8 still exceeds the limit
        crafted = mutate_scrypt(rsa_scrypt_der, N=1024, r=8, p=2**20)
        with pytest.raises(KdfIterationLimitError):
            RSA.import_key(crafted, passphrase=PASSWORD, max_iteration_count=2**16)
        assert blocked_scrypt.calls == 0

    def test_pem_and_ecc_paths_guarded(self, rsa_scrypt_pem, ecc_scrypt_der, blocked_scrypt):
        with pytest.raises(KdfIterationLimitError):
            RSA.import_key(mutate_scrypt(rsa_scrypt_pem, N=2**20),
                           passphrase=PASSWORD, max_iteration_count=1024)
        with pytest.raises(KdfIterationLimitError):
            ECC.import_key(mutate_scrypt(ecc_scrypt_der, N=2**20),
                           passphrase=PASSWORD, max_iteration_count=1024)
        assert blocked_scrypt.calls == 0


class TestScryptMemoryLimit:
    def test_explicit_memory_limit_before_kdf(self, rsa_scrypt_der, blocked_scrypt):
        # N=2^20, r=8 -> one thread needs ~128 MiB; cap at 1 KiB
        crafted = mutate_scrypt(rsa_scrypt_der, N=2**20, r=8, p=1)
        with pytest.raises(KdfMemoryLimitError) as excinfo:
            RSA.import_key(crafted, passphrase=PASSWORD, max_memory=1024)
        assert blocked_scrypt.calls == 0
        assert "1024" in str(excinfo.value)

    def test_default_memory_limit_before_kdf(self, rsa_scrypt_der, blocked_scrypt):
        # N=2^25 -> 128*(N+2)*8 ~= 4 GiB per thread, above the 256 MiB default
        crafted = mutate_scrypt(rsa_scrypt_der, N=2**25, r=8, p=1)
        with pytest.raises(KdfMemoryLimitError) as excinfo:
            RSA.import_key(crafted, passphrase=PASSWORD, max_iteration_count=0)
        assert blocked_scrypt.calls == 0
        assert "the default" in str(excinfo.value)
        assert str(_DEFAULT_MAX_MEMORY) in str(excinfo.value)

    def test_memory_error_distinct_from_passphrase_error(self, rsa_scrypt_der, blocked_scrypt):
        crafted = mutate_scrypt(rsa_scrypt_der, N=2**20)
        with pytest.raises(KdfMemoryLimitError):
            RSA.import_key(crafted, passphrase="wrong", max_memory=1024)
        assert blocked_scrypt.calls == 0

    def test_memory_under_cap_still_decrypts_for_real(self, rsa_scrypt_der):
        # N=1024,r=8,p=1 needs shared + each = 256*r*p + 128*(N+2)*r bytes;
        # a cap at exactly that value lets the single-threaded real KDF run.
        required = 256 * 8 * 1 + 128 * (1024 + 2) * 8
        key = RSA.import_key(rsa_scrypt_der, passphrase=PASSWORD, max_memory=required)
        assert key.has_private()


class TestScryptThreads:
    def test_threads_forwarded_to_kdf(self, ecc_scrypt_parallel_der, recording_scrypt):
        ECC.import_key(ecc_scrypt_parallel_der, passphrase=PASSWORD, threads=3)
        assert recording_scrypt.calls == 1
        assert recording_scrypt.kwargs[0]["threads"] == 3

    def test_threads_capped_by_parallelization(self, ecc_scrypt_parallel_der, recording_scrypt):
        # p=4: asking for 8 threads must be reduced to 4
        ECC.import_key(ecc_scrypt_parallel_der, passphrase=PASSWORD, threads=8)
        assert recording_scrypt.kwargs[0]["threads"] == 4

    def test_threads_zero_expands_to_cores_then_capped(self, ecc_scrypt_parallel_der, recording_scrypt):
        from Crypto.Util._cpu_features import available_cores

        ECC.import_key(ecc_scrypt_parallel_der, passphrase=PASSWORD, threads=0)
        assert recording_scrypt.kwargs[0]["threads"] == min(available_cores(), 4)

    def test_threads_reduced_to_fit_memory(self, ecc_scrypt_parallel_der, recording_scrypt):
        # N=1024,r=8,p=4: each thread ~1 MiB; a 2 MiB total cap leaves one thread
        shared = 2 * 128 * 8 * 4
        each = 128 * (1024 + 2) * 8
        cap = shared + each  # exactly one thread fits
        ECC.import_key(ecc_scrypt_parallel_der, passphrase=PASSWORD, threads=4, max_memory=cap)
        assert recording_scrypt.kwargs[0]["threads"] == 1


# ---------------------------------------------------------------------------
# 4. PBES1 (legacy PKCS#5 v1.5) and OpenSSH bcrypt_pbkdf
# ---------------------------------------------------------------------------


class TestPbes1Limit:
    def test_real_blob_roundtrips_and_boundary(self, rsa_pbes1_der):
        assert RSA.import_key(rsa_pbes1_der, passphrase=PASSWORD).has_private()
        assert RSA.import_key(rsa_pbes1_der, passphrase=PASSWORD,
                              max_iteration_count=4).has_private()

    def test_explicit_limit_before_pbkdf1(self, rsa_pbes1_der, blocked_pbkdf1):
        with pytest.raises(KdfIterationLimitError):
            RSA.import_key(rsa_pbes1_der, passphrase=PASSWORD, max_iteration_count=3)
        assert blocked_pbkdf1.calls == 0

    def test_default_limit_on_crafted_huge_count(self, rsa_key, blocked_pbkdf1):
        huge = make_pbes1_blob(rsa_key.export_key("DER", pkcs=8),
                               PASSWORD.encode(), _DEFAULT_MAX_ITERATION_COUNT + 1)
        with pytest.raises(KdfIterationLimitError):
            RSA.import_key(huge, passphrase=PASSWORD)
        assert blocked_pbkdf1.calls == 0


class TestOpenSshBcryptLimit:
    def test_rsa_explicit_limit_before_bcrypt(self, rsa_openssh_pem, blocked_bcrypt):
        with pytest.raises(KdfIterationLimitError):
            RSA.import_key(rsa_openssh_pem, passphrase=PASSWORD, max_iteration_count=2)
        assert blocked_bcrypt.calls == 0

    def test_rsa_default_limit_on_crafted_rounds(self, rsa_openssh_pem, blocked_bcrypt):
        crafted = bump_openssh_rounds(rsa_openssh_pem, 3, HUGE_BCRYPT_ROUNDS)
        with pytest.raises(KdfIterationLimitError) as excinfo:
            RSA.import_key(crafted, passphrase=PASSWORD)
        assert blocked_bcrypt.calls == 0
        assert str(_DEFAULT_MAX_BCRYPT_ROUNDS) in str(excinfo.value)

    def test_ed25519_limit_before_bcrypt(self, ed25519_openssh_pem, blocked_bcrypt):
        with pytest.raises(KdfIterationLimitError):
            ECC.import_key(ed25519_openssh_pem, passphrase=PASSWORD, max_iteration_count=2)
        assert blocked_bcrypt.calls == 0

    def test_wrong_passphrase_is_not_a_limit_error(self, rsa_openssh_pem):
        with pytest.raises(IncorrectPassphraseError):
            RSA.import_key(rsa_openssh_pem, passphrase="wrong")


# ---------------------------------------------------------------------------
# 5. Invalid control parameters and the exception taxonomy
# ---------------------------------------------------------------------------


class TestInvalidControlParameters:
    @pytest.mark.parametrize("bad", ["1000", 1.5, True, -1])
    def test_bad_max_iteration_count_type(self, rsa_pbkdf2_der, bad):
        # bool and non-int -> TypeError; negative -> ValueError; all before KDF
        expected = TypeError if isinstance(bad, bool) or not isinstance(bad, int) else ValueError
        with pytest.raises(expected):
            RSA.import_key(rsa_pbkdf2_der, passphrase=PASSWORD, max_iteration_count=bad)

    @pytest.mark.parametrize("bad", ["1024", 1.5, True, -1])
    def test_bad_max_memory_type(self, rsa_scrypt_der, bad):
        expected = TypeError if isinstance(bad, bool) or not isinstance(bad, int) else ValueError
        with pytest.raises(expected):
            RSA.import_key(rsa_scrypt_der, passphrase=PASSWORD, max_memory=bad)

    @pytest.mark.parametrize("bad", ["1", 1.5, True, -1])
    def test_bad_threads_type(self, rsa_scrypt_der, bad):
        expected = TypeError if isinstance(bad, bool) or not isinstance(bad, int) else ValueError
        with pytest.raises(expected):
            RSA.import_key(rsa_scrypt_der, passphrase=PASSWORD, threads=bad)

    def test_validation_runs_upfront_even_on_clear_key(self, rsa_key):
        clear_der = rsa_key.export_key("DER")
        with pytest.raises(TypeError):
            RSA.import_key(clear_der, max_iteration_count=1.5)
        with pytest.raises(ValueError):
            RSA.import_key(clear_der, max_memory=-1)
        with pytest.raises(TypeError):
            ECC.import_key(clear_der, threads=True)

    def test_ecc_rejects_bad_params_too(self, ecc_scrypt_der):
        with pytest.raises(ValueError):
            ECC.import_key(ecc_scrypt_der, passphrase=PASSWORD, max_iteration_count=-5)
        with pytest.raises(TypeError):
            ECC.import_key(ecc_scrypt_der, passphrase=PASSWORD, max_memory="nope")


class TestExceptionTaxonomy:
    def test_limit_errors_are_value_errors(self):
        assert issubclass(KdfIterationLimitError, ValueError)
        assert issubclass(KdfMemoryLimitError, ValueError)

    def test_limit_errors_distinct_from_passphrase_errors(self):
        assert not issubclass(KdfIterationLimitError, IncorrectPassphraseError)
        assert not issubclass(KdfMemoryLimitError, IncorrectPassphraseError)
        assert not issubclass(IncorrectPassphraseError, KdfIterationLimitError)

    def test_encrypted_blob_without_passphrase(self, rsa_pbkdf2_der):
        with pytest.raises(PassphraseRequiredError):
            RSA.import_key(rsa_pbkdf2_der)

    def test_wrong_passphrase_is_incorrect_not_limit(self, rsa_pbkdf2_der):
        with pytest.raises(IncorrectPassphraseError):
            RSA.import_key(rsa_pbkdf2_der, passphrase="wrong")

    def test_malformed_blob_is_plain_value_error(self, rsa_pbkdf2_der):
        with pytest.raises(ValueError) as excinfo:
            RSA.import_key(b"not a key at all", passphrase=PASSWORD)
        assert not isinstance(excinfo.value,
                              (KdfIterationLimitError, KdfMemoryLimitError, IncorrectPassphraseError))


# ---------------------------------------------------------------------------
# 6. The lower-level IO entry points enforce the same limits
# ---------------------------------------------------------------------------


class TestIoEntryPoints:
    def test_pkcs8_unwrap_iteration_limit(self, rsa_pbkdf2_der, blocked_pbkdf2):
        from Crypto.IO import PKCS8

        crafted = mutate_pbkdf2_count(rsa_pbkdf2_der, 1_000_000)
        with pytest.raises(KdfIterationLimitError):
            PKCS8.unwrap(crafted, PASSWORD, max_iteration_count=4)
        assert blocked_pbkdf2.calls == 0

    def test_pbes2_direct_scrypt_memory_limit(self, rsa_scrypt_der, blocked_scrypt):
        crafted = mutate_scrypt(rsa_scrypt_der, N=2**20)
        with pytest.raises(KdfMemoryLimitError):
            PBES2.decrypt(crafted, PASSWORD.encode(), max_iteration_count=0, max_memory=1024)
        assert blocked_scrypt.calls == 0

    def test_pbes1_direct_iteration_limit(self, rsa_pbes1_der, blocked_pbkdf1):
        with pytest.raises(KdfIterationLimitError):
            PBES1.decrypt(rsa_pbes1_der, PASSWORD.encode(), max_iteration_count=3)
        assert blocked_pbkdf1.calls == 0
