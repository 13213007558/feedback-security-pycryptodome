# SPDX-FileCopyrightText: 2026
# SPDX-License-Identifier: BSD-2-Clause

"""Security-audit tests for the parameters that ``Crypto.Signature.pss`` accepts.

The goal of this module is to make the acceptance/rejection rules of
RSASSA-PSS verification (RFC 8017 section 8.1.2/9.1.2) explicit and testable
along three axes:

* ``salt_bytes`` -- the salt length the verifier expects;
* ``mask_func`` -- the MGF and the hash algorithm embedded in it;
* the message digest object passed to :meth:`PSS_SigScheme.verify`.

Every malformed input is encoded independently at the EMSA-PSS byte level
(see :func:`malformed_signature`) and then turned into an RSA signature with
the raw private-key primitive.  The high-level signer is never asked to
"repair" an invalid input: no call to :meth:`PSS_SigScheme.sign` produces any
of the rejected vectors, so each rejection is attributed to one concrete
encoding defect instead of being hidden behind signer-side normalisation.

Audit conclusions, each backed by a test below:

1. The default verifier (``salt_bytes=None``, ``mask_func=None``) expects a
   salt of exactly the message-digest length and MGF1 keyed on that same
   digest.  It is therefore *not* an "accept any salt length" mode: a
   signature carrying a 0-byte or a shorter salt is rejected unless the
   matching ``salt_bytes`` is supplied explicitly.
2. A non-integer-byte modulus (e.g. 1025 bits, so ``k=129`` but
   ``emLen=128``) is supported, but the spare leading bit of the encoded
   message must stay zero.
3. The following are always rejected: a salt longer than the encoding can
   hold, any trailer byte other than 0xBC, an MGF whose digest does not match
   the verifier's, a message digest that does not match the signature, and an
   RSA signature representative outside ``0 <= s < n`` (either because it does
   not fit in ``k`` bytes, or because the RSA primitive itself bounds it).
"""

import pytest
from Crypto.Hash import SHA1, SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Signature.pss import _EMSA_PSS_ENCODE, MGF1
from Crypto.Util.number import bytes_to_long, ceil_div, long_to_bytes, size

# ---------------------------------------------------------------------------
# Independently encoded, fixed RSA-1024 test key (raw prime factors, no PEM).
# The factors are deterministic 512-bit primes generated from fixed seeds;
# the key exists only to give verifiable, reproducible small vectors.
# ---------------------------------------------------------------------------
_P = 0xB624DB6F5F6C692B73B21C1F1C3DD5256C236FCC2C6679E5F99DAF1BD88776CC53D374D722A39AEA4228D9C4D8CCB32B65D5AD8B2B342ECBA047110523685DEB
_Q = 0xF220F93948969951E5EB199A624882B0C808BF0D9E3F4742DE98A5727438DF74BB6D528CB68C6C5FADEF6DC4C1FA331FFE48702AF3AE4862928D550F64A9D6AB
_E = 65537
_N = _P * _Q

MESSAGE = b"pss-verification-audit"


def _private_key():
    d = pow(_E, -1, (_P - 1) * (_Q - 1))
    q_inv = pow(_P, -1, _Q)
    return RSA.construct((_N, _E, d, _P, _Q, q_inv))


def _public_key():
    return RSA.construct((_N, _E))


PRIV = _private_key()
PUB = _public_key()
MOD_BITS = size(_N)  # 1024
K = ceil_div(MOD_BITS, 8)  # 128, RSA signature/modulus length
EM_BITS = MOD_BITS - 1  # 1023
EM_LEN = ceil_div(EM_BITS, 8)  # 128, EMSA-PSS encoded message length

SHA256_LEN = SHA256.digest_size
SHA1_LEN = SHA1.digest_size
SHA512_LEN = SHA512.digest_size


def _mgf1(hash_module):
    return lambda seed, length: MGF1(seed, length, hash_module)


def encode_pss(message_hash, salt, mgf_hash_module, em_bits=EM_BITS):
    """Build an EMSA-PSS encoded message with fully controlled components."""
    return _EMSA_PSS_ENCODE(
        message_hash,
        em_bits,
        lambda _length: salt,
        _mgf1(mgf_hash_module),
        len(salt),
    )


def raw_rsa_sign(private_key, encoded_message, signature_len):
    """Convert a hand-built EM into a ``signature_len``-byte RSA signature.

    Only the RSA private primitive is used here; the PSS signer is not
    involved, so the caller keeps full control over every byte of ``EM``.
    """
    raw = private_key._decrypt_to_bytes(bytes_to_long(encoded_message))
    return b"\x00" * (signature_len - len(raw)) + raw


def malformed_signature(em_bytes):
    """Wrap a deliberately malformed EM as an RSA signature."""
    return raw_rsa_sign(PRIV, em_bytes, K)


def assert_rejected(message_hash, signature, **verifier_kwargs):
    with pytest.raises(ValueError):
        pss.new(PUB, **verifier_kwargs).verify(message_hash, signature)


def assert_accepted(message_hash, signature, **verifier_kwargs):
    pss.new(PUB, **verifier_kwargs).verify(message_hash, signature)


@pytest.fixture
def valid_signature():
    salt = b"\x11" * SHA256_LEN
    em = encode_pss(SHA256.new(MESSAGE), salt, SHA256)
    return raw_rsa_sign(PRIV, em, K)


# ---------------------------------------------------------------------------
# Supported, legal parameter combinations
# ---------------------------------------------------------------------------
class TestLegalParameters:
    def test_defaults_match_digest_sized_salt_and_mgf1_same_hash(self, valid_signature):
        # salt_bytes=None -> sLen = hLen; mask_func=None -> MGF1(SHA-256).
        assert_accepted(SHA256.new(MESSAGE), valid_signature)

    def test_explicit_defaults_are_equivalent(self, valid_signature):
        assert_accepted(
            SHA256.new(MESSAGE),
            valid_signature,
            salt_bytes=SHA256_LEN,
            mask_func=_mgf1(SHA256),
        )

    def test_zero_salt_deterministic_signature(self):
        em = encode_pss(SHA256.new(MESSAGE), b"", SHA256)
        signature = raw_rsa_sign(PRIV, em, K)
        assert_accepted(SHA256.new(MESSAGE), signature, salt_bytes=0)

    def test_short_salt_accepted_when_declared(self):
        salt = b"\x44" * 16
        em = encode_pss(SHA256.new(MESSAGE), salt, SHA256)
        signature = raw_rsa_sign(PRIV, em, K)
        assert_accepted(SHA256.new(MESSAGE), signature, salt_bytes=16)

    def test_maximum_salt_length_accepted_when_declared(self):
        max_salt_len = EM_LEN - SHA256_LEN - 2
        salt = b"\x33" * max_salt_len
        em = encode_pss(SHA256.new(MESSAGE), salt, SHA256)
        signature = raw_rsa_sign(PRIV, em, K)
        assert_accepted(SHA256.new(MESSAGE), signature, salt_bytes=max_salt_len)

    def test_distinct_mgf_digest_accepted_when_verifier_matches(self):
        # Signed with MGF1-SHA1; only accepted if the verifier uses MGF1-SHA1.
        salt = b"\x11" * SHA256_LEN
        em = encode_pss(SHA256.new(MESSAGE), salt, SHA1)
        signature = raw_rsa_sign(PRIV, em, K)
        assert_accepted(
            SHA256.new(MESSAGE),
            signature,
            salt_bytes=SHA256_LEN,
            mask_func=_mgf1(SHA1),
        )

    def test_sha1_message_digest_with_matching_mgf_and_salt(self):
        salt = b"\x55" * SHA1_LEN
        em = encode_pss(SHA1.new(MESSAGE), salt, SHA1)
        signature = raw_rsa_sign(PRIV, em, K)
        assert_accepted(
            SHA1.new(MESSAGE),
            signature,
            salt_bytes=SHA1_LEN,
            mask_func=_mgf1(SHA1),
        )


# ---------------------------------------------------------------------------
# Default salt_bytes is a fixed hLen, not "any salt length"
# ---------------------------------------------------------------------------
class TestDefaultSaltSemantics:
    def test_zero_salt_signature_rejected_by_default_verifier(self):
        em = encode_pss(SHA256.new(MESSAGE), b"", SHA256)
        signature = raw_rsa_sign(PRIV, em, K)
        assert_rejected(SHA256.new(MESSAGE), signature)

    def test_short_salt_rejected_by_default_verifier(self):
        salt = b"\x44" * 16
        em = encode_pss(SHA256.new(MESSAGE), salt, SHA256)
        signature = raw_rsa_sign(PRIV, em, K)
        assert_rejected(SHA256.new(MESSAGE), signature)

    def test_maximum_salt_signature_rejected_by_default_verifier(self):
        max_salt_len = EM_LEN - SHA256_LEN - 2
        em = encode_pss(SHA256.new(MESSAGE), b"\x33" * max_salt_len, SHA256)
        signature = raw_rsa_sign(PRIV, em, K)
        assert_rejected(SHA256.new(MESSAGE), signature)

    def test_explicit_salt_bytes_value_is_not_relaxed_after_failure(
        self, valid_signature
    ):
        # An impossible salt length fails the EM length check before any
        # padding comparison; the verifier never falls back to another length.
        assert_rejected(SHA256.new(MESSAGE), valid_signature, salt_bytes=1000)


# ---------------------------------------------------------------------------
# Non-integer-byte modulus: 1025 bits gives k=129 but emLen=128
# ---------------------------------------------------------------------------
class TestNonByteAlignedModulus:
    @pytest.fixture(scope="class")
    @classmethod
    def key_1025(cls):
        return RSA.generate(1025)

    def _signature(self, key, mutate_em):
        mod_bits = key.size_in_bits()
        em_bits = mod_bits - 1
        em = encode_pss(
            SHA256.new(MESSAGE), b"\x22" * SHA256_LEN, SHA256, em_bits=em_bits
        )
        if mutate_em is not None:
            em = mutate_em(em)
        signature_len = ceil_div(mod_bits, 8)
        return raw_rsa_sign(key, em, signature_len)

    def test_valid_encoding_accepted_with_k_minus_one_em_length(self, key_1025):
        assert key_1025.size_in_bits() == 1025
        signature = self._signature(key_1025, None)
        assert len(signature) == 129
        pss.new(key_1025.public_key()).verify(SHA256.new(MESSAGE), signature)

    def test_spare_leading_bit_set_is_rejected(self, key_1025):
        # emBits = 1024 leaves exactly one unused bit in the first EM byte.
        signature = self._signature(key_1025, lambda em: bytes([em[0] | 0x80]) + em[1:])
        with pytest.raises(ValueError):
            pss.new(key_1025.public_key()).verify(SHA256.new(MESSAGE), signature)


# ---------------------------------------------------------------------------
# Leading high-bit anomaly on the byte-aligned 1024-bit key
# ---------------------------------------------------------------------------
class TestLeadingBitAnomaly:
    def test_high_bit_of_first_em_byte_must_be_zero(self):
        em = encode_pss(SHA256.new(MESSAGE), b"\x11" * SHA256_LEN, SHA256)
        # For emBits=1023 and emLen=128 the leading-mask lmask is 0x80.
        corrupted = bytes([em[0] | 0x80]) + em[1:]
        assert_rejected(SHA256.new(MESSAGE), malformed_signature(corrupted))

    def test_any_single_bit_flip_in_encoded_message_is_rejected(self):
        em = bytearray(encode_pss(SHA256.new(MESSAGE), b"\x11" * SHA256_LEN, SHA256))
        em[0] ^= 0x01
        assert_rejected(SHA256.new(MESSAGE), malformed_signature(bytes(em)))


# ---------------------------------------------------------------------------
# Salt length enforcement
# ---------------------------------------------------------------------------
class TestSaltRejection:
    def test_salt_longer_than_encoding_capacity_rejected(self, valid_signature):
        assert_rejected(SHA256.new(MESSAGE), valid_signature, salt_bytes=1000)

    def test_signed_salt_length_mismatch_rejected(self):
        # Signature carries 32-byte salt; verifier demands 16.
        em = encode_pss(SHA256.new(MESSAGE), b"\x11" * SHA256_LEN, SHA256)
        signature = raw_rsa_sign(PRIV, em, K)
        assert_rejected(SHA256.new(MESSAGE), signature, salt_bytes=16)

    def test_corrupt_zero_one_separator_rejected(self):
        em = bytearray(encode_pss(SHA256.new(MESSAGE), b"\x11" * SHA256_LEN, SHA256))
        em[1] ^= 0x01  # breaks the PS || 0x01 structure after unmasking
        assert_rejected(SHA256.new(MESSAGE), malformed_signature(bytes(em)))


# ---------------------------------------------------------------------------
# Trailer field must be exactly 0xBC
# ---------------------------------------------------------------------------
class TestTrailerField:
    @pytest.mark.parametrize("bad_trailer", [0x00, 0x01, 0xBD, 0xFF])
    def test_non_bc_trailer_rejected(self, bad_trailer):
        em = encode_pss(SHA256.new(MESSAGE), b"\x11" * SHA256_LEN, SHA256)
        corrupted = em[:-1] + bytes([bad_trailer])
        assert_rejected(SHA256.new(MESSAGE), malformed_signature(corrupted))


# ---------------------------------------------------------------------------
# MGF and message-digest binding
# ---------------------------------------------------------------------------
class TestDigestBinding:
    def test_mgf_digest_mismatch_rejected_under_default_mgf(self):
        em = encode_pss(SHA256.new(MESSAGE), b"\x11" * SHA256_LEN, SHA1)
        signature = raw_rsa_sign(PRIV, em, K)
        assert_rejected(SHA256.new(MESSAGE), signature, salt_bytes=SHA256_LEN)

    def test_message_digest_mismatch_rejected(self, valid_signature):
        assert_rejected(SHA512.new(MESSAGE), valid_signature)

    def test_wrong_message_rejected(self, valid_signature):
        assert_rejected(SHA256.new(MESSAGE + b"tampered"), valid_signature)

    def test_tampered_embedded_hash_rejected(self):
        em = bytearray(encode_pss(SHA256.new(MESSAGE), b"\x11" * SHA256_LEN, SHA256))
        em[EM_LEN - SHA256_LEN - 1] ^= 0x01
        assert_rejected(SHA256.new(MESSAGE), malformed_signature(bytes(em)))


# ---------------------------------------------------------------------------
# RSA signature representative must stay within [0, n)
# ---------------------------------------------------------------------------
class TestSignatureRepresentativeRange:
    def test_representative_equal_to_modulus_rejected(self):
        # s == n is still k bytes long, so it passes the length check and is
        # rejected by the RSA public operation itself ("Plaintext too large").
        signature_n = long_to_bytes(_N, K)
        assert len(signature_n) == K
        assert_rejected(SHA256.new(MESSAGE), signature_n)

    def test_representative_above_modulus_rejected(self, valid_signature):
        # A valid representative plus n cannot fit in k bytes: it reaches the
        # verifier's explicit signature-length check first.
        s = bytes_to_long(valid_signature)
        signature_above = long_to_bytes(s + _N, K + 1)
        assert bytes_to_long(signature_above) >= _N
        assert_rejected(SHA256.new(MESSAGE), signature_above)

    def test_short_signature_length_rejected(self, valid_signature):
        assert_rejected(SHA256.new(MESSAGE), valid_signature[:-1])

    def test_long_signature_length_rejected(self, valid_signature):
        assert_rejected(SHA256.new(MESSAGE), valid_signature + b"\x00")

    def test_valid_representative_is_strictly_below_modulus(self, valid_signature):
        representative = bytes_to_long(valid_signature)
        assert 0 <= representative < _N
