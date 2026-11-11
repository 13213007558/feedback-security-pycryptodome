"""
OAEP 迁移兼容测试。

覆盖点：
* 固定测试密钥（RSA-2048 / RSA-3072）下的 golden 密文回归；
* 旧入口与历史 ``PKCS1_OAEP.new(key)`` 单参数调用完全等价；
* 主摘要与 MGF 不同（SHA-256 + MGF1-SHA1）的显式配对；
* 错误 label、错误 MGF、错误版本号、篡改密文一律失败，且无重试；
* 两种模长下的最大可封装长度边界（含越界）；
* 旧裸密文只能通过明确的旧版本入口解开，新入口解不开。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import oaep
from Crypto.Hash import SHA1, SHA256
from Crypto.Signature.pss import MGF1

import oaep_migration as om

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(os.path.dirname(HERE), "keys")


class SeededRNG:
    """确定性随机源：让密文可复现，仅用于测试。"""

    def __init__(self, seed):
        self._seed = seed
        self._out = b""
        self._counter = 0

    def read(self, n):
        while len(self._out) < n:
            self._out += hashlib.sha256(
                self._seed + self._counter.to_bytes(4, "big")
            ).digest()
            self._counter += 1
        result, self._out = self._out[:n], self._out[n:]
        return result


# 与 om.seal_raw(..., rand_func=SeededRNG(...)) 对齐的固定密文。
GOLDEN = {
    "2048": {
        'oaep-sha1-mgf1sha1-v1': (
            b'golden legacy plaintext v1',
            "isp3VaalgG9lvp23fvxE9D9wN5rEb6VneHcWz84AkIaunYrZouHSj+H/0D+gEjE/IinRs7JdIUT2"
            "1ZBBx7AlsLQEQ/23w9gMnBTWiyhNw/rENiBrJKcXZb8Yhbqt0Kvp0Q8gxwZ+JE382uA9RjIYHRw2"
            "YsyPYJbDEjmces6gsyK70MfI0Q9WqWowMIZ2diFD9iCwF464qTW9q/GXOuWQMTL3GtUBTROlwAjs"
            "y9tb4M+zLrp/CnGl8Ei7ORmVhabw1PYIkTDBviej/cub14W2YlRVkd66JReRgvwcZceqNcJNdSam"
            "PI8PMtGhNlY2YuTxTL/SV2sKPx9esBkjoG6Uow=="
        ),
        'oaep-sha256-mgf1sha256-v2': (
            b'golden current plaintext v2',
            "AgQKVFiIUa/LhnxbxDo2dXtZP2gYqFnSAR197EnOsKlgKMu7f50rgxwO01qLAZn9NjMCLjXspOPo"
            "/7u6KW07nii+gUw0pttiNevM4OvGHkE20q9luc6mRbIipkETbcVIYGHMUnGQukf3wPyrhNVoSQT/"
            "D4yXWvDqrXyQ4YO0208x9hOqCRE6AoUmQFplIcgmF0SDivqjWBGYUhRgSk4W8y6DJcVFfR4K2+qM"
            "crXVoX62ROoBGhhotspwZJTQobd2OOPD+WrRwZXctNuJxV5WrrXm74vv5QlGYc4WCRVJOzkezQnL"
            "UnUZCLJ0Nj71ncLFfcW0a4HJ26YRwDQjrfJQIw=="
        ),
    },
    "3072": {
        'oaep-sha1-mgf1sha1-v1': (
            b'golden legacy plaintext v1',
            "aOI0xIsvtME9JQZCqizWld4/TtldiAv9szJEcPHEkUnpNXe2wYhQxflfjokUAbv+964N+17rjjCR"
            "nw8j6Lm15hMqMcwdU3IFXD1Inxx8rucxn7neYz+2EoolR0NfJF3qxNKVR49uPoogOy1VamAnke/N"
            "KqW7CPD59+uLQbiRoBA1t9QBShEY1wnbt/NLDFisOwj2ey+9stiRoKSyuFmOuz8YyUWCSe64bEHS"
            "kgExk+EUzQmUlYVW7c+8xrIU8g7fXe0VMSzywo+g8WagqBuSbBorGnSTw/McHM3yWFNBS9PN6E+v"
            "qO1u5JWX9QmYLEbUCwgvPAfk8GWYviSjMmoThbEtCWDcu1gXqSRsutWJmTb7qdYWd5LlVqm4/IBM"
            "06RJC5YMqH/UmmvODWtdjhU4sKEJ+okPjcZan2Dg/eg7l96SaTvMVZ/aKNrDNl6hJvOnR7LrTRI6"
            "jgkD0/CANvpCFu1HDYoMEfnJUcoKffpUBtrjYg58D6fNYAHzBVSceKnv"
        ),
        'oaep-sha256-mgf1sha256-v2': (
            b'golden current plaintext v2',
            "T6DHsKD2lQReKxg5crYkNdXHFvQmM9QZP3WpMDSjwk55fQvRIAx1+DylBB8kijeGeNgEYBJ+7rMc"
            "j2cvBwzLcsQnK5vPrH0dQP/tsu07Dd58mpXza0R8ZiJ6iO+oI4xTCF3BJIgjRoSE3wPtFkVSCsBJ"
            "OGPiyYXorQ2BZ9UupZ1M0FfJ38VvIObp1CCQ1nwrkS/ZLFTvFCk0Dj0sb4NOs6rfUBAzYkRenTl9"
            "N9NfNJs0xyr54VQFLQ2HaS+4VRpZP3m/Dlp8b5cgPzBucSeXGq4ifoHRVolDIC+pEU2STi0ywOMm"
            "7FsEWRSCBtZILcJTXg6tMOYtiHCfzwNJuMyhxwcbXgYm/FsX8cxxiQjCMBrrWwC9Gamupdf9syDs"
            "KlPr27ua2hlmNn6wj6T4nGe6Dqfps5quHbnIw8hfGwLySBVQZOWfBoC6HbkL+dT4riJ5H+4ddVla"
            "r7+9RVF1cJxFW/J0mmON1gdAlZHq2yvZzq9H+duha+zIMHStVG53Ing8"
        ),
    },
}

# 历史单参数调用 PKCS1_OAEP.new(pubkey) 产生的固定密文。
HISTORICAL_ONE_ARG_CT = (
    "eWvC3HR4lrm24hTzinP8EOfCMTSnmrjnMVQfKxviP+Zi3VPpJXiRJIQGZZ9+2/gPSUq7H/I/NK7J"
    "9Q/htaALk8cSZGEQ+I7WjoX8nNkNsrFLPilO/rUkIceMaLPD2XfF4zeZ6Ts5Plqbrxkfl9xu13U+"
    "orKesfzOt9bgAXldd7iBULYDc3kXM8yowegozHDpbE0WxNDGQcbDrFOBdRS4rNXVjb3mnv6Q3vfn"
    "txQjkRDKxHfaKur+33WJq1o6+ynKPxH8sf1Ed+VzNUhn3V9X4yT+CTF+yHIS9fV9sz1OH9EuwfPS"
    "OpA0N1Wkbd8+b56ZORApESVzcBva8diA9nbaCg=="
)


@pytest.fixture(params=["2048", "3072"])
def key(request):
    return om.load_private_key(os.path.join(KEYS_DIR, "key%s.pem" % request.param))


@pytest.fixture
def key2048():
    return om.load_private_key(os.path.join(KEYS_DIR, "key2048.pem"))


class TestFixedKeys:
    def test_key_sizes_and_exponent(self, key):
        assert key.e == 65537
        assert key.size_in_bits() in (2048, 3072)
        assert key.has_private()
        assert not key.public_key().has_private()

    def test_keys_are_fixed_assets(self, key2048):
        # 固定测试密钥必须稳定：任何重新生成都应与签入的 PEM 一致。
        again = om.load_private_key(os.path.join(KEYS_DIR, "key2048.pem"))
        assert again.n == key2048.n
        assert again.d == key2048.d


class TestTrustedRegistry:
    def test_versions_are_pinned(self):
        legacy = om.params_for_version(om.LEGACY_VERSION)
        current = om.params_for_version(om.CURRENT_VERSION)
        assert (legacy.hash_name, legacy.mgf_name, legacy.label) == (
            "SHA-1",
            "SHA-1",
            b"",
        )
        assert (current.hash_name, current.mgf_name, current.label) == (
            "SHA-256",
            "SHA-256",
            om.CURRENT_LABEL,
        )

    def test_unknown_version_is_rejected_without_probing(self, key2048):
        with pytest.raises(om.OAEPVersionError):
            om.params_for_version("oaep-sha512-guessed")
        with pytest.raises(om.OAEPVersionError):
            om.open_raw(key2048, b"\x00" * key2048.size_in_bytes(), "nope")


class TestRoundTrips:
    @pytest.mark.parametrize("version", [om.LEGACY_VERSION, om.CURRENT_VERSION])
    def test_raw_seal_open_both_moduli(self, key, version):
        message = b"round trip %s" % version.encode()
        ct = om.seal_raw(key.public_key(), message, version=version)
        assert len(ct) == key.size_in_bytes()
        assert om.open_raw(key, ct, version) == message

    @pytest.mark.parametrize("version", [om.LEGACY_VERSION, om.CURRENT_VERSION])
    def test_envelope_round_trip_and_routing(self, key, version):
        envelope = om.seal_envelope(
            key.public_key(), b"envelope payload", "kek-%s" % key.size_in_bits(),
            version=version,
        )
        record = json.loads(envelope)
        assert set(record) == {"v", "kid", "ct"}
        assert record["v"] == version
        assert om.envelope_key_id(envelope) == "kek-%s" % key.size_in_bits()
        assert om.open_envelope(key, envelope) == b"envelope payload"

    def test_envelope_carries_no_algorithm_fields(self, key2048):
        envelope = om.seal_envelope(key2048.public_key(), b"x", "kid")
        record = json.loads(envelope)
        assert "hash" not in record and "mgf" not in record and "label" not in record


class TestGoldenVectors:
    @pytest.mark.parametrize("modulus", ["2048", "3072"])
    @pytest.mark.parametrize("version", [om.LEGACY_VERSION, om.CURRENT_VERSION])
    def test_fixed_ciphertext_regression(self, modulus, version):
        key = om.load_private_key(os.path.join(KEYS_DIR, "key%s.pem" % modulus))
        plaintext, ct_b64 = GOLDEN[modulus][version]
        ct = base64.b64decode(ct_b64)
        assert om.open_raw(key, ct, version) == plaintext

    @pytest.mark.parametrize("modulus", ["2048", "3072"])
    @pytest.mark.parametrize("version", [om.LEGACY_VERSION, om.CURRENT_VERSION])
    def test_seal_is_reproducible_under_fixed_rng(self, modulus, version):
        key = om.load_private_key(os.path.join(KEYS_DIR, "key%s.pem" % modulus))
        plaintext, ct_b64 = GOLDEN[modulus][version]
        rng = SeededRNG(b"golden-vector:" + modulus.encode() + b":" + version.encode())
        produced = om.seal_raw(
            key.public_key(), plaintext, version=version, rand_func=rng.read
        )
        assert produced == base64.b64decode(ct_b64)

    def test_historical_one_arg_call_is_legacy_version(self, key2048):
        ct = base64.b64decode(HISTORICAL_ONE_ARG_CT)
        # 历史 PKCS1_OAEP.new(key) 的产物只能按明确的旧版本解开。
        assert om.open_raw(key2048, ct, om.LEGACY_VERSION) == b"historical one-arg call"
        with pytest.raises(ValueError):
            om.open_raw(key2048, ct, om.CURRENT_VERSION)

    def test_legacy_entry_matches_one_arg_defaults_bit_for_bit(self, key2048):
        rng1 = SeededRNG(b"interop-a")
        rng2 = SeededRNG(b"interop-a")
        historical = PKCS1_OAEP.new(
            key2048.public_key(), randfunc=rng1.read
        ).encrypt(b"same params")
        explicit_legacy = om.build_legacy_cipher(key2048.public_key())
        # 显式旧入口注入同样的随机源后，密文应与单参数历史调用逐字节一致。
        explicit_legacy._randfunc = rng2.read
        assert explicit_legacy.encrypt(b"same params") == historical


class TestNoCrossVersionDecryption:
    def test_legacy_ciphertext_rejects_current_entry(self, key2048):
        legacy_ct = om.seal_raw(key2048.public_key(), b"old", version=om.LEGACY_VERSION)
        with pytest.raises(ValueError):
            om.open_raw(key2048, legacy_ct, om.CURRENT_VERSION)

    def test_current_ciphertext_rejects_legacy_entry(self, key2048):
        current_ct = om.seal_raw(
            key2048.public_key(), b"new", version=om.CURRENT_VERSION
        )
        with pytest.raises(ValueError):
            om.open_raw(key2048, current_ct, om.LEGACY_VERSION)

    def test_wrong_version_in_envelope_fails_closed(self, key2048):
        ct = om.seal_raw(key2048.public_key(), b"old", version=om.LEGACY_VERSION)
        forged = json.dumps(
            {"v": om.CURRENT_VERSION, "kid": "k", "ct": base64.b64encode(ct).decode()}
        ).encode()
        with pytest.raises(ValueError):
            om.open_envelope(key2048, forged)

    def test_unknown_envelope_version_raises_version_error(self, key2048):
        envelope = json.dumps(
            {"v": "mystery", "kid": "k", "ct": base64.b64encode(b"\x00" * 256).decode()}
        ).encode()
        with pytest.raises(om.OAEPVersionError):
            om.open_envelope(key2048, envelope)


class TestParameterMismatches:
    def test_main_hash_differs_from_mgf_must_pair_explicitly(self, key2048):
        # RFC 允许主摘要 SHA-256 搭配 MGF1-SHA1，但两端必须显式一致。
        sender = oaep.new(
            key2048.public_key(),
            hashmod=SHA256,
            mask_func=lambda seed, length: MGF1(seed, length, SHA1),
            label=b"",
        )
        ct = sender.encrypt(b"mixed")
        with pytest.raises(ValueError):
            oaep.new(key2048, hashmod=SHA256).decrypt(ct)  # 默认 MGF1-SHA256
        receiver = oaep.new(
            key2048,
            hashmod=SHA256,
            mask_func=lambda seed, length: MGF1(seed, length, SHA1),
            label=b"",
        )
        assert receiver.decrypt(ct) == b"mixed"

    def test_wrong_label_fails(self, key2048):
        ct = om.seal_raw(key2048.public_key(), b"labeled", version=om.CURRENT_VERSION)
        wrong_label = oaep.new(
            key2048,
            hashmod=SHA256,
            mask_func=lambda s, n: MGF1(s, n, SHA256),
            label=b"wrong-purpose-label",
        )
        with pytest.raises(ValueError):
            wrong_label.decrypt(ct)
        # 空 label（旧格式的 label）同样解不开新密文。
        empty_label = oaep.new(
            key2048,
            hashmod=SHA256,
            mask_func=lambda s, n: MGF1(s, n, SHA256),
            label=b"",
        )
        with pytest.raises(ValueError):
            empty_label.decrypt(ct)

    def test_wrong_mgf_hash_fails(self, key2048):
        ct = om.seal_raw(
            key2048.public_key(), b"mgf", version=om.CURRENT_VERSION
        )  # MGF1-SHA256
        mgf_sha1 = oaep.new(
            key2048,
            hashmod=SHA256,
            mask_func=lambda s, n: MGF1(s, n, SHA1),
            label=om.CURRENT_LABEL,
        )
        with pytest.raises(ValueError):
            mgf_sha1.decrypt(ct)

    def test_tampered_ciphertext_fails_without_retry(self, key2048):
        envelope = om.seal_envelope(key2048.public_key(), b"integrity", "kid")
        record = json.loads(envelope)
        raw = bytearray(base64.b64decode(record["ct"]))
        raw[-1] ^= 0x01
        record["ct"] = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError):
            om.open_envelope(key2048, json.dumps(record).encode())

    def test_ciphertext_length_must_equal_modulus(self, key2048):
        with pytest.raises(ValueError):
            om.open_raw(key2048, b"\x01" * (key2048.size_in_bytes() - 1),
                        om.CURRENT_VERSION)

    def test_no_brute_force_helper_exists(self):
        # 公共 API 中不得出现“尝试所有参数”的入口。
        banned = [
            name for name in dir(om)
            if any(word in name.lower() for word in ("probe", "guess", "try_all", "fallback"))
        ]
        assert banned == []


class TestMaxLength:
    @pytest.mark.parametrize(
        "modulus,expected_legacy,expected_current",
        [("2048", 256 - 40 - 2, 256 - 64 - 2), ("3072", 384 - 40 - 2, 384 - 64 - 2)],
    )
    def test_length_formula(self, modulus, expected_legacy, expected_current):
        key = om.load_private_key(os.path.join(KEYS_DIR, "key%s.pem" % modulus))
        assert om.max_message_length(key, om.LEGACY_VERSION) == expected_legacy
        assert om.max_message_length(key, om.CURRENT_VERSION) == expected_current

    @pytest.mark.parametrize("version", [om.LEGACY_VERSION, om.CURRENT_VERSION])
    def test_boundary_at_and_over_limit(self, key, version):
        limit = om.max_message_length(key, version)
        at_limit = b"b" * limit
        over_limit = b"b" * (limit + 1)
        recovered = om.open_raw(
            key, om.seal_raw(key.public_key(), at_limit, version=version), version
        )
        assert recovered == at_limit
        with pytest.raises(ValueError):
            om.seal_raw(key.public_key(), over_limit, version=version)

    def test_upgrade_shrinks_capacity_but_keeps_ciphertext_size(self, key2048):
        legacy_cap = om.max_message_length(key2048, om.LEGACY_VERSION)
        current_cap = om.max_message_length(key2048, om.CURRENT_VERSION)
        assert legacy_cap - current_cap == 2 * (SHA256.digest_size - SHA1.digest_size)
        ct = om.seal_raw(key2048.public_key(), b"x", version=om.CURRENT_VERSION)
        assert len(ct) == key2048.size_in_bytes()
