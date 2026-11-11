"""
PKCS#1 OAEP 迁移样例。

历史服务直接调用 ``PKCS1_OAEP.new(key)``，所有参数都落在隐式默认值上：
RFC 8017 的 RSAES-OAEP 默认组合 SHA-1 / MGF1-SHA1 / 空 label。

本样例把封装参数显式化，并固定为两个受信任的版本（见下方注册表）：

* ``oaep-sha1-mgf1sha1-v1``：旧格式，仅用于解开历史密文；
* ``oaep-sha256-mgf1sha256-v2``：新格式，SHA-256 主摘要、MGF1-SHA256、
  固定用途 label，所有新写入都走这个版本。

版本号是唯一的算法选择依据，由可信的封装记录（envelope）携带；解密时按
版本号在注册表里查到一组固定参数，只尝试一次。不存在、也不允许出现
“逐个算法尝试直到解密成功”的回退逻辑。
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from Crypto.Cipher import PKCS1_OAEP as _legacy_oaep
from Crypto.Cipher import oaep
from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature.pss import MGF1

# 受信任的版本标识。它们同时是存储系统里的记录格式版本号，
# 必须由调用方像 schema 版本一样持久化，不能从密文推断。
LEGACY_VERSION = "oaep-sha1-mgf1sha1-v1"
CURRENT_VERSION = "oaep-sha256-mgf1sha256-v2"

# 旧服务历史上 label 为空；新格式固定一个用途 label 做域分离。
# label 不参与密钥协商，也不会出现在密文里，丢失后只能解不开。
LEGACY_LABEL = b""
CURRENT_LABEL = b"example-kes-oaep-v2"

# envelope 里的固定字段名，禁止在记录里夹带逐消息的算法参数，
# 算法组合只能来自下面的受信任注册表。
_FIELD_VERSION = "v"
_FIELD_KEY_ID = "kid"
_FIELD_CIPHERTEXT = "ct"


class OAEPVersionError(ValueError):
    """传入了注册表之外、因此不被信任的版本号。"""


@dataclass(frozen=True)
class OAEPParams:
    """某个受信任版本对应的完整 OAEP 参数组合。"""

    version: str
    hashmod: Any
    hash_name: str
    mgf_hashmod: Any
    mgf_name: str
    label: bytes

    def mask_func(self) -> Callable[[bytes, int], bytes]:
        mgf_hashmod = self.mgf_hashmod
        return lambda seed, mask_len: MGF1(seed, mask_len, mgf_hashmod)

    def summary(self) -> Dict[str, str]:
        return {
            "version": self.version,
            "hash": self.hash_name,
            "mgf": "MGF1-" + self.mgf_name,
            "label": self.label.decode("utf-8"),
        }


def _mgf1_sha1(seed: bytes, mask_len: int) -> bytes:
    return MGF1(seed, mask_len, SHA1)


def _mgf1_sha256(seed: bytes, mask_len: int) -> bytes:
    return MGF1(seed, mask_len, SHA256)


# 受信任注册表：版本号 -> 固定参数。运行时只读，不接受外部扩充。
_TRUSTED_VERSIONS: Dict[str, OAEPParams] = {
    LEGACY_VERSION: OAEPParams(
        version=LEGACY_VERSION,
        hashmod=SHA1,
        hash_name="SHA-1",
        mgf_hashmod=SHA1,
        mgf_name="SHA-1",
        label=LEGACY_LABEL,
    ),
    CURRENT_VERSION: OAEPParams(
        version=CURRENT_VERSION,
        hashmod=SHA256,
        hash_name="SHA-256",
        mgf_hashmod=SHA256,
        mgf_name="SHA-256",
        label=CURRENT_LABEL,
    ),
}


def params_for_version(version: str) -> OAEPParams:
    """按受信任版本号取回固定参数；未知版本直接报错，绝不猜测。"""
    try:
        return _TRUSTED_VERSIONS[version]
    except KeyError:
        raise OAEPVersionError("Untrusted or unknown OAEP version: %r" % version)


def _build_cipher(key: RsaKey, params: OAEPParams) -> oaep.PKCS1OAEP_Cipher:
    # 统一走新模块并显式给出全部参数；旧版本也不依赖任何默认值。
    return oaep.new(
        key,
        hashmod=params.hashmod,
        mask_func=params.mask_func(),
        label=params.label,
    )


def build_legacy_cipher(key: RsaKey) -> _legacy_oaep.PKCS1OAEP_Cipher:
    """
    明确的旧入口：等价于历史代码 ``PKCS1_OAEP.new(key)``，
    但把 SHA-1 / MGF1-SHA1 / 空 label 全部显式写出，避免再依赖默认值。
    只应用于解开历史密文，不应用于新写入。
    """
    params = params_for_version(LEGACY_VERSION)
    return _legacy_oaep.new(
        key,
        hashAlgo=params.hashmod,
        mgfunc=params.mask_func(),
        label=params.label,
    )


def build_current_cipher(key: RsaKey) -> oaep.PKCS1OAEP_Cipher:
    """明确的新入口：SHA-256 / MGF1-SHA256 / 固定用途 label。"""
    return _build_cipher(key, params_for_version(CURRENT_VERSION))


def max_message_length(key: RsaKey, version: str) -> int:
    """
    返回该版本下一次 OAEP 封装能容纳的最大明文长度（字节）。

    公式（RFC 8017 7.1.1，k = RSA 模长字节数，hLen = 主摘要输出长度）：
        k - 2 * hLen - 2
    MGF 使用的摘要不影响长度；label 长度只受协议自身限制，不占用该预算。
    """
    params = params_for_version(version)
    return key.size_in_bytes() - 2 * params.hashmod.digest_size - 2


def seal_raw(
    public_key: RsaKey,
    message: bytes,
    version: str = CURRENT_VERSION,
    rand_func: Optional[Callable[[int], bytes]] = None,
) -> bytes:
    """按指定受信任版本封装，返回裸 OAEP 密文（长度等于 RSA 模长）。"""
    params = params_for_version(version)
    cipher = oaep.new(
        public_key,
        hashmod=params.hashmod,
        mask_func=params.mask_func(),
        label=params.label,
        rand_func=rand_func,
    )
    return cipher.encrypt(message)


def open_raw(private_key: RsaKey, ciphertext: bytes, version: str) -> bytes:
    """
    按调用方明确给出的版本解开裸密文。

    版本号必须由调用方从自己的存储中提供：裸密文里没有任何字段能判断
    它用的是哪种摘要、MGF 或 label，因此这里不提供自动探测。
    """
    params = params_for_version(version)
    cipher = _build_cipher(private_key, params)
    return cipher.decrypt(ciphertext)


def seal_envelope(
    public_key: RsaKey,
    message: bytes,
    key_id: str,
    version: str = CURRENT_VERSION,
    rand_func: Optional[Callable[[int], bytes]] = None,
) -> bytes:
    """
    封装并写成自描述（但不自带算法参数）的 JSON 记录：

        {"v": <受信任版本号>, "kid": <调用方分配的密钥 id>,
         "ct": <base64 的裸 OAEP 密文>}

    记录里只放版本号、密钥 id 和密文；摘要/MGF/label 始终由注册表按
    版本号决定，调用方无法逐消息指定算法，也就不存在算法降级面。
    """
    params = params_for_version(version)
    raw = seal_raw(public_key, message, version=version, rand_func=rand_func)
    record = {
        _FIELD_VERSION: params.version,
        _FIELD_KEY_ID: key_id,
        _FIELD_CIPHERTEXT: base64.b64encode(raw).decode("ascii"),
    }
    return json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8")


def open_envelope(private_key: RsaKey, envelope: bytes) -> bytes:
    """
    按 envelope 里的受信任版本号查表解密，全程只尝试一次。

    版本号不在注册表里 -> :class:`OAEPVersionError`；
    参数不匹配（错 label、错 MGF、密文被改）-> 底层 ``ValueError``，
    不会吞掉错误再换一组参数重试。
    """
    record = json.loads(envelope.decode("utf-8"))
    version = record[_FIELD_VERSION]
    # 唯一的分发点：可信版本号 -> 固定参数，没有任何尝试循环。
    params = params_for_version(version)
    raw = base64.b64decode(record[_FIELD_CIPHERTEXT])
    cipher = _build_cipher(private_key, params)
    return cipher.decrypt(raw)


def envelope_key_id(envelope: bytes) -> str:
    """读出密钥 id，供调用方路由到对应的私钥；算法参数仍须走注册表。"""
    record = json.loads(envelope.decode("utf-8"))
    return record[_FIELD_KEY_ID]


def load_private_key(pem_path: str) -> RsaKey:
    with open(pem_path, "rb") as pem_file:
        return RSA.import_key(pem_file.read())
