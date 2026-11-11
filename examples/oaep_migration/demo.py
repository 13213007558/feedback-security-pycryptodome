"""
端到端演示：旧格式与新格式并存、显式版本分发、升级前后边界。

运行：
    python3 examples/oaep_migration/demo.py
"""

from __future__ import annotations

import os

from Crypto.Cipher import oaep
from Crypto.Hash import SHA1, SHA256
from Crypto.Signature.pss import MGF1

from oaep_migration import (
    CURRENT_VERSION,
    LEGACY_VERSION,
    build_current_cipher,
    build_legacy_cipher,
    envelope_key_id,
    load_private_key,
    max_message_length,
    open_envelope,
    open_raw,
    params_for_version,
    seal_envelope,
    seal_raw,
)

HERE = os.path.dirname(os.path.abspath(__file__))


def show_boundaries(key, tag: str) -> None:
    k = key.size_in_bytes()
    print(f"[{tag}] 模长 {key.size_in_bits()} bit, 密文长度固定为 {k} 字节")
    for version in (LEGACY_VERSION, CURRENT_VERSION):
        params = params_for_version(version)
        h_len = params.hashmod.digest_size
        print(
            f"  {version}: hLen={h_len}, "
            f"最大明文 = {k} - 2*{h_len} - 2 = {max_message_length(key, version)} 字节"
        )


def main() -> None:
    key = load_private_key(os.path.join(HERE, "keys", "key2048.pem"))
    show_boundaries(key, "RSA-2048")

    print("\n-- 旧入口：完全复刻历史 PKCS1_OAEP.new(key) 的默认组合 --")
    message = b"legacy DEK, wrapped before the migration"
    legacy_bare = build_legacy_cipher(key.public_key()).encrypt(message)
    # 旧裸密文只有显式走 LEGACY_VERSION 才能解开
    assert open_raw(key, legacy_bare, LEGACY_VERSION) == message
    try:
        open_raw(key, legacy_bare, CURRENT_VERSION)
    except ValueError as exc:
        print(f"  用新入口解旧密文 -> ValueError: {exc}")

    print("\n-- 新入口：显式 SHA-256 / MGF1-SHA256 / 固定 label --")
    current_cipher = build_current_cipher(key.public_key())
    current_bare = current_cipher.encrypt(b"bare ciphertext via the current entry")
    print(f"  裸密文长度: {len(current_bare)} 字节（等于模长）")
    print(f"  裸密文按新版本解开: {open_raw(key, current_bare, CURRENT_VERSION)!r}")
    envelope = seal_envelope(
        key.public_key(), b"new DEK, wrapped after the migration", key_id="kek-2048-001"
    )
    print(f"  envelope: {envelope.decode()}")
    print(f"  路由用 key id: {envelope_key_id(envelope)}")
    print(f"  解密结果: {open_envelope(key, envelope)!r}")

    print("\n-- 版本号即参数：同一条旧密文，换版本号没有第二次机会 --")
    print(f"  旧版本注册表参数: {params_for_version(LEGACY_VERSION).summary()}")
    print(f"  新版本注册表参数: {params_for_version(CURRENT_VERSION).summary()}")

    print("\n-- 最大可封装长度边界 --")
    limit = max_message_length(key, CURRENT_VERSION)
    at_limit = b"a" * limit
    over_limit = b"a" * (limit + 1)
    assert open_envelope(key, seal_envelope(key.public_key(), at_limit, "kek-2048-001")) == at_limit
    try:
        seal_raw(key.public_key(), over_limit)
    except ValueError as exc:
        print(f"  {limit + 1} 字节明文 -> ValueError: {exc}")
    print(f"  {limit} 字节明文封装/解封成功")

    print("\n-- 主摘要与 MGF 解耦：SHA-256 主摘要 + MGF1-SHA1 必须显式配对 --")
    mixed = oaep.new(
        key.public_key(),
        hashmod=SHA256,
        mask_func=lambda seed, length: MGF1(seed, length, SHA1),
        label=b"",
    )
    mixed_ct = mixed.encrypt(b"mixed mgf demo")
    # 解密侧必须给出完全相同的组合；默认 MGF1-SHA256 解不开
    try:
        oaep.new(key, hashmod=SHA256).decrypt(mixed_ct)
    except ValueError as exc:
        print(f"  MGF 不匹配 -> ValueError: {exc}")
    recovered = oaep.new(
        key, hashmod=SHA256, mask_func=lambda s, n: MGF1(s, n, SHA1), label=b""
    ).decrypt(mixed_ct)
    print(f"  显式 MGF1-SHA1 解开: {recovered!r}")

    print("\n演示完成。")


if __name__ == "__main__":
    main()
