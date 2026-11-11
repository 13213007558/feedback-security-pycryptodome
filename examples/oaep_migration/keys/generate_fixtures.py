"""
确定性重建本目录的固定测试密钥（key2048.pem / key3072.pem）。

仅用于测试：固定种子 -> 确定性 RNG -> RSA.generate，重新运行应逐字节
复现签入的 PEM。生产密钥必须来自真正的安全随机源，切勿复用本脚本。
"""

from __future__ import annotations

import hashlib
import os

from Crypto.PublicKey import RSA


class SeededRNG:
    def __init__(self, seed: bytes):
        self._seed = seed
        self._buffer = b""
        self._counter = 0

    def read(self, n: int) -> bytes:
        while len(self._buffer) < n:
            self._buffer += hashlib.sha256(
                self._seed + self._counter.to_bytes(4, "big")
            ).digest()
            self._counter += 1
        result, self._buffer = self._buffer[:n], self._buffer[n:]
        return result


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    for bits in (2048, 3072):
        rng = SeededRNG(b"oaep-migration-fixed-seed:" + str(bits).encode())
        key = RSA.generate(bits, rng.read)
        path = os.path.join(here, "key%d.pem" % bits)
        with open(path, "wb") as pem_file:
            pem_file.write(key.export_key(format="PEM"))
        print("wrote", path)


if __name__ == "__main__":
    main()
