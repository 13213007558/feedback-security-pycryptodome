# PyCryptodome 随机数注入假设审计

- 审计对象：PyCryptodome **4.4.0**（本仓库 `lib/Crypto`，C 扩展为本地编译的 `*.abi3.so`）
- Python：3.12.11 / pytest 9.2.0
- 审计问题：测试中替换 `Crypto.Random.get_random_bytes`，能否同时控制 RSA/ECC 生成、OAEP、PSS 和对称模式的随机值？
- 结论摘要：**该假设部分成立且高度依赖导入时机。** 仅替换公共别名只能可靠控制"延迟绑定"入口（RSA、OAEP、PSS、DSA、ElGamal、PBES）；对"提前绑定"入口（ECC、全部对称模式、MLKEM/MLDSA、KDF、SecretSharing、PEM）无效，且失败时会**静默旁路**到真实 OS 随机源，不报错、不回退到其他 Python 随机对象。

---

## 1. 熵的真实来源（静态事实）

整个库只有一个文件直接接触 OS 熵：`lib/Crypto/Random/__init__.py`

```python
from os import urandom
...
get_random_bytes = urandom          # 第 56 行：模块级别名
```

- 4.4.0 已无 Fortuna/用户态 PRNG（`Random/` 下仅 `random.py`，其 `StrongRandom` 也回落到 `Random.get_random_bytes`）。
- `grep` 全部 C 源码（`src/**/*.c,*.h`）查找 `urandom|RAND_bytes|BCryptGenRandom|getentropy` **零命中**：C 扩展（`_raw_*.abi3.so` 等）只做密码运算，不产生随机数。所有 IV/nonce/种子都在 Python 包装层生成。
- 因此存在**单一汇聚点**：任何随机字节最终都经 `os.urandom`（macOS 上为 `getentropy`/`SecRandom` 路径）。库内没有第二个独立熵源，也就不存在"注入失败后悄悄换一个 RNG 实现"的代码——但提前绑定会让被替换的名字被绕过，原函数对象继续被使用。

## 2. 两种名字绑定模式（问题根因）

| 绑定模式 | 源码写法 | 名称解析时机 | 后置 monkeypatch 是否生效 |
|---|---|---|---|
| 延迟绑定 LATE | `from Crypto import Random`，调用时 `randfunc = Random.get_random_bytes` | 每次调用时按属性查找 | 生效 |
| 提前绑定 EARLY | `from Crypto.Random import get_random_bytes` | 模块导入时复制函数对象到本模块命名空间 | **失效**（本模块持有原 `os.urandom` 对象的副本） |

关键：`Crypto.Random.get_random_bytes = fake` 只改 `Crypto.Random` 模块的属性；提前绑定模块里的局部名 `get_random_bytes` 仍指向导入时的那个函数对象。`os.urandom` 本身也是在 `Random/__init__.py` 导入时被取别名，替换 `os.urandom` 同样影响不到已复制的引用。

## 3. 调用关系表（入口 → 随机用途 → 绑定 → 显式注入参数 → 验证状态）

| 公共入口 | 随机用途 / 默认长度 | 绑定模式（源码位置） | 显式注入参数 | 后置 patch | 验证 |
|---|---|---|---|---|---|
| `PublicKey.RSA.generate` | 素数候选 + Miller-Rabin（1024 位实测 966 次调用 / 30912 字节） | LATE `RSA.py:44,464,613` | `randfunc=` | 生效 | 已验证（计数+复现+失败） |
| `PublicKey.RSA` 密钥口令导出 | PBES2 IV/nonce | LATE `IO/_PBES.py:395`（`Random.get_random_bytes`） | `randfunc=`（经 `export_key`） | 生效 | 源码确认；失败路径未单独实测，标**未验证** |
| `PublicKey.ECC.generate` | Ed/X 曲线 seed；NIST 曲线经 `Integer.random_range` 取标量（p256 实测 2 次 `[1,31]`） | EARLY `ECC.py:57,696` | `randfunc=` | **失效/静默旁路** | 已验证 |
| `Cipher.PKCS1_OAEP.new/encrypt` | OAEP seed，长度=hLen（SHA-256 实测 32 字节，1 次） | LATE `oaep.py:88` | `randfunc=` | 生效 | 已验证 |
| `Cipher.PKCS1_v1_5` | 填充随机串 | LATE `PKCS1_v1_5.py:291` | `randfunc=` | 生效 | 源码确认，**未验证** |
| `Signature.pss.new/sign` | PSS salt（默认 hLen=32，1 次）；MGF1 本身确定性 | LATE `pss.py:389` | `rand_func=` | 生效 | 已验证 |
| `Cipher.AES.new(MODE_CBC/CFB/OFB)` | IV=block_size（16） | EARLY `_mode_cbc.py:14,283` 等；**模块在 `AES.new()` 内懒加载** `AES.py:39` | 无 randfunc；传 `iv=` | 仅在模块未被预加载时生效；预加载后**旁路** | 已验证 |
| `AES MODE_GCM/EAX/CCM/OCB/CTR/OPENPGP` | nonce 16/16/11/15/8/16 | EARLY，对应 `_mode_*.py`；同样懒加载 | 传 `nonce=` | 同上（懒加载顺序敏感） | CBC/GCM/EAX/CCM/OCB/CTR/CFB/OFB/OpenPGP 已实测默认长度；预加载旁路已验证 |
| `AES MODE_GCM_SIV` | nonce 12 | EARLY `_mode_gcm_siv.py:24,459`，懒加载 | 传 `nonce=` | 顺序敏感 | 已实测 |
| `AES MODE_SIV`（RFC 5297）/ XTS / KW / KWP / ECB / ARC4 | **无默认随机**（确定性或要求调用方给 IV） | 无 `get_random_bytes` 调用 | — | 无影响 | 源码 grep 确认 |
| `Cipher.ChaCha20.new` | nonce 8（或 12，Poly1305 路径） | EARLY **顶层导入** `ChaCha20.py:10,318,363` | 无 randfunc；传 `nonce=` | **始终旁路** | 已验证 |
| `Cipher.ChaCha20_Poly1305.new` | nonce 12 | EARLY `ChaCha20_Poly1305.py:14,297` | 传 `nonce=` | 顺序敏感 | 已实测默认长度 |
| `Cipher.Salsa20.new` | nonce 8 | EARLY 顶层 `Salsa20.py:29,246` | 传 `nonce=` | 旁路 | 已实测 |
| `PublicKey.MLKEM` | 密钥 seed 64、封装 coins 32 | EARLY `MLKEM.py:14,495,562` | `randfunc=` / `coins=` | **旁路** | 源码确认；封装入口实测受 API 形态限制，标**部分未验证** |
| `PublicKey.MLDSA` / `Signature.mldsa` | 签名随机化 | EARLY `MLDSA.py:14,580`、`mldsa.py:12,306` | `randfunc=` | 旁路 | 源码确认，**未验证** |
| `PublicKey.DSA` / `ElGamal` | 密钥/签名随机 | LATE `DSA.py:292,470`、`ElGamal.py:191` | `randfunc=` | 生效 | 源码确认，**未验证** |
| `PublicKey.Hybrid` | MLKEM coins + KEM seed | EARLY `Hybrid.py:19,223,275` | `randfunc=` | 旁路 | 源码确认，**未验证** |
| `Protocol.KDF`（PBKDF2 等的默认 salt） | salt 16 | EARLY `KDF.py:37,762` | 多数可显式传 `salt` | 旁路 | 源码确认，**未验证** |
| `Protocol.SecretSharing` | 分片随机 | EARLY（别名 `rng`）`SecretSharing.py:11` | 无 | 旁路 | 源码确认，**未验证** |
| `IO.PEM`（口令保护 PEM） | 加密 IV/nonce | EARLY `PEM.py:25`；但 `_PBES.py:395` 内部默认走 LATE | `randfunc=` | 取决于具体调用链 | 源码确认，**未验证** |

## 4. 实验证据矩阵（每个用例独立子进程，见 `audit_results.json`）

拦截列：计数型确定性 RNG（SHA-256 密钥流，可复现）是否真的被调用。失败列：故意抛错的 RNG 是否传播错误、是否触发 `os.urandom` 回退。

| 入口 | 后置 patch | 预加载后再 patch | 前置 patch | 显式 randfunc | 失败 RNG（后置） | 失败 RNG（显式） |
|---|---|---|---|---|---|---|
| RSA.generate | 拦截 | 拦截 | 拦截 | 拦截 | 抛错，无回退 | 抛错，无回退 |
| ECC.generate | **旁路（用真实 OS RNG）** | 旁路 | 拦截 | 拦截 | 旁路、无错误、无回退 | 抛错，无回退 |
| OAEP.encrypt | 拦截 | 拦截 | 拦截 | 拦截 | 抛错，无回退 | 抛错，无回退 |
| PSS.sign | 拦截 | 拦截 | 拦截 | 拦截 | 抛错，无回退 | 抛错，无回退 |
| AES-CBC IV | 拦截（懒加载未触发） | **旁路** | 拦截 | 不适用（传 `iv`） | 抛错，无回退 | 不适用 |
| AES-GCM nonce | 拦截（懒加载） | **旁路** | 拦截 | 传 `nonce` | 抛错，无回退 | 不适用 |
| ChaCha20 nonce | **旁路** | 旁路 | 拦截 | 传 `nonce` | 旁路、无错误 | 不适用 |

实测调用计数（确定性 RNG）：

- RSA-1024：`966` 次 draw，共 `30912` 字节，首批尺寸 `[1,63,1,63]`；同流再生成模数 `n` 完全一致。
- ECC p256：`2` 次，尺寸 `[1,31]`；同流标量 `d` 完全一致。
- OAEP/SHA-256：`1` 次 `[32]`，同流密文一致。
- PSS/SHA-256：显式注入时仅 `1` 次 `[32]`（salt）；全局 patch 时因还包含 RSA 自检等共 `7` 次。
- CBC/GCM/ChaCha20：分别 `[16]/[16]/[8]`，各 1 次。

## 5. 失败语义：不会"回退到其他随机源"，但会"静默忽略注入"

两类截然不同的表现，都已实测：

1. **延迟绑定入口（RSA/OAEP/PSS）**：注入的失败 RNG 被真正调用，异常**原样传播**（`RuntimeError: injected RNG failure`），`os.urandom` 哨兵零调用。不存在 try/except 吞错后换源。
2. **提前绑定入口（ECC/ChaCha20/预加载后的 AES 模式）**：后置 patch 安装的失败 RNG **根本不被调用**（`fail_calls=[]`），操作正常完成并使用真实 OS 熵。这不是"回退"，而是注入被绕过；危害是测试以为随机可控，实际断言跑在真实熵上——可能假绿或偶发失败，且无任何告警。

对称模式没有 `randfunc` 参数；"失败显式注入"对它们不适用（见接法）。

## 6. 不会污染生产的测试接法（推荐顺序）

1. **首选显式参数，零全局状态。** RSA/DSA/ECC/ElGamal/MLKEM/MLDSA 用 `randfunc=`；OAEP/PKCS1_v1_5 用 `randfunc=`；PSS 用 `rand_func=`。调用结束即失效，无需还原，导入顺序无关。
2. **对称模式传显式 `iv=`/`nonce=` 值**（用测试 RNG 生成该值），而不是 patch。这同时让结果可复现，且贴合"nonce 不应由全局补丁隐式决定"的工程实践。
3. **必须全局 patch 时**：用 fixture 快照并还原所有绑定点——既改 `Crypto.Random.get_random_bytes`，也改每个已导入模块的局部名（`Crypto.Cipher._mode_cbc.get_random_bytes`、`Crypto.Cipher.ChaCha20.get_random_bytes`、`Crypto.PublicKey.ECC.get_random_bytes` 等）。参考 `test_safe_rng_wiring.py::controlled_global_rng`，teardown 用 `setattr` 逐一还原，并用 `Random.get_random_bytes is os.urandom` 断言还原成功。
4. **失败注入放子进程**：让坏 RNG 的生命周期限定在单次 `subprocess`，父进程与生产代码永不持有它；断言异常传播且 `os.urandom` 哨兵无调用。参考 `test_failure_isolation.py`。
5. **禁止**在 session/conftest 导入期或生产代码里替换 `os.urandom` 或 `Crypto.Random.get_random_bytes`；本审计的所有替换都在隔离子进程或带 teardown 的函数级 fixture 内完成。

## 7. 复现方式

```bash
cd rng_audit
python3 run_isolated_audit.py     # 35+ 独立子进程，打印矩阵并写 audit_results.json
python3 -m pytest -q              # 17 个 pytest 用例（安全接法 + 子进程失败隔离）
```

文件：

- `_rng_helpers.py`：计数确定性 RNG（SHA-256 密钥流）、失败 RNG、`os.urandom` 哨兵。
- `probe_rng.py` / `run_isolated_audit.py`：隔离子进程探针与编排。
- `test_safe_rng_wiring.py`：生产安全的推荐接法（显式参数、受控 fixture、失败传播）。
- `test_failure_isolation.py`：子进程级失败注入与静默旁路检测。
- `audit_results.json`：机器可读原始结果。

## 8. 未验证 / 证据不足清单（按要求标注）

- RSA 口令保护导出（PBES2）、`PKCS1_v1_5`、DSA、ElGamal、PEM 链路：仅源码级 LATE/EARLY 分类，未跑计数/失败实测。
- MLKEM 封装、MLDSA/Hybrid 签名、KDF 默认 salt、SecretSharing：源码确认 EARLY 绑定与显式参数，但本环境未对每条入口做端到端计数复现（MLKEM 封装入口在 `Hybrid` 侧，API 形态与七入口不同）。
- 对称模式在非 AES 算法（DES/Blowfish/CAST/ARC2）下的默认 IV：源码显示复用同一 `_mode_*` 包装，推断行为一致，未逐一实测。
- Windows 的 `BCryptGenRandom`、Linux `getrandom` 与 macOS 熵路径差异：本环境仅 macOS，未跨平台验证；但库内无平台相关的第二 RNG 代码路径，结论应一致，标**未跨平台验证**。
