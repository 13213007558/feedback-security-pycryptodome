# PKCS#1 OAEP 封装迁移样例（SHA-1 默认 → 显式 SHA-256）

本目录是一个可运行的迁移样例与兼容测试，基于本仓库的 PyCryptodome。
历史服务直接调用 `PKCS1_OAEP.new(key)`，摘要、MGF、label 全部落在
RFC 8017 RSAES-OAEP 的隐式默认值上（SHA-1 / MGF1-SHA1 / 空 label）。
新代码改用显式参数的 `Crypto.Cipher.oaep`，固定为
**SHA-256 / MGF1-SHA256 / 固定用途 label**。

## 文件

- `oaep_migration.py`：受信任版本注册表、显式新旧入口、envelope 封装/解封。
- `demo.py`：端到端演示（边界长度、跨版本失败、MGF 解耦）。
- `tests/test_oaep_migration.py`：41 条 pytest 兼容测试，含固定密文回归向量。
- `keys/key2048.pem`、`keys/key3072.pem`：由固定种子确定性生成的测试密钥，
  仅用于测试，严禁用于生产。

运行方式（仓库根目录）：

```bash
python3 examples/oaep_migration/demo.py
python3 -m pytest examples/oaep_migration/tests/ -q
```

## 两个受信任版本

版本号是**唯一**的算法选择依据，由调用方像 schema 版本一样持久化；
解密时按版本号在只读注册表里查到一组固定参数，只构造一次 cipher、
只解密一次。注册表里没有的版本直接抛 `OAEPVersionError`，
参数不匹配（错 label / 错 MGF / 密文被改）抛底层 `ValueError`，
不存在“逐个算法尝试直到成功”的回退，代码里也没有这类入口
（`test_no_brute_force_helper_exists` 会守住这条边界）。

| 版本号 | 主摘要 | MGF | label | 用途 |
| --- | --- | --- | --- | --- |
| `oaep-sha1-mgf1sha1-v1` | SHA-1 (hLen=20) | MGF1-SHA1 | 空 | 仅解开历史密文，禁止新写入 |
| `oaep-sha256-mgf1sha256-v2` | SHA-256 (hLen=32) | MGF1-SHA256 | `example-kes-oaep-v2` | 所有新写入 |

旧入口 `build_legacy_cipher()` 与历史 `PKCS1_OAEP.new(key)` 逐字节等价
（测试在同一随机源下比对密文），但所有参数都显式写出，不再依赖默认值。

## 调用方必须保存哪些参数

裸 OAEP 密文是定长随机字节，里面**没有任何自描述字段**。
以下信息无法从密文猜出，必须由调用方在带外存储：

1. **版本号**（`v`）：决定主摘要、MGF、label 的整组参数。这是最关键的一项，
   丢失后无法判断该用 SHA-1 还是 SHA-256，也就无法解密。
2. **密钥 id**（`kid`）：密文不携带是哪把公钥封装的；轮换密钥后全靠它路由私钥。
3. **主摘要算法**（hash）：本样例由版本号隐含（v1=SHA-1，v2=SHA-256），
   若系统不引入版本号，则必须单独存。
4. **MGF 及其摘要**：MGF1 是标准 MGF，但它用的摘要（MGF1-SHA1 还是
   MGF1-SHA256）独立于主摘要，同样不可推断。RFC 允许
   “SHA-256 主摘要 + MGF1-SHA1”这类混搭，测试 `test_main_hash_differs_from_mgf_must_pair_explicitly`
   证明两端不显式配对就解不开。
5. **label（L）**：label 只参与 `lHash`，不进密文。空 label 与非空 label
   的密文外观完全一样，错 label 只表现为解密失败（`test_wrong_label_fails`）。
6. **RSA 模长/密钥参数**：密文长度等于模长字节数，能反推模长，
   但反推不出具体是哪把密钥，仍需 `kid`。
7. **填充方案本身**（OAEP vs PKCS#1 v1.5）：也应通过版本号固定，不要靠探测。

推荐直接使用本样例的 envelope：`{"v", "kid", "ct"}`，
其中 `ct` 是 base64 的裸密文。记录里**故意不放** hash/mgf/label 字段，
防止逐消息篡改算法参数形成降级面；这些永远由注册表按版本号决定。

## 升级前后的边界（固定测试密钥）

OAEP 最大明文长度公式（RFC 8017 §7.1.1）：

```
max_len = k − 2·hLen − 2        # k = 模长字节数，hLen = 主摘要输出长度
```

| 模长 | 密文长度 k | 旧 v1 (SHA-1) 上限 | 新 v2 (SHA-256) 上限 | 差值 |
| --- | --- | --- | --- | --- |
| RSA-2048 | 256 B | 256−40−2 = **214 B** | 256−64−2 = **190 B** | −24 B |
| RSA-3072 | 384 B | 384−40−2 = **342 B** | 384−64−2 = **318 B** | −24 B |

注意：

- 升级到 SHA-256 后每条密文的可封装容量减少 `2·(32−20) = 24` 字节，
  密文本身长度不变（仍等于模长）。典型用法是封装 128/256 位数据密钥，
  不受影响；若旧系统封装过接近 214 字节的载荷，需要先排查。
- 超限在加密侧立即抛 `ValueError: Plaintext is too long.`
  （`test_boundary_at_and_over_limit` 覆盖恰好上限与上限 +1）。
- MGF 用的摘要不影响长度预算；label 长度不占用该预算（受协议自身约束）。
- OAEP 加密含随机 seed，同一明文两次密文不同；测试通过注入确定性
  `rand_func` 得到可复现的 golden 密文做回归。

## 迁移操作建议

1. 先双写期：新数据一律 `seal_envelope(..., version=CURRENT_VERSION)`；
   解密侧部署版本分发，旧记录按 `v=oaep-sha1-mgf1sha1-v1` 走旧入口。
2. 回灌/重封装：用旧入口解开历史密文后，立即用新入口重新封装并写新版本号，
   逐步消灭 v1 数据。
3. 退役：确认无 v1 记录后，从注册表移除旧版本（或让旧入口直接报错），
   并删除对应旧私钥的解密授权。
4. 任何时候都不要为了“兼容”加入自动探测：它会把不可见的参数差异变成
   降级/填充预言机攻击面，且解密失败的原因本来就不可靠。
