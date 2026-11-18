# WebAuthn authData 公钥编码长度差分诊断

- 分析对象：本仓库（分支 `task/163`），`webauthn/helpers/parse_authenticator_data.py`、`webauthn/helpers/decode_credential_public_key.py` 及其调用方。
- 依赖版本：`uv.lock` 锁定 `cbor2==6.1.2`（`pyproject.toml` 要求 `>=6.1.2`）。全部实验在 6.1.2 上复跑确认；在 6.3.0 上行为一致。
- 实验方法：离线构造 authData 字节流，直接调用库内真实解析函数，不依赖网络。实验脚本与原始输出见文末附录。

## 解析路径与两条入口

**入口 1 — `parse_authenticator_data`**（`webauthn/helpers/parse_authenticator_data.py:10`）
注册链路 `verify_registration_response` → `parse_attestation_object` → 本函数；认证链路 `verify_authentication_response` → 本函数（`verify_authentication_response.py:136`）。它用定长字段 + 游标切分 authData：

| 字段 | 长度来源 |
|---|---|
| rpIdHash / flags / signCount | 固定 32 + 1 + 4 字节（不足 37 字节直接拒绝，`:20`） |
| aaguid / credentialIdLength / credentialId | 固定 16 字节 + 2 字节大端长度前缀 + 变长（`:56-63`） |
| **credentialPublicKey** | **无长度前缀**：对剩余字节 `parse_cbor(val[pointer:])` 解出一项，再 `encode_cbor()` 规范重编码，以**重编码后的长度**推进游标（`:83-85`） |
| extensions（ED 标志） | 同样的"解码 + 重编码量长"（`:95-97`） |
| 结尾 | `len(val) > pointer` 时报 "Leftover bytes"（`:101-104`） |

**入口 2 — `decode_credential_public_key`**（`webauthn/helpers/decode_credential_public_key.py:41`）
注册时在 `verify_registration_response.py:200`（alg 白名单校验）和各 attestation 格式（packed/tpm/apple/android_key/fido_u2f）中被调用；认证时在 `verify_authentication_response.py:175` 对 RP 数据库存的公钥调用。它对入口 1 切出的公钥字节**再次** `parse_cbor`，但**没有"剩余字节"检查**；另有 `key[0] == 0x04` 的 U2F 未压缩点分支，按 1+32+32 **定长假设**直接切片（`:56-63`）。

签名绑定关系：packed 等格式的 attestation 签名覆盖的是 **authData 原始字节**（`packed.py:40-41` 重新从 attestationObject 取 `authData`），认证签名覆盖原始 `authenticator_data_bytes`（`verify_authentication_response.py:172`）；而落库/比对的公钥是入口 1 的**规范重编码字节**。两条入口对"同一把公钥"的字节级结论是否一致，正是本报告的核心问题。

## 证据一：编码长度与游标

cbor2 6.1.2 解码器行为（实测）：

| 输入形态 | cbor2 行为 |
|---|---|
| 单项后有尾随字节 | **静默忽略**，只返回第一项（这是入口 1 能对 `val[pointer:]` 整体解码的前提） |
| 非最短整数（如 `-7` 写成 `0x38 0x06`） | 接受 |
| 非最短 bstr 长度（如 `0x79 0x0020`，甚至 8 字节长度） | 接受 |
| 不定长 map / bstr（`0xBF…0xFF`、`0x5F…0xFF`） | 接受，重编码为定长 |
| map 键乱序 | 接受；`dumps` 保留插入序，**不做规范排序** |
| 重复键 | 拒绝（`allow_duplicate_keys=False`，对应 issue #265） |
| float16（3 字节） | 接受，但 `dumps` 一律输出 8 字节 float64 —— **重编码可比原文长** |
| `undefined`(0xF7)、simple value | 接受且重编码字节不变 |
| 截断 / 空输入 | 抛 `CBORDecodeEOF`，被包装为 `InvalidCBORData` |

由此推出游标不变量：

- COSE 公钥只含整数、文本、字节串，规范（最短）编码是其最小长度。因此**凡是长度可变的非规范编码，重编码必然更短**，游标少推进 → 必然触发 `:101` 的 leftover 拒绝。长度不变的非规范形式（键乱序、多余标签、`undefined`）重编码字节与原字节**逐字节相同**，游标不漂移。
- 结论：**凡是被入口 1 接受的输入，落库公钥字节 == 认证器签名的原始公钥字节**。长度不同的必被拒绝，不存在"同长不同字节"的被接受样本（已用 `undefined`、simple value、乱序 map 实测验证）。
- 但 `:101` 的检查是**单侧**的：只查 `len(val) > pointer`（游标走少了），不查游标走过头。extensions 中若含 float16，重编码变长，游标越过 `len(val)` 时不报错（见样本 F16/F16b）。

## 证据二：规范输入与畸形输入

构造样本（ES256 规范键 77 字节：`a5010203262001215820<x32>225820<y32>`，前置 37 字节头 + 16 字节 AAGUID + 2+16 字节 credentialId），两条入口实测结果：

| # | 样本 | 入口 1 `parse_authenticator_data` | 入口 2 `decode_credential_public_key` |
|---|---|---|---|
| A | 规范键 | ✅ 接受，落库字节 == 原始字节 | ✅ 接受（L） |
| B2 | 规范键 + ED 扩展 `{"hxmp":true}` | ✅ 扩展正确切出 | — |
| C | 非最短 alg 编码（`0x38 0x06`，+1 字节） | ❌ Leftover bytes | ✅ **接受**（N） |
| D | 非最短 bstr 长度（`0x79 0x0020`，+1 字节） | ❌ Leftover bytes | ✅ 接受 |
| E | 不定长 map（`0xBF…0xFF`） | ❌ Leftover bytes | ✅ 接受 |
| F | map 键乱序（`{3,1,-1,-2,-3}`） | ✅ 接受，落库 == 原始 | ✅ 接受 |
| G | 多余未知标签（key_ops=4） | ✅ 接受，落库 == 原始 | ✅ 接受（多余键被忽略） |
| H | 截断（bstr 声明 32 实给 10） | ❌ `InvalidCBORData` | ❌ `InvalidCBORData` |
| I | 键后尾随垃圾、无 ED 标志 | ❌ Leftover bytes | ✅ **接受**（M：尾随垃圾被静默忽略） |
| J | 非最短 alg + ED + 扩展 | ❌ Leftover bytes（游标漂移后扩展解错位置） | — |
| J2 | 非最短 alg + ED、无扩展字节 | ⚠️ **静默接受**，extensions 被错切为 `b'\x05'` | — |
| K | 坏 EdDSA `0xA3` 修复路径 | ✅ 修复为 `0xA4` 后正常解析 | ✅ |
| O | U2F `0x04` 未压缩点，65 字节 | — | ✅ |
| P | U2F 键仅 33 字节 | — | ⚠️ **静默接受**，`y = b''`（定长切片无长度校验） |
| Q | U2F 键 75 字节（10 字节垃圾尾） | — | ⚠️ 接受，尾部静默丢弃 |
| R | 空公钥 | — | ⚠️ 抛裸 `IndexError`（非库自定义异常） |
| F16 | 扩展含 float16（重编码 +6 字节） | ⚠️ 接受，落库扩展为重编码字节（语义等价） | — |
| F16b | float16 扩展 + 4 字节垃圾尾 | ⚠️ **静默接受**，垃圾尾被过冲的游标"吃掉"，leftover 检查失效 | — |

两条入口的结果差异汇总：

1. **严格性不对称**：同一批非规范字节（C/D/E），入口 1 拒绝、入口 2 接受。入口 2 还接受尾随垃圾（M）。注册流程里入口 1 先跑，所以这些字节到不了入口 2；但 RP 若从其他渠道（旧库、手工导入）取得公钥字节直接走认证链路，入口 2 是唯一防线，而它不做长度/尾随校验。
2. **字节同一性**：凡入口 1 接受的，入口 1 落库字节与签名覆盖的原始字节逐字节相同（F/G 实测 `stored == raw`），入口 2 解出的 kty/alg/crv/x/y/n/e 与签名语义一致。
3. **定长假设的盲区**：U2F `0x04` 分支（`decode_credential_public_key.py:56-63`）不做任何长度检查，短键切出空 `y`、长键丢弃尾部——这是"定长字段假设"与"实际剩余长度"差异最大的点。

## 证据三：差异是否形成安全影响

**协议允许、无安全影响的差异：**

- 键乱序（F）、多余标签（G）：CTAP2 规范 CBOR 是对认证器的编码要求，WebAuthn RP 侧并不要求拒绝非规范 CBOR；重编码字节不变，签名绑定与 alg 白名单均不受影响。坏 EdDSA 修复（K）是对真实硬件的兼容兜底，修复的是签名前字节……注意修复发生在**解析侧**，签名验证仍用原始字节（packed 从 attestationObject 重取 authData），所以该兼容不削弱签名绑定。
- 非规范长度编码（C/D/E）被拒绝：符合"RP 应严格"的惯例，仅造成互操作性拒绝（DoS 面仅针对发起注册的本人），无绕过。
- 截断（H）、尾随（I）、重复键：均被拒绝，边界完整。

**未形成凭据算法或边界校验绕过的论证：**

- alg 混淆：注册时 alg 白名单（`verify_registration_response.py:204`）和 packed-self 的 `alg == att_stmt.alg` 检查都作用在入口 1 落库字节上，而该字节与签名覆盖字节相同；攻击者改 alg 必然改动被签名的 authData，签名失效。认证时 alg 取自 RP 库存键，authData 里的编码游戏够不到它。
- 边界绕过：公钥段的游标推进对一切被接受输入都是精确的（证据一的不变量）；leftover 检查兜住所有"游标走少"的情形。

**实际存在的缺口（低危，均不构成认证绕过，但属于边界校验缺陷）：**

1. **leftover 检查单侧化**（`parse_authenticator_data.py:101`）：只查 `len(val) > pointer`。extensions 含 float16 等"重编码变长"数据时游标过冲，F16b 证明 4 字节垃圾尾可被静默吞掉——库自定的"无剩余字节"不变量被破坏。当前扩展数据在本库中不参与安全判定，故无直接危害；若未来扩展（如 `appid`、`prf` 输出）进入安全判定，此处即成漏洞。
2. **J2 静默错切**：非规范键 + ED 标志且无扩展字节时，游标漂移 1 字节后恰好"解出"键尾字节 `0x05` 当作扩展，静默接受。说明"重编码量长"一旦遇到非规范输入，错误可以从"拒绝"退化为"接受错误数据"。
3. **入口 2 无尾随/长度校验**：`decode_credential_public_key` 对尾随垃圾（M）、非规范编码（N）静默接受；U2F 分支对短键给出空 `y`（P），下游 `decoded_public_key_to_cryptography` 会抛 `ValueError`（`verify_authentication_response.py:174` 只捕获 `InvalidSignature`），表现为 500 而非 4xx；空键抛裸 `IndexError`（R）。均为健壮性/错误分类缺陷，不影响签名验真的安全性。

## 不依赖网络的回归判据

以下判据全部可用构造字节流离线执行（无需认证器、无需网络），建议固化为单测：

1. **游标精确性**：对任意被接受的 authData，断言解析后内部游标 == `len(val)`；等价地，规范键 + 规范扩展的样本必须成功且 `credential_public_key` / `extensions` 落库字节与输入对应区段逐字节相等。
2. **非规范拒绝**：样本 C/D/E（非最短整数、非最短 bstr 长度、不定长 map）必须抛 `InvalidAuthenticatorDataStructure("Leftover bytes…")`；样本 H（截断）必须抛 `InvalidCBORData`；样本 I（无 ED 尾随）必须抛 leftover。
3. **语义等价接受**：样本 F/G 必须接受且落库字节 == 输入字节（防止未来给 `dumps` 加 `canonical=True` 排序导致落库字节与签名字节分叉——那会使 packed 自我证明等场景的字节级假设翻转，属于必须被测试锁死的行为）。
4. **单侧检查暴露**：样本 F16b（float16 扩展 + 垃圾尾）当前被接受——用 `pytest.raises` 的**反向断言**（或 xfail）锁定现状；若修复为双侧检查（`pointer != len(val)` 即拒绝），该测试应翻转为必须拒绝。修复建议：`parse_authenticator_data.py:101` 改为 `if len(val) != pointer`。
5. **入口 2 边界**：`decode_credential_public_key(b"")` 应抛库自定义异常而非 `IndexError`；U2F 分支应断言 `len(key) == 65`（短键/长键均拒绝）；如需保持现状，则以测试锁定"尾随垃圾被忽略、短键 y 为空"的行为，防止静默变化。
6. **两入口一致性**：对同一键字节，凡入口 1 接受的，入口 2 必须解出相同 kty/alg/crv 与坐标；对入口 1 拒绝的非规范字节，记录入口 2 的接受现状（判据 5 的延伸），防止两入口的宽松度差距在重构中无意扩大。

## 附录：实验环境

- cbor2 6.1.2（与 `uv.lock` 一致；6.3.0 复测行为相同），Python 3.12，离线 venv。
- 关键样本字节：
  - 规范 ES256 键：`a5 01 02 03 26 20 01 21 5820 <x×32> 22 5820 <y×32>`（77 字节）
  - 非最短 alg：`… 03 3806 20 01 …`（+1 字节）
  - 非最短 bstr：`… 21 790020 <x×32> …`（+1 字节）
  - 不定长 map：`bf 01 02 03 26 20 01 21 5820 … ff`
  - float16 扩展：`a1 61 66 f93c00`（`{"f": 1.0}`，重编码为 `a16166fb3ff0000000000000`，+6 字节）
- 实验脚本（`/tmp/wa-exp/`，会话临时目录）：`exp1/exp2`（cbor2 解码器行为）、`exp3`（两入口端到端 A–R 样本）、`exp4`（B2/F16/F16b/J2 跟进样本）。输出与本文表格一致。
