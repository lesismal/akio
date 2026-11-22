# ADR-052：SRTP 的 AES-f8 与 SEED，akio-crypto 的 SEED

[English](052-srtp-f8-seed.md) | 简体中文

状态：已采纳（2026-11-20）

## 背景

ADR-040 之后，`akio-srtp` 的 README 仍把两种变换列为未实现：

- **AES-f8**（RFC 3711 §4.1.2）：RFC 3711 中可选的加密变换，源自 3GPP（UMTS f8），是一种 OFB 变体，
  其 IV 先在第二个密钥下掩蔽。SDP 安全描述中称为 `F8_128_HMAC_SHA1_80`（RFC 4568 §6.2.3；RFC 4568
  的语法还列出了 `F8_128_HMAC_SHA1_32`）。
- **SEED**（RFC 5669）：韩国国家分组密码（RFC 4269），有三个套件：`SEED_CTR_128_HMAC_SHA1_80`（必须
  实现）、`SEED_128_CCM_80` 与 `SEED_128_GCM_96`，密钥用 SEED-CTR PRF 派生。

两者都没有 DTLS-SRTP 保护配置编号，WebRTC 从不协商它们；它们对用 SDES 协商密钥的 SIP/VoIP 对端有用
（SEED 用于韩国的部署）。`akio-crypto` 原先没有 SEED，也没有 CCM。我们常用的交叉验证参考 libsrtp
两者都没有实现。

## 决定

1. **`akio-crypto` 中的 SEED**（`akio_crypto::seed`）：`Seed`（RFC 4269；`new`、`from_slice`、
   `encrypt_block`/`decrypt_block`、`encrypt_blocks`/`decrypt_blocks`、128 位计数器的
   `apply_ctr`），`SeedGcm`（SP 800-38D：96 位 nonce，16 字节标签或截短为 15-12、8、4 字节；使用
   `gcm` 中可移植的常数时间 GHASH；先校验标签再解密）与 `SeedCcm`（RFC 3610：7 到 13 字节 nonce，
   4 到 16 字节的偶数长度标签；标签校验失败时输出被清零）。CCM 构造在 crate 内是泛型的，也用 AES
   对照 RFC 3610 做了验证。

   **常数时间，不查表。** SEED 的 S 盒是 GF(2⁸)（模 x⁸+x⁶+x⁵+x+1）上的 `S0(x) = A0·x²⁴⁷ ⊕ 0xA9` 与
   `S1(x) = A1·x²⁵¹ ⊕ 0x38`，而 `x²⁴⁷ = (x⁻¹)⁸`、`x²⁵¹ = (x⁻¹)⁴` 对 `x⁻¹` 是线性的：先求逆再做
   仿射变换，与 AES 相同。求逆用固定切片 AES 已有的 Boyar-Peralta 电路（去掉四个 NOT 的
   `aes::fixslice::sub_bytes`，即 AES 域中的 `M·y⁻¹`），经过把 x 映到 0x19 的域同构，两侧再加三个
   推导出的线性映射（共 68 个 XOR，在八个同构中选出），测试对每个输入都与 RFC 4269 的表比对。G 函数
   一次在 16 个 32 位字上位切片运行（8 个 64 位比特平面，64 个字节通道，进出各做一次三步 swapmove
   转置；G 的置换层与模加仍在字上进行），因此 CTR、GCM 与 ECB 同时处理 16 个分组，密钥扩展中互不依赖
   的 32 次 G 调用分两趟完成。单个分组（CCM 的 CBC-MAC、`encrypt_block`）使用单字 G，在寄存器内做
   8×8 转置：比一趟 16 通道快 2.4 倍。没有 SEED 指令，所以这是唯一路径。放弃的方案：RFC 的 SS 表
   （4 KiB、以秘密为下标的读取）、每次查表都全表扫描、通用的 GF(2⁸) 求幂（门数约为 Boyar-Peralta
   电路的三倍）。

2. **保护配置。** `Profile` 新增 `AesF8HmacSha1_80`、`AesF8HmacSha1_32`、`SeedCtrHmacSha1_80`、
   `SeedCcm80` 与 `SeedGcm96`（SDES 名称 `F8_128_HMAC_SHA1_80/32`、`SEED_CTR_128_HMAC_SHA1_80`、
   `SEED_128_CCM_80`、`SEED_128_GCM_96`；没有 DTLS-SRTP 编号；`Profile::ALL` 列出 15 种，新配置排在
   AES-192-CM 之后）。主密钥均为 16 字节、主盐均为 14 字节。标签：f8 为 10 或 4 字节（SRTCP 10），
   SEED-CTR 10，SEED-CCM 10，SEED-GCM 12（SRTP 与 SRTCP 相同）。`is_aead` 现在对 SEED-CCM 与
   SEED-GCM 也为真；新增 `session_salt_len`（所有 AEAD 配置为 12，其余为 14）。

   *SEED AEAD 的主盐。* RFC 5669 §3 只说 12 字节的会话盐由密钥派生产生，并没有缩短主盐，所以主盐保持
   RFC 3711 默认的 112 位（AES-GCM 的 96 位主盐是 RFC 7714 自己的选择）；标签 2 / 5 的 PRF 输出截为
   12 字节。按 RFC 7714 的方式解读 RFC 5669 的实现会需要 12 字节主盐；目前没有可比对的实现。

3. **AES-f8**（RFC 3711 §4.1.2）。SRTP 的 IV 为 `0x00 || M || PT || SEQ || TS || SSRC || ROC`
   （头部前 12 字节、第 0 字节清零，再接 ROC），SRTCP 为 `0⁴ || E || index || 前 8 字节`；
   `m = k_s || 0x55…`，`IV' = E(k_e ⊕ m, IV)`，`S(j) = E(k_e, IV' ⊕ j ⊕ S(j-1))`。每个分组依赖前一个，
   所以 f8 一次处理一个分组（AES 指令；可移植的固定切片 AES 每个分组要付四个分组的代价）。PRF 为
   AES-CM（RFC 3711 §4.3.3）。cryptex 加密的部分与 AES-CM 相同；IV 只读取固定头部的第 1-11 字节，
   cryptex 不会改动它们。RFC 6904 使用头部密钥与头部盐和该包的 IV 做 f8（RFC 6904 §3.2）；密钥流在
   被选中的元素之间单向向前生成（`F8Stream`），不会为每个元素重新计算。

4. **SRTP 中的 SEED**（RFC 5669）。三个套件都用 SEED-CTR PRF（§4：AES-CM 的构造换成 SEED）。
   SEED-CTR 就是用 SEED 的 AES-CM。SEED-CCM 与 SEED-GCM 使用 RFC 5669 §3 的 nonce（与 RFC 7714 相同）
   和 RFC 7714 的关联数据：RTP 头部；SRTCP 为前 8 字节加 E 标志与索引，E 为 0 时整个包作为关联数据、
   明文为空。标签接在密文之后，MKI 跟在标签后面，与 AES-GCM 相同。CCM 认证的是明文（RFC 5669 §2.2），
   所以接收方必须先解密才能校验；校验失败时结果被清零、从不返回，重放窗口不变。SEED-CCM 或 SEED-GCM
   下的 RFC 6904 使用头部密钥与 12 字节头部盐的 SEED-CTR（RFC 6904 §3.2），与 AES-GCM 使用 AES-CM
   一样。

5. **内部结构。** 会话的 AEAD 加密 / 解密对 SEED-GCM 与 SEED-CCM 走同一接口（标签长度取自配置，不再
   固定 16 字节；AES-GCM 保留直接路径，f8 与 SEED 放在不内联的函数中，WebRTC 所用变换的每包代码不变大），SRTCP 加密接收头部与索引字（f8 需要），头部扩展的密钥流是一个在 AES-CM、
   SEED-CTR 或 f8 上单向向前的小型流。没有新的解析代码，所以没有新的模糊测试目标：`srtp_unprotect` 与
   `srtp_features` 遍历 `Profile::ALL`，覆盖了五种新配置。

6. **未接入协商。** `akio-webrtc` 通过 DTLS-SRTP 获取 SRTP 密钥，而 DTLS-SRTP 没有这些套件的编号；
   它也没有实现 SDP 安全描述（`a=crypto`）。如果将来加入 SDES，`Profile::from_sdes_name` 已经能映射
   这些名称；那是后续工作，不在本次变更内。

## 验证

- **SEED**：RFC 4269 附录 B.1-B.4 双向、单个与批量（以及 B.4 的轮密钥）；两条路径上的 G 对每个 S 盒
  输入与 RFC 的表比对；OpenSSL 3.0.13 的 `seed-ecb`（legacy provider）三个密钥；跨批次边界与 128 位
  计数器回绕的 CTR。RFC 5669 附录 A.1（密钥流）、A.2（SEED-CCM）、A.3（SEED-GCM）及篡改；RFC 3610
  数据包向量 #1 与 #19 用 AES 验证 CCM 构造。
- **SRTP**：RFC 3711 附录 B.1（f8 的 IV、IV' 与密文，以及 ROC 为 0xd462564a 的完整数据包），RFC 5669
  A.1（SEED-CTR 载荷）、A.2 与 A.3 作为完整 SRTP 包双向验证。RFC 5669 A.1 的标签不做比对：它可以复现
  为对 RTP 头部与*明文*（不含 ROC）计算的 HMAC-SHA1，而不是 RFC 3711 §4.2 规定的头部、密文与 ROC。
- **独立交叉验证**：`testdata/f8_seed.py` 只依据 RFC 实现了 f8、SEED-CTR、CCM、GCM/GHASH、两种 PRF、
  RFC 6904、cryptex 与数据包布局，底层只用 pyca/cryptography 41 的 AES 与 SEED 的 ECB 模式，并先对照
  RFC 3711 B.1/B.3、RFC 4269 与 RFC 5669 A.1-A.3 自检。`testdata/f8_seed.txt`：libsrtp 交叉验证的输入
  在五种配置下的结果，共 25 组用例、115 个包（无 MKI；两个 MKI 密钥中途切换；单字节与双字节扩展的
  RFC 6904；带与不带 CSRC、以及带 MKI 的 cryptex；RTP 与 SRTCP），逐字节加密并解密回原文，另含七个
  SEED-CTR PRF 输出。
- **行为**：通用测试现在覆盖全部 15 种配置：重放与乱序、带乱序与第二次回绕的滚动、SRTCP 重放、逐字节
  篡改、截断、错误密钥、MKI 换钥、跨密钥块的密钥派生率 16、RFC 6904、cryptex 往返、缓冲区复用；模糊
  测试语料在 stable 上回放。
- **时序**：ct-dudect 目标 `seed-key`（密钥扩展加 CTR，全零密钥对随机密钥）与 `seed-block`（单个分组，
  全零明文对随机明文）：`seed-key` 在 1550 万次测量中 |t| 为 1.50，`seed-block` 在 5060 万次中为 1.52（各 60 秒，gpu51 静默，核心 2）：未见差异（docs/constant-time.zh-CN.md）。
- **速度**（gpu51，`quiet.sh`，CPU 2）：每个包，载荷 160 / 1200 字节，protect：AES-f8
  354 ns / 2.26 µs（同一轮中 AES-128-CM 为 251 ns / 1.18 µs：f8 的分组只能串行），SEED-CTR
  3.6 / 18.3 µs（1200 字节时 66 MB/s），SEED-GCM 3.9 / 20.4 µs，SEED-CCM 16.1 / 98 µs（12 MB/s）；
  unprotect 与 protect 相差不到 10%。`akio-crypto` 本身：SEED 单个分组 15.3 MB/s（约 1 µs）、SEED-CTR
  68.8 MB/s、SEED-GCM 61.3 MB/s、SEED-CCM 12.2 MB/s。原有配置对比 main aca9e988（三轮交替，取中位数）：
  AES-CM 与 160 字节 AES-GCM 在 ±1.6% 以内；1200 字节 AES-GCM 单独测量时持平（protect 0.999，
  unprotect 1.012），在完整用例序列中 protect +1.5-2.2%（那里它的耗时是单独测量的三倍，受内存分配
  主导）。A/B 发现并消除了两处回退：AES-GCM 改走新的通用 AEAD 接口（+3%；现在重新有自己的直接分支，
  f8 与 SEED 移到函数外）；SEED-GCM 与 AES-GCM 共用 `Ghash::update_padded` / `finish`，改变了它们的
  内联（1200 字节 AES-GCM unprotect +2.4%；SEED-GCM 现在使用独立的、不内联的 `portable_ghash`）。

## 影响

- `Profile` 与 `Profile::ALL` 再次扩充（内部层级；`Profile` 是 `#[non_exhaustive]`）。`is_aead` 覆盖
  SEED-CCM 与 SEED-GCM，因此它们的 `rtcp_tag_len` 返回各自的标签长度而不是 16。原有配置的行为完全
  不变。
- SEED 只有软件实现，比有指令的 AES 慢一个数量级；SEED-CCM 尤其如此，它的 CBC-MAC 一次只能处理一个
  分组。对 SIP/VoIP 的速率足够，不适合大流量。
- `akio-crypto` 有了第二个分组密码和第一个 CCM；CCM 代码是泛型的，将来某个协议需要 AES-CCM 时可以
  复用。
