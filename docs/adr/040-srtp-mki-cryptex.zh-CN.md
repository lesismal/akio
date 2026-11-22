# ADR-040：SRTP 的 MKI、密钥派生率、更多保护配置、头部扩展加密与 cryptex

[English](040-srtp-mki-cryptex.md) | 简体中文

状态：已采纳（2026-11-19）

## 背景

`akio-srtp` 覆盖了 WebRTC 目前协商的内容：四种 DTLS-SRTP 保护配置（AES-128-CM-HMAC-SHA1-80/32、
AEAD-AES-128/256-GCM），每个上下文一个主密钥，密钥派生率为 0，头部始终明文。它的 README 列出了缺失
项：主密钥标识（MKI）与换钥、非零密钥派生率、NULL 加密、AES-192/256-CM 配置（RFC 6188）、头部扩展
加密（RFC 6904）与 cryptex（RFC 9335）。`akio-dtls` 能解析 `use_srtp` 的 `srtp_mki` 字段，但拒绝
非空值。

cryptex 最重要：头部扩展（音量、MID、传输层序号）与 CSRC 会泄露谁在说话、发送方是什么应用；用
`a=cryptex` 协商的 cryptex 会把它们加密。MKI 与其他配置对 SIP/SDES 对端以及 DTLS-SRTP 换钥有用。参考
实现是 libsrtp（main 分支，支持 cryptex、MKI 与 RFC 6904，也是 libwebrtc 使用的实现）。

## 决定

1. **保护配置。** `Profile` 新增 `Aes192CmHmacSha1_80/32`、`Aes256CmHmacSha1_80/32`（RFC 6188：
   24/32 字节主密钥、14 字节盐、160 位 HMAC-SHA1 密钥、AES-192/256 CM PRF）与
   `NullHmacSha1_80/32`（RFC 5764 0x0005 / 0x0006：不加密，密钥派生仍用 16 字节主密钥与 14 字节盐，
   与 libsrtp 一样 SRTCP 发送时 E 标志清零）。`Profile` 改为 `#[non_exhaustive]`；`Profile::ALL`
   列出全部十种（四种 WebRTC 配置在前，顺序不变）。RFC 6188 的配置没有 DTLS-SRTP 编号，因此
   `Profile::id` 改为返回 `Option<u16>`（破坏性变更，内部层级）；`name` 给出 DTLS-SRTP 名称，没有时
   给出 SDES crypto suite 名称；`sdes_name` / `from_sdes_name` 对应 SDP 安全描述中的名称；`encrypts`
   区分 NULL 配置。
2. **MKI 与换钥**（RFC 3711 §3.1、§8.1）。`Context::new_with_mki(profile, mki, key, salt)`（1 到 255
   字节，即 DTLS 的上限）让每个包都携带 MKI：AES-CM / NULL 放在 HMAC 标签之前（不被认证），GCM 放在
   AEAD 标签之后（RFC 7714 §8.1、§9）。一个上下文最多持有 `MAX_MASTER_KEYS`（16）个 MKI 长度相同的
   主密钥：`add_master_key`、`set_send_mki`（`protect_*` 使用哪个）、`remove_master_key`（不能删除
   正在发送用的密钥）、`send_mki`、`mki_len`。`unprotect_*` 先按包里的 MKI 选密钥（都不匹配时为
   `Error::UnknownMki`）。滚动计数器、重放窗口与 SRTCP 序号在密钥之间按 SSRC 保持不变，因为 RFC 3711
   把它们放在加密上下文而不是密钥里。不带 MKI 的上下文（`Context::new`）行为不变。
3. **密钥派生率**（RFC 3711 §4.3.1）。`with_key_derivation_rate(rate)` 接受 0 或不超过 2^24 的 2 的幂
   （否则为 `Error::Config`），作用于所有主密钥：会话密钥以 `r = index DIV rate`（SRTP 为 48 位包序号，
   SRTCP 为 31 位 SRTCP 序号）右对齐异或到标签之后派生。每个主密钥按流保留最近一次 `r` 的会话密钥；
   其他 `r` 的包先派生（接收侧派生到临时变量，包认证通过后才替换缓存，伪造包无法把它挤掉）。派生率
   为 0 时不再派生，只多一次分支。
4. **RFC 6904 头部扩展加密。** `with_encrypted_header_extensions(&ids)`（单字节形式 ID 1-14，双字节
   形式 ID 1-255，由 `urn:ietf:params:rtp-hdrext:encrypt` 协商）用标签 6、7 派生头部密钥，以与载荷
   相同的 IV 生成 AES-CM 密钥流，只异或到所选元素的数据字节：元素头、填充与 4 字节扩展头保持明文，
   密钥流偏移就是扩展内的字节偏移。GCM 下密钥流为 AES-128/256-CM，12 字节头部盐补零到 14 字节
   （RFC 7714 §8.3，与 libsrtp 一致），加密后的扩展作为 AAD。加密在计算标签之前，解密在标签验证之后。
   元素越过扩展末尾为 `Error::Malformed`。NULL 配置不改动头部（RFC 6904 §3.2：密钥流全零）。交叉
   验证发现一处与 libsrtp 的差异：libsrtp 遇到元素之间的填充字节时不推进密钥流，而 RFC 6904 §3 让
   密钥流与掩码按扩展字节对齐；我们遵循 RFC，因此只有元素之间有填充的扩展两者结果不同（交叉验证向量
   里没有这种情况，`header_extension_encryption` 测试覆盖了它）。
5. **cryptex（RFC 9335）。** `with_cryptex(true)`：`protect_rtp` 对每个带 CSRC 或扩展的包加密 CSRC
   与整个扩展体，把扩展标记为 `0xC0DE` / `0xC2DE`；带 CSRC 而无扩展的包补一个空的 `0xC0DE` 扩展
   （§5.1，libsrtp 把这一步留给调用方）。在输出缓冲区里交换 CSRC 列表与扩展头，使 AAD（固定头与扩展头）
   与明文连续（§6.2，图 2），AES-CM 与 GCM 都如此，之后再换回。`0xBEDE` / `0x1000` 以外的扩展（带
   appbits 的双字节形式、非 RFC 8285 扩展）返回 `Error::Unsupported`，而不是让 CSRC 以明文发出。
   `unprotect_rtp` 解密标记为 `0xC0DE` / `0xC2DE` 的包，恢复 `0xBEDE` / `0x1000`，保留补上的空扩展
   （§5.2），并且仍接受未使用 cryptex 的包。cryptex 包不会同时使用 RFC 6904。NULL 配置收发都忽略 cryptex（没有可加密的内容）。
6. **无分配的变体。** `protect_rtp_into`、`unprotect_rtp_into`、`protect_rtcp_into`、
   `unprotect_rtcp_into` 写入调用方的缓冲区（先清空，出错时保持为空）；返回 `Vec` 的方法调用它们。
   每个包不再有其他分配（非零密钥派生率下每个包块重新派生一次会话密钥除外）：会话密钥经栈上数组派生，RFC 6904 密钥流在 272 字节的栈缓冲区里，cryptex 交换
   原地进行，未加密的 AEAD SRTCP 在输出缓冲区里构造 AAD，不再使用临时 `Vec`。
7. **新错误**（`Error` 不可穷举）：`Config`、`UnknownMki`、`Unsupported`。
8. **DTLS-SRTP MKI**（RFC 5764 §4.1.3）。`akio-dtls` 的 `Config::with_srtp_mki(mki)`（客户端：提供
   该 MKI；超过 255 字节会 panic）与 `Config::with_srtp_accept_mki(bool)`（服务端：回显客户端的
   MKI；默认关闭，不处理 MKI 的 SRTP 层照常工作）；`HandshakeInfo::srtp_mki` 是双方使用的 MKI（没有
   时为 `None`）。服务端回显了不同的非空 MKI 时，客户端以 illegal_parameter 终止握手；DTLS 1.2 的
   ServerHello 与 DTLS 1.3 的 EncryptedExtensions 都如此。
9. **尚未接入 akio-webrtc**：SDP offer/answer 中的 `a=cryptex`、RFC 6904 extmap 与 DTLS-SRTP MKI
   留作后续工作（另一个分支正在修改 akio-webrtc 的 SDP）。

## 验证

- 向量：RFC 3711 B.2/B.3、RFC 6188 §7（AES-192/256 密钥流与 PRF）、RFC 6904 A.1/A.2（头部密钥、
  头部扩展密文）、RFC 9335 附录 A（全部 12 个 cryptex 包，AES-CM 与 GCM）、原有的 RFC 7714；密钥
  派生率的 PRF 输入手工核对。
- 与 libsrtp 交叉验证（`testdata/libsrtp.txt`，由 `tools/interop/srtp/vec.c` 针对 libsrtp main
  052aa29 与 OpenSSL 3.0.13 生成）：230 个包，覆盖每种配置的无 MKI 与两个 MKI 密钥中途切换、单字节与
  双字节扩展的 RFC 6904、带与不带 CSRC（以及带 MKI）的 cryptex，RTP 与 SRTCP；protect 逐字节一致，
  unprotect 还原。
- 行为：两个密钥下都有在途包的换钥、伪造与未知 MKI、每种配置错误、派生率 16 下跨密钥块乱序与 SRTCP、
  cryptex 每个字节被篡改、缓冲区复用无重新分配；DTLS 1.2 与 1.3 的 MKI 协商（接受、拒绝、未提供、
  255 字节、无共同配置）。
- 模糊测试：新目标 `srtp_features`（按配置组合 MKI、头部扩展加密、cryptex、密钥派生率，往返校验），
  在 gpu51 上运行至少 10 分钟；`srtp_unprotect` 现在覆盖全部十种配置。
- gpu51 基准（`examples/srtp_bench.rs`，安静主机，与基线交替三轮）：已有配置的 unprotect 全部快 0-5 %，
  AES-CM protect 在 ±1.3 % 内，AEAD protect 在 1200 B 时在 ±0.3 % 内、160 B 时慢 1-2 %（约 2 ns）。
  过程中发现两点：每个包对 SSRC 表查找两次（旧代码里 LLVM 合并了两次 SipHash 计算，函数变大后哈希不再
  内联），现在只查一次；GCM 密钥嵌在会话结构里比放进 Box 每个小包多约 3 ns。数字见 CHANGELOG 条目。

## 影响

- 对 `akio-srtp` 使用者是破坏性变更（内部层级）：`Profile::id` 返回 `Option<u16>`，`Profile` 与
  `Profile::ALL` 变大。`akio-webrtc` 只用 `from_id`，不受影响。
- 一个 `Context` 现在可以跨越 DTLS 重新握手：以新 MKI 加入新密钥，切换发送，旧密钥的包排空后删除它。
