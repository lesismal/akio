# only-srtp

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 SRTP 与 SRTCP（RFC 3711、RFC 6188、RFC 6904、RFC 7714、RFC 9335），构建在
[`only-crypto`](../only-crypto) 之上，安全 Rust（`#![forbid(unsafe_code)]`），没有其他依赖。它是自研
WebRTC 协议栈的媒体加密层（密钥来自 DTLS-SRTP，见 [`only-dtls`](../only-dtls)）。这是内部 crate
（docs/api-stability.zh-CN.md）：API 跟随该协议栈的需要，可能在任何发布中变化。

## 使用 Context

`Context` 表示 SRTP 会话的一个方向，没有 I/O：传入数据包，得到数据包。发送方向用本端主密钥创建一个，
接收方向用对端主密钥再创建一个：

```rust,ignore
use only_srtp::{Context, Error, Profile};

let profile = Profile::from_id(srtp_profile_id).unwrap();     // 由 use_srtp 协商
let mut tx = Context::new(profile, &local_key, &local_salt)?;  // 来自 SrtpKeys::local(role)
let mut rx = Context::new(profile, &remote_key, &remote_salt)?
    .with_replay_window(1024);                                  // 带 NACK/RTX 的视频
let srtp = tx.protect_rtp(&rtp_packet)?;
let srtcp = tx.protect_rtcp(&compound_rtcp)?;
match rx.unprotect_rtp(&datagram) {
    Ok(rtp) => { /* 交付 */ }
    Err(Error::Replay) => { /* 重复包：静默丢弃 */ }
    Err(_) => { /* 伪造、损坏或不是 SRTP：丢弃 */ }
}
```

- `protect_rtp` 加密载荷（含填充）并追加认证标签；头部、CSRC 与头部扩展保持明文并参与认证。
  每个 SSRC 的 rollover counter 根据序列号跟踪。
- `unprotect_rtp` 估计包索引（RFC 3711 §3.3.1），拒绝重放，先校验标签再解密，成功后才更新重放窗口和
  rollover counter。
- `protect_rtcp` / `unprotect_rtcp` 对每个发送端 SSRC 使用 31 位 SRTCP 索引并设置 E 标志；收到
  E 标志为 0 的包只做认证。SRTCP 同样有重放保护。
- `protect_rtp_into` / `unprotect_rtp_into`（以及 RTCP 对应的方法）写入复用的缓冲区：每个包不分配。
- `Profile` 提供 `key_len`、`salt_len`、`rtp_tag_len`、`rtcp_tag_len`、`keying_material_len`、
  DTLS-SRTP 编号（`id` / `from_id`；AES-192/256-CM 为 `None`）以及 SDES crypto suite 名称
  （`sdes_name` / `from_sdes_name`）。

### MKI 与换钥

```rust,ignore
let mut rx = Context::new_with_mki(profile, &[1], &key1, &salt1)?; // MKI 来自 use_srtp / SDES
// 换钥：旧包排空之前，两个密钥下的包都接受。
rx.add_master_key(&[2], &key2, &salt2)?;
tx.add_master_key(&[2], &key2, &salt2)?;
tx.set_send_mki(&[2])?;
// ……之后
rx.set_send_mki(&[2])?; // 接收上下文的"发送"密钥只是它不能删除的那个
rx.remove_master_key(&[1]);
```

每个包都携带 MKI（HMAC 标签之前，AEAD 标签之后）；接收方据此选择密钥（否则为
`Error::UnknownMki`）。滚动计数器与重放窗口在密钥之间按 SSRC 保持。最多 16 个主密钥，MKI 长 1 到
255 字节。

### 头部加密

```rust,ignore
// RFC 9335 cryptex（a=cryptex）：加密 CSRC 与整个扩展体。
let tx = Context::new(profile, &key, &salt)?.with_cryptex(true);
// RFC 6904（a=extmap:N urn:ietf:params:rtp-hdrext:encrypt ...）：只加密所选元素的数据。
let tx = Context::new(profile, &key, &salt)?.with_encrypted_header_extensions(&[1, 3]);
```

启用 cryptex 后，带 CSRC 或扩展的包以 `0xC0DE` / `0xC2DE` 标记发出（只有 CSRC 时补一个空扩展）；
接收方解密这些包，也仍接受未使用 cryptex 的包。单字节 `0xBEDE` 与双字节 `0x1000` 以外的扩展不能使用
cryptex（`Error::Unsupported`）。RFC 6904 让 ID、长度与填充保持明文；AEAD 下密钥流为 AES-CM
（RFC 7714 §8.3）。

### 密钥派生率

`with_key_derivation_rate(2^n)`（n 不超过 24）按 RFC 3711 §4.3.1 每隔 2^n 个包序号重新派生会话密钥
（SRTP 与 SRTCP 各按自己的序号）；默认的 0 只派生一次。

## 覆盖范围

- 保护配置：`SRTP_AES128_CM_HMAC_SHA1_80`、`SRTP_AES128_CM_HMAC_SHA1_32`（SRTCP 仍用 80 位标签，
  RFC 5764 §4.1.2）、`SRTP_AEAD_AES_128_GCM`、`SRTP_AEAD_AES_256_GCM`（RFC 7714）、
  `AES_192_CM_HMAC_SHA1_80/32` 与 `AES_256_CM_HMAC_SHA1_80/32`（RFC 6188）、
  `SRTP_NULL_HMAC_SHA1_80/32`（只认证；SRTCP 的 E 标志为 0）。
- 密钥派生：AES-CM PRF（RFC 3711 §4.3；192 与 256 位密钥按 RFC 6188），支持任意密钥派生率；每个
  上下文最多 16 个主密钥的 MKI；RFC 6904 头部扩展加密；cryptex（RFC 9335）。
- 重放窗口默认 64 个包，最大 32768（`with_replay_window`）；每个方向最多 1024 个 SSRC
  （`with_max_ssrcs`），超出时淘汰最久未用的。

未实现：AES-f8 与 SEED 变换、RFC 4771 滚动计数器携带、SRTP 与 SRTCP 分别设置的密钥派生率。RFC 6904
在与 libsrtp 不同之处遵循 RFC（libsrtp 遇到扩展元素之间的填充时不推进密钥流；见 ADR-040）。
`only-webrtc` 尚未在 SDP 中协商 MKI、RFC 6904 或 cryptex。

## 测试

- RFC 3711 附录 B.2（AES-CM 密钥流）与 B.3（密钥派生）向量；RFC 7714 §16-17 中
  AEAD_AES_128_GCM 与 AEAD_AES_256_GCM 的 RTP 和 SRTCP 向量（加密与仅认证）。
- 与 pion/srtp v3.1.3 交叉验证：四种配置下带 CSRC、头部扩展和填充、跨越序列号回绕的 RTP 包以及
  SRTCP，双向逐字节一致。
- RFC 6188 §7（AES-192/256 密钥流与 PRF）、RFC 6904 附录 A（头部密钥与加密后的头部扩展）、
  RFC 9335 附录 A（全部 12 个 cryptex 包，AES-CM 与 GCM）。
- 与 libsrtp 交叉验证（main 分支，`testdata/libsrtp.txt` 由 `tools/interop/srtp` 生成）：230 个包，
  覆盖每种配置、无 MKI 与两个 MKI 密钥中途切换、单字节与双字节扩展的 RFC 6904、带与不带 CSRC 的
  cryptex，RTP 与 SRTCP，逐字节一致。
- 窗口内外的重放与乱序、回绕附近乱序及第二次回绕、逐字节篡改、截断、错误密钥、SSRC 淘汰；在途包下的
  换钥、伪造与未知 MKI、跨密钥块乱序的密钥派生率、配置错误、缓冲区复用。
- 模糊测试：`fuzz/` 中的 `srtp_unprotect`（任意输入经过每种配置的 unprotect，以及 protect /
  unprotect 往返）与 `srtp_features`（MKI、头部扩展加密、cryptex、密钥派生率）目标；
  `fuzzing::tests` 在 stable 上回放它们的语料。
- 基准：`cargo run --release -p only-srtp --example srtp_bench`。
