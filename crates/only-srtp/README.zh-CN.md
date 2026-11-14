# only-srtp

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 SRTP 与 SRTCP（RFC 3711、RFC 7714），构建在
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
- `Profile` 提供 `key_len`、`salt_len`、`rtp_tag_len`、`rtcp_tag_len`、`keying_material_len`
  以及 IANA 编号（`id` / `from_id`）。

## 覆盖范围

- 保护配置：`SRTP_AES128_CM_HMAC_SHA1_80`、`SRTP_AES128_CM_HMAC_SHA1_32`（SRTCP 仍用 80 位标签，
  RFC 5764 §4.1.2）、`SRTP_AEAD_AES_128_GCM`、`SRTP_AEAD_AES_256_GCM`（RFC 7714）。
- 密钥派生：AES-CM PRF，密钥派生率为 0（RFC 3711 §4.3；256 位密钥按 RFC 6188）。
- 重放窗口默认 64 个包，最大 32768（`with_replay_window`）；每个方向最多 1024 个 SSRC
  （`with_max_ssrcs`），超出时淘汰最久未用的。

未实现：MKI、非零密钥派生率与重新协商密钥、NULL 加密、AES-192/256-CM 配置、加密头部扩展
（RFC 6904）、cryptex（RFC 9335）。

## 测试

- RFC 3711 附录 B.2（AES-CM 密钥流）与 B.3（密钥派生）向量；RFC 7714 §16-17 中
  AEAD_AES_128_GCM 与 AEAD_AES_256_GCM 的 RTP 和 SRTCP 向量（加密与仅认证）。
- 与 pion/srtp v3.1.3 交叉验证：四种配置下带 CSRC、头部扩展和填充、跨越序列号回绕的 RTP 包以及
  SRTCP，双向逐字节一致。
- 窗口内外的重放与乱序、回绕附近乱序及第二次回绕、逐字节篡改、截断、错误密钥、SSRC 淘汰。
- 模糊测试：`fuzz/` 中的 `srtp_unprotect` 目标（任意输入经过每种配置的 unprotect，以及
  protect / unprotect 往返）；`fuzzing::tests` 在 stable 上回放其语料。
