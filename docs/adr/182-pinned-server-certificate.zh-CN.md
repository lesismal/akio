# ADR-182：akio-tls 客户端的固定服务端证书

[English](182-pinned-server-certificate.md) | 简体中文

状态：已采纳（2026-11-27）。akit 的 A235。

## 背景

fit 的隧道和 LLM 网格在握手中按 SHA-256 检查 hub（或监听端）的自签名证书，代替证书链和名称检查
（`certpin.Pinned`：在 `InsecureSkipVerify` 下使用 Go 的 `VerifyPeerCertificate`）：不匹配的证书
使握手失败。akio-tls 的客户端要么按根证书验证证书链和名称，要么什么也不验证（`insecure_skip_verify`，
它仍用叶子证书的公钥检查服务端的握手签名）。因此 akit 让握手在 `insecure_skip_verify` 下完成，用
定时器轮询 `tls_info` 直到握手结束，再把叶子证书与固定值比较后才启动链路：这是可靠的（签名证明了
私钥），但它是轮询，而且本应失败的握手成功了。

## 决定

1. **`ClientConfigBuilder::pin_sha256(Vec<[u8; 32]>)`**：服务端叶子证书（其 DER）的 SHA-256 必须
   是其中之一。摘要与每个固定值做常数时间比较（`akio_crypto::ct_eq`，遍历列表时不提前退出），因此
   耗时既不透露证书与某个固定值有多接近，也不透露匹配的是哪一个。
2. **固定值代替证书链、名称和有效期检查**，与 Go 在 `InsecureSkipVerify` 下的
   `VerifyPeerCertificate` 一样：不看根证书、服务端名称（仍作为 SNI 发送）和有效期，也不应用 OCSP
   与 CRL 策略。不匹配时握手以 `bad_certificate` 失败。它也优先于 `insecure_skip_verify`：两者都设置
   的配置检查固定值。
3. **叶子证书的公钥仍要为握手签名。** 叶子证书按 `insecure_skip_verify` 的方式解析（其密钥用途必须
   允许签名），其公钥验证 CertificateVerify（TLS 1.3）或 ServerKeyExchange（TLS 1.2），因此持有证书
   而没有私钥的服务端会失败（`decrypt_error`）。
4. **客户端状态机中只有一处**，即接收服务端 Certificate 的地方，TLS 1.3 与 1.2 共用；QUIC 客户端
   运行同一个状态机，因此由固定配置得到的 `akio_quic::client_config_from` 同样固定。HTTP、HTTP/2、
   WebSocket 和 gRPC 客户端使用同一个 `ClientConfig`。
5. **空列表是错误**，在 `build` 时报告，而不是得到一个什么都不接受或什么都接受的配置。

## 影响

- akit 隧道的 TLS 与 QUIC 链路，以及 LLM 网格的 `wss://` 链路，把固定值交给客户端配置并立即启动
  链路；它的 `when_handshaken` 轮询被去掉。
- 开销：固定配置的每次完整握手对叶子证书做一次 SHA-256；除此之外没有。恢复的会话不再检查（其票据
  来自同一配置的固定握手，而该配置有自己的会话缓存）。
- 测试：akio-tls 的 `pinned_server_certificate`（TLS 1.3 与 1.2：无根证书、任意名称，多个固定值之一，
  已过期的证书，即使设置了 `insecure_skip_verify` 或根证书本会接受也不匹配，空列表被拒绝）和
  `pinned_certificate_without_its_key_fails`（把固定的证书拼接进另一个服务端的 TLS 1.2 握手消息：
  固定值匹配，签名不匹配）；akio 的 `tests/tls.rs`（经由引擎）和 akio-quic 的 `tests/echo.rs`（经由
  QUIC）。
- 未做：基于 DTLS 的 TURN（akio-webrtc 的中继客户端）用根证书构造其 DTLS 验证器并忽略固定值，因此
  在那里固定配置按其根证书验证（没有根证书时失败）。
