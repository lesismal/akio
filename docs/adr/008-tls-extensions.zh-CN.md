# ADR-008：TLS record_size_limit、证书压缩与 OCSP stapling

[English](008-tls-extensions.md) | 简体中文

状态：已接受（2026-11-16）

## 背景

`only-tls` 自研 TLS 1.2/1.3。浏览器和服务器常用的三个扩展此前缺失：record_size_limit（RFC 8449，受限设备限制自己接收的记录大小）、证书压缩（RFC 8879，缩小 TLS 1.3 握手）和 OCSP stapling（RFC 6066 `status_request`；TLS 1.3 见 RFC 8446 4.4.2.1 节）。每个扩展都需要配置项，装订的 OCSP 响应也要交给应用，因此公开 API 需要增加。

## 决定

1. **只增加构建器选项，不增加新类型。**
   - `ServerConfigBuilder::record_size_limit(u16)` 和 `ClientConfigBuilder::record_size_limit(u16)`：取值按 RFC 8449 的口径，64 到 16385（TLS 1.3 含内容类型字节；TLS 1.2 上限 16384），默认 16385，越界在 `build` 时报错。
   - `ServerConfigBuilder::certificate_compression(bool)` 和 `ClientConfigBuilder::certificate_compression(bool)`：服务端默认开启，客户端默认关闭。
   - `ServerConfigBuilder::ocsp_response(der)`（默认证书链）和 `sni_ocsp_response(name, der)`（某个 `sni_cert` 证书链）；`ClientConfigBuilder::ocsp_stapling(bool)`，默认关闭。
   - `TlsInfo::ocsp_response: Option<Vec<u8>>`（该结构体为 `#[non_exhaustive]`）。
2. **record_size_limit。** 客户端总是发送自己的值（默认 16385，即"支持该扩展，没有更小的限制"）；只要客户端发了，服务端就回以自己的值。之后双方写出的受保护记录按对方的限制切分，收到超过自己限制的受保护记录则报 `record_overflow`。明文记录不受限制。早期数据（0-RTT）遵循签发该票据的连接上的限制（随客户端票据保存）；服务端不按新的限制检查早期数据。QUIC 中既不发送也不应答。服务端默认应答，客户端的限制才有约束力，这正是该扩展的用途；客户端默认发送 16385 只多 6 字节，对没有限制的对端没有任何影响。
3. **证书压缩：仅 zlib。** zlib 由自研的 `only-deflate`（本来就是工作区里的 crate）提供；没有自研的 brotli 或 zstd，因此只提供和接受 zlib（算法 1）。仅用于 TLS 1.3，服务端证书和客户端证书都支持（分别在 ClientHello 和 CertificateRequest 中提供）。服务端对每条证书链只压缩一次并复用；压缩后不更小就不发送压缩形式。收到的消息最多解压到 128 KiB（握手消息上限），长度必须与声明的完全一致（否则 `bad_certificate`）；使用未提供的算法则报 `illegal_parameter`。**服务端默认开启**：压缩只按证书链付出一次代价，每次握手没有额外开销，不支持该扩展的客户端看不到任何变化。**客户端默认关闭**：每收到一条压缩的证书链就要解压一次，约 1–2 µs（only-deflate 每个流约有 1 µs 的固定开销），同批握手 A/B 测得约占内存中完整握手的 1%，而省下的字节对单张自签名证书只有几十字节、对 CA 证书链也只有几百字节。在意线路字节数的客户端可以开启。
4. **OCSP stapling：只传递，不验证。** 客户端请求时，服务端装订配置的 DER 响应（TLS 1.3：叶证书 `CertificateEntry` 的扩展；TLS 1.2：ServerHello 中的 `status_request` 加 `CertificateStatus` 消息），会话恢复时不发送。配置的响应只检查是否具有成功的 `OCSPResponse` 外层结构；按时刷新由调用方负责（构建新的配置）。客户端公开收到的响应，但**不**验证：`only-x509` 还没有 OCSP（签名、响应者、有效期、证书 ID），只做一半的检查会让人误以为得到了更多保护。客户端默认关闭（与 OpenSSL 相同），因为协议栈中没有任何部分会使用它。
5. **`only-tls` 依赖 `only-deflate`。** 两者都是自研且无第三方依赖，依赖策略（ADR-005，经自研替换阶段修订）不变。

## 影响

- ClientHello 增加 record_size_limit 扩展（6 字节；开启证书压缩时再加 compress_certificate 的 7 字节）；不认识它们的服务端会忽略（OpenSSL、Go、curl 和 tlsfuzzer 的测试均如此）。
- 对端声明较小的限制时，我们会写出更多、更小的记录；此时拒绝（实验性的）内核 TLS 卸载，因为内核总是写满记录。
- OCSP 验证、brotli/zstd、TLS 1.3 CertificateRequest 中客户端的 `status_request` 以及 `status_request_v2` 尚未实现；以后添加都是增量的。
