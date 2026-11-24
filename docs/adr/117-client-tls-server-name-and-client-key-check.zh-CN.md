# ADR-117：HTTP/1 客户端的 TLS 服务器名，以及构建时检查客户端证书的私钥

[English](117-client-tls-server-name-and-client-key-check.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

akit 的迭代 I54 实现 fit 的上游 TLS 字段：`tls_server_name`（校验上游证书所用、并在 SNI 中发送的
名字，代替每个地址的主机名）、`tls_ca_file` 以及客户端证书（`tls_cert_file`、`tls_key_file`）。
`h2` 上游由 akio-http 的 `H2Client` 拨号，它本就把 TLS 名字与所连接的主机分开传入；但在 ALPN 中选择
HTTP/1.1 的服务器，以及这类地址的健康探测，走的是 akio-http 的 `Client`。akit 据此提出两项请求
（A108、A109），对照 akio main `c5cf4353`：

- **A108.** `Client` 以 `Tls::client(cfg, &key.host, ...)` 拨 `https://`：名字总是 URL 的主机名。
  经 `10.0.0.5:443` 访问、证书却写着 `app.internal` 的上游无法通过校验；URL 也不能改写成那个名字，
  因为连接就是发往 URL 的主机（`crates/akio-http/src/client.rs`，`Client::dial`）。
- **A109.** `ClientConfigBuilder::build` 解析了客户端证书的私钥，却没有像 `ServerConfigBuilder::build`
  那样与叶证书比对：不配套的证书和私钥也能构建出配置，直到每次服务器索要证书的握手才失败，离原因更远。
  fit（Go 的 `tls.LoadX509KeyPair`）在加载文件时就报告不匹配（`crates/akio-tls/src/config.rs`）。

约束：不用 unsafe，只增加 API，不触及热路径。

## 决定

- **A108：`Client::with_tls_server_name(name)`。** 客户端建立的每个 `https://` 连接都在 SNI 中发送
  `name`，并以它校验服务器证书，代替 URL 的主机名。连接仍按 URL 的主机和端口入池（名字属于客户端，
  对所有连接相同）。空名字恢复为 URL 的主机名。到 `https://` 代理本身的 TLS 仍用代理自己的名字。
- **A109：检查客户端证书的私钥。** `ClientConfigBuilder::build` 用服务端同样的 `certified_key`
  检查客户端证书链：链非空、叶证书可解析且带有该私钥的公钥；否则报
  `client certificate: private key does not match the certificate`。

否决的方案：

- **在 `akio_tls::ClientConfig` 中加服务器名**，覆盖每个连接所用的名字：`H2Client::connect` 和
  `Tls::client` 已经把名字作为参数，同一个值有两个来源，就得让每个调用者都知道哪个优先。
- **在 akit 中检查私钥**，用客户端的证书链临时构建一个 `ServerConfig`：可行，但每个使用客户端证书的
  人都得知道要这样做。

## 影响

- akit 的 I54 在 HTTP/2（`H2Client`）和 HTTP/1.1（`Client`）上都按 `tls_server_name` 校验上游，
  探测也一样；私钥与证书不匹配时在编译配置时报告。
- 代价：`Settings` 多一个 `Option<String>`，每次 TLS 拨号读一次。叶证书无法被 akio-x509 解析的客户端
  证书链现在在构建时被拒绝；以前是在握手时失败。
- 测试：`akio-http/tests/client.rs` 的 `https_with_a_tls_server_name`（按该名字校验通过，不设或设成
  别的名字则失败，按主机和端口复用连接，空名字恢复 URL 的主机名），在 epoll 和 io_uring 上；
  `akio-tls` `config_tests` 的 `bad_keys_and_errors_are_reported`（不是叶证书的客户端私钥、空的
  客户端证书链）。
