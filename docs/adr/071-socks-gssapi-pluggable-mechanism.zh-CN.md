# ADR-071：机制由应用提供的 SOCKS5 GSS-API 认证

[English](071-socks-gssapi-pluggable-mechanism.md) | 简体中文

状态：已接受（2026-11-21）

## 背景

RFC 1928 规定 GSS-API（方法 `0x01`，RFC 1961）是 SOCKS5 实现“必须”支持的认证方法；only-socks 此前没有
（DEV-PLAN：“未做：GSSAPI”）。实际上 GSS-API 就是 Kerberos（Dante 或 Windows 代理后面的企业网络）。

RFC 1961 有三部分：上下文建立（`MTYP` 1 的令牌，直到双方都完成）、保护级别协商（`MTYP` 2：一个字节，用
不带机密性的 `GSS_Wrap` 封装；级别 1 完整性、2 机密性、3 选择性；Dante 另加 0，即“clear”），以及级别
高于 0 时对之后一切内容的逐消息保护（携带 `GSS_Wrap` 令牌的 `MTYP` 3 消息：SOCKS 请求、应答与转发的数据）。

约束：

- 所有运行时依赖都是自研的（ADR-005），`unsafe` 只在 only-sys 与后端中。链接 `libgssapi_krb5` /
  Heimdal / SSPI 意味着引入 C 库与 FFI。
- 完全自研 Kerberos 不现实：协议只是其中一部分（KDC 交互、按磁盘格式存放的票据缓存与 keytab、各种
  enctype、PAC、跨域、DNS 规范化、凭据委派），而部署依赖系统的配置（`krb5.conf`、`KRB5CCNAME`、
  `KRB5_KTNAME`、`kinit`、SSSD）。任何重新实现都会恰好在要紧之处与站点的 Kerberos 不一致。
- 规则 1（docs/rules.zh-CN.md）：任何东西都不能阻塞 I/O 线程。`GSS_Init_sec_context` 可能阻塞：没有服务
  票据的 Kerberos initiator 会向 KDC 申请；acceptor 可能从磁盘读取 keytab 与重放缓存。

## 决定

### 1. 机制由应用提供：`GssContext`

`only_socks::gssapi::GssContext`（定义在 `only_ws::gss`，即 sans-io 客户端握手所在处，再重新导出）表示
一个安全上下文：

- `step(&mut self, token) -> io::Result<GssStep>`（`GSS_Init_sec_context` /
  `GSS_Accept_sec_context`；`GssStep::Continue(token)` 或 `GssStep::Complete(token)`）；
- `wrap(&mut self, confidential, msg)` / `unwrap(&mut self, token)`（`GSS_Wrap` / `GSS_Unwrap`）；
- `peer_name(&self)`（acceptor 看到的客户端主体名）。

它必须是 `Send`（建立步骤会把它移到工作线程上）。应用在自己选择的 GSS-API 绑定之上实现它；only-socks
在它周围执行 RFC 1961。

### 2. 建立步骤不在 I/O 线程上执行

- 服务端：每一步在逻辑池中执行（`Conn::spawn_blocking`）；会话缓存期间到达的数据（一个 64 KiB 令牌再多
  一点，而不是 4 KiB），步骤完成后继续。工厂（`Fn() -> io::Result<Box<dyn GssContext>>`）也在那里执行。
- 客户端：握手是 tunnel transport 内部的 sans-io 实现。`Handshake::feed` 不直接调用上下文，而是排入一个
  `GssJob`；tunnel 在一个短命的辅助线程（`only-socks-gss`）中执行它，并通过连接的 `TransportWaker`
  （ADR-062）恢复。带双向认证的 Kerberos 只有两步，所以每个隧道最多两个线程，只发生一次。阻塞辅助函数
  直接内联执行这些步骤（它们本来就阻塞）。工厂会拿到代理的主机名，用来构造服务名（按 RFC 1961 惯例与
  Dante 的默认值是 `rcmd@host`）。
- `wrap` / `unwrap` 是本地计算，与 TLS 记录保护一样，在 I/O 线程上逐消息执行。

### 3. 以 transport 实现逐消息保护：`GssLayer`

`GssLayer` 实现 `only::Transport`：把 `MTYP` 3 消息（可跨多次读取）解封为明文，把要发送的内容按每条最多
32 KiB 明文封装（这样在任何机制开销下令牌都放得进 16 位长度）。`ConnInner::send` 在连接的锁内 seal，所以
无论从哪个线程发送，封装（以及机制的序列号）都遵循发送顺序：从上游的 I/O 线程、BIND 线程或逻辑池发出的
应答依然有序。

- 服务端：GSS-API 服务端在每个连接上安装一个直通的 `GssLayer`。协商出的保护级别高于 none 时，会话通过
  `Conn::with_transport` 拿到它、向下转型并激活，同时交出协商消息之后已读到的字节（它们以直通方式到达，
  仍是封装状态）。从此会话与转发看到的是明文，每次发送都被封装。放在 `Tls::server` 里的服务端没有这一层
  （transport 是 TLS）：这类客户端在此时被关闭。
- 客户端：带保护的握手完成时，tunnel 把内层 transport（到目标的 TLS，若有）替换为套在其外的 `GssLayer`，
  封装内层 transport 已经 seal 的数据，并把代理放在应答同一条消息里的隧道字节交给内层。

### 4. 策略

- 级别 `Protection::{None, Integrity, Confidentiality}`（0、1、2；客户端的 3 视为完整性，即每条消息至少
  得到的保护）。服务端把客户端请求的级别限制在配置的范围内后授予（`Socks::gssapi(factory, min..=max)`）；
  客户端请求自己的级别并拒绝更低的级别（`SocksClient::gssapi(factory, level)`）。
- GSS-API 服务端关闭 SOCKS4，不再接受“无认证”；同时设置 `Socks::auth` 时两种方法都可以。客户端提供
  GSS-API（设置了凭据时再加用户名/密码），从不提供“无认证”，因此对端无法降级。
- 级别高于 none 时拒绝 `UDP ASSOCIATE`（RFC 1961 要封装每个数据报；转发 socket 不共享控制连接的上下文，
  而 Kerberos 的序列检查也不适合乱序的数据报）：服务端回复 7，客户端在任何级别都返回 `Unsupported`。
- 客户端的阻塞辅助函数返回 `TcpStream`：它们拒绝高于 none 的保护，代理授予的级别高于请求时也拒绝。
- 受保护的隧道不走 `sockmap` 快速路径（内核无法封装）。
- 失败遵循 RFC 1961：失败的步骤或错误的令牌以 `VER 1, MTYP 0xff` 回应并关闭；客户端报告拒绝
  （`ProxyRefused`，407）。

### 5. 在 workspace 不含 GSS-API 库的情况下验证

- 一个玩具机制（`only_ws::gss::toy`，`#[doc(hidden)]`：带密钥的校验和与 XOR，故意不安全）驱动单元测试与
  引擎测试：所有级别、双向 1 MiB、BIND、受保护隧道内到目标的 TLS、拒绝、访问钩子看到的用户、手工构造的
  线格式。
- `tools/interop/socks/gssapi.sh`：Docker 中的 KDC（MIT krb5）；机制是仅用于测试的 Python 垫片
  （`gss_shim.py`，基于 `python3-gssapi`），由 `socks-gss-interop` 示例通过管道适配为 `GssContext`。
  only-socks 的客户端与服务端、用 Debian 源码包 `--with-gssapi` 重新编译的 Dante（打包的版本以及 Alpine 的
  都不含 GSS-API），以及一个先在 Dante 上验证过的独立 Python RFC 1961 客户端：所有级别 15/15。Debian 12
  的 curl 7.88 无法参与：它的 SOCKS 状态机在部分读取后恢复时会重置 `allow_gssapi`，因此对任何服务端都失败。

## 后果

- 有 Kerberos 的应用只需在自己的 GSS-API 绑定之上写一个小适配器，就能与 Dante 及其他 RFC 1961 客户端
  互通；only-socks 依旧没有 C 依赖与 FFI。
- 不使用 GSS-API 的服务端与客户端没有任何变化：不安装 transport，转发与隧道的数据路径不变（不需要基准
  测试）。
- 每个建立步骤花费一个逻辑池任务（服务端）或一次线程创建（客户端）：对握手而言没有问题，并且让 KDC 的延迟
  远离 I/O 线程。
- 未做：带保护的 UDP ASSOCIATE；HTTP 与 WebSocket 客户端的 `socks5://` 代理使用 GSS-API（握手支持，但
  代理 URL 无法指定机制）。
