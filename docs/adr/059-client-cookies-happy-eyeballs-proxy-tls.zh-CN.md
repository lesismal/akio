# ADR-059：客户端的 cookie、Happy Eyeballs、DNS 缓存与到代理的 TLS；SOCKS 分片与 TLS

[English](059-client-cookies-happy-eyeballs-proxy-tls.md) | 简体中文

状态：已采纳（2026-11-20）

## 背景

ADR-010 为 HTTP/1、HTTP/2 与 WebSocket 客户端提供了重定向、超时、在调用线程之外解析域名、系统根证书
与 HTTP 代理，并列出了未做的部分：cookie 容器、TLS 与 SOCKS 代理、PAC、Happy Eyeballs、DNS 缓存、
macOS 信任设置与 Windows 证书库。ADR-019 随后加入 SOCKS 代理（`socks5://`、`socks5h://`、
`socks4://`、`socks4a://` 以及 `ALL_PROXY`）与 SOCKS 客户端，未做 GSSAPI、发送分片 UDP 数据报和到
代理的 TLS。本 ADR 补齐其余各项，PAC（需要 JavaScript 引擎）、Windows 证书库（Windows 不是目标平台）
与 GSSAPI 除外。

约束：不引入新的第三方依赖（ADR-005）；每张表、每个队列都有安全的上限（ADR-009、`docs/rules.zh-CN.md`）；
不在 I/O 线程上阻塞；公共 API 只有新增。

## 决策

1. **cookie 容器**（`only_http::cookie`、`Client::with_cookies`）。按 RFC 6265 存取，并采用浏览器遵循
   的 RFC 6265bis 规则：Domain（没有时只发回该主机；domain-match；是公共后缀的 Domain 被拒绝，除非
   它就是该主机本身）、Path（默认路径、path-match）、Secure（只能由 `https://` 设置、只发往
   `https://`；`http://` 响应不能覆盖或遮蔽 Secure cookie）、`__Secure-` / `__Host-` 前缀、HttpOnly
   （保存并报告：这个标志针对脚本）、SameSite（`None` 需要 Secure；经由离开第一个请求所在站点的重定向
   链到达的请求不带 `Strict` cookie，`Lax` cookie 只在安全方法下携带；没有 SameSite 的 cookie 不受
   限制，因为 HTTP 客户端没有“默认 Lax”的导航模型）、Max-Age 优先于 Expires、RFC 6265 的宽松日期
   解析、过期时间最多 400 天。公共后缀：单标签与 IP 地址总是算（IP 主机只接受只发回本主机的
   cookie）；完整列表（Public Suffix List）可以通过 `CookieJar::public_suffixes` 接入，不内置（那是一张
   需要持续更新的 200 KB 表）。上限（`CookieLimits`，RFC 6265 §6.1 的最低要求）：名字加值 4096 字节、
   每个域 50 个、总共 3000 个；超出时先淘汰已过期的，再淘汰最久未用的。客户端保存每个响应（包括重定向
   链中的每一跳）的 `Set-Cookie`，每个请求只发一个 `Cookie` 字段（请求自带的值在前，容器的在后）。
   不挂容器时不生效。
2. **DNS 缓存**（`only::dns`）。`getaddrinfo` 不返回 TTL，因此应答保存一个固定的、可配置的时间
   （`CacheConfig::ttl`，30 秒），最多 `max_entries` 个名字（1024；先淘汰已过期的，再淘汰最早过期的）；
   失败不缓存，除非设置 `negative_ttl`。与解析线程池一样是进程级的；`set_cache`、`cache_config`、
   `clear_cache`；`CacheConfig::disabled()` 关闭缓存。同一名字的并发查询共用一次 `getaddrinfo`。缓存的
   应答与 IP 字面量在调用线程上直接给出。默认 30 秒限定了陈旧程度；名字变化更快的部署应设更小的 TTL。
3. **Happy Eyeballs v2**（`only::dns::HappyEyeballs`，RFC 8305）。地址按协议族交替排列，从系统首选
   地址的协议族开始（§4）；每 250 毫秒（`attempt_delay`，限制在 10 毫秒到 2 秒之间）或前一次尝试失败
   时立即开始新的尝试（§5）；先建立的连接胜出，其余连接在发送任何字节之前关闭。竞速在一个专用线程
   （`only-connect`，按需启动，空闲 10 秒后退出）上进行，它用 `only_sys::Poller` 等待非阻塞连接；同时
   最多 `MAX_RACES`（256）场竞速，更多的照旧由 engine 逐个地址拨号；每场最多 16 个地址；每次尝试受
   `connect_timeout`（10 秒）限制。胜出的套接字通过 `Engine::adopt_tcp` 交给 engine，acceptor 看到的就是
   普通的拨号连接，运行在 I/O 线程上；只有一个地址时由 engine 直接拨号（路径不变）。HTTP/1 客户端
   （`ClientOptions::happy_eyeballs`）、WebSocket 客户端（`DialOptions::happy_eyeballs`）和新增的
   `H2Client::connect(engine, host, port, ...)` 都这样拨号。RFC 8305 中未做：分开的 AAAA 与 A 查询及
   50 毫秒的解析延迟（§3）：`getaddrinfo` 一起返回两个协议族。`only::dns::black_hole`（隐藏）让竞速器
   把某个地址当作黑洞，用于会应答已满接受队列的系统（macOS）上的测试；Linux 上的测试用真实的黑洞。
4. **到代理的 TLS。** `Proxy`（因而 `from_env`）支持 `https://` 代理 URL（端口 443）：代理的证书用
   客户端的 TLS 配置（默认系统根证书）按其主机名校验。`https://` 目标是 TLS 套 TLS：隧道的 `CONNECT`
   在与代理的会话中，目标的会话在隧道中；`http://` 目标以绝对形式在与代理的会话中发送。实现为分层
   传输（`only_ws::proxy::Layered`，隐藏）：外层传输（到代理的 TLS）承载内层（隧道及其中到目标的 TLS）
   写出的字节；隧道打开前外层的失败按隧道失败报告。`Connect::over_tls`（隐藏）可以加在任何隧道上。
5. **SOCKS**（`only-socks`）。`SocksClient::tls(cfg, server_name)`：engine 方法（`dial`、`bind` 以及
   `udp_associate` 的控制连接；数据报按 RFC 1928 仍是明文 UDP）经 TLS 连接代理；阻塞辅助函数返回
   `TcpStream`，因此以 `Unsupported` 拒绝；隧道打开前的 TLS 失败交给 `on_error`。发送分片（RFC 1928
   §7 `FRAG`）：`UdpAssociation::send_fragmented` / `BlockingUdp::send_fragmented` 把数据报切成每片
   最多 `max` 字节（位置 1、2、……，最后一片置高位；放得下时整个发送；超过 127 片返回 `InvalidInput`），
   服务端的 `Socks::udp_fragment_size(Some(n))` 把来自远端主机的数据报按 `n` 字节分片发给客户端（小于
   516 时提高到 516，使任何数据报都能放进 127 片；默认关闭，因为不是每个客户端都能重组）。客户端的
   UDP 关联在代理的某个地址不可达时改试下一个地址，与 `dial` 一致。
6. **macOS 信任设置**（`RootCerts::system`）。`security trust-settings-export` 能在不弹出提示的情况下
   把用户、管理员与系统三个域的设置写成 XML 属性列表（在 macOS 开发主机 Darwin 27 上验证）；它不能写
   到管道，因此经一个私有临时目录读取，再由一个有界的小型 plist 解析器（16 层、8 MiB）解析。证书的
   结论取自第一个有结论的域（用户、管理员、系统依次），取该域中第一个适用于 TLS 服务器的约束（没有
   策略、`sslServer` 或 `basicX509`；不限定于某个应用或主机名）：TrustRoot / TrustAsRoot 保留，Deny
   去掉，Unspecified 继续往下看。根证书于是由系统根证书、System 钥匙串与登录钥匙串按这些结论过滤
   而得；没有结论的证书只有是系统根证书时才算根证书。这也去掉了 System 钥匙串中没人标记为信任、而
   此前版本当作根证书的证书（macOS 本身不信任它们）。所有域都读不到时沿用原来的行为。
7. **API**，只有新增：`only::dns::{CacheConfig, set_cache, cache_config, clear_cache,
   HappyEyeballs, interleave, DEFAULT_CACHE_TTL, DEFAULT_CACHE_ENTRIES, ATTEMPT_DELAY,
   CONNECT_TIMEOUT, MAX_RACES, MAX_RACE_ADDRS}`；`only_http::cookie::{CookieJar, Cookie,
   CookieLimits, SameSite, MAX_AGE_CAP}`、`Client::{with_cookies, cookies}`、
   `ClientOptions::happy_eyeballs`、`H2Client::connect`；`only_ws::client::DialOptions::
   happy_eyeballs`；`only_socks::{SocksClient::tls, UdpAssociation::send_fragmented,
   BlockingUdp::send_fragmented, Socks::udp_fragment_size}`。`ClientOptions` 与 `DialOptions` 是
   `#[non_exhaustive]`，新字段不破坏任何调用方。隐藏项：`ProxyServer::tls`、`Connect::over_tls`、
   `Layered`、`dns::black_hole`。

## 后果

- 测试：cookie 单元测试（日期、解析、Domain / Path / Secure / 前缀 / SameSite 规则、过期、替换、上限
  与淘汰）以及跨重定向链的集成测试（链中途设置的 cookie 在下一跳发送、跨站链不带 Strict cookie，POST
  时也不带 Lax cookie、IP 主机的 cookie 不发往别的主机、请求自带的 Cookie 字段保持在前、Max-Age=0
  删除、不挂容器时什么也不做）；`only::dns` 缓存（缓存后直接应答、淘汰与过期）；engine 上的 Happy
  Eyeballs（在尝试间隔后从 IPv6 黑洞回退、更短的间隔、所有地址都超时、被拒绝的地址立即换下一个、
  超过竞速器容量的竞速、先解析再竞速）；HTTP 客户端经 `https://` 代理（https 为 TLS 套 TLS、http 为
  绝对形式、keep-alive、按名字校验代理证书）与 WebSocket 客户端（ws 与 wss）经本地测试代理前面的
  TLS 前端；SOCKS 双向分片（直接观察服务端发出的分片、服务端重组客户端的分片、客户端重组回显，阻塞与
  engine 两种方式）以及 `SocksClient::tls` 对 `Tls::server` 后面的 only-socks（CONNECT、UDP
  ASSOCIATE、证书名字不符、阻塞方式被拒）；信任设置的结论与域的优先级，以及 macOS 上真实的钥匙串。
- fuzz 目标 `cookie_parse`（Set-Cookie 与日期、容器的存储规则与上限）与 `tls_trust_plist`（plist
  解析器），种子语料由单元测试回放。
- Linux（gpu51，x86_64）：only、only-http、only-ws、only-socks 与 only-tls 在 epoll 与 io_uring 上
  通过；Happy Eyeballs 测试在那里遇到真实的 IPv6 黑洞（接受队列满时丢弃 SYN）。macOS：同样的 crate
  通过（`only-ws` 的 `large_and_fragmented_messages_and_limits` 在 debug 构建下于 main 上同样很慢，
  负载下需要 `ONLY_TEST_TIMEOUT_SCALE`）。gpu51 上各 fuzz 5 分钟：`cookie_parse` 420 万次，
  `tls_trust_plist` 630 万次，无发现。
- gpu51 上同轮 A/B（`quiet.sh`，CPU 2-9，7 轮交替，`examples/client-bench.rs`：HTTP/1 客户端 64 个
  keep-alive 请求循环对本地服务端）：为 main b22519ae 的 0.999 倍（27.00 万对 27.02 万请求/秒，各轮
  0.992-1.039 倍）：无退化。
- 代价：不挂容器的客户端对每个请求头多一次 `Option` 判断；`resolve` 查缓存时持有一个进程级锁（每个新
  连接一次，而不是每个请求）；一场竞速多一次经竞速线程的跳转，每次尝试多一次 poller 注册；`https://`
  代理让每个连接多一个 TLS 会话。
- 未做：PAC、Windows 证书库、GSSAPI（同上）；`H2Client` 与 WebSocket 握手的 cookie 容器（两者都可以
  发送取自 `CookieJar::header` 的 `Cookie` 头）；真实的 DNS TTL（需要自己的 DNS 客户端）；内置 Public
  Suffix List。
