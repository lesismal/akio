# ADR-186：供嵌入它的服务器使用的 akio-turn

[English](186-turn-embedding-server.md) | 简体中文

状态：已采纳（2026-11-27）。akit 的 A256。

## 背景

akit 的 TURN 角色（`webrtc.turn`）运行 akio-turn 的 `TurnServer`，使用的是 fit 的角色交给 pion/fib TURN
服务器的那些设置。其中三项在 akio-turn 中没有对应：`port_min`..`port_max`，中继套接字绑定的端口范围（服务器
前面的防火墙开放的范围；fit-examples 的 `webrtc-turn` 设为 49152-49999）；`nonce_secret`，生成 nonce 的密钥，
同一负载均衡器后面的多台服务器共用它，使每台都接受其他服务器发出的 nonce；`max_stream_message`，TCP 或 TLS
客户端可以发送的最大消息，它限制了连接为尚未完整的消息保留的字节（fit 默认 8 KiB）。akio-turn 把每个中继绑定在
`relay_ip` 的 0 端口上，用每台服务器自己的随机字节作为 nonce 密钥、以服务器启动时刻为起点计算有效期，并接受
最长 64 KiB 的流消息。akit 拒绝端口范围，并对另外两项给出“未生效”的警告。

## 决定

1. **`TurnConfig::relay_ports: Option<(u16, u16)>`**（`relay_ports(min, max)`，顺序不限，0 端口从不在内；
   默认 `None`，由内核选择端口）。`TurnServer` 绑定 0 端口的中继时，与 fib 一样从范围内一个随机端口开始依次
   尝试，使刚释放的端口（对端可能仍在向它发送）不会马上再分配出去：自己的中继占用的端口不经系统调用即被跳过
   （查中继表）；其他套接字占用的端口在绑定以 `AddrInUse` 失败时跳过（UDP 中继不设 `SO_REUSEPORT`，内核会如实
   报告）。其他错误结束查找（无法绑定的地址在每个端口上都会失败）。范围用尽是环境的 `open_relay` 的错误，核心
   以 508 应答，与此前绑定失败时相同。指定端口的中继（`EVEN-PORT` 在偶数端口之上预留的奇数端口）必须在范围内。
   `EVEN-PORT` 仍会多次尝试以得到偶数端口，每次都从范围中取。TCP 分配（RFC 6062）的监听套接字也使用该范围；
   它们设了 `SO_REUSEPORT`（到对端的连接从中继地址发出），这会让监听与另一个同样设了该选项的套接字共享端口，
   因此每个端口先用不带该选项的绑定探测一次。两种地址族使用同一个范围。
2. **`TurnConfig::nonce_secret: Option<Vec<u8>>`**（`nonce_secret(&[u8])`）。nonce 密钥由它派生（以固定标签
   对密钥做 HMAC-SHA-256），未设置时仍为随机。要让服务器互相接受对方的 nonce，nonce 就不能再依赖具体的服务器：
   其有效期现在以 UNIX 秒表示（服务器启动时的挂钟秒数加上此后的单调时间，因此启动后的时钟跳变不会影响它），
   校验时使用同一时钟。格式不变（16 位十六进制的有效期，16 位的 HMAC-SHA-1，覆盖有效期与客户端地址）；各服务器
   的时钟需要在几秒内一致。`Debug` 不显示该密钥。
3. **`TurnConfig::max_stream_message: usize`**（默认 `framing::MAX_FRAME`，即 TURN 能承载的任何消息，不设置时
   行为不变）。`framing::FrameReader::with_max(n)` 一旦读到消息头，若其声明的长度超过 `n` 字节（含填充），就以
   新增的 `FrameError::TooLong` 拒绝，因此读取器最多保留 `n` 字节；流接入器的读取器使用该设置，读取器出错的
   连接被关闭，与非 TURN 的流相同。akio-turn 不会抬高过小的值：akit 像 fit 一样检查它接受的下限（2048）。

## 影响

- akit 在成员配置的范围内绑定中继，并去掉其拒绝与两条警告。
- 设置范围后，每次 Allocate 对被其他套接字占用的每个端口付出一次绑定，范围用尽时最多为范围大小；被服务器
  自己的中继占用的端口只需一次哈希查找。
- 旧版服务器的 nonce（有效期从其启动时刻算起）会被视为早已过期：持有它的客户端收到一次 438 和新的 nonce，
  与任何一次重启之后相同。
