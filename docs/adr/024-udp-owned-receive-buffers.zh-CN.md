# ADR-024：UDP 接收缓冲区的所有权交付与带密钥的对端表

[English](024-udp-owned-receive-buffers.md) | 简体中文

状态：已采纳（2026-11-17）

## 背景

QUIC 数据路径优化（DEV-PLAN，M5）之后，一个收到的 QUIC 数据报仍要经过两次内存：UDP 循环把它
收进 `recvmmsg` 槽位（每批一块连续缓冲区），以 `&[u8]` 借给 handler，only-quic 再把它复制进池化
缓冲区，在原地解密，并与各帧的 `Bytes` 共享。`on_data(&[u8])` 做不到更好：槽位会被下一次
`recvmmsg` 复用，所以凡是要活过这次调用的数据都必须复制出来。UDP 循环的对端表
（`HashMap<SocketAddr, u64>`，每个数据报查一次）仍用 SipHash，此前 only-quic 的剖析显示它约占接收
线程的 2%。

## 决定

**接收 slab（`only_buf::slab`，`#[doc(hidden)]`）。** 一块堆分配，通过互不相交、带所有权的句柄
访问：`ChunkMut`（独占、可写的区间；`split_to`、`truncate`、`freeze`）、`Chunk`（共享、只读的区间；
`Clone` 只是引用计数加一）和 `SlabPool`（把整块 slab 作为 `ChunkMut` 交出；某块 slab 上的所有句柄在
任意线程释放之后复用它；有上限）。这是该 crate 唯一的 `unsafe`（`#![deny(unsafe_code)]`，仅此模块
放行）：内存只经由分配时的裸指针访问，从不经由指向整块 slab 的引用；模块不变式（存活的
`ChunkMut` 区间彼此不相交，且与存活的 `Chunk` 区间不相交）由构造方式保证：`ChunkMut` 只来自无人
引用的 slab（`Arc::get_mut`）或对另一个 `ChunkMut` 的切分，`Chunk` 只来自冻结一个 `ChunkMut`。
Miri（包括数据竞争检测下的跨线程释放）和一个“远端释放后复用”的 loom 模型覆盖这些代码。

**接收路径。** `only_sys::RecvBatch` 把每个槽位收进它自己那块 slab 的空闲尾部，slab 长度为两个
槽位（`2 × Config::read_buffer`）。数据报可以原地读取（`get`，同以前），也可以从 slab 上切下来
（`take`，返回 `ChunkMut`）；槽位继续收进 slab 余下的部分，剩余不足一个槽位时，再从本批的池里取
一块新的或已释放的 slab。小数据报因此排得很密：被保留的数据报只会占住它所在的 slab（最多
`2 × read_buffer`），而不是整批；保留大量数据报最多约占其大小的两倍。没有 `recvmmsg` 的循环
（macOS）用一块基于 slab 的缓冲区做同样的事。

**Handler 钩子。** `Handler` 增加两个隐藏项：`const OWNED_DATA: bool = false` 和
`fn on_data_owned(&mut self, c, data: only_buf::slab::ChunkMut)`（默认：`on_data(c, &data)`）。
epoll 后端的 UDP 循环（同时服务 io_uring 和 kqueue 的 UDP）对每个连接询问一次
（`DynHandler::wants_owned`），对设置了 `OWNED_DATA` 且没有传输层的 handler，把每个数据报（每个
GRO 分段）以所有权方式交出。其它 handler 与以前完全一样原地读取，没有引用计数。

**only-quic。** `Udp` 设置 `OWNED_DATA`。到达某个连接的数据报以 `PktBuf::Chunk` 进入（与池化的
`PktBuf::Vec` 并列的内部枚举）：在它自己的 slab 区间里去除头部保护并解密，随后冻结，各帧的
`Bytes` 是它的切片（`Bytes` 新增一个私有的 `Chunk` 表示，大小不变）。合并的包（握手阶段）仍像以前
一样复制进池化缓冲区；新连接的第一个数据报仍得到一份池化副本。

**带密钥的对端表。** only-quic 为 CID 和地址表引入的带密钥折叠乘法哈希（`KeyedHash`：每张表三个
随机字，每个字一次 64×64→128 位折叠乘法，最后一次带密钥的折叠）移到 `only_core::hash`
（`#[doc(hidden)]`），连同 `KeyedMap` / `KeyedSet`；UDP 循环的对端表（`SocketAddr` → 连接）改用
它。我方自己的 id 构成的表（绑定的 socket、被阻塞的对端）用 `IdHasher`。在对端可以选择键的地方
保留了抗 HashDoS 能力：密钥从不离开进程，进入每次乘法的两个操作数，且每张表不同。

## 考虑过的替代方案

- **继续复制（quinn 就是这样）**：quinn 把每个数据报从接收缓冲区复制进一个 `BytesMut`；本 ADR
  去掉的正是这次复制。
- **每批一块 slab，或每个槽位一整块 slab 且不切分**：一个被保留的数据报会占住整批
  （32 × 64 KiB）或一个 64 KiB 槽位而只为 1.2 KB 数据，内存最多是被保留数据的 50 倍。
- **先解密一批中的所有包再处理**：同一批的包之间密钥可能变化（握手会安装新密钥），顺序会被破坏。
- **把 unsafe 放进 only-sys 或新 crate**：only-quic 的 `Bytes` 需要这些句柄类型，而 only-buf 本就是
  各层都依赖的缓冲区 crate；unsafe 保持为一个经过审查的小模块。
- **公开 API**：钩子和 slab 类型保持 `#[doc(hidden)]`（与 `on_batch_end` 一样），以便随数据路径
  变化；公开 API 快照不变。

## 影响

- 公开 API 及其快照不变；`only-buf` 从 `forbid` 改为 `deny` `unsafe_code`，放行一个模块
  （docs/unsafe-review.zh-CN.md）。
- QUIC：1-RTT 数据报从内核到交给应用的帧之间不再有任何复制。
- 内存：每个 UDP 循环为每个 `recvmmsg` 槽位保留一块 slab（32 × 2 × `read_buffer`，默认 4 MiB，
  未写入的页不占内存），另加至多一半数量用于复用；以前是一块 32 × `read_buffer` 的缓冲区。应用代码
  若长期保留收到的 QUIC `Bytes`，会占住它们来自的 slab；要无限期保留请复制
  （`Bytes::copy_from_slice`）。
- 基准（gpu51，同轮 A/B）：见 docs/BENCHMARKS.zh-CN.md 的“UDP 接收缓冲区所有权交付”。
