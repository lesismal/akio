# ADR-066：静态文件缓存的变更通知（inotify / kqueue）

[English](066-static-files-change-notifications.md) | 简体中文

状态：已采纳（2026-11-20）

## 背景

`akio_http::files::Files` 把小文件缓存在内存里，大文件则缓存一个打开的句柄。缓存项在
`check_interval`（默认 5 秒）内被信任，过期后在磁盘线程池上重新 `stat`（文件及其 `.br` / `.zst` /
`.gz` 同名文件）。这有两个代价：一是改动最多要等一个间隔才可见；二是每个热点文件每个间隔都要重新
`stat` 一次，而且由于只有新鲜的命中才在 I/O 线程上应答，每个间隔都有一个请求要绕到磁盘线程池。
DEV-PLAN 把“基于 inotify 的变更跟踪”列为未完成项。

约束：默认行为不变；不引入第三方依赖；I/O 线程上的命中路径不变慢；通知无法担保的情况必须回到间隔
规则，不能提供过期内容。

## 决定

### 1. akio-sys：`FsWatcher`

新增 `akio_sys::{FsWatcher, FsEvent, WatchId}`：

- Linux：inotify（`IN_NONBLOCK | IN_CLOEXEC`），目录掩码为写入、属性、`CLOSE_WRITE`、移入/移出、
  创建、删除、自身删除/移动（`IN_ONLYDIR`）；文件掩码为其中针对自身的部分。`wait` 用 `ppoll` 同时等待
  inotify 描述符与一个 eventfd（`wake`）。事件按字节解析，没有 unsafe 指针转换。
- macOS：kqueue `EVFILT_VNODE`（`EV_CLEAR`），每个监视一个 `O_EVTONLY` 描述符，关闭描述符即删除
  kevent；监视 id 放在 `udata` 中（`ptr::without_provenance_mut`，从不解引用）；`wake` 用
  `EVFILT_USER` / `NOTE_TRIGGER`。
- 事件：`Changed { id, name, is_dir }`（Linux 的目录事件给出变化的目录项；macOS 的目录事件不给名字，
  文件内容需要文件自己的监视，见 `FsWatcher::DIR_EVENTS_NAME_ENTRIES`）、`Gone { id }`（被删除、移动、
  撤销或卸载）、`Overflow`。
- 新增的常量与函数声明加入 `ffi::layout` 与 `libc` 的对照测试。

### 2. akio-http：`Files::watch(true)`

默认关闭。打开后，第一个走到磁盘的请求创建监视器和一个名为 `akio-files-watch` 的线程（每个 `Files`
一个；线程只持有 `Weak<Inner>`，`Files` 被丢弃时由 `Drop` 唤醒并退出）。

- **监视什么。** 在 `stat` 之前，为从根目录到文件所在目录的每一级目录建立监视（目录请求还包括该目录
  本身）。macOS 上每个文件与同名压缩文件还在读取之前各取一个文件监视（`FileWatch`，由缓存项持有，最后
  一个持有者丢弃时结束），并确认监视的正是 `stat` 描述的那个文件（大小、修改时间、设备与 inode）。
- **担保。** 一个缓存项只有在以下都成立时才标记为 `watched`：路径上的目录都有监视；文件和每个同名压缩
  文件都可跟踪（Linux：普通文件且只有一个硬链接；macOS：取得了文件监视）；从开始查磁盘到缓存项放入
  缓存之间，没有应用过任何一批通知（见下）。`watched` 的缓存项不再受 `check_interval` 限制，直到通知把
  它丢弃；其余缓存项照旧按间隔重查。I/O 线程上的命中路径只多读一个 relaxed 原子量。
- **竞争。** 每批通知在丢弃任何缓存项之前先把纪元（`epoch`）加一。请求在建立监视之后、查磁盘之前记下
  纪元，缓存项放入缓存之后再比较：若期间应用过通知，该项不标记为 `watched`（这批通知可能正是关于刚读到
  的内容，而它在缓存项放入之前就已应用）。之后才发生的变化会产生通知，并在应用时丢弃这个已在缓存中的
  项。这是保守的：变化频繁的目录只会退化为间隔规则。
- **丢弃什么。** 文件或其所在目录的变化（Linux 按名字精确到项；macOS 丢弃该目录下的直接子项）丢弃该
  文件，同名压缩文件的变化还丢弃原文件；目录（或指向目录的符号链接）被移动、删除或替换时，丢弃它下面
  的全部缓存项并结束其下所有目录的监视，下次请求时重新建立（macOS 上目录事件不带名字，因此对其下已监视
  的子目录比较设备与 inode，以发现经符号链接的替换）；`Overflow` 丢弃全部缓存；读取通知出错时丢弃全部
  缓存并永久回到间隔规则。
- **上限。** `Files::max_watches(n)`（默认 1024）：目录监视数，macOS 上加上文件监视数（每个是一个
  文件描述符）。超过上限的新缓存项按间隔规则处理。Linux 上这些监视还计入
  `fs.inotify.max_user_watches`。
- **锁顺序。** 监视状态锁只在不持有 ring / 分片锁时获取，或在持有它们时由 `FileWatch::drop` 获取；
  持有监视状态锁时从不获取 ring / 分片锁。通知线程先在监视状态锁内收集要丢弃的路径，释放后再丢弃。

### 3. 有意不做

- **默认开启。** 网络文件系统与 FUSE（NFS、SMB、sshfs……）上其他机器的修改不产生通知，打开后缓存项
  将永远不会更新。文档中明确写出。
- **Linux 上逐文件监视。** 能覆盖经其他硬链接或符号链接目标的写入，但每个文件都要占用一个 inotify
  监视并需要随驱逐而移除；这类文件改为按间隔规则处理。
- **fanotify、macOS FSEvents。** fanotify 需要特权；FSEvents 需要链接 CoreServices 并处理流的延迟
  合并，而 macOS 只是开发平台。

## 结果

- 打开 `watch` 后，改动在通知送达后立即可见（测试中为毫秒级），未改动的热点文件不再每个间隔 `stat`、
  也不再每个间隔绕到磁盘线程池。
- 不打开 `watch` 时的代价：缓存命中（`fresh`，5000 万次查找，取 5 次中最好的一次）在本分支为
  96.1–96.9 ns，在 main `b22519ae` 上为 98.7–99.1 ns。两者在 gpu51（Ryzen 7 7800X3D，核心 2）上同一次
  `quiet.sh` 中交替运行各 5 次，没有退步。
- 公共 API 只有新增：`Files::watch`、`Files::max_watches`；akio-sys 的 `FsWatcher`、`FsEvent`、
  `WatchId`。
- 测试：akio-sys 的写入/创建/原子替换/目录删除/唤醒/错误路径，Linux 的 inotify 记录解析；akio-http 的
  写入、新增与修改同名压缩文件、重命名路径上的目录及重建、目录索引、`max_watches`、`Overflow`、处理中的
  通知、`Files` 丢弃后线程退出，以及 Linux 上的硬链接与符号链接回退。在 macOS 与 x86_64 Linux（gpu51）
  上通过。
