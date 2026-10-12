# scoped 分配根与服务接缝

## 有效边界

`ResourceRoot<R>`、`Rooted<T, R>`、`ScopedBuffer<R>` 管理自己实际拥有的
allocation。它们不接管 legacy 容器，不通过 ambient TLS 拦截分配，不将
token 当作任意子图的容量证明。`ScopedSpawner`、`ScopedClock`、`Cooperative`
是显式宿主服务合同；本模块不提供隐式 Tokio executor。

`client::connect_stream_scoped` 与独立 `ScopedHandle` 使用显式 spawn／clock／
cooperative 服务。none/password/多轮 KI、有根 external signer 公钥／证书认证、
RSA extension、主动／被动 channel、PTY/shell、data/window/resize、EOF/exit/close
与 shutdown 有真实协议实现。
**这是实验性候选 checkpoint，不是完整 W1：KEX/key、部分扩展与 SDK 图仍未闭合，
依赖接缝的局部证据不等于本库全部 RSA／秘密图已闭合。**
不能将此入口用于宣称累计活图 cap 或秘密 backing 全链已受保护的产品。
构建使用父提供的候选 Cargo.lock；下述初始布局源式针对 tokio 1.53.1，
依赖或 SDK 变更须重新核对，不能由本地测试峰值代替源式证明。

### 默认路径隔离与发布边界

旧 constructors、`client::connect`、`client::connect_stream` 仍构造 legacy Handle
并执行 Legacy runtime，不调用 `connect_stream_scoped`。候选路径要求显式调用新入口，
提供 scope/spawner/clock/cooperative，并使用独立 ScopedHandle 与 ScopedHandler。
这是运行入口隔离，不是 Cargo 编译期剔除，也不是总活图已获证的类型标记。

本 checkpoint 不启用 Guo normal 网络。所有未验收的正常接入继续由应用集成门槛关闭；
该关闭状态不是完整网络交付。下列 Pending 仍是完整 W1 必须满足的要求，
不能用当前通过的局部测试、依赖的独立修复或固定 packet 限额替代。

## 类型与真实布局

| 类型／site | 调用前准入 | backing 与最后持有者 |
| --- | --- | --- |
| `Rooted::try_new`，调用者静态 site | `Layout::new::<Header<R>>().extend(Layout::new::<T>()).pad_to_align()` | T 与 header 同块；唯一 typed owner 与所有显式 `ResourceRoot` |
| `ScopedBuffer::try_with_capacity`，调用者静态 site | `Layout::array::<u8>(capacity)` checked，再与 Header checked extend | 精确字节容量与 header 同块；buffer 与旧 backing 的显式 late root |
| `ScopedBuffer::try_reserve` | checked `len + additional`，新容量不足时预约完整新 allocation；不提前归还旧预约 | old + new 共存，复制后移动 owner；旧块最后 holder 释放才退额 |
| `ResourceRoot::try_clone` | 无 allocation；checked 原子 holder 递增 | 同一 allocation，不重复预约；不是不可失败的 Waker clone |
| `RootSlot<T,R>` | 与 Rooted 相同，在初始化前取得真实 backing | 未初始化取消也释放该 backing 后退额 |
| `Shared<T,R>` | 消费现有 Rooted，无新 allocation | 只读 typed holders 与同一 ResourceRoot，最后 holder 析构数据和 header |
| `RootedFuture<T,R>` | 实际 F 先以 Rooted 分配，再擦除 poll 函数类型 | 不 Box；唯一 poll owner 销毁时释放捕获图，late root 继续持有原 header 与完整预约 |
| `client.services/handle/connect.error/task.error` | 实际泛型 T 布局，错误槽在 I/O 与 spawn 前准备 | 服务、task、返回错误分别拥有自己的根；操作错误使用 Shared，不丢弃已记录的首个 terminal 结果 |
| `client.session` | Session 同块布局与 `client/scoped/source.rs` 初始外置上界 | 建立信号、split、peer id；Handle、Captures、建立信号接收端保留同一根 |
| `queue::channel` | `Header<R> + Mutex<State<T>>` 的真实 Layout | 同块 head/tail/closed/senders/waker；sender、receiver 持同一根 |
| `queue::Sender::try_send` | `Header<R> + Node<T>`，每次入队单独准入 | 节点拥有 value/next；取出 value 是 move，独立数据根随 value 移交；节点/值/waker 均不在 Mutex 内析构 |
| `client.auth.payload` | checked `1+(4+U)+(4+14)+(4+M)+tail` | private Request 的 Secret backing；password tail 为 `1+4+P`，KI tail 为两个 SSH string；无普通 String 副本 |
| `client.auth.responses` | checked `5 + Σ(4+response.len())` | borrowed 回答直接编码到同一 Secret backing，经命令节点移交认证状态 |
| `client.auth.prompts` | 原 INFO_REQUEST 实际字节数 | 先验证 UTF-8、数量及结束位置，再复制到 Secret 根；文本 getter 只借用，回复节点不复制数据 |
| `client.auth.publickey` | checked `1+(4+U)+(4+14)+(4+9)+1+(4+A)+(4+K)` | 借用公钥／证书 blob 直接编码 Secret probe；认证 actor 保持原根核对 PK_OK 的算法与 key blob |
| `client.auth.sign` | checked `4+session_id.len()+probe.len()` | session-id 与签名前 USERAUTH_REQUEST 同一 Secret backing；ScopedSignRequest getter 借用，reply 节点 move 原根 |
| `client.auth.signed` | checked `request.len()+4+signature.len()` | 有根 signature 与原请求同时持额，合并到 Secret backing；普通／SK signature framing 校验无动态临时容器 |
| `client.packet.read` | 协议长度检查后 checked `4 + packet_length + tag_len` | 16-byte probe 在实际 read future 内；主体在 read_exact/decrypt 前准入；增长覆盖 old+new |
| `client.packet.seal` | checked `4 + 1 + payload.len() + padding_length(payload) + tag_len` | Secret backing 原位编码、padding、seal；与原 payload 同时持额；WritePacket 持发送残留 |
| `client.packet.decode` | IncomingSshPacket 本体与确切输入字节数 | 交给 legacy 分支的原始 Vec 副本先准入；不覆盖分支后续派生分配 |
| `client.channel.handle/state/events/pending` | 各自实际 T、queue state 的 Layout | handle、actor 链表、事件与 pending 队列各有实际根；关闭后移除 actor 节点 |
| `client.channel.data/incoming/output` | 实际输入或 chunk 长度，framing 单独 checked | 窗口只限制进度，不代替累计活图准入；getter 返回 ScopedBuffer，不返回裸 Vec |
| `client.channel.request` | request 名、UTF-8 term、固定字段、`1+5*N` 有效 PTY modes | 不借用 Encrypted.write 的 Vec；metadata/data 分配分别收费 |
| `client.channel.open.info` | 已验证 CHANNEL_OPEN 的实际字节数 | Secret backing；ScopedOpenInfo 的名称、地址、路径、原参数 getter 都借用该根 |
| `client.channel.open.decision` | `Header<R> + Mutex<Decision>` | actor 与 open token 共享同块；accept/reject/Drop 只改预分配决定并 wake，不申请节点；Drop 拒绝码为 1 |
| `client.channel.open.reply` | confirmation／空描述 failure 都为 17-byte payload | 原 actor 先封确认或拒绝，再处理关闭；未决 token 可在 callback 返回后由 caller 持有 |
| `client.control.queue/replies` | queue state 的实际 Layout | 控制待发项和待回复项分别由真实有根队列拥有；状态随 SessionOwner 清理 |
| `client.control.node/reply.node` | 实际 `Node<Pending>`／`Node<usize>` Layout | pending 项无可变外置图；回复项记录它之前未完成的 legacy 全局请求数量，保持 wire 回复顺序 |
| `client.control.cleanup` | Secret backing 容量 `4+1+13+255+64` 与 Header | I/O 前准入；13 为 disconnect payload，255 为 SSH padding 字段上界，64 为已实现 MAC 最大长度；不依据运行峰值 |
| `cipher::CIPHERS/mac::MACS/kex::KEXES` | 只读静态表，没有运行时 allocation | 所有名字、别名与算法实现均静态引用；不创建 HashMap、随机状态或每连接副本 |

Header 字段为原子 holder 数、实际 Layout、payload offset／size、AtomicBool 初始化位、
wipe 位、析构函数指针、`ManuallyDrop<R>`。对齐与 padding 均由 `Layout`
运算计算，不以指针大小估计 T。`allocation_layout` 对外返回相同布局源式，
不硬编码任一 SDK／target 的数字。

初始化顺序：检查布局 → scope 预约 → `alloc_zeroed` → 写 header → 调用
初始化闭包 → 写 T → 标记 initialized。NULL 是 `AllocationFailed`，不是
`ByteBudget`；构造闭包不会被调用。闭包 unwind 时释放未初始化 backing。
T 的捕获图、初始化闭包内部的外置分配须分别已有真实根；本 API 不把任意
`Vec`、`Arc` 或 opaque key 的 size_of 误算成完整子图。

析构顺序：最后 holder 的 release/acquire → 原位析构 T → Secret payload
全 capacity volatile wipe → 将 reservation 移到栈 → dealloc 原 Layout →
drop reservation。析构 guard 覆盖 T 的 unwind，Reservation 的 Drop 合同
禁止 unwind。header 释放后不再访问 header。没有弱引用或独立未收费 header。

initialized 在写完 T 后 Release store；唯一 future poll owner 提前析构时和最后
root 释放时均通过共享 Header 的 AcqRel swap(false) 取得析构资格。共享期间
不创建 Header 的独占引用。future owner 先析构捕获图，late root 仍可并发读取
layout／offset、clone 及释放；原 allocation 与预约直到最后 header dealloc 才退额。

`Rooted` 不可 Clone，无 into_inner；移动 owner 不移动 payload。
只有 typed owner 可访问 T；保留根不提供 payload 引用。`get_mut` 要求 T:
Unpin；`as_pin_mut` 支持真实泛型 future 原位 poll。T 必须 Send + 'static，
最后根可在其他线程运行析构。Secret 类只擦除本块，不能替代 T 外置秘密的
保护。`ScopedBuffer` 不导出裸 Vec，也不靠 clear/truncate 退还 capacity。

私有 ErasedRooted/ErasedShared/ErasedBuffer 只擦除释放函数类型，释放时仍还原
同一 ResourceRoot<R>，没有第二套 Box/header。buffer 回到泛型接口时核对
reservation TypeId 并移动原根。SessionOwner 在 poll owner 结束时清理认证、
发送残留、控制队列和 channel actor；late Handle/header 根继续计费，逻辑完成不是 free。

显式 keepalive、自动 keepalive 与普通全局请求回复使用 scoped 控制队列；封包
走 `scoped_packet`，不把这些消息交给 legacy Msg 或 Encrypted.write。scoped
rekey 命令也经有根队列，但后续 KEX 分配仍在下述未闭合范围内。
控制回复跟踪保留与旧 Handler 全局请求的线序；无需回复的 keepalive 不创建
待回复项。`hostkeys-00@openssh.com` 仍由旧 Handler 分支处理，不包含在这里的证明中。

disconnect 原因写入已准入 Services 的原子字段，不为关闭再分配节点或错误槽。
关闭优先于新 read／消息准入；已有半包与 disconnect 各至多尝试一次 write，
Pending／短写时本地关闭，不把通知到达对端当作 cleanup 条件。cleanup backing
按当前 cipher 的精确长度核对后复用，不增长；退出时仍 full-capacity wipe。
shutdown 只 poll 一次 transport shutdown，Pending 时释放本地 transport owner。
这不是所有应用输出已经交付的承诺。旧 connect_stream 的 shutdown 语义不变。

scoped 收尾调用 `ScopedHandler::disconnected_scoped`，以 ScopedDisconnectReason
借用远端信息或原 Shared 操作错误，不消费或改写主错误。回调每次 poll 先登记
control wake，检查资源终结和 closing；关闭时取消 Pending 回调而不等它就绪。
已有操作错误优先于回调的次级结果；正常远端断开时回调错误保持其资源／操作类别。
取消后释放 callback future 和 SessionOwner 捕获图；晚到错误／Handle 根继续持额。
legacy 路径仍调用原 Handler::disconnected，不受此收尾边界影响。

## 宿主适配条件

- `AdmissionScope::Reservation` 装实际 App grant，所有用途映射到同一 cap。
  该关联类型不要求 Clone，必须 Send + Sync + 'static，Drop 不 unwind。
- `ResourceRequest` 含 `class/site/layout/out_of_line_upper/slots`；本内核
  同块分配的 `out_of_line_upper = 0`、`slots = 1`。源闭包额外预约由调用方
  持到所有对应外置 backing 释放，不能把 out-of-line 重记进 layout。
- `ScopedSpawner::try_spawn<F>` 接收未 Box 的 F。宿主应在构造 F 前完成
  捕获图准入，在分配真实 task/waker/header 前计算 Layout。返回 Task 的
  Output 为 `Result<F::Output, ScopedFault>`；Task 还须实现 `ScopedTask`、Send、
  Unpin。`cancel(&self)` 撤销执行，不得把 ready/join/cancel 当作 header 已释放。
- `ScopedClock::sleep_until/reset` 可失败，Sleep 自身持实际 timer 根。
  Drop 取消交付，不代表已排队 callback 消失。clock 不得偷用 Tokio timer。
- `Cooperative::begin_poll/poll_budget` 每次 task poll 重置宿主预算；耗尽
  注册一次不分配的 wake 后 Pending。两方法接收 `&self`，状态由宿主显式
  服务持有；`run_inner_with` 在每次自身 poll 开始调用 begin_poll。
- `ScopedError<E>` 保留 `Resource(ScopedFault)` 与 `Operation(E)`，不增加
  旧公开错误枚举 variant，也不把额度错误字符串化成认证失败。
- `connect_stream_scoped(config, stream, handler, scope, spawner, clock, cooperative)`
  要求 S／clock／cooperative 为 Send + Sync + 'static，handler Error 为
Send + Sync + 'static。返回 `ScopedHandle<H,S,P,C,B>`；操作错误实际类型为
  `ScopedError<Shared<H::Error,S::Reservation>>`。既有配置、stream、handler
  与宿主服务的外置资源仍须由调用方实际 owners 持额，不重复收费共享元数据。
- H 实现 `ScopedHandler<S,C,B>: Handler`，其 `server_channel_open_scoped` 收到
  `ScopedChannelOpen<S,C,B>`。具体宿主类型允许 callback 返回后继续持有 channel。
  已知类型默认接受，未知类型默认拒绝；旧 Handler 方法及旧入口不变。
- `authenticate_publickey_with(user, key_blob, hash_alg, signer)` 和
  `authenticate_certificate_with(user, certificate_blob, hash_alg, signer)` 借用 caller
  原操作根持有的 SSH 编码。`ScopedSigner<S, Error=H::Error>::sign` 接收 scope、
  `&ScopedSignRequest<S::Reservation>` 与 hash hint；输出为
  `Result<ScopedBuffer<S::Reservation>, ScopedError<Shared<H::Error,S::Reservation>>>`。
  provider 内部私钥／agent 图和实际 future 须由 provider 原操作根闭合；这不是
  本库 ssh-key／RSA 已加载私钥转换、编码或签名的容量／擦除证明。
  signer 的首个资源或操作错误在本次 attempt 和连接 terminal 保持原类别及原根。
- password 接收 `(&str,&str)`，KI respond 接收 `&[&str]`；ScopedAuthInfo<R>
  提供 borrowed 名称、说明、prompts iterator 与 root，不构造 String/Vec。
- channel_open_session 返回 ScopedChannel<S,C,B>。request_pty/request_shell/
  data/window_change/eof/close 只确认进入有根队列，SSH ACK 经 wait 返回。
  wait 返回 `Result<Option<ScopedChannelMsg<S::Reservation>>, ScopedFault>`。
  连接的 Handler/协议错误仍由 ScopedHandle 交付；宿主须驱动并监视连接 task。
- Data/ExtendedData/ExitSignal 保持 ScopedBuffer，getter 交付后才排窗口 credit。
  ExitSignal buffer 是已校验的完整 CHANNEL_REQUEST payload。转成应用输出时
  须移交原根，或另外先准入再复制。
- `disconnect(reason)` 是无额外准入的本地关闭请求；`shutdown(self)` 请求关闭
  并等待 task 的既有 terminal 结果，不覆盖先前的资源或操作错误。

## Pending：尚未闭合的库内可达面

以下仍需真实实现和定向验证，不能由上述 root 或单 packet 限额发证。

| 源位置 | 必需接线／证明 |
| --- | --- |
| `client/scoped/source.rs` | oneshot、split 与 peer id 初始外置上界仍须完整 SDK 源式核对；scoped 命令、回复与被动 channel 使用自有 rooted queue，旧 inbound mpsc 仅在 legacy Session 构造 |
| `Session::run/run_inner`、`Session::flush` | scoped 控制与认证/channel 有根，KEX 输出也使用逐次 poll 的 I/O pump；KEX 和旧 Handler 写队列仍经过 Vec/Bytes，尚不是完整计费／秘密 backing 路径 |
| `client/scoped.rs::operation_error` | 错误 owner 与 header 生命周期已有根；H::Error 或库错误中 Vec／String 等外置图尚需生成点之前的源式准入，不能只计错误枚举本体 |
| client RSA extension wait | scoped Handle 通过服务根内的原子状态与 clock 等待，不使用 Legacy Handle 或其 Tokio timeout；等待取消与晚到 waker 仍需专项覆盖 |
| `client/encrypted.rs::client_read_encrypted` | scoped 认证、主动／被动 channel、普通全局控制在此之前处理；host-key 公告及其余扩展解析的 handler 前派生分配仍须接入 |
| ssh-key 已加载私钥／证书编码、RSA／EC 签名 | 有根 external signer 入口可用；RSA CRT 依赖的局部擦除证据见下文，原始 blob 的加载／编码、本地密钥签名及完整私有运算图的分配前准入仍待闭合 |
| `sshbuffer.rs::PacketWriter` | scoped_packet/cleanup backing 已保护；legacy prepare_packet/packet_bytes/write_buffer 的 Vec/BytesMut、retain、旧 Handler/KEX 分支仍需接线，逐次 poll 写入不能代替该分配证明 |
| `cipher/mod.rs` 与具体 key 实现 | packet backing 已准入；dyn key Box、MAC、key derive、RNG/TLS、第三方 seal/open scratch 须给出算法闭包及最后 holder |
| `compression.rs` | flate2 状态和输出增长未闭合；scoped 在该调用前给出具体 compression/decompression PolicyUnavailable，None 压缩正常认证/channel 不被拒绝 |
| 旧 Handler 中的 `&mut Session` 回调 | 新被动 channel 不产生旧 Channel/Bytes；其他旧回调自行调用 Session API 时，仍须覆盖派生写队列和外置 owners，不得沿用默认 no-op 回调的证明 |
| bytes 1.12.1 `Owned<T>/owned_drop_impl` | Box header 释放晚于 owner 析构；只在 owner 中放 grant 不能证明 header dealloc 后退款。公开 Bytes 的 clone/into_mut 也不能视为零分配 |
| `client/kex.rs`、`kex`、`negotiation`、`keys` | 精确算法分支的第三方 allocate/encode/sign 调用闭包，完整旧新 key/rekey 共存界；不能用经验倍率 |
| `kex/hybrid_mlkem.rs::client_dh` | client_ephemeral、c_init、ML-KEM secret Box 须在 generate/encode/Box 分配前分别给出实际容量与类型 Layout；RNG/TLS 持有期不能用本次调用完成代替 |
| `kex/hybrid_mlkem.rs::compute_exchange_hash/compute_keys` | 共享秘密直接分段输入 SHA-256，不经拼接 Vec；CryptoVec 编码、hash 输出、SharedSecret 与 compute_keys 的后续分配及 stack secret guard 仍须闭合 |
| `kex/mod.rs::compute_keys` 的 `KEY_BUF/NONCE_BUF/MAC_BUF/BUFFER` | thread-local CryptoVec 的容量与秘密可越过连接结束继续存活；必须换为 scoped 拥有的 scratch 或证明持到线程最后 backing 释放的实际根，不能将注册表静态化当作此项已解决 |
| `client/scoped/auth.rs::process`、`channel.rs::data/request_pty`、签名／被动 channel metadata | 容量有实际限界；大输入复制、提示遍历及不可分 crypto 操作的 CPU 源界仍须闭合，一个 poll unit 不等于任意字节数 |

### RSA 依赖秘密释放边界

候选依赖图使用 `MoyuTeams/crypto-bigint` 提交
`9a4f70ace040b57f5f5cffc0d4389d2676baee9d`，版本仍为 0.7.5。
该安全擦除接缝针对共享 Montgomery 参数及其最后 owner；父侧独立 GNU/MSVC
Debug/Release 擦除证据的适用范围是该依赖接缝，不是本库完整私有运算图。

`ssh-key 0.7.0-rc.11` 的 RSA signer 将私钥转换为 `rsa 0.10.0-rc.18` 的
SigningKey，其 CRT 图包含 `qinv/p_params/q_params`。独立门槛
`tests/source_audit/rsa_wipe.rs` 使用当前候选锁依赖的实际 rsa/rand rlib，
经 `from_components` 构造 RAM 合成密钥，在 allocator dealloc 前检查
`p_params.modulus().as_limbs()` 的确切 backing，不输出秘密。
当前候选依赖的实际 rlib 审计在 GNU 1.98.1／MSVC 1.99.0 Debug 图上均观察到
该 backing dealloc 且 dealloc 前全零；父侧仍须复核实际依赖来源和适用边界。
此证据只覆盖被探测的 p_params modulus，不覆盖全部 CRT、运算 scratch 或
分配前准入；外层 Root 不替代内层 backing 的擦除责任。
私有运算 scratch、before-allocation、重键共存及全部最后 owners 仍为 Pending。
不得将 external signer 可用、局部 backing 擦除或未验收路径关闭描述为完整实现。

## 验证面

`tests.rs` 的 allocator recorder 仅在测试编译中存在，不进入产品。
它在真实 alloc/dealloc 边界观察准入拒绝、NULL、增长旧新共存、全容量
wipe-before-free、header dealloc-before-refund。另测构造 unwind、对齐/ZST、
checked overflow、跨线程最后 holder、真实泛型 future ready 后 late waker
持根。测试 Wake 的 Arc 是测试夹具，不是生产 task/waker header 的计费证明。
并发 late root 回归在捕获图析构期间读取 layout／offset 并反复 clone，验证
捕获图只析构一次，原 Header 继续持额到最后根；没有运行 Miri，此测试不代替
共享 Header 引用与原子初始化位的静态安全论证。

`client/scoped_runtime_tests.rs` 在无 Tokio runtime 的线程上直接 poll 实际
Session 内循环：测试有根 sleep 的准入失败、reset 失败、inactivity 终结、
连续 ready timer 的每 poll 预算和取消释放，以及 RSA 等待使用的 timeout
内核。测试用流不建立正常 SSH 连接。

`tests/scoped_connect.rs` 在无 Tokio runtime 的客户端线程上通过独立服务端
线程完成真实密钥交换、公钥核对、none/password/两轮 KI、RSA 扩展、keepalive、
PTY 前 data、UTF-8 term/modes、shell、多 flow window 传输、resize、rekey、
exit/EOF/close 与 shutdown/join。两个存活连接共享计数器，一个命令准入失败后
另一个继续终端操作；认证写永久 Pending 时取消仍终结。入口/消息/read/seal
拒额保持 typed fault，late Handle/prompt/data root 保额。测试由 join poll 驱动真实 F，不是
App 的生产 executor，也不证明 task/waker 全部宿主 header 的源式上界。
另验证实际 keepalive ACK 后回复节点释放、服务端 ping 在 PTY 前得到真实回复、
控制节点与回复节点拒额直达 terminal Resource，以及正常／写 Pending／rekey 写
Pending 三种关闭。后者在关闭前拒绝所有新 grant，关闭仍无需新准入。
ring 专属夹具以真实 Ed25519 签名和 CA 签发证书覆盖 external signer 公钥／证书认证、
签名结果和 signed packet 拒额、provider 操作错误保持原 terminal 根。
被动 forwarded channel 覆盖 borrowed UTF-8 metadata、callback 返回后 accept、
双向 data、EOF/Close、显式拒绝／Drop 拒绝、handler 前两个准入拒绝点、
永久 Pending callback 下 shutdown，以及晚于连接的 metadata 根。
收尾回归使用真实远端 DISCONNECT 和重键 Handler 操作错误，两路进入永久
Pending disconnected_scoped 后 shutdown 在一次 poll 内完成，并检查 callback
只析构一次、原操作错误类别保持、late Handle／错误根最后释放后退款。
ring 夹具和它的两个测试仅在 ring feature 下编译；其余 scoped target 不依赖 ring。

Session 事件选择显式轮转 read/write/control/keepalive/inactivity/三个消息入口，不依赖
select 宏的线程局部随机选择；每次 drain 只消费进入该批次时已在队列的数量。
Legacy 分支保留 Tokio sleep 和 cooperative；scoped 服务实现不调用这些分支。
`RunError<HandlerError, RuntimeFault>` 直接区分断开、协议／handler 错误与
runtime fault，不使用旧错误值或字符串还原额度错误。
每次 poll 先登记 control wake 并检查资源原因；run future 在 callback Pending
且已关闭时可本地终结，不要求用户 callback 再次就绪。
发送至多保留一个密文 packet 残留，每次 poll_write 后回到事件轮转；channel
也轮转。allocator 测试观察认证输入经 queue 取消/late root、packet 取消时的
full-capacity wipe 与 header-before-refund；消息节点和 seal 拒额期间监视全部
Rust allocator 调用，要求次数为零。
控制节点／回复节点拒额同样要求所有 Rust allocator 调用为零；预留 cleanup
在普通预算已满时原位封包且 full-capacity wipe。固定算法表遍历与协议名字解析
不调用 allocator；动态 key 构造、签名和派生不属于这个零分配范围。
被动 open token 在冻结预算后的 Drop 没有 allocator 调用，metadata 最后根释放时
full-capacity wipe；取消签名请求的未使用容量及 late holder 也在真实 dealloc 处检查。

`tests/scoped_auth_log.rs` 使用真实 legacy SSH 协议、临时内存密钥和精确公钥
核对，覆盖密码拒绝／成功、多轮 KI 和关闭。它捕获实际 Trace 日志并检查秘密
明文及字节 Debug 表示，不绑定日志措辞；不证明 scoped 秘密 backing 生命周期。

完整 scoped 网络、全部 legacy 外部 API／serde、App host trust、生产
Tokio-free client runtime 和第三方调用闭包仍须另由整库定向测试证明。
