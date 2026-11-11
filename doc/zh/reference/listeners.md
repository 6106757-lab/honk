# 入站监听（listeners）

`listeners {}` 提供普通的 TCP 入站端口，在同一个端口上同时接受 HTTP 代理与 SOCKS5，并在同端口提供 SOCKS5 `UDP ASSOCIATE`。它和 eBPF 透明代理并行工作，用于「每个浏览器配置文件 / 每台设备用一个固定端口」这类场景。

> 监听默认只绑定 `127.0.0.1`。要暴露到局域网必须显式写 `listen`，并且**配置了认证的监听不允许绑定通配地址**。

## 基本写法

```dae
listeners {
    shop1 {
        type: mixed            # 目前只支持 mixed（HTTP + SOCKS5）
        listen: 127.0.0.1      # 默认 127.0.0.1
        port: 12000
        auth: 'user:pass'      # 可选；SOCKS5 userpass / HTTP Basic
    }
    shop2 {
        port: 12001
    }
}

routing {
    # 用入站名字决定出口，而不是在 listener 上写 proxy:
    inbound(shop1) -> '🇵🇭 菲律宾-1'
    inbound(shop2) && domain(geosite: cn) -> direct
    inbound(shop2) -> Proxy
    fallback: Proxy
}
```

### 为什么出口不写在 listener 上

`inbound(name)` 走的是 honk 原有的 `Router`，因此：

- 规则可以和 `domain()` / `dip()` / `dport()` 等任意组合，也能用 `!inbound(...)` 反选；
- 组选择、连接表、doona 连接页、规则证据链、reload 全部复用同一套设施；
- DNS 解析带客户端来源上下文，`qname()` 规则与 `-> follow`（DNS 出口跟随内容出口）依然生效；
- 不需要第二份节点配置，也不会出现「DNS 出口和内容出口地理不一致」。

`inbound()` 是**用户态专用**匹配器：透明代理 / eBPF 流量没有入站身份，这类规则在内核路由计划里会被整体跳过，不会误命中。

## 字段

| 字段 | 默认值 | 说明 |
|---|---|---|
| `type` | `mixed` | 目前只支持 `mixed` |
| `listen` | `127.0.0.1` | IPv4 / IPv6 地址 |
| `port` | 必填 | 1–65535 |
| `auth` | 无 | `user:password`，SOCKS5 用 userpass 子协商，HTTP 用 `Proxy-Authorization: Basic` |
| `handshake_timeout_ms` | `10000` | 整个协议握手的**总**截止时间 |
| `request_timeout_ms` | `30000` | 每个 HTTP 请求头的总截止时间 |
| `max_header_bytes` | `16384` | 请求头缓冲上限 |

同名监听、`(listen, port)` 冲突（含 `0.0.0.0` 与 `127.0.0.1` 同端口）、端口为 0、**无认证**监听绑定通配地址（`0.0.0.0`），都会在**绑定之前**被拒绝，不会出现半启动状态。

`listen: 0.0.0.0` **允许用于带 `auth` 的监听**——认证本身就是防护，这也是把服务发布到公网的常规写法（等价 3proxy / Xray）。而带密码的监听绑通配地址还有个额外好处：SOCKS5 `UDP ASSOCIATE` 回复天然就是 `0.0.0.0:port`,严格客户端（NekoBox）会自动回退到它连进来的公网地址，无需再配 `udp_host`。反过来，**无 auth** 的监听绑 `0.0.0.0` 等于开一个公网免费代理,所以被明确禁止；只绑具体地址则可以。

## 协议行为

- **首字节分派**：读到第一个字节判断 SOCKS5 还是 HTTP，该字节不会被消耗，目标解析器仍能看到完整请求。
- **HTTP keep-alive**：每个请求都重新解析 `Host`、重新走路由、重新拨号上游。换域名的第二个请求不会被发到第一个请求的上游。上游被强制 `Connection: close`，客户端连接保持可复用。
- **CONNECT**：回复 `200` 后，把预读缓冲里剩余的字节（可能是同包携带的 TLS ClientHello）先冲给上游，再进入双向转发。
- **hop-by-hop 头**：`Proxy-Connection`、`Proxy-Authorization`、`Connection` 及其列出的头、`Keep-Alive`、`TE`、`Trailer`、`Upgrade` 会被剥离。
- **超时**：握手与请求头各用一个总截止时间，慢速逐字节 drip 无法续命；读完请求头即解除，长连接不受影响。
- **错误**：所有错误响应都带 `Connection: close`；SOCKS5 的拒绝会回对应的 REP 码（规则禁止 `0x02`、拨号失败 `0x05`）。
- **SOCKS5**：支持 `CONNECT`、`UDP ASSOCIATE` 与 IPv4 / IPv6 / 域名地址；`BIND` 不支持。

## UDP（SOCKS5 UDP ASSOCIATE）

`listeners {}` 同时绑定一个 UDP socket，**与 TCP 监听同 IP 同端口**（TCP/UDP 端口空间独立，不冲突）。所以如果你把某个端口映射到公网，只要把 **TCP 和 UDP 都放行**，客户端就能用同一个地址走 UDP，无需额外端口。

客户端发起 `UDP ASSOCIATE` 后，服务端在 SOCKS5 回复里带回中继地址（BND.ADDR）；那条 TCP 连接变成控制通道，保持打开即代表 UDP 会话有效，关闭则整个会话终止（RFC 1928）。

**关于 BND.ADDR（重要，公网转发必看）**：严格遵循 RFC 1928 的客户端（sing-box / NekoBox / NekoRay）会把 UDP 包**直接发给回复里的 BND.ADDR**；小火箭（Shadowrocket）会忽略它、改用 TCP 连接的对端地址。所以当 `listen` 绑在内网地址（如 `172.20.1.128`）而端口由路由器映射到公网时，回内网地址会让 NekoBox 的**第一个 UDP 包就发不出去**（TCP 却正常），表现就是「UDP 不通」。

- 默认自动处理：当客户端来自公网、而监听地址是不可路由的私网地址时，BND.ADDR 回 `0.0.0.0:port`，让客户端回退到它连进来的公网地址（与 Xray 默认用 TCP 本地地址是同一目的）。局域网客户端仍回具体绑定地址，行为不变。
- 更简洁的做法：直接让带 auth 的监听绑 `0.0.0.0`，回复自然是 `0.0.0.0:port`，不必写 `udp_host`。
- 显式指定（等价 Xray / 3x-ui 里的 `ip` 字段）：在 listener 里写 `udp_host: 公网IP`，服务端会把这个地址原样回给客户端。当 `listen` 必须绑具体内网地址、或公网 IP 无法从 TCP 连接推断时用这个：
  ```dae
  shopauth { type: mixed listen: 172.20.1.128 port: 12001 auth: 'adminshop:shoppassword' udp_host: 117.174.205.95 }
  ```
  注意端口仍回监听端口；若做了端口转发（公网端口 ≠ `port`），需要在客户端/转发侧按实际端口处理。

实现要点：

- 走的是**独立的用户态转发路径**，不进入 eBPF 的 `udp_endpoint` 池（那套依赖 tproxy mark、BPF conn info 和 janitor），而是复用 `ProxyRegistry::dial_udp_transport()`，因此所有支持 UDP 的节点协议（direct、socks5、shadowsocks、vless 等）都能用。
- **连接 = 一个 `UDP ASSOCIATE` 会话，不是一个目标。** 会话内部按 `(目标地址, 端口)` 建立/复用 flow，但 doona 里**一个会话只有一行**（`network = udp`）。否则手机一个 tun 会话里的 DNS / QUIC / STUN / 局域网探测会在连接表刷出上千行。
- 每个目标各自走 `inbound()` 规则与带客户端来源的 DNS（`qname()` / `-> follow` 照常生效），组选择用 `ProbeDomain::DataUdp`（TCP 仍是 `ProbeDomain::Tcp`）。连接表那一行的规则列取会话第一个非 bypass 目标的规则。
- 回包的 SOCKS5 头使用 `PacketTransport::recv_packet()` 返回的**真实对端**，不会伪造原始请求目标（伪造会让客户端把回包当成新会话）。
- 分片数据报（`FRAG != 0`）直接丢弃；单会话最多 256 条 flow，空闲 120 秒回收 flow（会话行随控制通道结束才移除）；UDP 无背压，队列满则丢弃数据报。
- 一个 dispatcher 独占 `recv_from`，按**客户端 IP** 分发到各控制连接对应的会话，因此 NAT 后 UDP 源端口与 TCP 源端口不同也能工作。
- 若 UDP 端口绑定失败（例如被别的进程占用），该监听**降级为仅 TCP**，不影响现有连接；此时 `UDP ASSOCIATE` 会回 REP `0x07`。

## 连接表与 `must`

- **`direct(must)` 不建观测行**：内核路径里 `must` 是终端直连，流量根本不进控制面，所以连接表里没有它。用户态入站现在沿用同一语义，命中 `must` 的直连连接 / UDP 会话在 doona 里不可见、也无法被面板关闭。这样一台把全部流量代理进来的手机不会把国内直连刷满连接表。
- **一行 = 一条 TCP 连接**：客户端每发起一次 `CONNECT` 就占一行，源端口各不相同。Telegram 之类客户端会对同一个 IP / 域名并发开多条连接并周期性重连，因此连接表里出现「同 IP 多行」「同域名多行」是正常形态，不是重复行。判断是否为重复行要看 `src` 的**端口**是否相同。
- **生命周期回收**：内核路径有 eBPF janitor / TTL 兜底，用户态 relay 没有内核 flow，因此用三层机制保证观测行一定会消失：
  1. **RAII 绑定**：观测行由一个连接 guard 持有，guard 被析构时必定 ack `CloseSignal` 并移除该行。正常结束、API 关闭、注册后提前返回（`?`）、reload 取消整个 task，四条路径都覆盖。此前只有正常结束会清理，其余路径会留下 `CloseSignal` 永不 terminal 的行，连 `sweep_terminal()` 都回收不了，这才是「断开后一直在」的根子。
  2. **内核检测**：accepted socket 开启 TCP keepalive（空闲 60 秒 / 间隔 10 秒 / 3 次探测）与 `TCP_USER_TIMEOUT = 120 秒`。手机切网、掉线不发 FIN/RST 时由内核判定连接已死；后者还能覆盖「上游持续推送、看门狗被字节数不断重置」这种看门狗救不了的场景。
  3. **用户态兜底**：连续 120 秒双向零字节（检查周期 10 秒）结束 relay；有心跳的长连接不受影响。

  客户端正常断开后，relay 会先把上游剩余数据排空（最长 30 秒）再结束，所以连接表最多延迟约 30 秒清除，不是残留。

## 关闭连接

从 listeners 进来的 TCP 连接和 UDP **会话**都注册了可关闭的传输 owner，因此 doona 里：

- **单条关闭**（`DELETE /api/v1/connections/{id}`）会真正断开该连接，返回 `204`；
- **「全部关闭」**（`DELETE /api/v1/connections?all=true`）会把它们计入 `closed`，不会计入 `skipped`。

TCP 连接在关闭请求到达时直接丢弃双向 relay（两个 socket 一起断开）；UDP 一行对应整个会话，关闭它即终止控制通道、收回会话内所有 flow。

注意：入站连接没有内核 flow，**不参与「切换节点组时打断该组连接」**（`snapshot_group` 按组过滤不到它们）。这是唯一仍会跳过入站连接的关闭路径，其余按 id / 按来源 / 全部关闭都生效。

## 已知限制

1. 入站连接没有以太网 L2 头，因此 `mac()` / `pname()` 规则不命中；`sport()` 使用的是客户端连接的真实端口。
2. 组选择器用的是探测类型而不是具体目标域名（honk 的组选择接口不接受目标域名），但目标域名仍会作为 `target_domain` 传给节点，域名信息不丢。
3. 重载配置时会随 epoch 重建重新绑定监听；`InboundListenerSet::patch` 已实现按名字增量替换，尚未挂到 reload 事件路径。
4. 入站连接不生成 flow 证据记录，因此 doona 里「重新评估」按钮不可用；规则列由连接表在注册时快照的 `rule` / `rule_payload` 提供，证据表被清空或 TTL 淘汰也不会变成「—」。
5. UDP 会话按客户端 IP 分发：同一个 IP 上后建立的 `UDP ASSOCIATE` 会接管先前的会话。多设备经同一个 NAT 出口共用时，只有最后一个会话生效。
