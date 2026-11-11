# 入站监听（listeners）

`listeners {}` 提供普通的 TCP 入站端口，在同一个端口上同时接受 HTTP 代理与 SOCKS5。它和 eBPF 透明代理并行工作，用于「每个浏览器配置文件 / 每台设备用一个固定端口」这类场景。

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

同名监听、`(listen, port)` 冲突（含 `0.0.0.0` 与 `127.0.0.1` 同端口）、端口为 0、认证监听绑定通配地址，都会在**绑定之前**被拒绝，不会出现半启动状态。

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

客户端发起 `UDP ASSOCIATE` 后，服务端在 SOCKS5 回复里带回中继地址；那条 TCP 连接变成控制通道，保持打开即代表 UDP 会话有效，关闭则整个会话终止（RFC 1928）。

实现要点：

- 走的是**独立的用户态转发路径**，不进入 eBPF 的 `udp_endpoint` 池（那套依赖 tproxy mark、BPF conn info 和 janitor），而是复用 `ProxyRegistry::dial_udp_transport()`，因此所有支持 UDP 的节点协议（direct、socks5、shadowsocks、vless 等）都能用。
- 每个数据报按 `(目标地址, 端口)` 建立/复用一条 flow，`inbound()` 规则与 DNS `qname()` / `-> follow` 全部照常生效，域名目标通过带客户端来源的解析器解析。
- 组选择使用 `ProbeDomain::DataUdp`（TCP 流量仍是 `ProbeDomain::Tcp`）。
- 分片数据报（`FRAG != 0`）直接丢弃；单会话最多 256 条 flow，空闲 120 秒回收；UDP 无背压，队列满则丢弃数据报。
- 每条 UDP flow 会在 doona 连接表出现（`network = udp`），规则列同样由连接表快照提供。
- 一个 dispatcher 独占 `recv_from`，按**客户端 IP** 分发到各控制连接对应的会话，因此 NAT 后 UDP 源端口与 TCP 源端口不同也能工作。
- 若 UDP 端口绑定失败（例如被别的进程占用），该监听**降级为仅 TCP**，不影响现有连接；此时 `UDP ASSOCIATE` 会回 REP `0x07`。

## 关闭连接

从 listeners 进来的 TCP 连接和 UDP flow 都注册了可关闭的传输 owner，因此 doona 里：

- **单条关闭**（`DELETE /api/v1/connections/{id}`）会真正断开该连接，返回 `204`；
- **「全部关闭」**（`DELETE /api/v1/connections?all=true`）会把它们计入 `closed`，不会计入 `skipped`。

TCP 连接在关闭请求到达时直接丢弃双向 relay（两个 socket 一起断开）；UDP flow 由会话统一收回，reply 任务被中止、连接表行被移除。

注意：入站连接没有内核 flow，**不参与「切换节点组时打断该组连接」**（`snapshot_group` 按组过滤不到它们）。这是唯一仍会跳过入站连接的关闭路径，其余按 id / 按来源 / 全部关闭都生效。

## 已知限制

1. 入站连接没有以太网 L2 头，因此 `mac()` / `pname()` 规则不命中；`sport()` 使用的是客户端连接的真实端口。
2. 组选择器用的是探测类型而不是具体目标域名（honk 的组选择接口不接受目标域名），但目标域名仍会作为 `target_domain` 传给节点，域名信息不丢。
3. 重载配置时会随 epoch 重建重新绑定监听；`InboundListenerSet::patch` 已实现按名字增量替换，尚未挂到 reload 事件路径。
4. 入站连接不生成 flow 证据记录，因此 doona 里「重新评估」按钮不可用；规则列由连接表在注册时快照的 `rule` / `rule_payload` 提供，证据表被清空或 TTL 淘汰也不会变成「—」。
5. UDP 会话按客户端 IP 分发：同一个 IP 上后建立的 `UDP ASSOCIATE` 会接管先前的会话。多设备经同一个 NAT 出口共用时，只有最后一个会话生效。
