//! SOCKS5 UDP ASSOCIATE relay (RFC 1928 section 7).
//!
//! Design: the relay socket shares the listener's IP **and port** with the TCP
//! listener (TCP and UDP port spaces are independent). A single dispatcher task
//! owns `recv_from` and fans datagrams out to per-control-connection sessions
//! keyed by peer IP, so NAT clients whose UDP source port differs from their
//! TCP source port still work. That is why one shared socket is used instead
//! of a socket per association: a per-association socket would get an ephemeral
//! port that a fixed public port-forward can never reach.
//!
//! This path deliberately does **not** enter the eBPF `udp_endpoint` pool. That
//! pool assumes tproxy-redirected sockets with BPF conn info, leases and a
//! janitor; userspace SOCKS5 datagrams have none of that. Instead each target
//! dials the ordinary `PacketTransport` through `ProxyRegistry`, reusing every
//! existing UDP-capable proxy handler (direct, socks5, shadowsocks, vless, ...).
//!
//! **The connection is the UDP ASSOCIATE session, not a destination.** One
//! association can carry datagrams for hundreds of targets (DNS, QUIC, STUN,
//! network discovery). Registering one observation row per `(target, port)`
//! produced the 1000+ row flood; now the session owns exactly one row, and the
//! per-target flows are internal implementation details with no tracker rows.
//! A `direct(must)` session is terminal-bypassed like its kernel counterpart
//! and owns no row at all.
//!
//! Lifecycle: the TCP control connection owns the session (RFC 1928 says the
//! UDP association terminates when the control connection closes). Closing it
//! unregisters the session, aborts every reply task and acknowledges the single
//! session row, so reload/teardown leaves no zombie observation.

use super::super::connection::ControlPlaneHandle;
use super::dial::resolve_inbound_node;
use super::param::InboundTarget;
use crate::connection_tracker::{
    CloseAction, CloseCompletion, CloseSignal, ConnectionEntry, ConnectionOwner,
};
use crate::routing::ConnectionInfo;
use honk_config::ListenerConfig;
use honk_outbound::alive::{IpVersion, ProbeDomain};
use honk_outbound::proxy::PacketTransport;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Idle flow timeout. Long enough for QUIC keep-alives, short enough that a
/// client that disappears does not pin a proxy transport forever.
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-session flow cap; bounds a single client's transport/FD consumption.
const MAX_FLOWS_PER_SESSION: usize = 256;
/// RFC 1928 datagrams are bounded by UDP itself; cap the buffer we allocate.
const MAX_DATAGRAM: usize = 65535;
/// Sweep interval for idle flows.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Encode a SOCKS5 address (`ATYP` + `ADDR`) into `out`.
pub(super) fn encode_address(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Parse `ATYP + ADDR + PORT` out of a SOCKS5 message. Returns the target,
/// port and the offset of the first payload byte.
fn parse_address(bytes: &[u8], start: usize) -> Option<(InboundTarget, u16, usize)> {
    let atyp = *bytes.get(start)?;
    let (target, next) = match atyp {
        0x01 => {
            let octets: [u8; 4] = bytes.get(start + 1..start + 5)?.try_into().ok()?;
            (
                InboundTarget::Ip(IpAddr::V4(Ipv4Addr::from(octets))),
                start + 5,
            )
        }
        0x04 => {
            let octets: [u8; 16] = bytes.get(start + 1..start + 17)?.try_into().ok()?;
            (
                InboundTarget::Ip(IpAddr::V6(Ipv6Addr::from(octets))),
                start + 17,
            )
        }
        0x03 => {
            let len = *bytes.get(start + 1)? as usize;
            if len == 0 {
                return None;
            }
            let raw = bytes.get(start + 2..start + 2 + len)?;
            let domain = std::str::from_utf8(raw)
                .ok()?
                .trim_end_matches('.')
                .to_owned();
            (InboundTarget::Domain(domain), start + 2 + len)
        }
        _ => return None,
    };
    let port_bytes: [u8; 2] = bytes.get(next..next + 2)?.try_into().ok()?;
    let port = u16::from_be_bytes(port_bytes);
    Some((target, port, next + 2))
}

/// Wrap an upstream reply in a SOCKS5 UDP request header. The source is the
/// **real peer returned by `PacketTransport::recv_packet`**, never a captured
/// request target: the packet contract requires replies to carry the genuine
/// peer, and faking it makes clients treat a reply as a new association.
fn wrap_reply_addr(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    encode_address(&mut out, source.ip());
    out.extend_from_slice(&source.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

type Datagram = (SocketAddr, Vec<u8>);
type SessionTable = Arc<Mutex<HashMap<IpAddr, mpsc::UnboundedSender<Datagram>>>>;

/// One shared UDP socket per listener plus the session registry.
pub(super) struct UdpRelay {
    socket: Arc<UdpSocket>,
    sessions: SessionTable,
    local_addr: SocketAddr,
}

impl UdpRelay {
    pub(super) fn new(socket: std::net::UdpSocket) -> std::io::Result<Arc<Self>> {
        socket.set_nonblocking(true)?;
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        Ok(Arc::new(Self {
            socket,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            local_addr,
        }))
    }

    pub(super) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Address advertised in the SOCKS5 `UDP ASSOCIATE` reply.
    ///
    /// RFC 1928 requires the client to send datagrams to the returned
    /// BND.ADDR. When the listener is bound to a private address behind a
    /// port-forward (typical: `listen: 172.20.1.128` with the router mapping a
    /// public IP:port to it), advertising that private address is unusable for
    /// a client on the public internet. Strict clients such as sing-box
    /// (NekoBox/NekoRay) dial exactly `response.Bind` and fail on the first UDP
    /// packet; lenient clients (Shadowrocket) ignore it and fall back to the
    /// TCP peer, which is why only the former broke.
    ///
    /// Advertising `0.0.0.0` keeps the port and lets the client fall back to
    /// the address it already reached us on (its TCP connection's remote end),
    /// which is the public IP:port in exactly this NAT scenario. LAN clients
    /// keep getting the concrete bound address so nothing changes for them.
    ///
    /// `udp_host` is the explicit override (Xray/3x-ui's `ip` field): when the
    /// public port is mapped to a different port or the public IP cannot be
    /// inferred from the TCP peer, set it to the address clients should use.
    pub(super) fn associate_bind_for(
        &self,
        client: IpAddr,
        udp_host: Option<IpAddr>,
    ) -> SocketAddr {
        if let Some(host) = udp_host {
            return SocketAddr::new(host, self.local_addr.port());
        }
        let bound = self.local_addr.ip();
        let client_is_global = is_globally_routable(client);
        let bound_not_routable_to_client = !is_globally_routable(bound);
        if client_is_global && bound_not_routable_to_client {
            SocketAddr::new(
                if bound.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                },
                self.local_addr.port(),
            )
        } else {
            self.local_addr
        }
    }

    fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Dispatcher loop. Returned as a future so the listener's `JoinSet` owns
    /// it and `abort_all()` during teardown actually cancels the recv loop.
    pub(super) async fn run_dispatcher(
        self: &Arc<Self>,
        mut phase: watch::Receiver<super::ListenerPhase>,
    ) {
        let socket = self.socket();
        let sessions = Arc::clone(&self.sessions);
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            tokio::select! {
                biased;
                changed = phase.changed() => {
                    if changed.is_err() || *phase.borrow() != super::ListenerPhase::Running {
                        break;
                    }
                }
                received = socket.recv_from(&mut buf) => {
                    let (size, peer) = match received {
                        Ok(value) => value,
                        Err(error) => {
                            // A transient error must not spin the loop.
                            tracing::debug!(%error, "入站 UDP relay 接收失败");
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            continue;
                        }
                    };
                    let sender = sessions.lock().await.get(&peer.ip()).cloned();
                    if let Some(sender) = sender {
                        // UDP has no backpressure: drop rather than block
                        // the single dispatcher on one slow session.
                        let _ = sender.send((peer, buf[..size].to_vec()));
                    }
                }
            }
        }
    }
}

/// Whether `ip` is a globally routable unicast address, using only stable
/// `std::net` APIs (`Ipv4Addr::is_global` / `Ipv6Addr::is_global` are still
/// unstable on the toolchain this project builds with). Used solely to decide
/// whether a client can reach a private listener bind address directly.
fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() || v4.is_loopback() || v4.is_private() || v4.is_link_local() {
                return false;
            }
            let o = v4.octets();
            // 100.64.0.0/10 carrier-grade NAT.
            if o[0] == 100 && (o[1] & 0xc0) == 64 {
                return false;
            }
            // 192.0.0.0/24 and 198.18.0.0/15 benchmarking ranges.
            if o[0] == 192 && o[1] == 0 && o[2] == 0 {
                return false;
            }
            if o[0] == 198 && (o[1] & 0xfe) == 18 {
                return false;
            }
            // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved.
            o[0] < 224
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_loopback() || v6.is_unicast_link_local() {
                return false;
            }
            // IPv4-mapped addresses follow their v4 part.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_globally_routable(IpAddr::V4(mapped));
            }
            // fc00::/7 unique local.
            let first = v6.segments()[0];
            !(first & 0xfe00 == 0xfc00)
        }
    }
}

/// Guard that removes the session from the registry on drop. `same_channel`
/// makes sure a session cannot unregister a newer session from the same IP.
struct Registration {
    sessions: SessionTable,
    ip: IpAddr,
    sender: mpsc::UnboundedSender<Datagram>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let sessions = Arc::clone(&self.sessions);
        let ip = self.ip;
        let sender = self.sender.clone();
        tokio::spawn(async move {
            let mut table = sessions.lock().await;
            if table
                .get(&ip)
                .is_some_and(|live| live.same_channel(&sender))
            {
                table.remove(&ip);
            }
        });
    }
}

/// Routing decision for one datagram, computed before the flow is created.
struct RoutedDatagram {
    target: SocketAddr,
    target_domain: Option<String>,
    outbound: String,
    rule: String,
    rule_payload: String,
    chains: Vec<String>,
    /// `must` on a direct action: same terminal-bypass semantics as TCP.
    terminal_direct: bool,
    connect_timeout: Duration,
    ipver: IpVersion,
}

/// A per-target transport. This is **not** a connection — the ASSOCIATE
/// session is — so a flow owns no tracker row.
struct UdpFlow {
    transport: Arc<dyn PacketTransport>,
    last_active: Instant,
    /// Owns the reply loop; aborted when the flow is dropped.
    reply_task: JoinHandle<()>,
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.reply_task.abort();
    }
}

/// The single observation row owned by one UDP ASSOCIATE session.
/// Retirement is RAII for the same reason as the TCP `Tracked` guard: a task
/// aborted by a reload would otherwise leave a row whose `CloseSignal` never
/// becomes terminal, so even `sweep_terminal()` cannot reclaim it.
struct SessionRow {
    id: Option<String>,
    completion: Option<CloseCompletion>,
    handle: ControlPlaneHandle,
}

impl SessionRow {
    fn retire(&mut self) {
        if let Some(completion) = self.completion.take() {
            completion.0.finish(true);
        }
        if let Some(id) = self.id.take() {
            self.handle.connection_tracker.remove(&id);
        }
    }
}

impl Drop for SessionRow {
    fn drop(&mut self) {
        self.retire();
    }
}

fn register_session(
    handle: &ControlPlaneHandle,
    peer: SocketAddr,
    routed: &RoutedDatagram,
    cancel: &Arc<Notify>,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
) -> SessionRow {
    let signal = CloseSignal::new();
    let owner = ConnectionOwner {
        signal: Arc::clone(&signal),
        // One row per session, so one notification is enough: claiming it
        // terminates the whole association (including the control channel).
        action: CloseAction::Inbound {
            cancel: Arc::clone(cancel),
        },
        groups: Vec::new(),
    };
    let id = handle.connection_tracker.register_owned(
        ConnectionEntry {
            id: uuid::Uuid::new_v4().to_string(),
            source: peer.to_string(),
            destination: routed.target.to_string(),
            proxy: routed.outbound.clone(),
            #[cfg(feature = "native-api")]
            routed_outbound: Some(routed.outbound.clone()),
            #[cfg(feature = "native-api")]
            native_flow_id: None,
            rule: routed.rule.clone(),
            rule_payload: routed.rule_payload.clone(),
            chains: routed.chains.clone(),
            upload: Arc::clone(&upload),
            download: Arc::clone(&download),
            start_time: std::time::Instant::now(),
            domain: routed.target_domain.clone(),
            network: "udp".to_owned(),
            process: None,
            process_path: None,
        },
        owner,
    );
    SessionRow {
        id: Some(id),
        completion: Some(CloseCompletion(signal)),
        handle: handle.clone(),
    }
}

/// Serve one UDP ASSOCIATE control connection. Returns when the client closes
/// the TCP control connection (which terminates the association).
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_udp_associate(
    stream: &mut tokio::net::TcpStream,
    client_addr: SocketAddr,
    config: &ListenerConfig,
    handle: &ControlPlaneHandle,
    relay: &Arc<UdpRelay>,
    deadline: Instant,
) -> anyhow::Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Datagram>();
    {
        let mut table = relay.sessions.lock().await;
        table.insert(client_addr.ip(), tx.clone());
    }
    let _registration = Registration {
        sessions: Arc::clone(&relay.sessions),
        ip: client_addr.ip(),
        sender: tx,
    };

    let mut flows: HashMap<(InboundTarget, u16), UdpFlow> = HashMap::new();
    let mut control_byte = [0u8; 1];
    let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let session_cancel = Arc::new(Notify::new());
    // Byte counters are session-wide: every target contributes to the one
    // observation row regardless of how many flows the association carries.
    let session_upload = Arc::new(AtomicU64::new(0));
    let session_download = Arc::new(AtomicU64::new(0));
    // Created on the first non-bypassed datagram; a session whose traffic is
    // entirely `direct(must)` stays invisible, like its kernel counterpart.
    let mut session_row: Option<SessionRow> = None;
    // Never let the control connection outlive the handshake deadline plus a
    // hard ceiling; a client that parks the TCP channel forever must not pin
    // transports indefinitely.
    let session_deadline = deadline + Duration::from_secs(3600);

    loop {
        tokio::select! {
            biased;
            _ = session_cancel.notified() => {
                // The session's single row was claimed for closure: terminate
                // the whole association, not just one destination.
                break;
            }
            read = stream.read(&mut control_byte) => {
                // RFC 1928: any data on the control channel is ignored; only
                // EOF (or an error) terminates the association.
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            _ = tokio::time::sleep_until(session_deadline) => break,
            _ = sweep.tick() => {
                let now = Instant::now();
                // Idle flows disappear, but the session row stays until the
                // control channel ends: it is the connection, not a target.
                flows.retain(|_, flow| now.duration_since(flow.last_active) < FLOW_IDLE_TIMEOUT);
            }
            datagram = rx.recv() => {
                let Some((peer, bytes)) = datagram else { break; };
                let prepared = match parse_udp_datagram(&bytes) {
                    Ok(value) => value,
                    Err(reason) => {
                        tracing::debug!(%reason, %peer, "入站 UDP 数据报格式错误，丢弃");
                        continue;
                    }
                };
                let routed = match route_datagram(&prepared, peer, config, handle).await {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::debug!(%error, %peer, "入站 UDP 路由失败，丢弃");
                        continue;
                    }
                };
                if session_row.is_none() && !routed.terminal_direct {
                    session_row = Some(register_session(
                        handle,
                        peer,
                        &routed,
                        &session_cancel,
                        Arc::clone(&session_upload),
                        Arc::clone(&session_download),
                    ));
                }
                let key = (prepared.target.clone(), prepared.port);
                if !flows.contains_key(&key) && flows.len() >= MAX_FLOWS_PER_SESSION {
                    tracing::debug!(%peer, "入站 UDP 会话 flow 数达上限，丢弃数据报");
                    continue;
                }
                let entry = match ensure_flow(
                    &mut flows, key.clone(), &routed, peer, handle, relay,
                    Arc::clone(&session_download),
                ).await {
                    Ok(flow) => flow,
                    Err(error) => {
                        tracing::debug!(%error, %peer, "入站 UDP flow 建立失败");
                        continue;
                    }
                };
                entry.last_active = Instant::now();
                session_upload.fetch_add(prepared.payload.len() as u64, Ordering::Relaxed);
                if let Err(error) = entry.transport.send_packet(&prepared.payload).await {
                    tracing::debug!(%error, %peer, "入站 UDP 发送失败，移除 flow");
                    flows.remove(&key);
                }
            }
        }
    }

    flows.clear();
    // Acknowledge before the transports go away so an in-flight bulk close
    // observes `Closed`, not `Failed`. Dropping the guard is idempotent.
    drop(session_row);
    Ok(())
}

struct PreparedDatagram {
    target: InboundTarget,
    port: u16,
    payload: Vec<u8>,
}

fn parse_udp_datagram(bytes: &[u8]) -> Result<PreparedDatagram, &'static str> {
    if bytes.len() < 10 {
        return Err("数据报过短");
    }
    if bytes[0] != 0x00 || bytes[1] != 0x00 {
        return Err("RSV 非零");
    }
    if bytes[2] != 0x00 {
        // Fragmentation is explicitly optional in RFC 1928; drop fragments.
        return Err("不支持分片");
    }
    let (target, port, offset) = parse_address(bytes, 3).ok_or("目标地址解析失败")?;
    if port == 0 {
        return Err("目标端口为零");
    }
    if offset > bytes.len() {
        return Err("数据报截断");
    }
    Ok(PreparedDatagram {
        target,
        port,
        payload: bytes[offset..].to_vec(),
    })
}

/// Route one datagram before any transport is created: client-aware DNS,
/// `inbound()` rules, and the `must` terminal-bypass decision all live here.
async fn route_datagram(
    datagram: &PreparedDatagram,
    peer: SocketAddr,
    config: &ListenerConfig,
    handle: &ControlPlaneHandle,
) -> anyhow::Result<RoutedDatagram> {
    let (target_ip, target_domain) = match &datagram.target {
        InboundTarget::Ip(ip) => (*ip, None),
        InboundTarget::Domain(domain) => {
            let resolved = handle
                .dns_controller
                .resolve_domain_for_source(domain, peer)
                .await?;
            let ip = resolved
                .iter()
                .copied()
                .find(IpAddr::is_ipv4)
                .or_else(|| resolved.first().copied())
                .ok_or_else(|| anyhow::anyhow!("DNS 解析 '{domain}' 无结果"))?;
            (ip, Some(domain.clone()))
        }
    };
    let target = SocketAddr::new(target_ip, datagram.port);
    let ipver = if target_ip.is_ipv4() {
        IpVersion::V4
    } else {
        IpVersion::V6
    };

    let connect_timeout = {
        let cfg = handle.config.read().await;
        Duration::from_millis(cfg.global.connect_timeout_ms)
    };
    let conn = ConnectionInfo {
        domain: target_domain.clone(),
        dst_ip: target_ip,
        dst_port: datagram.port,
        src_ip: peer.ip(),
        src_port: peer.port(),
        protocol: "udp",
        process_name: None,
        mac: None,
        dscp: None,
    };
    let (outbound, rule, rule_payload, chains, terminal_direct) = {
        let router = handle.router.read().await;
        let (action, matched) = router.route_action_inbound(&conn, &config.name);
        (
            action.outbound.clone(),
            matched
                .as_ref()
                .map(|hit| hit.rule_type.to_owned())
                .unwrap_or_else(|| "Match".to_owned()),
            matched
                .as_ref()
                .map(|hit| hit.rule_payload.to_owned())
                .unwrap_or_default(),
            vec![action.outbound.clone()],
            action.must && action.outbound == "direct",
        )
    };
    if outbound == "block" {
        anyhow::bail!("规则禁止该 UDP 目标");
    }
    // Marks are applied by the eBPF datapath; this is a plain userspace socket.
    Ok(RoutedDatagram {
        target,
        target_domain,
        outbound,
        rule,
        rule_payload,
        chains,
        terminal_direct,
        connect_timeout,
        ipver,
    })
}

/// Create (or reuse) the transport for one target. A flow is internal to the
/// session and owns no tracker row; the session-level `download` counter is
/// shared by every target's reply loop.
async fn ensure_flow<'a>(
    flows: &'a mut HashMap<(InboundTarget, u16), UdpFlow>,
    key: (InboundTarget, u16),
    routed: &RoutedDatagram,
    peer: SocketAddr,
    handle: &ControlPlaneHandle,
    relay: &Arc<UdpRelay>,
    download: Arc<AtomicU64>,
) -> anyhow::Result<&'a mut UdpFlow> {
    if flows.contains_key(&key) {
        return Ok(flows.get_mut(&key).expect("checked above"));
    }

    let groups = handle.group_manager.read().clone();
    let node = resolve_inbound_node(
        &groups,
        &routed.outbound,
        routed.ipver,
        ProbeDomain::DataUdp,
    )?;
    let transport = handle
        .proxy_registry
        .dial_udp_transport(
            &node,
            routed.target,
            routed.target_domain.as_deref(),
            routed.connect_timeout,
        )
        .await?;

    // One reply task per flow. It owns `recv_packet` and writes replies back
    // through the shared relay socket, addressed to the session's peer.
    let reply_transport = Arc::clone(&transport);
    let reply_socket = relay.socket();
    let reply_task = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            match reply_transport.recv_packet(&mut buf).await {
                Ok((size, source)) => {
                    // The packet contract requires the real peer from
                    // recv_packet as the reply source; using the captured
                    // request target makes clients open a new association.
                    let packet = wrap_reply_addr(source, &buf[..size]);
                    if reply_socket.send_to(&packet, peer).await.is_err() {
                        break;
                    }
                    download.fetch_add(size as u64, Ordering::Relaxed);
                }
                Err(error) => {
                    tracing::debug!(%error, "入站 UDP flow 接收结束");
                    break;
                }
            }
        }
    });

    flows.insert(
        key.clone(),
        UdpFlow {
            transport,
            last_active: Instant::now(),
            reply_task,
        },
    );
    Ok(flows.get_mut(&key).expect("just inserted"))
}

/// Bind the UDP half of a listener on the same address as the TCP half. A
/// failure here degrades to TCP-only instead of breaking an existing listener.
pub(super) fn bind_udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay_bound_to_private() -> UdpRelay {
        // A bound std socket supplies the local_addr; the socket itself is not
        // used by associate_bind_for.
        let socket = std::net::UdpSocket::bind("172.20.1.128:0")
            .or_else(|_| std::net::UdpSocket::bind("127.0.0.1:0"))
            .unwrap();
        UdpRelay::new(socket).unwrap()
    }

    #[test]
    fn globally_routable_ip_classification() {
        for ip in ["8.8.8.8", "117.174.205.95", "1.1.1.1"] {
            assert!(
                is_globally_routable(ip.parse().unwrap()),
                "{ip} should be global"
            );
        }
        for ip in [
            "172.20.1.128",
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "0.0.0.0",
        ] {
            assert!(
                !is_globally_routable(ip.parse().unwrap()),
                "{ip} should not be global"
            );
        }
    }

    #[test]
    fn associate_advertises_zero_for_public_client_behind_private_bind() {
        let relay = relay_bound_to_private();
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let advertised = relay.associate_bind_for(public, None);
        assert!(advertised.ip().is_unspecified(), "got {}", advertised.ip());
        assert_eq!(advertised.port(), relay.local_addr().port());
    }

    #[test]
    fn associate_advertises_concrete_bind_for_lan_client() {
        let relay = relay_bound_to_private();
        let lan: IpAddr = "172.20.1.185".parse().unwrap();
        assert_eq!(relay.associate_bind_for(lan, None), relay.local_addr());
    }

    #[test]
    fn associate_honors_explicit_udp_host() {
        let relay = relay_bound_to_private();
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let host: IpAddr = "117.174.205.95".parse().unwrap();
        assert_eq!(relay.associate_bind_for(public, Some(host)).ip(), host);
    }

    #[test]
    fn parses_ipv4_udp_datagram() {
        let mut bytes = vec![0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35];
        bytes.extend_from_slice(b"dns-query");
        let parsed = parse_udp_datagram(&bytes).unwrap();
        assert_eq!(
            parsed.target,
            InboundTarget::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        );
        assert_eq!(parsed.port, 53);
        assert_eq!(parsed.payload, b"dns-query");
    }

    #[test]
    fn parses_domain_udp_datagram() {
        let mut bytes = vec![0x00, 0x00, 0x00, 0x03, 0x0b];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&443u16.to_be_bytes());
        bytes.extend_from_slice(b"payload");
        let parsed = parse_udp_datagram(&bytes).unwrap();
        assert_eq!(
            parsed.target,
            InboundTarget::Domain("example.com".to_owned())
        );
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.payload, b"payload");
    }

    #[test]
    fn rejects_fragments_and_bad_rsv() {
        let base = vec![0x00, 0x00, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x35];
        assert!(parse_udp_datagram(&base).is_ok());
        let mut fragment = base.clone();
        fragment[2] = 0x01;
        assert!(parse_udp_datagram(&fragment).is_err());
        let mut bad_rsv = base;
        bad_rsv[1] = 0x01;
        assert!(parse_udp_datagram(&bad_rsv).is_err());
    }

    #[test]
    fn reply_header_uses_real_peer() {
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let reply = wrap_reply_addr(source, b"ok");
        let parsed = parse_udp_datagram(&reply).unwrap();
        assert_eq!(
            parsed.target,
            InboundTarget::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.payload, b"ok");
    }

    #[test]
    fn reply_header_handles_ipv6_peer() {
        let source: SocketAddr = "[2001:db8::1]:5353".parse().unwrap();
        let reply = wrap_reply_addr(source, b"x");
        assert_eq!(reply[3], 0x04);
        let parsed = parse_udp_datagram(&reply).unwrap();
        assert_eq!(
            parsed.target,
            InboundTarget::Ip("2001:db8::1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(parsed.port, 5353);
        assert_eq!(parsed.payload, b"x");
    }

    #[test]
    fn encode_address_handles_v6() {
        let mut out = Vec::new();
        encode_address(&mut out, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(out[0], 0x04);
        assert_eq!(out.len(), 17);
    }
}
