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
//! janitor; userspace SOCKS5 datagrams have none of that. Instead each flow
//! dials the ordinary `PacketTransport` through `ProxyRegistry`, reusing every
//! existing UDP-capable proxy handler (direct, socks5, shadowsocks, vless, ...).
//!
//! Lifecycle: the TCP control connection owns the session (RFC 1928 says the
//! UDP association terminates when the control connection closes). Closing it
//! unregisters the session, aborts every reply task and drops every connection
//! tracker row, so reload/teardown leaves no zombie flows.

use super::dial::resolve_inbound_node;
use super::param::InboundTarget;
use super::super::connection::ControlPlaneHandle;
use crate::connection_tracker::ConnectionEntry;
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
use tokio::sync::{Mutex, mpsc, watch};
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
            (InboundTarget::Ip(IpAddr::V4(Ipv4Addr::from(octets))), start + 5)
        }
        0x04 => {
            let octets: [u8; 16] = bytes.get(start + 1..start + 17)?.try_into().ok()?;
            (InboundTarget::Ip(IpAddr::V6(Ipv6Addr::from(octets))), start + 17)
        }
        0x03 => {
            let len = *bytes.get(start + 1)? as usize;
            if len == 0 {
                return None;
            }
            let raw = bytes.get(start + 2..start + 2 + len)?;
            let domain = std::str::from_utf8(raw).ok()?.trim_end_matches('.').to_owned();
            (InboundTarget::Domain(domain), start + 2 + len)
        }
        _ => return None,
    };
    let port_bytes: [u8; 2] = bytes.get(next..next + 2)?.try_into().ok()?;
    let port = u16::from_be_bytes(port_bytes);
    Some((target, port, next + 2))
}

/// Wrap an upstream reply in a SOCKS5 UDP request header so the client sees a
/// normal datagram from the original destination.
fn wrap_reply(source: &InboundTarget, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    match source {
        InboundTarget::Ip(ip) => encode_address(&mut out, *ip),
        InboundTarget::Domain(domain) => {
            let raw = domain.as_bytes();
            out.push(0x03);
            out.push(raw.len().min(255) as u8);
            out.extend_from_slice(&raw[..raw.len().min(255)]);
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
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
            if table.get(&ip).is_some_and(|live| live.same_channel(&sender)) {
                table.remove(&ip);
            }
        });
    }
}

struct UdpFlow {
    transport: Arc<dyn PacketTransport>,
    last_active: Instant,
    upload: Arc<AtomicU64>,
    tracker_id: String,
    /// Owns the reply loop; aborted when the flow is dropped.
    reply_task: JoinHandle<()>,
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.reply_task.abort();
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
    // Never let the control connection outlive the handshake deadline plus a
    // hard ceiling; a client that parks the TCP channel forever must not pin
    // transports indefinitely.
    let session_deadline = deadline + Duration::from_secs(3600);

    loop {
        tokio::select! {
            biased;
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
                let key = (prepared.target.clone(), prepared.port);
                if !flows.contains_key(&key) && flows.len() >= MAX_FLOWS_PER_SESSION {
                    tracing::debug!(%peer, "入站 UDP 会话 flow 数达上限，丢弃数据报");
                    continue;
                }
                let entry = match ensure_flow(
                    &mut flows, key.clone(), &prepared, peer, config, handle, relay,
                ).await {
                    Ok(flow) => flow,
                    Err(error) => {
                        tracing::debug!(%error, %peer, "入站 UDP flow 建立失败");
                        continue;
                    }
                };
                entry.last_active = Instant::now();
                entry.upload.fetch_add(prepared.payload.len() as u64, Ordering::Relaxed);
                if let Err(error) = entry.transport.send_packet(&prepared.payload).await {
                    tracing::debug!(%error, %peer, "入站 UDP 发送失败，移除 flow");
                    let flow = flows.remove(&key);
                    if let Some(flow) = flow {
                        handle.connection_tracker.remove(&flow.tracker_id);
                    }
                }
            }
        }
    }

    for (_, flow) in flows.drain() {
        handle.connection_tracker.remove(&flow.tracker_id);
    }
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
    let (target, port, offset) =
        parse_address(bytes, 3).ok_or("目标地址解析失败")?;
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

/// Create (or reuse) a flow for `(target, port)`. All the policy lives here:
/// DNS with client context, `inbound()` routing, group selection for UDP, and
/// the ordinary proxy registry's UDP transport.
#[allow(clippy::too_many_arguments)]
async fn ensure_flow<'a>(
    flows: &'a mut HashMap<(InboundTarget, u16), UdpFlow>,
    key: (InboundTarget, u16),
    datagram: &PreparedDatagram,
    peer: SocketAddr,
    config: &ListenerConfig,
    handle: &ControlPlaneHandle,
    relay: &Arc<UdpRelay>,
) -> anyhow::Result<&'a mut UdpFlow> {
    if flows.contains_key(&key) {
        return Ok(flows.get_mut(&key).expect("checked above"));
    }

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
    let (outbound, mark, rule, rule_payload, chains) = {
        let router = handle.router.read().await;
        let (action, matched) = router.route_action_inbound(&conn, &config.name);
        (
            action.outbound.clone(),
            action.mark,
            matched
                .as_ref()
                .map(|hit| hit.rule_type.to_owned())
                .unwrap_or_else(|| "Match".to_owned()),
            matched
                .as_ref()
                .map(|hit| hit.rule_payload.to_owned())
                .unwrap_or_default(),
            vec![action.outbound.clone()],
        )
    };
    if outbound == "block" {
        anyhow::bail!("规则禁止该 UDP 目标");
    }
    let _ = mark; // marks are applied by the eBPF datapath, not by this socket

    let groups = handle.group_manager.read().clone();
    let node = resolve_inbound_node(&groups, &outbound, ipver, ProbeDomain::DataUdp)?;
    let transport = handle
        .proxy_registry
        .dial_udp_transport(&node, target, target_domain.as_deref(), connect_timeout)
        .await?;

    let upload = Arc::new(AtomicU64::new(0));
    let download = Arc::new(AtomicU64::new(0));
    let tracker_id = handle.connection_tracker.register(ConnectionEntry {
        id: uuid::Uuid::new_v4().to_string(),
        source: peer.to_string(),
        destination: target.to_string(),
        proxy: outbound.clone(),
        #[cfg(feature = "native-api")]
        routed_outbound: Some(outbound.clone()),
        #[cfg(feature = "native-api")]
        native_flow_id: None,
        rule,
        rule_payload,
        chains,
        upload: Arc::clone(&upload),
        download: Arc::clone(&download),
        start_time: std::time::Instant::now(),
        domain: target_domain.clone(),
        network: "udp".to_owned(),
        process: None,
        process_path: None,
    });

    // One reply task per flow: it owns `recv_packet` and writes replies back
    // through the shared relay socket, addressed to the session's peer.
    let reply_transport = Arc::clone(&transport);
    let reply_socket = relay.socket();
    let reply_source = datagram.target.clone();
    let reply_port = datagram.port;
    let reply_download = Arc::clone(&download);
    let reply_task = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            match reply_transport.recv_packet(&mut buf).await {
                Ok((size, _)) => {
                    let packet = wrap_reply(&reply_source, reply_port, &buf[..size]);
                    if reply_socket.send_to(&packet, peer).await.is_err() {
                        break;
                    }
                    reply_download.fetch_add(size as u64, Ordering::Relaxed);
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
            upload,
            tracker_id,
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

    #[test]
    fn parses_ipv4_udp_datagram() {
        let mut bytes = vec![0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35];
        bytes.extend_from_slice(b"dns-query");
        let parsed = parse_udp_datagram(&bytes).unwrap();
        assert_eq!(parsed.target, InboundTarget::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
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
        assert_eq!(parsed.target, InboundTarget::Domain("example.com".to_owned()));
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
    fn reply_header_round_trips() {
        let reply = wrap_reply(&InboundTarget::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), 443, b"ok");
        let parsed = parse_udp_datagram(&reply).unwrap();
        assert_eq!(parsed.target, InboundTarget::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.payload, b"ok");
    }

    #[test]
    fn encode_address_handles_v6() {
        let mut out = Vec::new();
        encode_address(&mut out, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(out[0], 0x04);
        assert_eq!(out.len(), 17);
    }
}
