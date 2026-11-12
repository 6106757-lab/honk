//! Mixed-port dispatcher and connection lifecycle.
//!
//! One byte decides the protocol (mihomo `Peek(1)`), but the byte is left in
//! [`ReadBuffer`] so the chosen parser still sees a complete request.
//!
//! HTTP uses a per-request loop: every iteration re-parses the head, re-dials
//! through the router, and re-registers the connection. A keep-alive client
//! that switches `Host` therefore gets a fresh upstream instead of having its
//! second request silently delivered to the first request's server.
//! CONNECT is a tunnel: it returns after the relay ends.

use super::super::connection::ControlPlaneHandle;
use super::dial::{InboundDial, InboundDialError};
use super::http::{self, CONNECT_ESTABLISHED};
use super::param::{self, ClientParam, InboundTarget, ProtoError, ReadBuffer};
use super::socks::{self, SocksRequest};
use super::udp::{self, UdpRelay};
use crate::connection_tracker::{
    CloseAction, CloseCompletion, CloseSignal, ConnectionEntry, ConnectionOwner,
};
use honk_config::ListenerConfig;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Instant;

/// A userspace listener relay has no kernel flow, no eBPF janitor and no TTL.
/// When a peer disappears without FIN/RST (cellular handover, radio drop),
/// `relay_proxy` would otherwise wait forever and its observation row would
/// stay `active` indefinitely. This watchdog is this path's lifecycle
/// endpoint, symmetric to the kernel path's janitor sweep. It is deliberately
/// longer than the listener's TCP keepalive detection window: keepalive is
/// authoritative, this is only the last-resort backstop.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const RELAY_IDLE_CHECK: Duration = Duration::from_secs(10);

/// Owns exactly one observation row for the lifetime of one listener
/// connection. Retirement is RAII: the row is acked and removed when this
/// value is dropped, whichever way the connection ends — a normal relay
/// finish, an API close, an early `?` return after registration, or the whole
/// task being aborted by a reload. A row left behind by any of those paths
/// never reaches a terminal `CloseSignal`, so `sweep_terminal()` cannot reap
/// it either; that is the zombie-row source this guard closes.
struct Tracked {
    /// `None` for a `direct(must)` relay: the kernel path bypasses the control
    /// plane for those and therefore has no observation row either.
    id: Option<String>,
    /// Owning transport acknowledgement. Dropping it without an explicit
    /// `finish(true)` would make a close request report a failure.
    completion: Option<CloseCompletion>,
    handle: ControlPlaneHandle,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

impl Tracked {
    fn register(handle: &ControlPlaneHandle, param: &ClientParam, dial: &InboundDial) -> Self {
        let handle = handle.clone();
        let upload = Arc::new(AtomicU64::new(0));
        let download = Arc::new(AtomicU64::new(0));
        if dial.terminal_direct {
            // `must` + direct means terminal bypass. Keep the relay invisible
            // in the panel instead of registering every domestic direct
            // connection of a phone that proxies all of its traffic here.
            return Self {
                id: None,
                completion: None,
                handle,
                upload,
                download,
            };
        }
        let signal = CloseSignal::new();
        let owner = ConnectionOwner {
            signal: Arc::clone(&signal),
            // No kernel-side teardown: the relay below awaits `cancelled()`
            // directly, which `claim()` wakes by leaving `Active`.
            action: CloseAction::Tcp,
            // Inbound connections have no kernel flow, so group interrupts do
            // not target them. They are still closable by id and in bulk.
            groups: Vec::new(),
        };
        let entry = ConnectionEntry {
            id: uuid::Uuid::new_v4().to_string(),
            source: param.client_addr.to_string(),
            destination: dial.target.to_string(),
            proxy: dial.outbound.clone(),
            #[cfg(feature = "native-api")]
            routed_outbound: Some(dial.outbound.clone()),
            // Inbound connections do not create a flow-evidence record. The
            // connections API falls back to the tracker fields captured here,
            // so the rule column survives evidence-table resets / TTL anyway.
            #[cfg(feature = "native-api")]
            native_flow_id: None,
            rule: dial.rule.clone(),
            rule_payload: dial.rule_payload.clone(),
            chains: dial.chains.clone(),
            upload: Arc::clone(&upload),
            download: Arc::clone(&download),
            start_time: std::time::Instant::now(),
            domain: dial.domain.clone(),
            network: "tcp".to_owned(),
            process: None,
            process_path: None,
        };
        let id = handle.connection_tracker.register_owned(entry, owner);
        Self {
            id: Some(id),
            completion: Some(CloseCompletion(signal)),
            handle,
            upload,
            download,
        }
    }

    /// Resolves as soon as the API claims this row for closure. A bypassed
    /// relay has no row to claim, so it simply never resolves.
    async fn cancelled(&self) {
        match &self.completion {
            Some(completion) => completion.0.cancelled().await,
            None => std::future::pending().await,
        }
    }

    /// Resolves once the relay has carried no bytes at all for
    /// `RELAY_IDLE_TIMEOUT`. Any traffic (including keep-alives) resets it,
    /// so live long-lived connections are never cut.
    async fn idle(&self) {
        let mut last = self.total();
        let mut quiet = Duration::ZERO;
        loop {
            tokio::time::sleep(RELAY_IDLE_CHECK).await;
            let now = self.total();
            if now != last {
                last = now;
                quiet = Duration::ZERO;
            } else {
                quiet += RELAY_IDLE_CHECK;
                if quiet >= RELAY_IDLE_TIMEOUT {
                    return;
                }
            }
        }
    }

    fn total(&self) -> u64 {
        self.upload.load(Ordering::Relaxed) + self.download.load(Ordering::Relaxed)
    }

    fn retire(&mut self) {
        // Acknowledge before removing the row: an in-flight close request is
        // waiting on this signal and must observe `Closed`, not `Failed`.
        // `take` makes this idempotent — `Drop` runs it a second time on the
        // normal path without touching the tracker again.
        if let Some(completion) = self.completion.take() {
            completion.0.finish(true);
        }
        if let Some(id) = self.id.take() {
            self.handle.connection_tracker.remove(&id);
        }
    }

    fn progress(&self) -> crate::relay::RelayProgress {
        crate::relay::RelayProgress {
            upload: Arc::clone(&self.upload),
            download: Arc::clone(&self.download),
            outbound_upload: None,
            outbound_download: None,
            first_response: None,
            on_transfer: None,
        }
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Listener sockets have no eBPF janitor. A client that vanishes without
/// FIN/RST (cellular handover, radio drop) must therefore be detected by the
/// kernel, not by a userspace timer. Keepalive covers the idle case;
/// `TCP_USER_TIMEOUT` bounds how long unacknowledged upstream data may pin a
/// relay that keeps making progress — such a relay never trips the idle
/// watchdog because its byte counters keep changing.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn arm_client_liveness(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    if let Err(error) = sock.set_keepalive(true) {
        tracing::debug!(%error, "入站连接 keepalive 开启失败");
        return;
    }
    let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(60));
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let keepalive = keepalive
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    if let Err(error) = sock.set_tcp_keepalive(&keepalive) {
        tracing::debug!(%error, "入站连接 keepalive 参数失败");
    }
    if let Err(error) = sock.set_tcp_user_timeout(Some(Duration::from_secs(120))) {
        tracing::debug!(%error, "入站连接 user timeout 设置失败");
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn arm_client_liveness(_stream: &TcpStream) {}

pub(super) async fn serve_mixed_connection(
    stream: TcpStream,
    client_addr: SocketAddr,
    config: &ListenerConfig,
    handle: &ControlPlaneHandle,
    relay: Option<&Arc<UdpRelay>>,
) -> anyhow::Result<()> {
    arm_client_liveness(&stream);
    let mut param = ClientParam {
        listener: config.name.clone(),
        user: None,
        client_addr,
        target: InboundTarget::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        target_port: 0,
    };
    let mut rb = ReadBuffer::new(stream, config.max_header_bytes);
    let handshake_deadline =
        Instant::now() + std::time::Duration::from_millis(config.handshake_timeout_ms);

    let first = match rb.peek_u8(handshake_deadline).await {
        Ok(byte) => byte,
        Err(ProtoError::Closed) => return Ok(()),
        Err(error) => {
            tracing::debug!(%error, %client_addr, "inbound first byte failed");
            return Ok(());
        }
    };

    if first == 0x05 {
        return serve_socks(
            &mut rb,
            &mut param,
            config,
            handle,
            relay,
            handshake_deadline,
        )
        .await;
    }
    serve_http(&mut rb, &mut param, config, handle, handshake_deadline).await
}

#[allow(clippy::too_many_arguments)]
async fn serve_socks(
    rb: &mut ReadBuffer<TcpStream>,
    param: &mut ClientParam,
    config: &ListenerConfig,
    handle: &ControlPlaneHandle,
    relay: Option<&Arc<UdpRelay>>,
    deadline: Instant,
) -> anyhow::Result<()> {
    let request = match socks::negotiate(rb, config.auth.as_ref(), deadline).await {
        Ok(value) => value,
        Err(ProtoError::Closed) => return Ok(()),
        Err(error) => {
            tracing::debug!(%error, "SOCKS5 negotiation failed");
            let code = match error {
                ProtoError::Auth | ProtoError::Unsupported(_) => 0x02,
                _ => 0x01,
            };
            let _ = socks::write_reply(rb, code).await;
            return Ok(());
        }
    };
    let (target, port, user) = match request {
        SocksRequest::Connect { target, port, user } => (target, port, user),
        SocksRequest::UdpAssociate { user, .. } => {
            param.user = user;
            let Some(relay) = relay else {
                tracing::debug!("listener has no UDP relay; rejecting UDP ASSOCIATE");
                let _ = socks::write_reply(rb, 0x07).await; // command not supported
                return Ok(());
            };
            // Advertise a bind address the client can actually reach. udp_host
            // is returned verbatim (IP or DDNS hostname); the client resolves
            // a hostname with its own DNS. Omit it on mihomo, which cannot
            // handle a domain BND.ADDR and falls back from 0.0.0.0 instead.
            let advertised = relay.associate_bind_for(config.udp_host.as_ref());
            if let Err(error) = socks::write_reply_addr(rb, 0x00, advertised).await {
                tracing::debug!(%error, "SOCKS5 UDP ASSOCIATE 回复失败");
                return Ok(());
            }
            return udp::serve_udp_associate(
                rb.stream_mut(),
                param.client_addr,
                config,
                handle,
                relay,
                deadline,
            )
            .await;
        }
    };
    socks::fill_param(param, target, port, user);

    let dial = match handle.dial_for_inbound(param).await {
        Ok(dial) => dial,
        Err(InboundDialError::Blocked(name)) => {
            tracing::debug!(%name, "SOCKS5 connection blocked by routing");
            let _ = socks::write_reply(rb, 0x02).await;
            return Ok(());
        }
        Err(InboundDialError::Failed(error)) => {
            tracing::debug!(%error, "SOCKS5 dial failed");
            let _ = socks::write_reply(rb, 0x05).await;
            return Ok(());
        }
    };
    socks::write_reply(rb, 0x00).await?;

    let pending = rb.drain_buffered();
    let mut tracked = Tracked::register(handle, param, &dial);
    let mut stream = dial.stream;
    if !pending.is_empty() {
        stream.stream.write_all(&pending).await?;
    }
    let relay = crate::relay::relay_proxy(
        rb.stream_mut(),
        stream,
        param.client_addr,
        dial.target,
        tracked.progress(),
    );
    // Dropping the relay future drops both sockets, which is exactly what a
    // "close connection" request must do for a userspace listener.
    let result = tokio::select! {
        biased;
        _ = tracked.cancelled() => None,
        _ = tracked.idle() => None,
        result = relay => Some(result),
    };
    tracked.retire();
    if let Some(result) = result {
        result?;
    }
    Ok(())
}

async fn serve_http(
    rb: &mut ReadBuffer<TcpStream>,
    param: &mut ClientParam,
    config: &ListenerConfig,
    handle: &ControlPlaneHandle,
    handshake_deadline: Instant,
) -> anyhow::Result<()> {
    let mut first = true;
    loop {
        // One total deadline per request head. A slow drip cannot renew it.
        let deadline = if first {
            first = false;
            handshake_deadline
        } else {
            Instant::now() + std::time::Duration::from_millis(config.request_timeout_ms)
        };
        let head = match rb.read_head(deadline).await {
            Ok(head) => head,
            Err(ProtoError::Closed) => return Ok(()),
            Err(error) => {
                tracing::debug!(%error, "HTTP request head failed");
                let status = match error {
                    ProtoError::TooLarge => 431,
                    ProtoError::Timeout => 408,
                    _ => 400,
                };
                param::http_error(rb, status, "Bad Request").await;
                return Ok(());
            }
        };
        let request = match http::parse_http_head(&head, config.auth.as_ref()) {
            Ok(request) => request,
            Err(error) => {
                let (status, reason) = match error {
                    ProtoError::Auth => (407, "Proxy Authentication Required"),
                    ProtoError::Unsupported(_) => (405, "Method Not Allowed"),
                    _ => (400, "Bad Request"),
                };
                tracing::debug!(%error, "HTTP request rejected");
                param::http_error(rb, status, reason).await;
                return Ok(());
            }
        };
        param.target = request.target.clone();
        param.target_port = request.port;
        param.user = request.user.clone();

        let dial = match handle.dial_for_inbound(param).await {
            Ok(dial) => dial,
            Err(InboundDialError::Blocked(name)) => {
                tracing::debug!(%name, "HTTP connection blocked by routing");
                param::http_error(rb, 403, "Forbidden").await;
                return Ok(());
            }
            Err(InboundDialError::Failed(error)) => {
                tracing::debug!(%error, "HTTP dial failed");
                param::http_error(rb, 502, "Bad Gateway").await;
                return Ok(());
            }
        };

        let mut tracked = Tracked::register(handle, param, &dial);
        let mut stream = dial.stream;
        if request.connect {
            rb.write_all(CONNECT_ESTABLISHED).await?;
            let pending = rb.drain_buffered();
            if !pending.is_empty() {
                stream.stream.write_all(&pending).await?;
            }
            let relay = crate::relay::relay_proxy(
                rb.stream_mut(),
                stream,
                param.client_addr,
                dial.target,
                tracked.progress(),
            );
            let result = tokio::select! {
                biased;
                _ = tracked.cancelled() => None,
                _ = tracked.idle() => None,
                result = relay => Some(result),
            };
            tracked.retire();
            if let Some(result) = result {
                result?;
            }
            // A CONNECT tunnel owns the rest of the client connection.
            return Ok(());
        }

        let forward = http::forward_plain(
            rb,
            &request,
            &mut *stream.stream,
            &tracked.upload,
            &tracked.download,
        );
        let result = tokio::select! {
            biased;
            _ = tracked.cancelled() => None,
            _ = tracked.idle() => None,
            result = forward => Some(result),
        };
        tracked.retire();
        match result {
            Some(Err(error)) => {
                tracing::debug!(%error, "HTTP request forwarding ended");
                return Ok(());
            }
            // The API closed this connection, or the idle watchdog decided
            // the peer vanished. Either way stop serving this client socket.
            None => return Ok(()),
            Some(Ok(())) => {}
        }
        // Upstream closed (we forced `Connection: close`). Loop for the next
        // keep-alive request with a fresh dial and a fresh rule decision.
    }
}
