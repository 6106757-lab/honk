//! MASQUE connect-ip outbound (RFC 9484).
//!
//! A MASQUE endpoint does not proxy a destination for us — it hands us an IP
//! interface. The tunnel therefore carries *IP packets*, not streams, which
//! makes it structurally different from every other outbound in honk:
//!
//! * we open an extended CONNECT with `:protocol = connect-ip`;
//! * the endpoint replies with ADDRESS_ASSIGN, telling us which source address
//!   our packets must use;
//! * IP packets travel inside DATAGRAM capsules (HTTP/2) or QUIC DATAGRAMs
//!   (HTTP/3).
//!
//! Rather than reimplementing TCP in userspace, honk exposes the tunnel as a
//! TUN device and lets the **kernel** own TCP and UDP. A dialled socket is
//! bound to the TUN device (`SO_BINDTODEVICE`) and to the assigned source
//! address, so the kernel routes it through the tunnel with full BBR, window
//! scaling and retransmit behaviour. See [`tun`] and [`bind`].

pub mod bind;
pub mod capsule;
pub mod carrier;
pub mod http2;
pub mod tun;
pub mod warp;

use async_trait::async_trait;
use honk_config::node::Node;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use super::{
    AsyncReadWrite, PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound,
    UdpSocketTransport, WarmRequirement, WarmableOutbound,
};
use crate::runtime::{NodeRuntime, ProtocolRuntime};

/// Reaches the MASQUE endpoint through another node.
///
/// An endpoint that the direct path out cannot reach is often reachable from
/// an existing node, so a node may name a detour and ride it. Only the
/// generation can turn that name into a dial, so it supplies the dialer once
/// the node set is known.
pub trait CarrierDialer: Send + Sync {
    /// Connect to `endpoint` through the detour node.
    fn connect(
        &self,
        endpoint: SocketAddr,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Box<dyn AsyncReadWrite>>> + Send>>;
}

/// MASQUE outbound handler. Stateless: the tunnel itself lives in the node's
/// generation runtime ([`MasqueRuntime`]) so a reload tears down the old TUN
/// device instead of leaking it.
#[derive(Default)]
pub struct MasqueHandler;

impl MasqueHandler {
    pub fn new() -> Self {
        Self
    }
}

/// Generation-owned MASQUE state: one IP tunnel per node.
///
/// Every flow on the node shares this tunnel — a MASQUE endpoint assigns one
/// address per CONNECT, and each dialled socket simply binds it as its source.
/// Establishing it lazily keeps a node that never carries traffic from owning
/// a TUN device.
pub struct MasqueRuntime {
    tunnel: Mutex<Option<Arc<http2::MasqueTunnel>>>,
    /// Dialer for the node's detour, bound once the generation knows the node
    /// the detour names.
    detour: std::sync::OnceLock<Arc<dyn CarrierDialer>>,
}

impl Default for MasqueRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MasqueRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let established = self.tunnel_count().is_some_and(|count| count != 0);
        formatter
            .debug_struct("MasqueRuntime")
            .field("established", &established)
            .finish()
    }
}

impl MasqueRuntime {
    pub fn new() -> Self {
        Self {
            tunnel: Mutex::new(None),
            detour: std::sync::OnceLock::new(),
        }
    }

    /// Give the runtime the dialer for the node's detour. Ignored when the
    /// node names none, or when the generation binds twice.
    pub fn bind_detour(&self, dialer: Arc<dyn CarrierDialer>) {
        let _ = self.detour.set(dialer);
    }

    /// The node's tunnel, opening it on first use. Concurrent callers share one
    /// CONNECT: a second TUN device for the same node would fight over the
    /// assigned address.
    pub async fn tunnel(
        &self,
        node: &Node,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<http2::MasqueTunnel>> {
        let mut guard = self.tunnel.lock().await;
        if let Some(tunnel) = guard.as_ref() {
            if tunnel.is_alive() {
                return Ok(Arc::clone(tunnel));
            }
            // The carrier died: drop the tunnel so its TUN device goes with
            // it, then rebuild. Cached TUN devices outlive their endpoint.
            guard.take();
        }
        let tunnel = Arc::new(
            carrier::open_tunnel(node, connect_timeout, self.detour.get().map(Arc::as_ref)).await?,
        );
        *guard = Some(Arc::clone(&tunnel));
        Ok(tunnel)
    }

    /// `Some(1)` when the tunnel is up, `Some(0)` when it is not, and `None`
    /// while another task is mid-CONNECT.
    pub fn tunnel_count(&self) -> Option<usize> {
        let guard = self.tunnel.try_lock().ok()?;
        let live = guard.as_ref().is_some_and(|tunnel| tunnel.is_alive());
        Some(usize::from(live))
    }

    /// Drop the tunnel, deleting its TUN device.
    pub async fn close(&self) {
        self.tunnel.lock().await.take();
    }
}

/// Resolve the node's MASQUE runtime, so both dial paths share one message
/// when a node is dispatched without its generation.
fn masque_runtime(runtime: &NodeRuntime) -> anyhow::Result<&MasqueRuntime> {
    match &runtime.runtime {
        ProtocolRuntime::Masque(runtime) => Ok(runtime),
        _ => anyhow::bail!(
            "masque node {} has no masque runtime; it cannot be dialled without its generation",
            runtime.node.name
        ),
    }
}

#[async_trait]
impl TcpOutbound for MasqueHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!(
            "masque node {} needs a generation runtime to own its tunnel; target {target} not dialled",
            node.name
        )
    }

    /// Kernel TCP through the tunnel: bind the socket to the TUN device and to
    /// the address the endpoint assigned, then connect normally.
    async fn dial_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let masque = masque_runtime(runtime.as_ref())?;
        let tunnel = masque
            .tunnel(runtime.node.as_ref(), connect_timeout)
            .await?;
        let source = tunnel.source_for(target).ok_or_else(|| {
            anyhow::anyhow!(
                "masque node {} has no {} source address for {target}",
                runtime.node.name,
                if target.is_ipv4() { "IPv4" } else { "IPv6" },
            )
        })?;
        let stream = bind::connect_via_tun(tunnel.tun_name(), source, target, connect_timeout)
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "masque node {} cannot reach {target} through {}: {error}",
                    runtime.node.name,
                    tunnel.tun_name()
                )
            })?;
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }
}

#[async_trait]
impl PacketOutbound for MasqueHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        anyhow::bail!(
            "masque node {} needs a generation runtime to own its tunnel; UDP {target} not dialled",
            node.name
        )
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        _target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let masque = masque_runtime(runtime.as_ref())?;
        let tunnel = masque
            .tunnel(runtime.node.as_ref(), connect_timeout)
            .await?;
        let source = tunnel.source_for(target).ok_or_else(|| {
            anyhow::anyhow!(
                "masque node {} has no {} source address for UDP {target}",
                runtime.node.name,
                if target.is_ipv4() { "IPv4" } else { "IPv6" },
            )
        })?;
        let socket = bind::udp_via_tun(tunnel.tun_name(), source)?;
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        socket.connect(target).await?;
        Ok(Arc::new(UdpSocketTransport::new(Arc::new(socket), target)))
    }
}

#[async_trait]
impl WarmableOutbound for MasqueHandler {
    /// Establish the tunnel ahead of the first flow. UDP needs nothing extra:
    /// the kernel owns UDP exactly as it owns TCP once the interface exists.
    async fn warm(
        &self,
        runtime: Arc<NodeRuntime>,
        connect_timeout: Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        let masque = masque_runtime(runtime.as_ref())?;
        masque
            .tunnel(runtime.node.as_ref(), connect_timeout)
            .await?;
        Ok(())
    }
}

impl ProbeableOutbound for MasqueHandler {}
