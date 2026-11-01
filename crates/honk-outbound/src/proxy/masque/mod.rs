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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use super::{
    PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound,
    UdpSocketTransport, WarmRequirement, WarmableOutbound,
};
use crate::runtime::{NodeRuntime, ProtocolRuntime};

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

/// Generation-owned MASQUE state: one IP tunnel per path.
///
/// Every flow on the node shares the tunnel for the path it takes — a MASQUE
/// endpoint assigns one address per CONNECT, and each dialled socket simply
/// binds it as its source. Establishing it lazily keeps a node that never
/// carries traffic from owning a TUN device.
///
/// One per path rather than one per node, because the tunnel *is* the path:
/// its carrier is the connection to the endpoint, and a carrier opened over
/// the node's own path is not one a flow that was told to ride a detour may
/// use. Each path therefore gets its own TUN device and its own default-route
/// metric, which is what stops the two from covering each other.
pub struct MasqueRuntime {
    tunnels: Mutex<std::collections::HashMap<Option<String>, TunnelSlot>>,
}

/// A live tunnel and the device slot it holds.
///
/// The slot is kept so a name and a route metric are never handed out twice
/// while a live tunnel still answers to them.
struct TunnelSlot {
    slot: usize,
    tunnel: Arc<http2::MasqueTunnel>,
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
            tunnels: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The node's own tunnel, opening it on first use.
    ///
    /// The detour is read from the node's runtime rather than kept here: the
    /// generation binds it in one place, so a carrier can only ever take the
    /// path once.
    pub async fn tunnel(
        &self,
        runtime: &NodeRuntime,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<http2::MasqueTunnel>> {
        self.tunnel_for(runtime, connect_timeout, runtime.detour().map(Arc::as_ref))
            .await
    }

    /// The tunnel for a path the caller names, which is how a group's detour
    /// reaches a MASQUE member.
    ///
    /// Callers on the same path share one CONNECT. Callers on different paths
    /// get different tunnels, each with its own TUN device and route metric.
    pub async fn tunnel_for(
        &self,
        runtime: &NodeRuntime,
        connect_timeout: Duration,
        detour: Option<&crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<Arc<http2::MasqueTunnel>> {
        let key = detour.map(|path| path.key());
        let mut guard = self.tunnels.lock().await;
        if guard.get(&key).is_some_and(|entry| entry.tunnel.is_alive()) {
            return Ok(Arc::clone(&guard[&key].tunnel));
        }
        // The carrier died: drop the tunnel so its TUN device goes with it,
        // then rebuild. Cached TUN devices outlive their endpoint.
        guard.remove(&key);
        // The lowest slot nobody is holding.
        let slot = (0..=guard.len())
            .find(|candidate| !guard.values().any(|entry| entry.slot == *candidate))
            .unwrap_or(guard.len());
        let tunnel = Arc::new(
            carrier::open_tunnel(runtime.node.as_ref(), connect_timeout, detour, slot).await?,
        );
        guard.insert(
            key,
            TunnelSlot {
                slot,
                tunnel: Arc::clone(&tunnel),
            },
        );
        Ok(tunnel)
    }

    /// How many tunnels are up, and `None` while another task is mid-CONNECT.
    pub fn tunnel_count(&self) -> Option<usize> {
        let guard = self.tunnels.try_lock().ok()?;
        Some(
            guard
                .values()
                .filter(|entry| entry.tunnel.is_alive())
                .count(),
        )
    }

    /// Drop the tunnels, deleting their TUN devices.
    pub async fn close(&self) {
        self.tunnels.lock().await.clear();
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
        let tunnel = masque.tunnel(runtime.as_ref(), connect_timeout).await?;
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

    /// The same dial over a detour the caller names.
    ///
    /// The tunnel *is* the path — its carrier is the one connection to the
    /// endpoint that every flow on the node shares — so a flow that was told
    /// to ride a detour cannot use the tunnel that was opened over the
    /// node's own path. It gets the tunnel for *this* path, which the node
    /// opens on its own device if it does not have one yet.
    async fn dial_runtime_detoured(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        detour: &Arc<crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<ProxyStream> {
        let masque = masque_runtime(runtime.as_ref())?;
        let tunnel = masque
            .tunnel_for(runtime.as_ref(), connect_timeout, Some(detour.as_ref()))
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
        let tunnel = masque.tunnel(runtime.as_ref(), connect_timeout).await?;
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
        masque.tunnel(runtime.as_ref(), connect_timeout).await?;
        Ok(())
    }
}

impl ProbeableOutbound for MasqueHandler {}
