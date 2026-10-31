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
//! scaling and retransmit behaviour. See [`tun`] and [`carrier`].

pub mod capsule;
pub mod http2;
pub mod tun;

use async_trait::async_trait;
use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::{
    PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound, WarmRequirement,
    WarmableOutbound,
};
use crate::runtime::NodeRuntime;

/// MASQUE outbound handler.
#[derive(Default)]
pub struct MasqueHandler;

impl MasqueHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TcpOutbound for MasqueHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!("masque tunnel is not established yet for {target}")
    }
}

#[async_trait]
impl PacketOutbound for MasqueHandler {
    async fn dial_udp_transport(
        &self,
        _node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        anyhow::bail!("masque UDP tunnel is not established yet for {target}")
    }
}

#[async_trait]
impl WarmableOutbound for MasqueHandler {
    async fn warm(
        &self,
        _runtime: Arc<NodeRuntime>,
        _connect_timeout: Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        // The tunnel is owned per generation; until the carrier is wired the
        // warm pass has nothing to establish.
        Ok(())
    }
}

impl ProbeableOutbound for MasqueHandler {}
