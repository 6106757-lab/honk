//! The path a node takes out when it names a detour.
//!
//! A server the direct path out cannot reach is often reachable from another
//! node, so a node may name one. Turning that name into a dial needs both the
//! node set and the proxy registry, so the generation resolves it once and
//! hands the node a [`DetourPath`].
//!
//! A dial through it yields the same byte stream a socket would, and for UDP
//! the same framed transport, so the protocol above does not have to know
//! which path it is on.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::proxy::{AsyncReadWrite, PacketTransport, ProxyRegistry};
use crate::runtime::OutboundRuntimeRegistry;

/// Resolve a `host:port` pair to an address a detour can dial.
///
/// The detour is dialled by address, so the name has to be resolved here
/// rather than inside the detour node: only this end knows which host the
/// node's traffic is actually for.
pub async fn resolve_endpoint(address: &str) -> anyhow::Result<SocketAddr> {
    tokio::net::lookup_host(address)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("endpoint {address} resolved to nothing"))
}

/// The node this one dials through, pinned to the generation that built it.
///
/// Dials stay inside that generation: a retired one refuses them, and the node
/// is rebuilt with the next.
#[derive(Debug)]
pub struct DetourPath {
    proxies: Arc<ProxyRegistry>,
    generation: Arc<OutboundRuntimeRegistry>,
    node_id: uuid::Uuid,
}

impl DetourPath {
    /// Pin a detour to the generation whose node set named it.
    pub fn new(
        proxies: Arc<ProxyRegistry>,
        generation: Arc<OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
    ) -> Self {
        Self {
            proxies,
            generation,
            node_id,
        }
    }

    /// Open a stream to `target` through the detour node.
    ///
    /// A detour that cannot carry the stream fails the dial. Falling back to
    /// the direct path would send traffic out of the real interface without
    /// saying so, which is worse than a node that is simply down.
    pub async fn connect(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let stream = self
            .proxies
            .dial_runtime(
                Arc::clone(&self.generation),
                self.node_id,
                target,
                None,
                timeout,
            )
            .await?;
        Ok(stream.stream)
    }

    /// Open a framed UDP transport to `target` through the detour node.
    pub async fn connect_udp(
        &self,
        target: SocketAddr,
        target_domain: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.proxies
            .dial_udp_transport_runtime(
                Arc::clone(&self.generation),
                self.node_id,
                target,
                target_domain,
                timeout,
            )
            .await
    }
}
