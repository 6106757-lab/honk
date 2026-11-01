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

use honk_config::node::Node;

use crate::proxy::{AsyncReadWrite, PacketTransport, ProxyRegistry};
use crate::runtime::OutboundRuntimeRegistry;

/// Refuse a dial for a node that names a detour this generation has not bound.
///
/// A node on a detour has to ride it. Dialling the direct path because the
/// binding is missing would send its traffic out of the real interface while
/// looking like a perfectly ordinary connection.
pub fn ensure_bound(node: &Node, detour: Option<&DetourPath>) -> anyhow::Result<()> {
    if detour.is_none()
        && let Some(name) = node.detour_name()
    {
        anyhow::bail!(
            "node {}: detour {name:?} is not bound in this generation",
            node.name
        );
    }
    Ok(())
}

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
pub struct DetourPath {
    proxies: Arc<ProxyRegistry>,
    generation: Arc<OutboundRuntimeRegistry>,
    node_id: uuid::Uuid,
}

impl std::fmt::Debug for DetourPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DetourPath")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn node_named(name: &str) -> Node {
        Node {
            name: name.to_string(),
            host: "example.com".to_string(),
            address: "example.com:443".to_string(),
            port: 443,
            ..Default::default()
        }
    }

    /// A node that names a detour it does not have must fail its dial rather
    /// than quietly take the direct path: the operator asked for the traffic to
    /// leave through another node.
    #[test]
    fn a_named_detour_without_a_binding_refuses_the_dial() {
        let mut node = node_named("back");
        node.detour = Some("front".into());
        let error = ensure_bound(&node, None).unwrap_err().to_string();
        assert!(
            error.contains("is not bound in this generation") && error.contains("back"),
            "{error}"
        );
    }

    #[test]
    fn a_node_on_its_own_path_needs_no_binding() {
        ensure_bound(&node_named("plain"), None).unwrap();
    }

    /// The check is about the binding, not the name: with one bound the dial
    /// proceeds however it was named.
    #[test]
    fn a_bound_detour_satisfies_the_check() {
        let generation = Arc::new(OutboundRuntimeRegistry::build(&[]).unwrap());
        let path = DetourPath::new(
            Arc::new(ProxyRegistry::new()),
            Arc::clone(&generation),
            uuid::Uuid::new_v4(),
        );
        let mut node = node_named("back");
        node.detour = Some("front".into());
        ensure_bound(&node, Some(&path)).unwrap();
    }

    /// The registry carries no group: nothing on the dial path can resolve one,
    /// which is why configuration drops those names before they get this far.
    #[test]
    fn the_path_is_pinned_to_one_node() {
        let generation = Arc::new(OutboundRuntimeRegistry::build(&[]).unwrap());
        let node_id = uuid::Uuid::new_v4();
        let path = DetourPath::new(Arc::new(ProxyRegistry::new()), generation, node_id);
        assert!(
            format!("{path:?}").contains(&node_id.to_string()),
            "the debug form names the node it rides: {path:?}"
        );
    }
}
