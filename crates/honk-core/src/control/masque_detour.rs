//! Wiring a MASQUE node's carrier through another node.
//!
//! A MASQUE endpoint the direct path out cannot reach is often reachable from
//! an existing node, so a node may name a detour. The dialer lives here
//! because turning that name into a dial needs both the node set and the proxy
//! registry, neither of which the outbound layer owns.

use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use honk_outbound::proxy::masque::CarrierDialer;
use honk_outbound::proxy::{AsyncReadWrite, ProxyRegistry};
use honk_outbound::runtime::OutboundRuntimeRegistry;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Dial the MASQUE endpoint from the detour node.
struct DetourDialer {
    proxies: Arc<ProxyRegistry>,
    /// The generation this tunnel was built in. Dials stay inside it: a
    /// retired generation refuses them, and the tunnel is rebuilt with the
    /// next one.
    generation: Arc<OutboundRuntimeRegistry>,
    node_id: uuid::Uuid,
}

impl CarrierDialer for DetourDialer {
    fn connect(
        &self,
        endpoint: SocketAddr,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Box<dyn AsyncReadWrite>>> + Send>> {
        let proxies = Arc::clone(&self.proxies);
        let generation = Arc::clone(&self.generation);
        let node_id = self.node_id;
        Box::pin(async move {
            let stream = proxies
                .dial_runtime(generation, node_id, endpoint, None, timeout)
                .await?;
            Ok(stream.stream)
        })
    }
}

/// Bind a dialer on every MASQUE node that names a detour.
///
/// Unknown names, and detours that would send a tunnel through another
/// tunnel, are reported and skipped rather than failing the generation.
pub(crate) fn bind_masque_detours(
    registry: &Arc<OutboundRuntimeRegistry>,
    nodes: &[Node],
    proxies: &Arc<ProxyRegistry>,
) {
    for node in nodes {
        let Some(config) = node.masque() else {
            continue;
        };
        let Some(name) = config.detour.as_deref() else {
            continue;
        };
        let Some(target) = nodes.iter().find(|candidate| candidate.name == name) else {
            tracing::warn!(
                "masque node {}: detour {name:?} is not a node in this configuration",
                node.name
            );
            continue;
        };
        if target.protocol() == NodeProtocol::Masque {
            tracing::warn!(
                "masque node {}: detour {name:?} is itself a MASQUE node, which would nest \
                 tunnels; ignored",
                node.name
            );
            continue;
        }
        let dialer = Arc::new(DetourDialer {
            proxies: Arc::clone(proxies),
            generation: Arc::clone(registry),
            node_id: target.id,
        });
        if !registry.bind_masque_detour(node.id, dialer) {
            tracing::warn!(
                "masque node {}: detour {name:?} could not be bound to its runtime",
                node.name
            );
        }
    }
}
