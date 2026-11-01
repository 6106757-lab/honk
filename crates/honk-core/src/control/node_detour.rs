//! Wiring a node's detour to the node it names.
//!
//! A server the direct path out cannot reach is often reachable from another
//! node, so a node may name one. Turning that name into a dial needs both the
//! node set and the proxy registry, neither of which the outbound layer owns,
//! so the binding happens here — once per generation, at startup and on every
//! reload.

use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use honk_outbound::proxy::ProxyRegistry;
use honk_outbound::proxy::detour::DetourPath;
use honk_outbound::runtime::OutboundRuntimeRegistry;
use std::sync::Arc;

/// Bind every node that names a detour to the path it names.
///
/// A detour is bound in exactly one place and read from exactly one, so no
/// protocol can end up taking it twice. Unknown names, and a MASQUE node whose
/// detour is another MASQUE node, are reported and skipped rather than failing
/// the generation: one unreachable node should not take down the rest.
pub(crate) fn bind_node_detours(
    registry: &Arc<OutboundRuntimeRegistry>,
    nodes: &[Node],
    proxies: &Arc<ProxyRegistry>,
) {
    for node in nodes {
        let Some(name) = node.detour_name() else {
            continue;
        };
        let Some(target) = nodes.iter().find(|candidate| candidate.name == name) else {
            tracing::warn!(
                "node {}: detour {name:?} is not a node in this configuration",
                node.name
            );
            continue;
        };
        if node.protocol() == NodeProtocol::Masque && target.protocol() == NodeProtocol::Masque {
            tracing::warn!(
                "masque node {}: detour {name:?} is itself a MASQUE node, which would nest \
                 tunnels; ignored",
                node.name
            );
            continue;
        }
        let path = Arc::new(DetourPath::new(
            Arc::clone(proxies),
            Arc::clone(registry),
            target.id,
        ));
        if !registry.bind_detour(node.id, path) {
            tracing::warn!(
                "node {}: detour {name:?} could not be bound to its runtime",
                node.name
            );
        }
    }
}
