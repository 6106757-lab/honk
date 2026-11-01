//! The path a node takes out when it names a detour.
//!
//! A server the direct path out cannot reach is often reachable from another
//! node, so a node may name one — or a group, whose current member carries it.
//! Turning that name into a dial needs the node set, the groups and the proxy
//! registry, so the generation resolves it once and hands the node a
//! [`DetourPath`]. A group is the one part that cannot be resolved that early,
//! and it is resolved again on every dial instead.
//!
//! A dial through it yields the same byte stream a socket would, and for UDP
//! the same framed transport, so the protocol above does not have to know
//! which path it is on.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use honk_config::node::Node;
use honk_config::types::NodeProtocol;

use crate::alive::{IpVersion, ProbeDomain};
use crate::group::GroupManager;
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

/// What the operator named: one node, or a group that picks one.
///
/// A group is resolved at dial time rather than at bind time. That is the
/// point of naming one — the front follows the group's current choice, so a
/// selector the operator has just switched, or a fallback that has failed over
/// since the last reload, carries the next dial without a reload of its own.
enum DetourTarget {
    Node(uuid::Uuid),
    Group {
        name: String,
        manager: Arc<GroupManager>,
    },
}

/// The node this one dials through, pinned to the generation that built it.
///
/// Dials stay inside that generation: a retired one refuses them, and the node
/// is rebuilt with the next.
pub struct DetourPath {
    proxies: Arc<ProxyRegistry>,
    generation: Arc<OutboundRuntimeRegistry>,
    target: DetourTarget,
    /// Whether the node riding this path is itself MASQUE. Only a group
    /// reaches this field: a node target is judged when it is bound, but a
    /// group gives no answer until the dial asks.
    rider_is_masque: bool,
}

impl std::fmt::Debug for DetourPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("DetourPath");
        match &self.target {
            DetourTarget::Node(node_id) => debug.field("node_id", node_id),
            DetourTarget::Group { name, .. } => debug.field("group", name),
        };
        debug.finish_non_exhaustive()
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
            target: DetourTarget::Node(node_id),
            rider_is_masque: false,
        }
    }

    /// Pin a detour to a group, resolved on each dial to whichever node the
    /// group then picks for that network.
    ///
    /// The rider's protocol comes along because the pair cannot be judged
    /// before the group answers.
    pub fn to_group(
        proxies: Arc<ProxyRegistry>,
        generation: Arc<OutboundRuntimeRegistry>,
        name: &str,
        manager: Arc<GroupManager>,
        rider: NodeProtocol,
    ) -> Self {
        Self {
            proxies,
            generation,
            target: DetourTarget::Group {
                name: name.to_string(),
                manager,
            },
            rider_is_masque: rider == NodeProtocol::Masque,
        }
    }

    /// The node that carries this dial, for this network.
    fn resolve(&self, domain: ProbeDomain) -> anyhow::Result<uuid::Uuid> {
        match &self.target {
            DetourTarget::Node(node_id) => Ok(*node_id),
            DetourTarget::Group { name, manager } => {
                let node = manager
                    .select_node_for_domain(name, domain, IpVersion::V4)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "detour group {name:?} has no node that can carry this dial"
                        )
                    })?;
                if self.rider_is_masque && node.protocol() == NodeProtocol::Masque {
                    anyhow::bail!(
                        "detour group {name:?} selected {:?}, which is MASQUE and would nest \
                         tunnels",
                        node.name
                    );
                }
                Ok(node.id)
            }
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
        let node_id = self.resolve(ProbeDomain::Tcp)?;
        let stream = self
            .proxies
            .dial_runtime(Arc::clone(&self.generation), node_id, target, None, timeout)
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
        let node_id = self.resolve(ProbeDomain::DataUdp)?;
        self.proxies
            .dial_udp_transport_runtime(
                Arc::clone(&self.generation),
                node_id,
                target,
                target_domain,
                timeout,
            )
            .await
    }
}

/// Open the connection to a node's own server: through its detour when the
/// node names one, and to the real network when it does not.
///
/// Every protocol that reaches its server over a socket of its own has to come
/// through here rather than connecting directly. One that connects directly
/// ignores a detour the operator configured and sends the node's traffic out
/// of the real interface, which looks exactly like an ordinary connection —
/// the one outcome this feature exists to prevent.
pub(crate) async fn connect_server(
    node: &Node,
    detour: Option<&DetourPath>,
    connect_timeout: Duration,
) -> anyhow::Result<crate::transport_quality::tcp::Carrier> {
    ensure_bound(node, detour)?;
    let address = crate::proxy::transport::endpoint_address(node);
    let Some(path) = detour else {
        return Ok(crate::transport_quality::tcp::Carrier::Socket(
            crate::util::connect_outbound(&address, connect_timeout).await?,
        ));
    };
    let endpoint = resolve_endpoint(&address).await?;
    let stream = path
        .connect(endpoint, connect_timeout)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "node {}: detour could not reach {address}: {error}",
                node.name
            )
        })?;
    Ok(crate::transport_quality::tcp::Carrier::Chained(stream))
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

    fn group_path(name: &str) -> DetourPath {
        DetourPath::to_group(
            Arc::new(ProxyRegistry::new()),
            Arc::new(OutboundRuntimeRegistry::build(&[]).unwrap()),
            name,
            Arc::new(GroupManager::new(&[], &[])),
            NodeProtocol::Trojan,
        )
    }

    /// A group detour has no node to name, so it names the group instead.
    #[test]
    fn a_group_detour_names_the_group_it_resolves() {
        let path = group_path("fronts");
        assert!(
            format!("{path:?}").contains("fronts"),
            "the debug form names the group: {path:?}"
        );
    }

    /// A group that can produce nothing refuses the dial. Sending it on its own
    /// path would be indistinguishable from a node with no detour at all.
    #[test]
    fn a_group_with_no_member_refuses_to_carry_the_dial() {
        let path = group_path("empty");
        let error = path
            .resolve(ProbeDomain::Tcp)
            .expect_err("an empty group carries nothing")
            .to_string();
        assert!(error.contains("empty"), "{error}");
    }
}
