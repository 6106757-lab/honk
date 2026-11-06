use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use honk_config::node::Node;
use honk_config::types::DnsProtocol;
use honk_outbound::alive::{IpVersion, ProbeDomain};
use honk_outbound::group::GroupManager;
use honk_outbound::group::{
    ScoreAttempt, ScoreContinuation, ScoreSelectionContext, ScoreTarget, SelectionNetwork,
};
use tracing::debug;

use super::UpstreamPool;
use super::entries::UpstreamEntry;
use crate::routing::ConnectionInfo;

pub(super) struct DnsDialRoute {
    pub(super) target: SocketAddr,
    pub(super) node: Option<Node>,
    pub(super) feedback: Option<ScoreAttempt>,
    pub(super) observation: Option<crate::observe::flows::record::OutboundAttempt>,
}

#[derive(Default)]
struct SelectedLeaf {
    node: Option<Node>,
    feedback: Option<ScoreAttempt>,
    path: crate::observe::flows::dns::SelectionPath,
}

impl SelectedLeaf {
    fn explicit(node: &Node) -> Self {
        Self {
            node: Some(node.clone()),
            ..Self::default()
        }
    }
}

pub(super) fn target_context(entry: &UpstreamEntry, target: SocketAddr) -> ScoreSelectionContext {
    // Health gate and score bucket follow the carrier the dial actually
    // exercises: proxied udp:// is pooled TCP-DNS (never real UDP through
    // the node), while DoQ/DoH3 run QUIC over the leaf's PacketTransport.
    // Direct dials never reach this context.
    let (network, probe_domain) = match entry.protocol {
        DnsProtocol::Udp => (SelectionNetwork::Tcp, ProbeDomain::Tcp),
        DnsProtocol::Quic | DnsProtocol::H3 => (SelectionNetwork::Udp, ProbeDomain::DataUdp),
        DnsProtocol::Tcp | DnsProtocol::Tls | DnsProtocol::Https => {
            (SelectionNetwork::Tcp, ProbeDomain::Tcp)
        }
    };
    let family = if target.is_ipv4() {
        IpVersion::V4
    } else {
        IpVersion::V6
    };
    ScoreSelectionContext {
        network,
        probe_domain,
        target_family: Some(family),
        health_family: family,
        target: Some(if entry.endpoint.host.parse::<IpAddr>().is_ok() {
            ScoreTarget::from(target)
        } else {
            ScoreTarget::domain(&entry.endpoint.host, target.port())
        }),
    }
}
pub(super) fn tcp_target_context(
    entry: &UpstreamEntry,
    target: SocketAddr,
) -> ScoreSelectionContext {
    let mut context = target_context(entry, target);
    context.network = SelectionNetwork::Tcp;
    context.probe_domain = ProbeDomain::Tcp;
    context
}

fn select_group_leaf_for_target(
    group_manager: &GroupManager,
    outbound: &str,
    entry: &UpstreamEntry,
    target: SocketAddr,
    original: Option<&ScoreContinuation>,
) -> Option<SelectedLeaf> {
    group_manager.get_group_policy(outbound)?;
    let select = || {
        group_manager.selection_plan_for_target_with_health_fallback(
            outbound,
            &target_context(entry, target),
            original,
        )
    };
    let plan = match honk_outbound::runtime::flow_observation::current() {
        Some(observer) => observer.sync_scope(select),
        None => select(),
    };
    let selections = crate::observe::flows::dns::selection_evaluated(plan.observation.as_deref());
    let family = plan.health_family;
    plan.entries
        .into_iter()
        .next()
        .map(|selected| SelectedLeaf {
            node: Some(selected.node.clone()),
            feedback: selected.feedback,
            path: crate::observe::flows::dns::selection_path(
                &selections,
                &selected.selection_chain,
                selected.node,
                family,
            ),
        })
}

impl UpstreamPool {
    fn resolve_outbound_for_target(
        &self,
        outbound: &str,
        entry: &UpstreamEntry,
        target: SocketAddr,
        original: Option<&ScoreContinuation>,
    ) -> SelectedLeaf {
        if outbound.eq_ignore_ascii_case("direct") {
            return SelectedLeaf::default();
        }

        if let Some(group_manager) = self.group_manager_snapshot.read().as_ref() {
            if let Some(selected) =
                select_group_leaf_for_target(group_manager, outbound, entry, target, original)
            {
                return selected;
            }
            if group_manager.get_group_policy(outbound).is_some() {
                return SelectedLeaf::default();
            }
        } else if let Some(cell) = self.group_manager.read().as_ref() {
            let group_manager = cell.read();
            if group_manager.get_group_policy(outbound).is_some() {
                if let Some(selected) =
                    select_group_leaf_for_target(&group_manager, outbound, entry, target, original)
                {
                    return selected;
                }
                debug!(
                    "DNS outbound group '{}' has no available node (GroupManager)",
                    outbound
                );
                return SelectedLeaf::default();
            }
        }

        if let Some(node) = self.nodes.iter().find(|node| node.name == outbound) {
            return SelectedLeaf::explicit(node);
        }
        if self.group_manager.read().is_none()
            && let Some(group) = self.groups.iter().find(|group| group.name == outbound)
            && let Some(node) = group
                .nodes
                .iter()
                .find_map(|id| self.nodes.iter().find(|node| node.id == *id))
        {
            return SelectedLeaf::explicit(node);
        }
        debug!("DNS outbound '{}' resolved to no node", outbound);
        SelectedLeaf::default()
    }
    pub(super) fn tcp_feedback_for_route(
        &self,
        entry: &UpstreamEntry,
        route: &DnsDialRoute,
    ) -> anyhow::Result<Option<ScoreAttempt>> {
        route
            .feedback
            .clone()
            .map(|feedback| feedback.with_context(tcp_target_context(entry, route.target)))
            .transpose()
            .map_err(Into::into)
    }
    #[cfg(test)]
    pub(super) async fn resolve_dial_route(
        &self,
        entry: &UpstreamEntry,
    ) -> anyhow::Result<DnsDialRoute> {
        let target = self.resolve_upstream_addr(entry).await?;
        self.resolve_dial_route_for_address(entry, target, None, None)
            .await
    }

    pub(super) async fn resolve_dial_route_for_address(
        &self,
        entry: &UpstreamEntry,
        target: SocketAddr,
        original: Option<&ScoreContinuation>,
        qname: Option<&str>,
    ) -> anyhow::Result<DnsDialRoute> {
        if let Some(tag) = entry.outbound.as_deref() {
            if tag.eq_ignore_ascii_case("block") {
                crate::observe::flows::dns::decision("rejected", Some("policy_block"));
                anyhow::bail!("DNS upstream outbound 'block' rejected the dial");
            }
            if tag.eq_ignore_ascii_case("follow") {
                // Follow-policy: route the DNS query through the same group the
                // domain's *content* traffic would use, so DNS egress and content
                // egress stay geographically aligned (e.g. TikTok content via
                // Taiwan => DNS also via Taiwan). The traffic router resolves the
                // group from the static domain/geosite rules alone.
                if let Some(domain) = qname {
                    let group = self.group_for_domain(domain).await;
                    if !group.is_empty() {
                        return self
                            .dial_through_outbound(
                                &group,
                                entry,
                                target,
                                original,
                                crate::observe::vocab::RoutingSource::Evaluation,
                                None,
                            )
                            .await;
                    }
                }
                // No domain available or no matching group: fall through to the
                // resolver-IP routing path (equivalent to an upstream without a tag).
            } else {
                return self
                    .dial_through_outbound(
                        tag,
                        entry,
                        target,
                        original,
                        crate::observe::vocab::RoutingSource::Forced,
                        None,
                    )
                    .await;
            }
        }

        let host_is_ip = entry.endpoint.host.parse::<IpAddr>().is_ok();
        let protocol = match entry.protocol {
            DnsProtocol::Udp | DnsProtocol::Quic | DnsProtocol::H3 => "udp",
            DnsProtocol::Tcp | DnsProtocol::Tls | DnsProtocol::Https => "tcp",
        };
        let connection = ConnectionInfo {
            domain: (!host_is_ip).then(|| entry.endpoint.host.clone()),
            dst_ip: target.ip(),
            dst_port: target.port(),
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            protocol,
            process_name: None,
            mac: None,
            dscp: None,
        };
        let (outbound_name, evaluation_id) =
            if let Some(router) = self.traffic_router_snapshot.read().as_ref() {
                crate::observe::flows::dns::route_upstream(router, &connection)
            } else {
                let router_cell = self.traffic_router.read().clone();
                let Some(router) = router_cell else {
                    debug!("DNS dial leaf (no traffic router): direct");
                    return Ok(DnsDialRoute {
                        observation: crate::observe::flows::dns::outbound_evidence(
                            "direct",
                            crate::observe::vocab::RoutingSource::Builtin,
                            None,
                            None,
                            target,
                            Default::default(),
                        ),
                        target,
                        node: None,
                        feedback: None,
                    });
                };
                let router = router.read().await;
                crate::observe::flows::dns::route_upstream(&router, &connection)
            };
        debug!(
            "DNS dial route: {} {}:{} (host={}) l4={} → outbound '{}'",
            entry.endpoint.host,
            target.ip(),
            target.port(),
            entry.endpoint.host,
            protocol,
            outbound_name
        );
        self.dial_through_outbound(
            &outbound_name,
            entry,
            target,
            original,
            crate::observe::vocab::RoutingSource::Evaluation,
            evaluation_id,
        )
        .await
    }

    /// Resolve the traffic-routing group that the *content* traffic for
    /// `domain` would take, using only the static domain/geosite rules (no
    /// IP/DNS hints). Returns an empty string when the router is unavailable
    /// or no rule matches. Used by the follow-policy path so DNS egress
    /// follows the same group as the domain's data traffic. Global mode is
    /// handled naturally: the traffic router already resolves every domain to
    /// the global group, so `route_domain` returns it here without any extra
    /// configuration.
    async fn group_for_domain(&self, domain: &str) -> String {
        if let Some(router) = self.traffic_router_snapshot.read().as_ref() {
            return router.route_domain(domain).to_owned();
        }
        let router_cell = self.traffic_router.read().clone();
        let Some(router) = router_cell else {
            return String::new();
        };
        let router = router.read().await;
        router.route_domain(domain).to_owned()
    }

    /// Dial `entry`'s upstream through `outbound` (a group name or `direct`).
    ///
    /// Shared by the explicit `-> tag` path, the follow-policy path and the
    /// resolver-IP routing path. `source` records whether the outbound was
    /// user-forced or derived from a routing evaluation; `evaluation_id` is the
    /// route trace id (only present for the resolver-IP evaluation path).
    #[allow(clippy::too_many_arguments)]
    async fn dial_through_outbound(
        &self,
        outbound: &str,
        entry: &UpstreamEntry,
        target: SocketAddr,
        original: Option<&ScoreContinuation>,
        source: crate::observe::vocab::RoutingSource,
        evaluation_id: Option<String>,
    ) -> anyhow::Result<DnsDialRoute> {
        if outbound.eq_ignore_ascii_case("block") {
            crate::observe::flows::dns::decision("rejected", Some("policy_block"));
            anyhow::bail!("DNS dial route selected block");
        }
        if outbound.eq_ignore_ascii_case("direct") {
            return Ok(DnsDialRoute {
                observation: crate::observe::flows::dns::outbound_evidence(
                    outbound,
                    source,
                    evaluation_id,
                    None,
                    target,
                    Default::default(),
                ),
                target,
                node: None,
                feedback: None,
            });
        }
        let selected = self.resolve_outbound_for_target(outbound, entry, target, original);
        if selected.node.is_none() {
            crate::observe::flows::dns::decision("rejected", Some("no_available_outbound"));
            anyhow::bail!(
                "DNS dial route selected outbound '{outbound}' but no leaf node is available"
            );
        }
        debug!(
            "DNS dial leaf (routed via {}): {:?}",
            outbound,
            selected.node.as_ref().map(|node| node.name.as_str())
        );
        Ok(DnsDialRoute {
            observation: crate::observe::flows::dns::outbound_evidence(
                outbound,
                source,
                evaluation_id,
                selected.node.as_ref(),
                target,
                selected.path,
            ),
            target,
            node: selected.node,
            feedback: selected.feedback,
        })
    }

    #[cfg(test)]
    pub(super) async fn resolve_dial_leaf(
        &self,
        entry: &UpstreamEntry,
    ) -> anyhow::Result<Option<Node>> {
        Ok(self.resolve_dial_route(entry).await?.node)
    }
}
