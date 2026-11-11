//! Inbound dial path: route through the *existing* router, then use the
//! *existing* outbound pool. There is deliberately no second routing table
//! and no listener-pinned `proxy:`.
//!
//! Differences from the reference PR:
//! * routing goes through `Router::route_action_inbound` with the listener
//!   name, so `inbound(name)` rules and all ordinary matchers apply;
//! * DNS uses `resolve_domain_for_source`, which carries the client address
//!   into `qname()` rules and the `follow` upstream logic, instead of the
//!   node-host resolver (`resolve_domain`);
//! * the config read lock is released *before* awaiting the router read lock,
//!   avoiding the AB-BA deadlock with reload (`router.write` -> `config.write`).

use super::param::{ClientParam, InboundTarget};
use super::super::connection::ControlPlaneHandle;
use crate::routing::ConnectionInfo;
use honk_config::Config;
use honk_outbound::alive::{IpVersion, ProbeDomain};
use honk_outbound::proxy::ProxyStream;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// A dialled upstream plus the routing metadata needed by the connection
/// tracker (so inbound connections show up in doona with their rule).
pub(super) struct InboundDial {
    pub stream: ProxyStream,
    pub target: SocketAddr,
    pub outbound: String,
    pub rule: String,
    pub rule_payload: String,
    pub chains: Vec<String>,
    pub domain: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum InboundDialError {
    #[error("connection blocked by outbound '{0}'")]
    Blocked(String),
    #[error(transparent)]
    Failed(#[from] anyhow::Error),
}

impl ControlPlaneHandle {
    pub(super) async fn dial_for_inbound(
        &self,
        param: &ClientParam,
    ) -> Result<InboundDial, InboundDialError> {
        let (target_ip, target_domain) = match &param.target {
            InboundTarget::Ip(ip) => (*ip, None),
            InboundTarget::Domain(domain) => {
                // Client-aware resolution: qname() rules, source-based
                // policies and the follow upstream all see this query.
                let resolved = self
                    .dns_controller
                    .resolve_domain_for_source(domain, param.client_addr)
                    .await?;
                let ip = resolved
                    .iter()
                    .copied()
                    .find(IpAddr::is_ipv4)
                    .or_else(|| resolved.first().copied())
                    .ok_or_else(|| {
                        InboundDialError::Failed(anyhow::anyhow!(
                            "DNS resolution for '{domain}' returned no address"
                        ))
                    })?;
                (ip, Some(domain.clone()))
            }
        };
        let target_addr = SocketAddr::new(target_ip, param.target_port);
        let ipver = if target_ip.is_ipv4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        };

        // Read the timeout, then release the config lock BEFORE touching the
        // router lock. reload takes router.write() then config.write();
        // holding config.read() across that await would deadlock.
        let connect_timeout = {
            let config = self.config.read().await;
            Duration::from_millis(config.global.connect_timeout_ms)
        };

        let conn = ConnectionInfo {
            domain: target_domain.clone(),
            dst_ip: target_ip,
            dst_port: param.target_port,
            src_ip: param.client_addr.ip(),
            src_port: param.client_addr.port(),
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        };
        let groups = self.group_manager.read().clone();
        let (outbound, mark, rule, rule_payload) = {
            let router = self.router.read().await;
            let (action, matched) = router.route_action_inbound(&conn, &param.listener);
            (
                action.outbound.clone(),
                action.mark,
                matched
                    .as_ref()
                    .map(|hit| hit.rule_type.to_owned())
                    .unwrap_or_else(|| "Match".to_owned()),
                matched
                    .as_ref()
                    .map(|hit| hit.rule_payload.to_owned())
                    .unwrap_or_default(),
            )
        };
        if outbound == "block" {
            return Err(InboundDialError::Blocked(outbound));
        }

        let node = resolve_inbound_node(&groups, &outbound, ipver)?;
        if node.protocol() == honk_config::types::NodeProtocol::Block {
            return Err(InboundDialError::Blocked(outbound));
        }

        // Domain is meaningful for proxy outbounds; a direct dial uses the IP.
        let dial_domain = if outbound == "direct" {
            None
        } else {
            target_domain.as_deref()
        };
        let generation = self.runtime_registry.read().clone();
        let scope = generation.dial_scope(|| {});
        let (stream, _fresh) = ControlPlaneHandle::dial_pooled(
            &self.proxy_registry,
            &self.connection_pool,
            &generation,
            &node,
            (target_addr, dial_domain),
            connect_timeout,
            mark,
            &scope,
            None,
        )
        .await
        .map_err(InboundDialError::Failed)?;

        Ok(InboundDial {
            stream,
            target: target_addr,
            chains: vec![outbound.clone()],
            outbound,
            rule,
            rule_payload,
            domain: target_domain,
        })
    }
}

/// Resolve a routed outbound name to one node. A bare node name resolves
/// directly; a group contributes one leaf selected for TCP traffic.
fn resolve_inbound_node(
    groups: &honk_outbound::group::GroupManager,
    name: &str,
    ipver: IpVersion,
) -> Result<honk_config::node::Node, InboundDialError> {
    match name {
        "direct" => Ok(Config::builtin_direct_node()),
        "block" => Ok(Config::builtin_block_node()),
        _ => {
            if let Some(node) = groups.node_by_name(name) {
                return Ok(node.clone());
            }
            // ProbeDomain is an enum (Tcp/DnsUdp/DataUdp), not a target
            // domain: honk's group selector has no per-target key. The
            // concrete domain is still passed to the proxy as target_domain
            // above, so node-side routing keeps the original hostname.
            if let Some(node) = groups.select_node_for_domain(name, ProbeDomain::Tcp, ipver) {
                return Ok(node.clone());
            }
            Err(InboundDialError::Failed(anyhow::anyhow!(
                "unknown inbound outbound '{name}'"
            )))
        }
    }
}
