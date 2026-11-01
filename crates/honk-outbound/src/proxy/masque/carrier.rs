//! Carrier setup: how a MASQUE node's IP tunnel reaches its endpoint.
//!
//! `network: h2`    -> TCP + WARP TLS + HTTP/2 CONNECT-IP.
//! `network: quic`  -> HTTP/3, which this carrier does not carry yet.
//!                     MASQUE over H3 needs extended CONNECT with
//!                     `:protocol = connect-ip`, and the pinned `h3` 0.0.8
//!                     refuses that value at the HEADERS layer (upstream added
//!                     it later), so opening it would mean vendoring a patched
//!                     `h3`. It also needs QUIC DATAGRAM framing, whose layout
//!                     differs from the HTTP/2 capsule this carrier already
//!                     gets right — a second chance to get the wire format
//!                     wrong. Reported instead of silently dialling a plain
//!                     HTTP/3 stream.

use honk_config::node::Node;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::http2::MasqueTunnel;
use super::warp::WarpIdentity;
use crate::proxy::AsyncReadWrite;
use crate::proxy::detour::DetourPath;

/// Default tunnel MTU. IPv6 requires >= 1280 and every MASQUE endpoint we
/// know advertises WARP-sized packets, so 1280 is the safe floor.
pub const DEFAULT_MTU: u32 = 1280;

/// Open the node's IP tunnel over its configured carrier.
///
/// `detour` carries the connection to the endpoint through another node when
/// the node names one; the generation supplies it, since only it can reach
/// that node's runtime.
pub async fn open_tunnel(
    node: &Node,
    connect_timeout: Duration,
    detour: Option<&DetourPath>,
) -> anyhow::Result<MasqueTunnel> {
    let config = node
        .masque()
        .ok_or_else(|| anyhow::anyhow!("masque node {} has no masque config", node.name))?;
    let network = config.network();
    match network {
        "h2" | "http2" | "" => open_h2(node, connect_timeout, detour).await,
        "quic" | "h3" | "http3" => anyhow::bail!(
            "masque node {}: `network: quic` needs HTTP/3 connect-ip, which honk does not \
             carry yet; use `network: h2`",
            node.name
        ),
        other => anyhow::bail!("masque node {}: unsupported network {other:?}", node.name),
    }
}

/// TCP + WARP TLS + HTTP/2 CONNECT-IP.
async fn open_h2(
    node: &Node,
    connect_timeout: Duration,
    detour: Option<&DetourPath>,
) -> anyhow::Result<MasqueTunnel> {
    let config = node
        .masque()
        .ok_or_else(|| anyhow::anyhow!("masque node {} has no masque config", node.name))?;
    let address = endpoint_address(node);
    let tcp = match (node.detour_name(), detour) {
        (Some(name), Some(dialer)) => {
            let endpoint = resolve_endpoint(&address).await?;
            dialer
                .connect(endpoint, connect_timeout)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "masque node {}: detour {name:?} could not reach {address}: {error}",
                        node.name
                    )
                })?
        }
        (Some(name), None) => anyhow::bail!(
            "masque node {}: detour {name:?} is not bound in this generation",
            node.name
        ),
        (None, _) => Box::new(crate::util::connect_outbound(&address, connect_timeout).await?)
            as Box<dyn AsyncReadWrite>,
    };
    let identity = WarpIdentity::build(node)?;
    let tls = identity.connect(tcp, connect_timeout).await?;
    tracing::debug!(
        "masque: TLS to {address} established (sni {})",
        identity.sni()
    );
    let io = crate::tls::BatchRead::new(tls);

    let mtu = config.mtu.map(u32::from).unwrap_or(DEFAULT_MTU);
    let tun_name = tun_name(node);
    let preferred = tunnel_addresses(node);
    tracing::debug!(
        "masque: opening connect-ip tunnel to {address} via h2 on {tun_name} \
         (mtu {mtu}, addresses {preferred:?})"
    );
    MasqueTunnel::open_h2(io, mtu, &tun_name, &preferred).await
}

/// Resolve the endpoint literal to an address a detour can dial.
async fn resolve_endpoint(address: &str) -> anyhow::Result<SocketAddr> {
    tokio::net::lookup_host(address)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("masque endpoint {address} resolved to nothing"))
}

/// The node's `host:port`, bracketed when the endpoint is an IPv6 literal.
fn endpoint_address(node: &Node) -> String {
    let host = node.host();
    if host.contains(':') {
        format!("[{host}]:{}", node.port)
    } else {
        format!("{host}:{}", node.port)
    }
}

/// The addresses the node expects the tunnel to carry, from its `ip` and
/// `ipv6` settings. Both may carry a CIDR suffix (`172.16.0.2/32`), which is
/// what subscriptions emit; only the address part is needed here because the
/// TUN gets a host route.
fn tunnel_addresses(node: &Node) -> Vec<IpAddr> {
    let config = match node.masque() {
        Some(config) => config,
        None => return Vec::new(),
    };
    [&config.local_ipv4, &config.local_ipv6]
        .iter()
        .filter_map(|value| value.as_deref())
        .filter_map(|value| value.split('/').next())
        .filter_map(|value| value.parse().ok())
        .collect()
}

/// Interface name for a node's TUN device. `IFNAMSIZ` is 16 including the
/// terminator, so the suffix is trimmed to fit.
fn tun_name(node: &Node) -> String {
    let suffix = node.id.as_u128() & 0xffff;
    format!("masq{suffix:04x}")
}
