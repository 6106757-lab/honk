//! Carrier setup: how a MASQUE node's IP tunnel reaches its endpoint.
//!
//! `network: h2`    -> TCP + TLS + HTTP/2 extended CONNECT (`connect-ip`).
//! `network: quic`  -> HTTP/3, which needs `h3` to expose `connect-ip`; the
//!                     upstream crate keeps that protocol value private, so
//!                     this carrier reports the limitation instead of
//!                     silently opening a plain HTTP/3 stream.

use honk_config::node::Node;
use std::time::Duration;

use super::http2::MasqueTunnel;

/// Default tunnel MTU. IPv6 requires >= 1280 and every MASQUE endpoint we
/// know advertises WARP-sized packets, so 1280 is the safe floor.
pub const DEFAULT_MTU: u32 = 1280;

/// Open the node's IP tunnel over its configured carrier.
pub async fn open_tunnel(node: &Node, connect_timeout: Duration) -> anyhow::Result<MasqueTunnel> {
    let config = node
        .masque()
        .ok_or_else(|| anyhow::anyhow!("masque node {} has no masque config", node.name))?;
    let network = config.network.as_deref().unwrap_or("h2");
    match network {
        "h2" | "http2" | "" => open_h2(node, connect_timeout).await,
        "quic" | "h3" | "http3" => anyhow::bail!(
            "masque node {}: `network: quic` needs HTTP/3 connect-ip, which the h3 crate \
             does not expose yet; use `network: h2`",
            node.name
        ),
        other => anyhow::bail!("masque node {}: unsupported network {other:?}", node.name),
    }
}

/// TCP + TLS + HTTP/2 extended CONNECT.
async fn open_h2(node: &Node, connect_timeout: Duration) -> anyhow::Result<MasqueTunnel> {
    let config = node
        .masque()
        .ok_or_else(|| anyhow::anyhow!("masque node {} has no masque config", node.name))?;
    let address = format!("{}:{}", node.host(), node.port);
    let tcp = crate::util::connect_outbound(&address, connect_timeout).await?;

    let connector = crate::tls::build_connector(node)?;
    let server_name = config
        .tls
        .sni
        .clone()
        .unwrap_or_else(|| node.host().to_string());
    let tls = tokio::time::timeout(connect_timeout, connector.connect(&server_name, tcp))
        .await
        .map_err(|_| {
            anyhow::anyhow!("masque TLS handshake timed out after {connect_timeout:?}")
        })??;
    let io = crate::tls::BatchRead::new(tls);

    let mtu = config.mtu.map(u32::from).unwrap_or(DEFAULT_MTU);
    let tun_name = tun_name(node);
    tracing::debug!(
        "masque: opening connect-ip tunnel to {address} via h2 on {tun_name} (mtu {mtu})"
    );
    MasqueTunnel::open_h2(io, &server_name, mtu, &tun_name).await
}

/// Interface name for a node's TUN device. `IFNAMSIZ` is 16 including the
/// terminator, so the suffix is trimmed to fit.
fn tun_name(node: &Node) -> String {
    let suffix = node.id.as_u128() & 0xffff;
    format!("masq{suffix:04x}")
}
