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

#[cfg(test)]
mod tests {
    //! Chain verification over loopback.
    //!
    //! A SOCKS5 relay stands in for the front hop, a Trojan relay for the
    //! chained node's own server, and an echo server for the far side. Each
    //! relay records every target it is asked to reach, so a test can name the
    //! hop that carried a leg instead of only that bytes arrived: a node on a
    //! detour shows up as a request at the front for the chained node's own
    //! server, and never at that server directly.
    //!
    //! The chained node is deliberately Trojan and not SOCKS5. Only the
    //! protocols that dial through the shared transport consult the detour, so
    //! a test built on one that does not would pass whatever the chain did.

    use super::*;
    use honk_config::node::{OutboundConfig, TrojanConfig};
    use honk_config::types::{NodeProtocol, SubscriptionType};
    use honk_outbound::proxy::ProtocolEntry;
    use honk_outbound::proxy::socks5::Socks5Handler;
    use honk_outbound::proxy::trojan::TrojanHandler;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const TIMEOUT: Duration = Duration::from_secs(5);
    const PASSWORD: &str = "chain-secret";

    /// A relay that records every target it is asked to reach.
    struct Relay {
        address: SocketAddr,
        requested: Arc<Mutex<Vec<SocketAddr>>>,
    }

    impl Relay {
        fn targets(&self) -> Vec<SocketAddr> {
            self.requested.lock().unwrap().clone()
        }
    }

    async fn spawn_relay(trojan: bool) -> Relay {
        let requested = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sink = Arc::clone(&requested);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    let served = if trojan {
                        serve_trojan(&mut stream, &sink).await
                    } else {
                        serve_socks5(&mut stream, &sink).await
                    };
                    let _ = served;
                });
            }
        });
        Relay { address, requested }
    }

    async fn serve_socks5(
        stream: &mut TcpStream,
        sink: &Mutex<Vec<SocketAddr>>,
    ) -> anyhow::Result<()> {
        let mut greeting = [0_u8; 2];
        stream.read_exact(&mut greeting).await?;
        let mut methods = vec![0_u8; greeting[1] as usize];
        stream.read_exact(&mut methods).await?;
        stream.write_all(&[0x05, 0x00]).await?;

        let mut head = [0_u8; 4];
        stream.read_exact(&mut head).await?;
        if head[1] != 0x01 {
            anyhow::bail!("only CONNECT is supported");
        }
        let target = read_address(stream, head[3]).await?;
        sink.lock().unwrap().push(target);
        // Success, bound to an unspecified address: the client reads the reply
        // and starts sending, so the bound fields are not consulted.
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        relay_to(stream, target).await
    }

    /// Serve one Trojan connection: `hex(sha224(password)) CRLF cmd addr CRLF`
    /// and then the payload. The password is not checked, because which hop
    /// carried the leg is what is under test here, not authentication.
    async fn serve_trojan(
        stream: &mut TcpStream,
        sink: &Mutex<Vec<SocketAddr>>,
    ) -> anyhow::Result<()> {
        let mut hash = [0_u8; 56];
        stream.read_exact(&mut hash).await?;
        let mut crlf = [0_u8; 2];
        stream.read_exact(&mut crlf).await?;
        let mut command = [0_u8; 1];
        stream.read_exact(&mut command).await?;
        let mut address_type = [0_u8; 1];
        stream.read_exact(&mut address_type).await?;
        let target = read_address(stream, address_type[0]).await?;
        stream.read_exact(&mut crlf).await?;
        sink.lock().unwrap().push(target);
        relay_to(stream, target).await
    }

    /// The SOCKS5-style address both hops write: a type byte, the host, a port.
    async fn read_address(stream: &mut TcpStream, address_type: u8) -> anyhow::Result<SocketAddr> {
        let port = |bytes: [u8; 2]| u16::from_be_bytes(bytes);
        match address_type {
            0x01 => {
                let mut rest = [0_u8; 6];
                stream.read_exact(&mut rest).await?;
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3])),
                    port([rest[4], rest[5]]),
                ))
            }
            0x04 => {
                let mut rest = [0_u8; 18];
                stream.read_exact(&mut rest).await?;
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&rest[..16]);
                Ok(SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                    port([rest[16], rest[17]]),
                ))
            }
            0x03 => {
                let mut length = [0_u8; 1];
                stream.read_exact(&mut length).await?;
                let mut host = vec![0_u8; length[0] as usize];
                stream.read_exact(&mut host).await?;
                let mut bytes = [0_u8; 2];
                stream.read_exact(&mut bytes).await?;
                let name = String::from_utf8_lossy(&host).into_owned();
                let address = tokio::net::lookup_host((name.as_str(), port(bytes)))
                    .await?
                    .next();
                address.ok_or_else(|| anyhow::anyhow!("{name} resolved to nothing"))
            }
            other => anyhow::bail!("unknown address type {other}"),
        }
    }

    async fn relay_to(stream: &mut TcpStream, target: SocketAddr) -> anyhow::Result<()> {
        let mut upstream = TcpStream::connect(target).await?;
        tokio::io::copy_bidirectional(stream, &mut upstream).await?;
        Ok(())
    }

    /// The far side: whatever it is sent comes straight back.
    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        address
    }

    fn node_named(name: &str, server: SocketAddr, outbound: OutboundConfig) -> Node {
        let mut node = Node {
            name: name.to_owned(),
            address: server.to_string(),
            host: server.ip().to_string(),
            port: server.port(),
            outbound,
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    }

    fn socks5_node(name: &str, server: SocketAddr) -> Node {
        node_named(
            name,
            server,
            OutboundConfig::from_protocol(NodeProtocol::Socks5),
        )
    }

    fn trojan_node(name: &str, server: SocketAddr) -> Node {
        node_named(
            name,
            server,
            OutboundConfig::Trojan(TrojanConfig {
                password: Some(PASSWORD.into()),
                ..Default::default()
            }),
        )
    }

    /// A generation that can dial either hop, with detours bound the way the
    /// control plane binds them.
    fn registries(nodes: &[Node]) -> (Arc<OutboundRuntimeRegistry>, Arc<ProxyRegistry>) {
        let (registry, _) = OutboundRuntimeRegistry::build_reusing(nodes, 4, None).unwrap();
        let mut proxies = ProxyRegistry::new();
        proxies.register(ProtocolEntry::new(
            NodeProtocol::Socks5,
            Arc::new(Socks5Handler::new()),
        ));
        proxies.register(ProtocolEntry::new(
            NodeProtocol::Trojan,
            Arc::new(TrojanHandler::new()),
        ));
        let registry = Arc::new(registry);
        let proxies = Arc::new(proxies);
        bind_node_detours(&registry, nodes, &proxies);
        (registry, proxies)
    }

    /// Send a sentinel and require it back, so a stream that was accepted but
    /// carries nothing does not count as a working chain.
    async fn say_ping(stream: &mut Box<dyn honk_outbound::proxy::AsyncReadWrite>) {
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0_u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping", "the bytes must travel every hop");
    }

    /// The chain, end to end: the front is asked for the chained node's own
    /// server, and the far side is only ever asked of the chained node.
    #[tokio::test]
    async fn a_chained_node_reaches_its_server_through_the_front() {
        let front = spawn_relay(false).await;
        let back = spawn_relay(true).await;
        let echo = spawn_echo().await;

        let front_node = socks5_node("front", front.address);
        let mut back_node = trojan_node("back", back.address);
        back_node.detour = Some("front".into());
        back_node.id = back_node.derive_id();

        let nodes = [front_node, back_node.clone()];
        let (registry, proxies) = registries(&nodes);

        let mut stream = proxies
            .dial_runtime(Arc::clone(&registry), back_node.id, echo, None, TIMEOUT)
            .await
            .expect("a chained node must dial through its front")
            .stream;
        say_ping(&mut stream).await;

        assert_eq!(
            front.targets(),
            vec![back.address],
            "the front must be asked to reach the chained node's own server"
        );
        assert_eq!(
            back.targets(),
            vec![echo],
            "the chained node must be asked for the far side"
        );
    }

    /// The control: an identical node that names no detour leaves on its own
    /// path, and the front that carries nothing sees nothing.
    #[tokio::test]
    async fn a_node_without_a_detour_never_touches_the_front() {
        let front = spawn_relay(false).await;
        let solo = spawn_relay(true).await;
        let echo = spawn_echo().await;

        let front_node = socks5_node("front", front.address);
        let solo_node = trojan_node("solo", solo.address);
        let nodes = [front_node, solo_node.clone()];
        let (registry, proxies) = registries(&nodes);

        let mut stream = proxies
            .dial_runtime(Arc::clone(&registry), solo_node.id, echo, None, TIMEOUT)
            .await
            .expect("a node on its own path must dial")
            .stream;
        say_ping(&mut stream).await;

        assert_eq!(
            solo.targets(),
            vec![echo],
            "the node must reach the far side itself"
        );
        assert!(
            front.targets().is_empty(),
            "a node it does not carry must never appear at the front"
        );
    }

    /// The chain is mandatory. A front that cannot be dialled fails the node
    /// rather than letting it leave through the real interface, which would
    /// look exactly like an ordinary connection.
    #[tokio::test]
    async fn a_chained_node_fails_when_its_front_is_unreachable() {
        let closed = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let back = spawn_relay(true).await;
        let echo = spawn_echo().await;

        let front_node = socks5_node("front", closed);
        let mut back_node = trojan_node("back", back.address);
        back_node.detour = Some("front".into());
        back_node.id = back_node.derive_id();

        let nodes = [front_node, back_node.clone()];
        let (registry, proxies) = registries(&nodes);

        let error = proxies
            .dial_runtime(Arc::clone(&registry), back_node.id, echo, None, TIMEOUT)
            .await
            .expect_err("a dead front must fail the chained node");
        assert!(
            !format!("{error:#}").is_empty(),
            "a refusal must carry a cause"
        );
        assert!(
            back.targets().is_empty(),
            "the chained node's own server must not be dialled directly"
        );
    }

    /// The subscription path, whole: the body a provider serves is parsed, the
    /// generation binds what it named, and the dial is carried by the node the
    /// subscription pointed at.
    #[tokio::test]
    async fn a_subscription_dialer_proxy_carries_the_node_through_the_front() {
        let front = spawn_relay(false).await;
        let back = spawn_relay(true).await;
        let echo = spawn_echo().await;

        let subscription = honk_config::subscription::Subscription {
            name: "chain".into(),
            url: "https://example.test/chain.yaml".into(),
            sub_type: SubscriptionType::Clash,
            ..Default::default()
        };
        // Flow mappings keep the body flat, so no indentation carries a meaning
        // the reader has to work out before the assertions.
        let body = [
            "proxies:".to_string(),
            format!(
                "  - {{name: front, type: socks5, server: {}, port: {}}}",
                front.address.ip(),
                front.address.port()
            ),
            format!(
                "  - {{name: back, type: socks5, server: {}, port: {}, dialer-proxy: front}}",
                back.address.ip(),
                back.address.port()
            ),
            String::new(),
        ]
        .join("\n");

        let nodes = crate::subscription::parse_subscription_content(&subscription, &body)
            .expect("a Clash subscription naming a dialer-proxy must parse");
        let back_node = nodes
            .iter()
            .find(|node| node.name == "back")
            .expect("the chained proxy must import");
        assert_eq!(
            back_node.detour_name(),
            Some("front"),
            "the detour must survive parsing"
        );

        let (registry, proxies) = registries(&nodes);
        let mut stream = proxies
            .dial_runtime(Arc::clone(&registry), back_node.id, echo, None, TIMEOUT)
            .await
            .expect("the chained node must dial through its front")
            .stream;
        say_ping(&mut stream).await;

        assert_eq!(
            front.targets(),
            vec![back.address],
            "the front named in the subscription must carry the chained node's server"
        );
        assert_eq!(
            back.targets(),
            vec![echo],
            "only the chained node is asked for the far side"
        );
    }
}
