//! MASQUE connect-ip carrier over HTTP/2.
//!
//! Uses the extended CONNECT shape (RFC 8441) with Cloudflare's endpoint
//! conventions. Because HTTP/2 has no unreliable datagram, IP packets travel
//! as DATAGRAM capsules (RFC 9297) inside ordinary DATA frames — reliable and
//! ordered, which costs some latency but needs no QUIC DATAGRAM support.
//!
//! Two details differ from a textbook connect-ip client, both dictated by
//! Cloudflare's endpoints (and mirrored by `usque` and mihomo):
//!
//! * the request goes to `https://cloudflareaccess.com/`, **not** to
//!   `/.well-known/masque/ip/*/`, and carries `cf-connect-proto:
//!   cf-connect-ip` instead of relying on the `:protocol` pseudo-header;
//! * the tunnel addresses come from the node's configuration (`ip` / `ipv6`);
//!   the endpoint's ADDRESS_ASSIGN capsule is only a fallback.

use crate::proxy::masque::capsule::{self, Capsule, CapsuleError};
use bytes::BytesMut;
use h2::RecvStream;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncWrite};

use super::tun::TunDevice;

/// Authority of the CONNECT-IP request. Cloudflare's endpoints answer on their
/// Access host regardless of which edge handled the TLS connection.
const CONNECT_AUTHORITY: &str = "cloudflareaccess.com";

/// Capsule protocol version 1, per RFC 9297.
const CAPSULE_PROTOCOL_HEADER: (&str, &str) = ("capsule-protocol", "?1");

/// Clears a tunnel's liveness flag when the task owning it exits, whichever
/// way it exits.
struct LivenessGuard(Arc<AtomicBool>);

impl LivenessGuard {
    fn new(flag: Arc<AtomicBool>) -> Self {
        Self(flag)
    }
}

impl Drop for LivenessGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// An established IP tunnel: a TUN device fed by a MASQUE carrier.
pub struct MasqueTunnel {
    tun: Arc<TunDevice>,
    /// Source addresses the kernel may use: as many of IPv4 and IPv6 as the
    /// endpoint (or the configuration) gave us.
    addresses: Vec<IpAddr>,
    /// Cleared by whichever direction notices the carrier is gone, so the
    /// runtime can rebuild the tunnel instead of handing out a dead one.
    alive: Arc<AtomicBool>,
}

impl MasqueTunnel {
    /// Perform the CONNECT, set the tunnel addresses up, and start shuttling
    /// packets between the TUN device and the stream.
    ///
    /// The send half is spawned rather than named in a signature: `h2` keeps
    /// `SendStream` behind a private module, so its type can only be inferred.
    pub async fn open_h2<IO>(
        io: IO,
        mtu: u32,
        tun_name: &str,
        preferred: &[IpAddr],
    ) -> anyhow::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let alive = Arc::new(AtomicBool::new(true));

        let (mut sender, connection) = h2::client::Builder::new()
            .enable_push(false)
            .max_header_list_size(64 * 1024)
            .handshake(io)
            .await?;
        // The connection driver must run for the stream to make progress.
        let carrier_alive = Arc::clone(&alive);
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!("masque h2 connection closed: {error}");
            }
            carrier_alive.store(false, Ordering::Relaxed);
        });

        let uri = format!("https://{CONNECT_AUTHORITY}/");
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(&uri)
            .header(CAPSULE_PROTOCOL_HEADER.0, CAPSULE_PROTOCOL_HEADER.1)
            .header("cf-connect-proto", "cf-connect-ip")
            // Post-quantum key agreement is not implemented here.
            .header("pq-enabled", "false")
            .header("user-agent", "")
            .body(())?;

        let (response, mut send_stream) = sender.send_request(request, false)?;
        let response = response.await?;
        let status = response.status();
        tracing::debug!("masque: connect-ip on {tun_name} answered {status}");
        if !status.is_success() {
            anyhow::bail!("masque endpoint rejected connect-ip with status {status}");
        }
        let mut body: RecvStream = response.into_body();

        let assigned = read_address_assign(&mut body).await?;
        let addresses = if preferred.is_empty() {
            assigned
        } else {
            preferred.to_vec()
        };
        if addresses.is_empty() {
            anyhow::bail!("masque endpoint assigned no address and the node configures none");
        }

        let tun = Arc::new(TunDevice::create(tun_name)?);
        tun.configure(&addresses, mtu)?;

        // TUN -> endpoint.
        let upstream = tun.clone();
        let upstream_alive = LivenessGuard::new(Arc::clone(&alive));
        tokio::spawn(async move {
            let _alive = upstream_alive;
            let mut packet = vec![0u8; mtu as usize];
            loop {
                match upstream.recv(&mut packet).await {
                    Ok(0) => break,
                    Ok(length) => {
                        let capsule = capsule::encode_datagram(&packet[..length]).freeze();
                        if let Err(error) = send_stream.send_data(capsule, false) {
                            tracing::debug!("masque upstream closed: {error}");
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::debug!("masque TUN read failed: {error}");
                        break;
                    }
                }
            }
        });

        // Endpoint -> TUN.
        let downstream = tun.clone();
        let downstream_alive = LivenessGuard::new(Arc::clone(&alive));
        tokio::spawn(async move {
            let _alive = downstream_alive;
            let mut buffer = BytesMut::new();
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(chunk) => buffer.extend_from_slice(&chunk),
                    Err(error) => {
                        tracing::debug!("masque downstream closed: {error}");
                        break;
                    }
                }
                loop {
                    if buffer.is_empty() {
                        break;
                    }
                    match capsule::decode(&mut buffer) {
                        Ok(Capsule::Datagram { payload, .. }) => {
                            if let Err(error) = downstream.send(&payload).await {
                                tracing::debug!("masque TUN write failed: {error}");
                                return;
                            }
                        }
                        Ok(_) => {}
                        Err(CapsuleError::Incomplete) => break,
                        Err(error) => {
                            tracing::debug!("masque capsule decode failed: {error}");
                            return;
                        }
                    }
                }
            }
        });

        Ok(Self {
            tun,
            addresses,
            alive,
        })
    }

    /// Whether the carrier is still running. A tunnel whose carrier died is
    /// unusable: the runtime replaces it rather than dialling through a TUN
    /// device that no longer forwards packets.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// Interface name of the TUN device backing this tunnel.
    pub fn tun_name(&self) -> &str {
        self.tun.name()
    }

    /// Source address of the same family as `target`, which dialled sockets
    /// must bind: the endpoint routes by source, so a mismatched family is a
    /// dead flow.
    pub fn source_for(&self, target: std::net::SocketAddr) -> Option<IpAddr> {
        self.addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == target.is_ipv4())
    }
}

/// Read capsules until the endpoint assigns us an address.
async fn read_address_assign(body: &mut RecvStream) -> anyhow::Result<Vec<IpAddr>> {
    let mut assigned = Vec::new();
    let mut buffer = BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        buffer.extend_from_slice(&chunk);
        loop {
            if buffer.is_empty() {
                break;
            }
            match capsule::decode(&mut buffer) {
                Ok(Capsule::AddressAssign { addresses }) => {
                    for address in &addresses {
                        assigned.push(address.ip.to_std());
                    }
                }
                Ok(_) => {}
                Err(CapsuleError::Incomplete) => break,
                Err(error) => return Err(error.into()),
            }
        }
        if !assigned.is_empty() {
            break;
        }
    }
    Ok(assigned)
}
