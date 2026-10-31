//! MASQUE connect-ip carrier over HTTP/2.
//!
//! Uses extended CONNECT (RFC 8441) with `:protocol = connect-ip`. Because
//! HTTP/2 has no unreliable datagram, IP packets travel as DATAGRAM capsules
//! (RFC 9297) inside ordinary DATA frames — reliable and ordered, which costs
//! some latency but needs no QUIC DATAGRAM support from the endpoint.
//!
//! The endpoint must advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`; that is a
//! server-side setting the client only reads, so no `h2` fork is needed.

use crate::proxy::masque::capsule::{self, Capsule, CapsuleError};
use bytes::BytesMut;
use h2::RecvStream;
use h2::ext::Protocol;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

use super::tun::TunDevice;

/// Default path template for an IP tunnel accepting any destination.
const CONNECT_IP_PATH: &str = "/.well-known/masque/ip/*/";

/// Capsule protocol version 1, per RFC 9297.
const CAPSULE_PROTOCOL_HEADER: (&str, &str) = ("capsule-protocol", "?1");

/// An established IP tunnel: a TUN device fed by a MASQUE carrier.
pub struct MasqueTunnel {
    tun: Arc<TunDevice>,
    assigned: Vec<IpAddr>,
    mtu: u32,
}

impl MasqueTunnel {
    /// Perform the extended CONNECT, learn our assigned address, and start
    /// shuttling packets between the TUN device and the stream.
    ///
    /// The send half is spawned rather than named in a signature: `h2` keeps
    /// `SendStream` behind a private module, so its type can only be inferred.
    pub async fn open_h2<IO>(
        io: IO,
        authority: &str,
        mtu: u32,
        tun_name: &str,
    ) -> anyhow::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, connection) = h2::client::Builder::new()
            .enable_push(false)
            .max_header_list_size(64 * 1024)
            .handshake(io)
            .await?;
        // The connection driver must run for the stream to make progress.
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!("masque h2 connection closed: {error}");
            }
        });

        let uri = format!("https://{authority}{CONNECT_IP_PATH}");
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(&uri)
            .header(CAPSULE_PROTOCOL_HEADER.0, CAPSULE_PROTOCOL_HEADER.1)
            .body(())?;
        request
            .extensions_mut()
            .insert(Protocol::from_static("connect-ip"));

        let (response, mut send_stream) = sender.send_request(request, false)?;
        let response = response.await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("masque endpoint rejected connect-ip with status {status}");
        }
        let mut body: RecvStream = response.into_body();

        let assigned = read_address_assign(&mut body).await?;
        let address = assigned
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("masque endpoint sent no ADDRESS_ASSIGN capsule"))?;
        let prefix_len = if address.is_ipv4() { 32 } else { 128 };

        let tun = Arc::new(TunDevice::create(tun_name)?);
        tun.configure(address, prefix_len, mtu)?;

        // TUN -> endpoint.
        let upstream = tun.clone();
        tokio::spawn(async move {
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
        tokio::spawn(async move {
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

        Ok(Self { tun, assigned, mtu })
    }

    /// Interface name of the TUN device backing this tunnel.
    pub fn tun_name(&self) -> &str {
        self.tun.name()
    }

    /// Source address the endpoint assigned, which dialled sockets must bind.
    pub fn assigned_address(&self) -> Option<IpAddr> {
        self.assigned.first().copied()
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
