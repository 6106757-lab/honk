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
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use h2::ext::Protocol;
use h2::RecvStream;
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
    /// Perform the extended CONNECT and bring up the TUN device.
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

        let (response, send_stream) = sender.send_request(request, false)?;
        let response = response.await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("masque endpoint rejected connect-ip with status {status}");
        }
        let body = response.into_body();

        let mut tunnel = MasqueTunnel {
            tun: Arc::new(TunDevice::create(tun_name)?),
            assigned: Vec::new(),
            mtu,
        };
        tunnel.exchange_capsules(send_stream, body).await?;
        Ok(tunnel)
    }

    /// Read the opening capsules until the endpoint assigns us an address,
    /// then start shuttling packets both ways.
    async fn exchange_capsules(
        &mut self,
        mut send_stream: h2::client::SendStream<Bytes>,
        mut body: RecvStream,
    ) -> anyhow::Result<()> {
        let mut buffer = BytesMut::new();
        let mut saw_address = false;

        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            buffer.extend_from_slice(&chunk);
            loop {
                if buffer.is_empty() {
                    break;
                }
                match capsule::decode(&mut buffer) {
                    Ok(Capsule::AddressAssign { addresses }) => {
                        for assigned in &addresses {
                            self.assigned.push(assigned.ip.to_std());
                        }
                        saw_address = true;
                    }
                    Ok(Capsule::Datagram { .. }) => {
                        // Packets before the address assignment cannot be
                        // routed yet; the endpoint should not send any.
                        tracing::debug!("masque endpoint sent a datagram before ADDRESS_ASSIGN");
                    }
                    Ok(_) => {}
                    Err(CapsuleError::Incomplete) => break,
                    Err(error) => return Err(error.into()),
                }
            }
            if saw_address {
                break;
            }
        }

        let address = self
            .assigned
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("masque endpoint sent no ADDRESS_ASSIGN capsule"))?;
        let prefix_len = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        self.tun.configure(address, prefix_len, self.mtu)?;

        let tun = self.tun.clone();
        let mtu = self.mtu as usize;
        tokio::spawn(async move {
            let mut packet = vec![0u8; mtu];
            loop {
                match tun.recv(&mut packet).await {
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

        let tun = self.tun.clone();
        tokio::spawn(async move {
            let mut buffer = BytesMut::new();
            while let Some(chunk) = body.next().await {
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
                            if let Err(error) = tun.send(&payload).await {
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

        Ok(())
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
