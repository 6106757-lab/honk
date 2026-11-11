//! SOCKS5 frontend (RFC 1928 CONNECT, RFC 1929 username/password).
//!
//! Unlike the reference PR, the entire negotiation is wrapped in *one* total
//! deadline. A client sending only `\x05` cannot hold a connection slot
//! forever, and a slow drip cannot renew the timer per read.

use super::param::{ClientParam, InboundTarget, ProtoError, ReadBuffer};
use honk_config::ListenerAuth;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

const METHOD_NOAUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NONE: u8 = 0xff;

const CMD_CONNECT: u8 = 0x01;

/// Fill in the target/user part of [`ClientParam`]. Returns the negotiated
/// identity so the caller can keep the param construction in one place.
pub(super) async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    rb: &mut ReadBuffer<S>,
    auth: Option<&ListenerAuth>,
    deadline: Instant,
) -> Result<(InboundTarget, u16, Option<String>), ProtoError> {
    let version = rb.read_exact_buffered(1, deadline).await?[0];
    if version != 0x05 {
        return Err(ProtoError::Unsupported("only SOCKS5 is supported"));
    }
    let count = rb.read_exact_buffered(1, deadline).await?[0] as usize;
    let methods = rb.read_exact_buffered(count, deadline).await?;

    let method = if auth.is_some() {
        if methods.contains(&METHOD_USERPASS) {
            METHOD_USERPASS
        } else {
            rb.write_all(&[0x05, METHOD_NONE]).await?;
            return Err(ProtoError::Auth);
        }
    } else if methods.contains(&METHOD_NOAUTH) {
        METHOD_NOAUTH
    } else {
        rb.write_all(&[0x05, METHOD_NONE]).await?;
        return Err(ProtoError::Unsupported("no acceptable SOCKS5 method"));
    };
    rb.write_all(&[0x05, method]).await?;

    let mut user = None;
    if method == METHOD_USERPASS {
        let header = rb.read_exact_buffered(2, deadline).await?;
        if header[0] != 0x01 {
            rb.write_all(&[0x01, 0x01]).await?;
            return Err(ProtoError::Malformed("bad userpass sub-negotiation version"));
        }
        let name = rb.read_exact_buffered(header[1] as usize, deadline).await?;
        let length = rb.read_exact_buffered(1, deadline).await?[0] as usize;
        let password = rb.read_exact_buffered(length, deadline).await?;
        let expected = auth.expect("userpass method implies configured auth");
        if name != expected.username.as_bytes() || password != expected.password.as_bytes() {
            rb.write_all(&[0x01, 0x01]).await?;
            return Err(ProtoError::Auth);
        }
        rb.write_all(&[0x01, 0x00]).await?;
        user = Some(expected.username.clone());
    }

    let request = rb.read_exact_buffered(4, deadline).await?;
    let (version, command, _, address_type) =
        (request[0], request[1], request[2], request[3]);
    if version != 0x05 {
        return Err(ProtoError::Malformed("bad SOCKS5 request version"));
    }
    if command != CMD_CONNECT {
        // UDP ASSOCIATE and BIND have no userspace endpoint pool here.
        return Err(ProtoError::Unsupported("only CONNECT is supported"));
    }
    let target = match address_type {
        0x01 => {
            let bytes = rb.read_exact_buffered(4, deadline).await?;
            InboundTarget::Ip(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }
        0x03 => {
            let length = rb.read_exact_buffered(1, deadline).await?[0] as usize;
            if length == 0 {
                return Err(ProtoError::Malformed("empty SOCKS5 domain"));
            }
            let bytes = rb.read_exact_buffered(length, deadline).await?;
            InboundTarget::Domain(
                String::from_utf8(bytes)
                    .map_err(|_| ProtoError::Malformed("non-UTF8 SOCKS5 domain"))?
                    .trim_end_matches('.')
                    .to_owned(),
            )
        }
        0x04 => {
            let bytes = rb.read_exact_buffered(16, deadline).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes);
            InboundTarget::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => return Err(ProtoError::Malformed("unknown SOCKS5 address type")),
    };
    let port_bytes = rb.read_exact_buffered(2, deadline).await?;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    if port == 0 {
        return Err(ProtoError::Malformed("SOCKS5 destination port is zero"));
    }
    Ok((target, port, user))
}

/// SOCKS5 reply. `0x00` = succeeded, `0x02` = blocked by ruleset,
/// `0x05` = dial failure, `0x01` = generic failure.
pub(super) async fn write_reply<S: AsyncRead + AsyncWrite + Unpin>(
    rb: &mut ReadBuffer<S>,
    code: u8,
) -> Result<(), ProtoError> {
    rb.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

pub(super) fn fill_param(
    param: &mut ClientParam,
    target: InboundTarget,
    port: u16,
    user: Option<String>,
) {
    param.target = target;
    param.target_port = port;
    param.user = user;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn deadline() -> Instant {
        Instant::now() + std::time::Duration::from_secs(2)
    }

    #[tokio::test]
    async fn noauth_connect_domain() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut rb = ReadBuffer::new(server, 16 * 1024);
        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb,
            ])
            .await
            .unwrap();
        let (target, port, user) = negotiate(&mut rb, None, deadline()).await.unwrap();
        assert_eq!(target, InboundTarget::Domain("example.com".to_owned()));
        assert_eq!(port, 443);
        assert!(user.is_none());
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn userpass_rejects_wrong_password() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut rb = ReadBuffer::new(server, 16 * 1024);
        let auth = ListenerAuth {
            username: "u".into(),
            password: "p".into(),
        };
        client
            .write_all(&[0x05, 0x01, 0x02, 0x01, 0x01, b'u', 0x01, b'x'])
            .await
            .unwrap();
        assert!(matches!(
            negotiate(&mut rb, Some(&auth), deadline()).await,
            Err(ProtoError::Auth)
        ));
    }

    #[tokio::test]
    async fn udp_associate_is_rejected() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut rb = ReadBuffer::new(server, 16 * 1024);
        client
            .write_all(&[0x05, 0x01, 0x00, 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        assert!(matches!(
            negotiate(&mut rb, None, deadline()).await,
            Err(ProtoError::Unsupported(_))
        ));
    }

    #[tokio::test]
    async fn single_version_byte_cannot_hold_the_slot() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut rb = ReadBuffer::new(server, 16 * 1024);
        client.write_all(&[0x05]).await.unwrap();
        assert!(matches!(
            negotiate(&mut rb, None, Instant::now() + std::time::Duration::from_millis(50))
                .await,
            Err(ProtoError::Timeout)
        ));
    }
}
