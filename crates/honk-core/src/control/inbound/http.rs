//! HTTP/1.1 proxy frontend.
//!
//! The request loop lives in `mixed.rs`; this module owns one request's
//! parsing and forwarding. Key properties borrowed from 3proxy / Xray:
//!
//! * **One request per upstream dial.** Every iteration re-parses `Host` and
//!   re-dials, so the second request on a keep-alive connection can never be
//!   sent to the first request's upstream (the reference PR's worst bug).
//! * **Hop-by-hop headers are stripped** and the upstream is forced to
//!   `Connection: close`, so `tokio::io::copy_bidirectional` terminates on a
//!   well-defined EOF while the *client* connection stays available for the
//!   next iteration.
//! * **Pre-read bytes are never lost**: `ReadBuffer::drain_buffered` hands
//!   everything after the head to the upstream, including a pipelined body
//!   or a CONNECT ClientHello.
//! * **Every error reply closes the connection.**

use super::param::{InboundTarget, ProtoError, ReadBuffer};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use honk_config::ListenerAuth;
use honk_outbound::proxy::AsyncReadWrite;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

const HOP_BY_HOP: &[&str] = &[
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
];

/// One parsed request. `outbound_head` is empty for CONNECT (the tunnel is
/// raw bytes), otherwise it is the rewritten request head ready to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HttpRequest {
    pub connect: bool,
    pub target: InboundTarget,
    pub port: u16,
    pub user: Option<String>,
    pub outbound_head: Vec<u8>,
}

fn split_authority(raw: &str, default_port: u16) -> Result<(InboundTarget, u16), ProtoError> {
    let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err(ProtoError::Malformed("unterminated IPv6 literal"));
        };
        let host = &rest[..close];
        let port = match rest[close + 1..].strip_prefix(':') {
            Some(value) => value
                .parse::<u16>()
                .map_err(|_| ProtoError::Malformed("bad port"))?,
            None => default_port,
        };
        (host, port)
    } else if let Some((host, port)) = raw.rsplit_once(':') {
        // A bare IPv6 address without brackets is ambiguous; treat it as a
        // literal only when it parses as one and no port was appended.
        let port = port
            .parse::<u16>()
            .map_err(|_| ProtoError::Malformed("bad port"))?;
        (host, port)
    } else {
        (raw, default_port)
    };
    if host.is_empty() || port == 0 {
        return Err(ProtoError::Malformed("empty host or zero port"));
    }
    let target = match host.parse::<IpAddr>() {
        Ok(ip) => InboundTarget::Ip(ip),
        Err(_) => InboundTarget::Domain(host.trim_end_matches('.').to_owned()),
    };
    Ok((target, port))
}

fn check_auth(
    headers: &[(String, String)],
    auth: Option<&ListenerAuth>,
) -> Result<Option<String>, ProtoError> {
    let Some(expected) = auth else {
        return Ok(None);
    };
    let Some((_, value)) = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
    else {
        return Err(ProtoError::Auth);
    };
    let Some(encoded) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    else {
        return Err(ProtoError::Auth);
    };
    let decoded = STANDARD
        .decode(encoded.trim())
        .map_err(|_| ProtoError::Auth)?;
    let decoded = String::from_utf8(decoded).map_err(|_| ProtoError::Auth)?;
    let Some((user, password)) = decoded.split_once(':') else {
        return Err(ProtoError::Auth);
    };
    if user != expected.username || password != expected.password {
        return Err(ProtoError::Auth);
    }
    Ok(Some(expected.username.clone()))
}

/// Parse one HTTP request head and produce the upstream head to send.
pub(super) fn parse_http_head(
    head: &[u8],
    auth: Option<&ListenerAuth>,
) -> Result<HttpRequest, ProtoError> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(ProtoError::Malformed("empty request"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(ProtoError::Malformed("missing method"))?;
    let raw_target = parts
        .next()
        .ok_or(ProtoError::Malformed("missing request target"))?;
    let version = parts
        .next()
        .ok_or(ProtoError::Malformed("missing HTTP version"))?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(ProtoError::Malformed("unsupported HTTP version"));
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ProtoError::Malformed("malformed header line"));
        };
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    let user = check_auth(&headers, auth)?;

    let connect = method.eq_ignore_ascii_case("CONNECT");
    if connect {
        let (target, port) = split_authority(raw_target, 443)?;
        return Ok(HttpRequest {
            connect: true,
            target,
            port,
            user,
            outbound_head: Vec::new(),
        });
    }

    // Absolute-form: http://host[:port]/path. Everything else is origin-form
    // and takes its authority from Host.
    let (authority, path) = if let Some(rest) = raw_target.strip_prefix("http://") {
        let split = rest.find('/').unwrap_or(rest.len());
        let path = &rest[split..];
        (
            Some(&rest[..split]),
            if path.is_empty() {
                "/".to_owned()
            } else {
                path.to_owned()
            },
        )
    } else if raw_target.starts_with('/') {
        (None, raw_target.to_owned())
    } else {
        return Err(ProtoError::Malformed("unsupported request target form"));
    };
    let authority = match authority {
        Some(value) => value.to_owned(),
        None => headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.clone())
            .ok_or(ProtoError::Malformed("missing Host header"))?,
    };
    // An absolute-form https:// target should have used CONNECT.
    if let Some(rest) = authority.strip_prefix("https://") {
        let _ = rest;
        return Err(ProtoError::Unsupported("use CONNECT for https targets"));
    }
    let (target, port) = split_authority(&authority, 80)?;

    let mut extra_hop_by_hop: Vec<String> = Vec::new();
    for (name, value) in &headers {
        if name.eq_ignore_ascii_case("connection") {
            extra_hop_by_hop.extend(
                value
                    .split(',')
                    .map(|item| item.trim().to_ascii_lowercase())
                    .filter(|item| !item.is_empty()),
            );
        }
    }
    let mut outbound = format!("{method} {path} {version}\r\n").into_bytes();
    for (name, value) in &headers {
        let lower = name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || extra_hop_by_hop.contains(&lower) {
            continue;
        }
        outbound.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    // Force the upstream to close: one request, one upstream, one EOF. The
    // *client* connection is kept and the loop in mixed.rs serves the next
    // request with a fresh dial.
    outbound.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(HttpRequest {
        connect: false,
        target,
        port,
        user,
        outbound_head: outbound,
    })
}

pub(super) const CONNECT_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// Send one plain request over an already dialled upstream and copy the
/// response back until the upstream closes. Then the caller loops for the
/// next keep-alive request.
pub(super) async fn forward_plain<S: AsyncRead + AsyncWrite + Unpin>(
    rb: &mut ReadBuffer<S>,
    request: &HttpRequest,
    upstream: &mut dyn AsyncReadWrite,
    upload: &AtomicU64,
    download: &AtomicU64,
) -> Result<(), ProtoError> {
    // `ProxyStream` is a wrapper; the boxed `stream` is the actual
    // AsyncRead + AsyncWrite object (see relay/mod.rs).
    upstream.write_all(&request.outbound_head).await?;
    let pending = rb.drain_buffered();
    if !pending.is_empty() {
        upstream.write_all(&pending).await?;
    }
    upstream.flush().await?;
    let (to_upstream, to_client) =
        tokio::io::copy_bidirectional(rb.stream_mut(), &mut *upstream).await?;
    upload.fetch_add(to_upstream, Ordering::Relaxed);
    download.fetch_add(to_client, Ordering::Relaxed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_request_is_rewritten_to_origin_form_and_closed() {
        let head = b"GET http://example.com/a?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nConnection: X-Foo\r\nX-Foo: leak\r\n\r\n";
        let request = parse_http_head(head, None).unwrap();
        assert_eq!(request.target, InboundTarget::Domain("example.com".into()));
        assert_eq!(request.port, 80);
        let out = String::from_utf8(request.outbound_head).unwrap();
        assert!(out.starts_with("GET /a?q=1 HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com\r\n"));
        assert!(!out.contains("Proxy-Connection"));
        assert!(!out.contains("X-Foo"));
        assert!(out.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn connect_keeps_domain_and_default_port() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let request = parse_http_head(head, None).unwrap();
        assert!(request.connect);
        assert_eq!(request.target, InboundTarget::Domain("example.com".into()));
        assert_eq!(request.port, 443);
        assert!(request.outbound_head.is_empty());
    }

    #[test]
    fn host_header_is_used_for_origin_form() {
        let head = b"GET /x HTTP/1.1\r\nHost: 1.2.3.4:8080\r\n\r\n";
        let request = parse_http_head(head, None).unwrap();
        assert_eq!(
            request.target,
            InboundTarget::Ip("1.2.3.4".parse().unwrap())
        );
        assert_eq!(request.port, 8080);
    }

    #[test]
    fn basic_auth_is_checked() {
        let auth = ListenerAuth {
            username: "u".into(),
            password: "p".into(),
        };
        let head = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert!(matches!(
            parse_http_head(head, Some(&auth)),
            Err(ProtoError::Auth)
        ));
        let good = format!(
            "GET / HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic {}\r\n\r\n",
            STANDARD.encode("u:p")
        );
        let request = parse_http_head(good.as_bytes(), Some(&auth)).unwrap();
        assert_eq!(request.user.as_deref(), Some("u"));
    }

    #[test]
    fn ipv6_literal_with_brackets() {
        let head = b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: x\r\n\r\n";
        let request = parse_http_head(head, None).unwrap();
        assert_eq!(
            request.target,
            InboundTarget::Ip("2001:db8::1".parse().unwrap())
        );
        assert_eq!(request.port, 8443);
    }
}
