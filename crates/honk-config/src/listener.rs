//! Named inbound listeners (`listeners { ... }`).
//!
//! Design note: a listener deliberately carries **no** `proxy:` field. Which
//! outbound a connection uses is decided by the ordinary routing table through
//! the `inbound(name)` matcher, the same way mihomo uses `IN-NAME`, sing-box
//! uses `inbound` and Xray uses `inboundTag`. Pinning an outbound on the
//! listener would create a second routing path that bypasses the router, the
//! DNS `qname()` rules, the connection tracker and reload.
//!
//! Names are kept verbatim (Chinese / emoji allowed), never case-folded.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// Default bind address: loopback only. LAN exposure must be explicit.
pub fn default_listen() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_MAX_HEADER_BYTES: usize = 16 * 1024;

/// Optional username/password authentication. Kept as a plain pair: the
/// protocol layer maps it onto SOCKS5 userpass and HTTP Proxy-Authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerAuth {
    pub username: String,
    pub password: String,
}

/// Listener protocol. Only `mixed` (HTTP + SOCKS5 on one port) is supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ListenerType {
    #[default]
    Mixed,
}

/// One named TCP listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// Identity used by `inbound(name)` routing rules.
    pub name: String,
    #[serde(rename = "type", default)]
    pub listener_type: ListenerType,
    #[serde(default = "default_listen")]
    pub listen: IpAddr,
    pub port: u16,
    /// `user:password` in dae syntax. None means no authentication; such a
    /// listener should only ever bind loopback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<ListenerAuth>,
    /// Address advertised in the SOCKS5 `UDP ASSOCIATE` reply, i.e. the
    /// equivalent of Xray/3x-ui's `ip` field. Set this to the public IP when
    /// the listener binds a private address behind a port-forward. When
    /// unset, honk infers a reachable address from the client's source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_host: Option<IpAddr>,
    /// Deadline covering the *entire* protocol handshake, not each read.
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    /// Deadline covering each request head (HTTP keep-alive: per request).
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Hard cap on buffered request-head bytes.
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
}

fn default_handshake_timeout_ms() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_MS
}
fn default_request_timeout_ms() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_MS
}
fn default_max_header_bytes() -> usize {
    DEFAULT_MAX_HEADER_BYTES
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            listener_type: ListenerType::Mixed,
            listen: default_listen(),
            port: 0,
            auth: None,
            udp_host: None,
            handshake_timeout_ms: DEFAULT_HANDSHAKE_TIMEOUT_MS,
            request_timeout_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
        }
    }
}

impl ListenerConfig {
    pub fn bind_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.listen, self.port)
    }

    /// Parse `user:password`. A value without `:` is rejected rather than
    /// silently becoming a username with an empty password.
    pub fn parse_auth(raw: &str) -> Result<ListenerAuth, &'static str> {
        let (user, password) = raw
            .split_once(':')
            .ok_or("listener auth must be 'user:password'")?;
        if user.is_empty() || password.is_empty() {
            return Err("listener auth username and password must not be empty");
        }
        Ok(ListenerAuth {
            username: user.to_owned(),
            password: password.to_owned(),
        })
    }
}

/// Two bind addresses conflict when they share the port and either address is
/// a wildcard in the same family, or they are literally equal. Checking the
/// pair rather than the `IpAddr` alone catches `0.0.0.0:7890` vs
/// `127.0.0.1:7890`, which would otherwise fail only at bind time.
fn bind_conflicts(a: IpAddr, b: IpAddr) -> bool {
    if a == b {
        return true;
    }
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.is_unspecified() || b.is_unspecified(),
        (IpAddr::V6(a), IpAddr::V6(b)) => a.is_unspecified() || b.is_unspecified(),
        // A dual-stack IPv6 wildcard also covers IPv4 on Linux when
        // IPV6_V6ONLY is disabled (see inbound::bind_tcp_listener).
        (IpAddr::V6(a), IpAddr::V4(_)) | (IpAddr::V4(_), IpAddr::V6(a)) => a.is_unspecified(),
    }
}

/// Validate the whole listener set before any socket is bound.
pub fn validate_listeners(listeners: &[ListenerConfig]) -> Result<(), String> {
    for (index, listener) in listeners.iter().enumerate() {
        let label = format!(
            "listeners[{}] ('{}')",
            index + 1,
            if listener.name.is_empty() {
                "<unnamed>"
            } else {
                &listener.name
            }
        );
        if listener.name.trim().is_empty() {
            return Err(format!("{label}: name must not be empty"));
        }
        if listener.port == 0 {
            return Err(format!("{label}: port must be between 1 and 65535"));
        }
        if listener.handshake_timeout_ms == 0 || listener.request_timeout_ms == 0 {
            return Err(format!("{label}: timeouts must be greater than zero"));
        }
        if listener.max_header_bytes == 0 || listener.max_header_bytes > 1024 * 1024 {
            return Err(format!(
                "{label}: max_header_bytes must be between 1 and 1048576"
            ));
        }
        if listeners[..index]
            .iter()
            .any(|other| other.name == listener.name)
        {
            return Err(format!("{label}: duplicate listener name"));
        }
        if let Some(other) = listeners[..index].iter().find(|other| {
            other.port == listener.port && bind_conflicts(other.listen, listener.listen)
        }) {
            return Err(format!(
                "{label}: bind address {} conflicts with listener '{}' ({})",
                listener.bind_addr(),
                other.name,
                other.bind_addr()
            ));
        }
        // An unauthenticated wildcard listener is an open proxy: binding every
        // interface would expose it to the internet with no credential. An
        // authenticated one is the normal way to publish a listener and is
        // allowed — the credentials are the protection. This also makes the
        // SOCKS5 UDP ASSOCIATE reply advertise 0.0.0.0, which strict clients
        // (sing-box/NekoBox) need to fall back to the public TCP peer.
        if listener.auth.is_none() && listener.listen.is_unspecified() {
            return Err(format!(
                "{label}: refusing to expose an unauthenticated listener on a wildcard address; set auth or bind a specific address"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(name: &str, port: u16, listen: IpAddr) -> ListenerConfig {
        ListenerConfig {
            name: name.to_owned(),
            port,
            listen,
            ..Default::default()
        }
    }

    #[test]
    fn duplicate_names_rejected() {
        let items = vec![
            listener("a", 12000, default_listen()),
            listener("a", 12001, default_listen()),
        ];
        assert!(
            validate_listeners(&items)
                .unwrap_err()
                .contains("duplicate")
        );
    }

    #[test]
    fn wildcard_and_loopback_same_port_conflict() {
        let items = vec![
            listener("a", 7890, "0.0.0.0".parse().unwrap()),
            listener("b", 7890, "127.0.0.1".parse().unwrap()),
        ];
        assert!(
            validate_listeners(&items)
                .unwrap_err()
                .contains("conflicts")
        );
    }

    #[test]
    fn distinct_ports_are_fine() {
        let items = vec![
            listener("a", 12000, default_listen()),
            listener("b", 12001, default_listen()),
        ];
        assert!(validate_listeners(&items).is_ok());
    }

    #[test]
    fn wildcard_requires_auth() {
        let wildcard = "0.0.0.0".parse().unwrap();
        let mut open = listener("open", 12000, wildcard);
        open.auth = None;
        assert!(
            validate_listeners(&[open])
                .unwrap_err()
                .contains("unauthenticated")
        );

        let mut secured = listener("secured", 12000, wildcard);
        secured.auth = Some(ListenerAuth {
            username: "u".to_owned(),
            password: "p".to_owned(),
        });
        assert!(validate_listeners(&[secured]).is_ok());
    }

    #[test]
    fn auth_requires_colon() {
        assert!(ListenerConfig::parse_auth("user").is_err());
        assert_eq!(
            ListenerConfig::parse_auth("u:p").unwrap().password,
            "p".to_owned()
        );
    }
}
