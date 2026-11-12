//! `listeners { ... }` section: one named mixed listener per block.
//!
//! ```dae
//! listeners {
//!     shop1 {
//!         type: mixed
//!         listen: 127.0.0.1
//!         port: 12000
//!         auth: 'user:pass'
//!     }
//! }
//! ```
//!
//! There is intentionally no `proxy` key: outbound selection belongs to
//! `routing { inbound(shop1) -> ... }`, not to the listener. Names are kept
//! verbatim so Chinese / emoji names work. Cross-field validation lives in
//! [`crate::listener::validate_listeners`] so the serde paths share it.

use std::collections::HashMap;

use super::cursor::Segment;
use super::diagnostics::ParserDiagnostics;
use super::read::{self, Text};
use crate::diagnostic::Severity;
use crate::listener::ListenerConfig;

const KNOWN_KEYS: &[&str] = &[
    "type",
    "listen",
    "port",
    "auth",
    "udp_host",
    "handshake_timeout_ms",
    "request_timeout_ms",
    "max_header_bytes",
];

pub(super) fn parse_listeners_section(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Vec<ListenerConfig>, super::ParseFailure> {
    let mut listeners = Vec::new();

    for root in section {
        let Some(body) = root.body_with(super::cursor::BodySyntax::Declarations) else {
            continue;
        };
        for segment in body {
            diagnostics.at_section("listeners", Text::segment(&segment));
            let Some(name_text) = read::block_header(&segment) else {
                Text::segment(&segment).notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-statement",
                    "listener declaration requires a block",
                );
                continue;
            };
            let index = listeners.len() + 1;
            let name = name_text.unquote().raw().trim().to_owned();

            let mut fields: HashMap<&str, Text<'_, '_>> = HashMap::new();
            for statement in
                read::child_statements(&segment, diagnostics, super::cursor::BodySyntax::Statements)
            {
                let Some((key, value)) = statement.kv() else {
                    statement.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-statement",
                        "unknown listener statement ignored",
                    );
                    continue;
                };
                if !KNOWN_KEYS.contains(&key.raw()) {
                    key.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-key",
                        "unknown listener key ignored (outbound is selected by inbound() routing rules)",
                    );
                    continue;
                }
                let key = key.raw().trim();
                diagnostics.register_field(key, value);
                fields.insert(key, value.unquote());
            }

            let mut listener = ListenerConfig {
                name,
                ..Default::default()
            };
            if let Some(value) = fields.get("type").copied() {
                let raw = value.raw().trim();
                if !raw.eq_ignore_ascii_case("mixed") {
                    return Err(listener_scalar_error(
                        value,
                        index,
                        "type",
                        "listener type must be 'mixed'; other listener types are not supported",
                    )
                    .into());
                }
            }
            if let Some(value) = fields.get("listen").copied() {
                listener.listen = value
                    .raw()
                    .trim()
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| {
                        listener_scalar_error(
                            value,
                            index,
                            "listen",
                            "listen must be an IP address",
                        )
                    })?;
            }
            let Some(port) = fields.get("port").copied() else {
                return Err(listener_scalar_error(
                    name_text,
                    index,
                    "port",
                    "listener port is required",
                )
                .into());
            };
            listener.port = port.raw().trim().parse::<u16>().map_err(|_| {
                listener_scalar_error(
                    port,
                    index,
                    "port",
                    "listener port must be an integer between 1 and 65535",
                )
            })?;
            if listener.port == 0 {
                return Err(listener_scalar_error(
                    port,
                    index,
                    "port",
                    "listener port must be an integer between 1 and 65535",
                )
                .into());
            }
            if let Some(value) = fields.get("auth").copied() {
                let raw = value.raw().trim();
                if !raw.is_empty() {
                    listener.auth =
                        Some(ListenerConfig::parse_auth(raw).map_err(|message| {
                            listener_scalar_error(value, index, "auth", message)
                        })?);
                }
            }
            if let Some(value) = fields.get("udp_host").copied() {
                listener.udp_host = Some(
                    ListenerConfig::parse_udp_host(value.raw()).map_err(|message| {
                        listener_scalar_error(value, index, "udp_host", message)
                    })?,
                );
            }
            for (key, target) in [
                ("handshake_timeout_ms", &mut listener.handshake_timeout_ms),
                ("request_timeout_ms", &mut listener.request_timeout_ms),
            ] {
                if let Some(value) = fields.get(key).copied() {
                    *target = value.raw().trim().parse::<u64>().map_err(|_| {
                        listener_scalar_error(value, index, key, "timeout must be milliseconds")
                    })?;
                }
            }
            if let Some(value) = fields.get("max_header_bytes").copied() {
                listener.max_header_bytes = value.raw().trim().parse::<usize>().map_err(|_| {
                    listener_scalar_error(
                        value,
                        index,
                        "max_header_bytes",
                        "max_header_bytes must be a byte count",
                    )
                })?;
            }

            listeners.push(listener);
        }
    }

    Ok(listeners)
}

fn listener_scalar_error(
    value: Text<'_, '_>,
    index: usize,
    field: &'static str,
    message: &'static str,
) -> crate::error::DetailedConfigError {
    let mut error = crate::error::DetailedConfigError::new(
        crate::error::ErrorCategory::Validation,
        "invalid-config-value",
        value.source.reference(),
        crate::diagnostic::SettingPath::new("listeners")
            .index(index)
            .field(field),
        message,
    );
    error.diagnostic.line = Some(value.source.location(value.span.start).0);
    error
}
