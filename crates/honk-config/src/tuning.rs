//! Process-wide relay tuning knobs.
//!
//! The userspace copy relay moves one buffer per direction at a time, so a
//! single flow is limited to roughly `buffer / RTT` bytes per second. The
//! buffer used to be a hard-coded constant, which made high-RTT paths (a
//! 60 ms tunnel is capped near 1 MB/s with a 64 KiB buffer) impossible to fix
//! without rebuilding the binary. The value now comes from
//! `global { relay_buf_size: '1MiB' }` and is installed through
//! [`set_relay_buf_size`] during startup; the hot path only reads
//! [`relay_buf_size`].

use std::sync::atomic::{AtomicUsize, Ordering};

/// Default per-direction relay buffer. One MiB keeps a 60 ms path above
/// 100 Mbit/s (`1 MiB / 60 ms ≈ 17 MB/s`).
pub const DEFAULT_RELAY_BUF_SIZE: usize = 1024 * 1024;

/// Smallest accepted buffer; below this the relay fragments every frame.
pub const MIN_RELAY_BUF_SIZE: usize = 8 * 1024;

/// Largest accepted buffer, per direction and per flow.
pub const MAX_RELAY_BUF_SIZE: usize = 16 * 1024 * 1024;

static RELAY_BUF_SIZE: AtomicUsize = AtomicUsize::new(DEFAULT_RELAY_BUF_SIZE);

/// Current relay buffer size in bytes.
pub fn relay_buf_size() -> usize {
    RELAY_BUF_SIZE.load(Ordering::Relaxed)
}

/// Clamp and install a new relay buffer size, returning the effective value.
pub fn set_relay_buf_size(bytes: usize) -> usize {
    let clamped = bytes.clamp(MIN_RELAY_BUF_SIZE, MAX_RELAY_BUF_SIZE);
    RELAY_BUF_SIZE.store(clamped, Ordering::Relaxed);
    clamped
}

/// Whether `bytes` already sits inside the supported relay buffer range.
pub fn relay_buf_size_in_range(bytes: usize) -> bool {
    (MIN_RELAY_BUF_SIZE..=MAX_RELAY_BUF_SIZE).contains(&bytes)
}

/// Parse sizes such as `65536`, `512K`, `512KB`, `512KiB` or `2MiB`.
///
/// Bare numbers are bytes. `K`/`KB` and `M`/`MB` are decimal, `KiB`/`MiB` are
/// binary; the suffix is case-insensitive.
pub fn parse_size(text: &str) -> Option<usize> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let digits_end = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (number, unit) = trimmed.split_at(digits_end);
    if number.is_empty() {
        return None;
    }
    let value: u64 = number.parse().ok()?;
    let multiplier: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1000,
        "ki" | "kib" => 1024,
        "m" | "mb" => 1000 * 1000,
        "mi" | "mib" => 1024 * 1024,
        _ => return None,
    };
    usize::try_from(value.checked_mul(multiplier)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_size_forms() {
        assert_eq!(parse_size("65536"), Some(65_536));
        assert_eq!(parse_size("512K"), Some(512_000));
        assert_eq!(parse_size("512KB"), Some(512_000));
        assert_eq!(parse_size("512KiB"), Some(512 * 1024));
        assert_eq!(parse_size("1MiB"), Some(1024 * 1024));
        assert_eq!(parse_size(" 2mib "), Some(2 * 1024 * 1024));
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("abc"), None);
        assert_eq!(parse_size("12XB"), None);
    }

    #[test]
    fn clamps_out_of_range_values() {
        assert_eq!(set_relay_buf_size(1), MIN_RELAY_BUF_SIZE);
        assert_eq!(set_relay_buf_size(usize::MAX), MAX_RELAY_BUF_SIZE);
        assert_eq!(
            set_relay_buf_size(DEFAULT_RELAY_BUF_SIZE),
            DEFAULT_RELAY_BUF_SIZE
        );
    }
}
