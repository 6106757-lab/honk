//! Process-wide relay tuning knobs.
//!
//! Two different quantities used to be conflated here.
//!
//! 1. The **copy chunk** of the userspace relay (`relay::mod::copy_way`).
//!    That loop is strictly serial — `read` → `write_all` → `read` — so its
//!    pipeline depth is one regardless of buffer size. Throughput is set by the
//!    two TCP windows, not by this number; a bigger chunk only changes how many
//!    syscalls a bulk flow makes. It is additionally capped by the framed
//!    outbounds: `AnyTLS` truncates every `poll_write` to `u16::MAX` and
//!    `Trojan` rejects anything larger, so a chunk above one frame is split
//!    into several frames and pays the framing cost for nothing.
//!
//! 2. The **duplex capacity** on the WebSocket path (`transport::ws_bridge_relay`).
//!    That one really is an in-flight buffer: the bridge writer drains it while
//!    the relay keeps filling it, so `capacity / RTT` does bound a single flow.
//!
//! Hence two knobs with two defaults. The copy chunk defaults to
//! [`MAX_FRAME_PAYLOAD`] and never exceeds it; the duplex capacity is free to
//! be larger because it is a pipe, not a frame.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Largest payload a framed outbound accepts in a single `poll_write`.
///
/// `AnyTLS` does `buf.len().min(u16::MAX)` and `Trojan` errors above the same
/// bound. Note this is 65535, not 64 KiB: a 65536-byte write is split into
/// 65535 + 1 and costs an extra frame.
pub const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;

/// Default buffer size.
///
/// For the copy chunk this is already the ceiling; for the duplex pipe it is a
/// middle ground that keeps a 60 ms path moving without pinning megabytes per
/// flow.
pub const DEFAULT_RELAY_BUF_SIZE: usize = MAX_FRAME_PAYLOAD;

/// Smallest accepted buffer; below this the relay fragments every frame.
pub const MIN_RELAY_BUF_SIZE: usize = 8 * 1024;

/// Largest accepted buffer, per direction and per flow.
///
/// Only the duplex pipe benefits from going past one frame, and even there the
/// gain stops once the pipe covers roughly one bandwidth-delay product. Four
/// frames' worth is past that point on any tunnel this binary is likely to see.
pub const MAX_RELAY_BUF_SIZE: usize = 4 * MAX_FRAME_PAYLOAD;

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

/// Copy-loop chunk size: the configured buffer, capped at one protocol frame.
///
/// Exceeding one frame cannot raise throughput — the copy loop is serial — and
/// forces the framed outbounds to split every write.
pub fn relay_copy_chunk() -> usize {
    relay_buf_size().min(MAX_FRAME_PAYLOAD)
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

    /// `set_relay_buf_size` is process-wide, so tests that touch it must not
    /// interleave.
    static TUNING_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        let _guard = TUNING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(set_relay_buf_size(1), MIN_RELAY_BUF_SIZE);
        assert_eq!(set_relay_buf_size(usize::MAX), MAX_RELAY_BUF_SIZE);
        assert_eq!(
            set_relay_buf_size(DEFAULT_RELAY_BUF_SIZE),
            DEFAULT_RELAY_BUF_SIZE
        );
    }

    /// The configured buffer may sit far above one frame, but the copy loop
    /// must never hand a framed outbound more than it can write in one piece.
    #[test]
    fn copy_chunk_never_exceeds_one_frame() {
        let _guard = TUNING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = relay_buf_size();
        for requested in [1, MIN_RELAY_BUF_SIZE, MAX_FRAME_PAYLOAD, MAX_RELAY_BUF_SIZE] {
            set_relay_buf_size(requested);
            assert!(
                relay_copy_chunk() <= MAX_FRAME_PAYLOAD,
                "copy chunk {} over one frame at configured {}",
                relay_copy_chunk(),
                relay_buf_size()
            );
        }
        // 64 KiB is one byte past the frame bound and would split 65535 + 1.
        set_relay_buf_size(64 * 1024);
        assert_eq!(relay_copy_chunk(), MAX_FRAME_PAYLOAD);
        set_relay_buf_size(previous);
    }
}
