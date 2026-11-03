//! Direct ring reservations keep event payloads off the bounded TC call-chain stack.

use crate::maps::{EVENT_RINGBUF, FLOW_EXPIRY_HINT, FlowExpiryHint};
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;
use honk_ebpf_common::event::DaeEvent;

/// Zero a ringbuf event slot with volatile word stores.
///
/// `write_bytes` lowers to a call to the embedded `memset` subprogram, whose
/// frame adds 32 bytes to every verifier call chain that ends in an event —
/// on pre-6.12 kernels the TC classifiers sit exactly at that 512B combined
/// stack limit. Volatile stores cannot be merged back into a `memset` call,
/// and the event is written in ringbuf memory, so per-packet cost is
/// unchanged (same stores the helper would perform).
#[inline(always)]
fn zero_event_volatile(ptr: *mut DaeEvent) {
    let words = core::mem::size_of::<DaeEvent>() / 8;
    let tail = core::mem::size_of::<DaeEvent>() % 8;
    let wp = ptr.cast::<u64>();
    let mut i = 0;
    while i < words {
        unsafe { core::ptr::write_volatile(wp.add(i), 0) };
        i += 1;
    }
    if tail != 0 {
        let bp = ptr.cast::<u8>();
        let mut j = words * 8;
        while j < core::mem::size_of::<DaeEvent>() {
            unsafe { core::ptr::write_volatile(bp.add(j), 0) };
            j += 1;
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn send_dae_event(
    type_: u32,
    pid: u32,
    pname: Option<&[u8; 16]>,
    outbound: u8,
    l4proto: u8,
    sip: Option<&[u32; 4]>,
    dip: Option<&[u32; 4]>,
    sport: u16,
    dport: u16,
) -> i32 {
    let Some(mut reservation) = EVENT_RINGBUF.reserve(0) else {
        return -1;
    };
    let e: &mut DaeEvent = unsafe {
        zero_event_volatile(reservation.as_mut_ptr());
        reservation.assume_init_mut()
    };

    e.timestamp = unsafe { bpf_ktime_get_ns() };
    e.type_ = type_;
    e.pid = pid;
    e.outbound = outbound;
    e.l4proto = l4proto;
    e.sport = sport;
    e.dport = dport;

    if let Some(p) = pname {
        e.pname.copy_from_slice(p);
    }
    if let Some(s) = sip {
        e.sip.copy_from_slice(s);
    }
    if let Some(d) = dip {
        e.dip.copy_from_slice(d);
    }

    reservation.submit(0);
    0
}

/// At most one advisory hint per tuple owner per second on each CPU while
/// cached. Physical reclamation always belongs to fenced userspace retirement.
/// Suppression is recorded only once the ring accepted the hint, so a full ring
/// never silences the tuple for the next second.
#[inline(never)]
pub fn send_flow_expired(key: &honk_ebpf_common::redirect_need::TuplesKey, incarnation: u64) {
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(previous) = FLOW_EXPIRY_HINT.get_ptr(key) {
        let previous = unsafe { &*previous };
        if previous.incarnation == incarnation
            && now.saturating_sub(previous.last_hint_ns) < 1_000_000_000
        {
            return;
        }
    }
    let Some(mut reservation) = EVENT_RINGBUF.reserve(0) else {
        return;
    };
    let event: &mut DaeEvent = unsafe {
        zero_event_volatile(reservation.as_mut_ptr());
        reservation.assume_init_mut()
    };
    event.timestamp = now;
    event.type_ = honk_ebpf_common::event::DaeEventType::FlowExpired as u32;
    event.incarnation = incarnation;
    event.l4proto = key.l4proto;
    event.sip = unsafe { key.src_ip.u6_addr32 };
    event.dip = unsafe { key.dst_ip.u6_addr32 };
    event.sport = key.src_port;
    event.dport = key.dst_port;
    reservation.submit(0);
    if let Some(previous) = FLOW_EXPIRY_HINT.get_ptr_mut(key) {
        let previous = unsafe { &mut *previous };
        previous.incarnation = incarnation;
        previous.last_hint_ns = now;
    } else {
        let _ = FLOW_EXPIRY_HINT.insert(
            key,
            FlowExpiryHint {
                incarnation,
                last_hint_ns: now,
            },
            0,
        );
    }
}
