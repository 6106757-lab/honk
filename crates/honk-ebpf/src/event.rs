//! Direct ring reservations keep event payloads off the bounded TC call-chain stack.

use crate::maps::{EVENT_RINGBUF, FLOW_EXPIRY_HINT, FlowExpiryHint};
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;
use honk_ebpf_common::event::DaeEvent;

/// Initialize a ringbuf event slot field-by-field with volatile stores.
///
/// A bulk `write_bytes(0)` (or any contiguous run of constant-zero stores)
/// is merged by LLVM into a call to the embedded `memset` subprogram, whose
/// frame adds 32 bytes to every verifier call chain that ends in an event —
/// on pre-6.12 kernels the TC classifiers sit exactly at that 512B combined
/// stack limit. This helper writes every byte exactly once: fields the caller
/// supplies get their runtime value, the rest get zero, and the constant-zero
/// stores are ordered so that no two of them cover adjacent addresses back to
/// back. Without a contiguous zero-run LLVM cannot form a `memset` call, and
/// the payload is written in ringbuf memory, so per-event cost is unchanged.
///
/// DaeEvent layout (80 bytes): timestamp@0, type_@8, pid@12, pname@16,
/// outbound@32, l4proto@33, pad@34, sip@36, dip@52, sport@68, dport@70,
/// incarnation@72.
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
    let p: *mut DaeEvent = reservation.as_mut_ptr();
    unsafe {
        // Zero-only stores are interleaved with runtime stores (marked R) so
        // no two zero stores cover adjacent addresses consecutively.
        core::ptr::write_volatile(&raw mut (*p).timestamp, bpf_ktime_get_ns()); // R
        core::ptr::write_volatile(&raw mut (*p).incarnation, 0); // Z @72
        core::ptr::write_volatile(&raw mut (*p).type_, type_); // R
        core::ptr::write_volatile(&raw mut (*p).pad, [0; 2]); // Z @34
        core::ptr::write_volatile(&raw mut (*p).pid, pid); // R
        match pname {
            Some(src) => core::ptr::copy_nonoverlapping(src.as_ptr(), (*p).pname.as_mut_ptr(), 16), // R
            None => core::ptr::write_volatile((&raw mut (*p).pname).cast::<u64>().add(1), 0), // Z @24
        }
        core::ptr::write_volatile(&raw mut (*p).sport, sport); // R
        match sip {
            Some(src) => core::ptr::copy_nonoverlapping(src.as_ptr(), (*p).sip.as_mut_ptr(), 4), // R
            None => core::ptr::write_volatile((&raw mut (*p).sip).cast::<u64>().add(1), 0), // Z @44
        }
        if pname.is_none() {
            core::ptr::write_volatile((&raw mut (*p).pname).cast::<u64>(), 0); // Z @16
        }
        core::ptr::write_volatile(&raw mut (*p).dport, dport); // R
        match dip {
            Some(src) => core::ptr::copy_nonoverlapping(src.as_ptr(), (*p).dip.as_mut_ptr(), 4), // R
            None => core::ptr::write_volatile((&raw mut (*p).dip).cast::<u64>().add(1), 0), // Z @60
        }
        core::ptr::write_volatile(&raw mut (*p).outbound, outbound); // R
        if sip.is_none() {
            core::ptr::write_volatile((&raw mut (*p).sip).cast::<u64>(), 0); // Z @36
        }
        if dip.is_none() {
            core::ptr::write_volatile((&raw mut (*p).dip).cast::<u64>(), 0); // Z @52
        }
        core::ptr::write_volatile(&raw mut (*p).l4proto, l4proto); // R
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
    let p: *mut DaeEvent = reservation.as_mut_ptr();
    unsafe {
        // Zero-only stores (pid, pname, outbound, pad) are interleaved with
        // the runtime stores; FlowExpired != 0 so type_ is a barrier too.
        core::ptr::write_volatile(&raw mut (*p).timestamp, now); // R
        core::ptr::write_volatile((&raw mut (*p).pname).cast::<u64>().add(1), 0); // Z @24
        core::ptr::write_volatile(&raw mut (*p).incarnation, incarnation); // R
        core::ptr::addr_of_mut!((*p).sip).write(key.src_ip.u6_addr32); // R
        core::ptr::write_volatile((&raw mut (*p).pname).cast::<u64>(), 0); // Z @16
        core::ptr::addr_of_mut!((*p).dip).write(key.dst_ip.u6_addr32); // R
        core::ptr::write_volatile(&raw mut (*p).pid, 0); // Z @12
        core::ptr::write_volatile(&raw mut (*p).outbound, 0); // Z @32
        core::ptr::write_volatile(
            &raw mut (*p).type_,
            honk_ebpf_common::event::DaeEventType::FlowExpired as u32,
        ); // R (nonzero)
        core::ptr::write_volatile(&raw mut (*p).pad, [0; 2]); // Z @34
        core::ptr::write_volatile(&raw mut (*p).l4proto, key.l4proto); // R
        core::ptr::write_volatile(&raw mut (*p).sport, key.src_port); // R
        core::ptr::write_volatile(&raw mut (*p).dport, key.dst_port); // R
    }
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
