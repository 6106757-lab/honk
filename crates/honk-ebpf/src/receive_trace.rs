//! Candidate skb metadata becomes evidence only at successful outer recvmsg exit.
//!
//! Every hook exists twice: as fentry/fexit for kernels that carry the function
//! tracer, and as kprobe/kretprobe for the many router kernels that disable it.
//! Userspace attaches the cheap tracing pair first and falls back to the probes.
//!
//! A kretprobe is handed the callee's return registers only, so the `sock` argument
//! is long gone by then; the probe path stages it per task on entry and consumes it
//! on the way back out.

use aya_ebpf::{
    Global,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{fentry, fexit, kprobe, kretprobe, map},
    maps::HashMap,
    programs::{FEntryContext, FExitContext, ProbeContext, RetProbeContext},
};
use honk_ebpf_common::receive_trace::{
    RECEIVE_PROBE_TASKS, RECEIVE_TRACE_BATCH_SIZE, RECEIVE_TRACE_SOCKETS, RECEIVE_TRACE_VALID,
    ReceiveTraceBatch,
};

#[unsafe(no_mangle)]
pub static RECEIVE_SOCK_COOKIE_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
pub static RECEIVE_SKB_PRIORITY_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
pub static RECEIVE_SKB_MARK_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
pub static RECEIVE_OWNER_TGID: Global<u32> = Global::new(0);

#[map]
pub static RECEIVE_TRACE: HashMap<u64, ReceiveTraceBatch> =
    HashMap::with_max_entries(RECEIVE_TRACE_SOCKETS, 0);

/// The `sock` argument staged by a probe entry hook for the matching return hook.
///
/// Keyed by task so a migration between entry and return cannot mix sockets up.
#[map]
pub static RECEIVE_PROBE_SK: HashMap<u64, u64> = HashMap::with_max_entries(RECEIVE_PROBE_TASKS, 0);

#[inline(always)]
fn stage(sk: *const u8) {
    let sk = if sk.is_null() { 0 } else { sk as u64 };
    let _ = RECEIVE_PROBE_SK.insert(bpf_get_current_pid_tgid(), sk, 0);
}

#[inline(always)]
fn staged() -> *const u8 {
    match RECEIVE_PROBE_SK.get(bpf_get_current_pid_tgid()) {
        Ok(sk) => *sk as *const u8,
        Err(_) => core::ptr::null(),
    }
}

#[inline(always)]
fn unstage() {
    let _ = RECEIVE_PROBE_SK.remove(bpf_get_current_pid_tgid());
}

#[inline(always)]
fn state(sk: *const u8) -> Option<*mut ReceiveTraceBatch> {
    // The hooks run for every UDP receive on the host.
    if sk.is_null() || (bpf_get_current_pid_tgid() >> 32) as u32 != RECEIVE_OWNER_TGID.load() {
        return None;
    }
    let cookie = unsafe {
        bpf_probe_read_kernel::<u64>(sk.add(RECEIVE_SOCK_COOKIE_OFFSET.load() as usize).cast())
    }
    .ok()?;
    if cookie == 0 {
        return None;
    }
    let state = RECEIVE_TRACE.get_ptr_mut(&cookie)?;
    (unsafe { (*state).active } != 0).then_some(state)
}

#[inline(always)]
fn enter(sk: *const u8, flags: i32) -> bool {
    let Some(ptr) = state(sk) else { return false };
    let batch = unsafe { &mut *ptr };
    let owner = bpf_get_current_pid_tgid();
    if batch.depth != 0 {
        batch.lost = 1;
        batch.depth = batch.depth.saturating_add(1);
        return true;
    }
    batch.owner = owner;
    batch.depth = 1;
    batch.candidate.valid = 0;
    // PEEK and ERRQUEUE are never data-consumption witnesses.
    if flags & (0x2 | 0x2000) != 0 {
        batch.lost = 1;
    }
    true
}

#[inline(always)]
fn exit(sk: *const u8, result: Result<i32, i32>) {
    let Some(ptr) = state(sk) else { return };
    let batch = unsafe { &mut *ptr };
    if batch.depth == 0 || batch.owner != bpf_get_current_pid_tgid() {
        batch.lost = 1;
        return;
    }
    batch.depth -= 1;
    if batch.depth != 0 {
        return;
    }
    let Ok(length) = result else {
        batch.lost = 1;
        return;
    };
    if length < 0 {
        batch.candidate.valid = 0;
        return;
    }
    let index = batch.count as usize;
    if index >= RECEIVE_TRACE_BATCH_SIZE {
        batch.lost = 1;
        return;
    }
    // Zero bytes is a successfully consumed datagram, not an empty batch.
    batch.candidate.length = length as u32;
    batch.packets[index] = batch.candidate;
    batch.count += 1;
    batch.candidate.valid = 0;
}

#[inline(always)]
fn candidate(sk: *const u8, skb: Result<*const u8, i32>) {
    let Some(ptr) = state(sk) else {
        return;
    };
    let batch = unsafe { &mut *ptr };
    if batch.depth != 1 || batch.owner != bpf_get_current_pid_tgid() {
        batch.lost = 1;
        return;
    }
    // A checksum-discarded candidate is overwritten by the next helper return.
    batch.candidate.valid = 0;
    let Ok(skb) = skb else {
        return;
    };
    if skb.is_null() || skb as usize >= usize::MAX - 4095 {
        return;
    }
    let priority = unsafe {
        bpf_probe_read_kernel::<u32>(skb.add(RECEIVE_SKB_PRIORITY_OFFSET.load() as usize).cast())
    };
    let mark = unsafe {
        bpf_probe_read_kernel::<u32>(skb.add(RECEIVE_SKB_MARK_OFFSET.load() as usize).cast())
    };
    if let (Ok(priority), Ok(mark)) = (priority, mark) {
        batch.candidate.priority = priority;
        batch.candidate.mark = mark;
        batch.candidate.valid = RECEIVE_TRACE_VALID;
    }
}

#[fentry]
pub fn honk_udp_receive_enter(ctx: FEntryContext) -> u32 {
    enter(ctx.arg(0), ctx.arg(3));
    0
}

#[fentry]
pub fn honk_udp6_receive_enter(ctx: FEntryContext) -> u32 {
    enter(ctx.arg(0), ctx.arg(3));
    0
}

#[fexit]
pub fn honk_udp_receive_exit(ctx: FExitContext) -> u32 {
    exit(ctx.arg(0), ctx.ret());
    0
}

#[fexit]
pub fn honk_udp6_receive_exit(ctx: FExitContext) -> u32 {
    exit(ctx.arg(0), ctx.ret());
    0
}

#[fexit]
pub fn honk_udp_receive_candidate(ctx: FExitContext) -> u32 {
    candidate(ctx.arg(0), ctx.ret::<*const u8>());
    0
}

#[kprobe]
pub fn honk_udp_receive_enter_probe(ctx: ProbeContext) -> u32 {
    let sk = ctx.arg::<*const u8>(0).unwrap_or(core::ptr::null());
    if enter(sk, ctx.arg::<i32>(3).unwrap_or(0)) {
        stage(sk);
    }
    0
}

#[kprobe]
pub fn honk_udp6_receive_enter_probe(ctx: ProbeContext) -> u32 {
    let sk = ctx.arg::<*const u8>(0).unwrap_or(core::ptr::null());
    if enter(sk, ctx.arg::<i32>(3).unwrap_or(0)) {
        stage(sk);
    }
    0
}

#[kretprobe]
pub fn honk_udp_receive_exit_probe(ctx: RetProbeContext) -> u32 {
    let sk = staged();
    if !sk.is_null() {
        exit(sk, Ok(ctx.ret::<i32>()));
        unstage();
    }
    0
}

#[kretprobe]
pub fn honk_udp6_receive_exit_probe(ctx: RetProbeContext) -> u32 {
    let sk = staged();
    if !sk.is_null() {
        exit(sk, Ok(ctx.ret::<i32>()));
        unstage();
    }
    0
}

#[kretprobe]
pub fn honk_udp_receive_candidate_probe(ctx: RetProbeContext) -> u32 {
    candidate(staged(), Ok(ctx.ret::<*const u8>()));
    0
}
