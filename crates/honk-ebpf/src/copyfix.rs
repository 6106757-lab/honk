//! Fixed-size byte copies that never lower to a counted loop.
//!
//! `copy_from_slice`/`copy_nonoverlapping` over a compile-time length becomes
//! either a byte loop or a `memcpy` subprogram call. The loop is far worse on
//! 6.6: every iteration advances the destination pointer by one byte, so the
//! verifier explores a fresh state per byte and keeps the trip count precise
//! (`mark_precise` then re-walks the whole chain). A single 16-byte `pname`
//! copy accounted for ~25k of the 50k states that exhausted `wan_egress_l3`'s
//! 1M-insn budget.
//!
//! These helpers copy 4/2-byte chunks at compile-time-known offsets and mark
//! every store volatile, which stops LLVM from re-merging the sequence back
//! into `memcpy`. All chunk stores stay 4-aligned (or 2-aligned), so they hold
//! for any field offset inside a packed map value.

/// Copy a 16-byte slot (task comm / pname) as four 4-byte stores.
#[inline(always)]
pub unsafe fn copy16(dst: *mut [u8; 16], src: *const [u8; 16]) {
    let d = dst as *mut u32;
    let s = src as *const u32;
    core::ptr::write_volatile(d, core::ptr::read_unaligned(s));
    core::ptr::write_volatile(d.add(1), core::ptr::read_unaligned(s.add(1)));
    core::ptr::write_volatile(d.add(2), core::ptr::read_unaligned(s.add(2)));
    core::ptr::write_volatile(d.add(3), core::ptr::read_unaligned(s.add(3)));
}

/// Copy a 6-byte MAC address as one 4-byte and one 2-byte store.
#[inline(always)]
pub unsafe fn copy6(dst: *mut [u8; 6], src: *const [u8; 6]) {
    let d = dst as *mut u8;
    let s = src as *const u8;
    core::ptr::write_volatile(d as *mut u32, core::ptr::read_unaligned(s as *const u32));
    core::ptr::write_volatile(
        d.add(4) as *mut u16,
        core::ptr::read_unaligned(s.add(4) as *const u16),
    );
}
