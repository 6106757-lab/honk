---
type: fix
scope: ebpf
summary: "Host the WAN egress routing freplace slot on the wan_egress_l2/l3 entry classifiers"
---

Linux 7.2+ refuses `BPF_LINK_CREATE EXT` against a program that is a
`WAN_EGRESS_TAIL` jump-table member (CVE-2024-47794, `EBUSY`), so the WAN egress
tail classifiers (`wan_egress_{tcp,udp}_tail`) could not be freplace targets.

The previous carrier approach — hosting the slot on a never-attached
`wan_egress_routing_carrier` program — failed in CI because the carrier was dead
code: it was never invoked, so the published WAN policy never applied, while the
tails kept calling their own (unreplaced) slot copy. That broke real routing on
WAN egress and panicked the `dns_ownership` datapath tests on both the 6.12 and
7.2 lanes.

This change moves the routing slot call from the tails up into the
`wan_egress_l2/l3` TC entry classifiers. Those classifiers are attached straight
to the hook and are never tail-called, so their slot can be freplaced on every
supported kernel, including 7.2. The entry computes the decision in
`route_wan_egress_at_entry` (a `#[inline(never)]` subprogram, so it stays out of
the entry's verifier state budget and keeps 6.6 within its limit) for the same
cases the tail used to route — a fresh TCP SYN and a UDP miss / short-lived HIT —
and carries the result to the tail through `PKT_SCRATCH_KEY`:
`ParsedPacket.routing_generation`, `trace_id`, `routing_computed`, and
`route_witness.output.decision`. The tails now read the decision from scratch
instead of calling the slot. `ROUTING_TARGETS` lists `wan_egress_l2/l3` together
with the LAN ingress classifiers; the dead carrier program is removed.

The routing outcome is unchanged: the TCP publisher claim and the conntrack
cache refresh stay in the tail exactly as before, and a routing failure at the
entry still drops the packet (`TC_ACT_SHOT`), preserving the original tail
behavior.

This keeps every executed program within its verifier budget — the tails shrink
(no routing computation) and the entry only gains a non-inline call — and does
not change the 6.6/6.12 data path beyond where the routing slot is hosted.
