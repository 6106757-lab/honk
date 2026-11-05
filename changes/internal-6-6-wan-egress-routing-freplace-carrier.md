---
type: fix
scope: ebpf
summary: "Host the WAN egress routing freplace slot on a non-jump-table carrier program"
---

Linux 7.2+ refuses `BPF_LINK_CREATE EXT` against a program that is a
`WAN_EGRESS_TAIL` jump-table member, so publishing compiled routing failed on
7.2 kernels with `EBUSY`. The WAN egress tail classifiers
(`wan_egress_{tcp,udp}_tail`) are tail-call targets and were also the freplace
targets, which combined the two forbidden roles.

Add `wan_egress_routing_carrier`, a classifier that is never attached and never
tail-called, whose only purpose is to carry `honk_route_slot0` /
`honk_route_slot1` as freplace targets (it references them so they appear in its
BTF). `ROUTING_TARGETS` now lists the carrier instead of the two tails. The
tails keep invoking the slot through their shared, object-global call path, so
the published policy still applies to WAN egress traffic.

This does not change the verifier budget of any executed program: the routing
policy remains a separately-verified `EXT` program, and the tail programs only
gain a single call to the slot. It also does not change the 6.6/6.12 data path;
the tail classifiers and the jump table are byte-for-byte unchanged.

Reported by the `datapath_observation_crosschecks_program_hook_root_and_admission`
real-kernel test on the `recent` (7.2.5) VM lane; the `floor` (6.12.0) lane was
already green because 6.12 permits the tail-call + freplace combination.
