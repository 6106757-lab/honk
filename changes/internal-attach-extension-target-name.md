<!-- changelog type: internal -->

## Internal: name the routing EXT link target in attach errors

`BPF_LINK_CREATE EXT` failures now report which target program rejected the
link instead of only the BTF function id. The Linux 7.2.5 CI lane currently
fails `BPF_LINK_CREATE EXT target btf 288: EBUSY` without identifying whether
`lan_ingress_l2`, `lan_ingress_l3`, or one of the WAN egress tail programs
refused the attach; the target name makes the next diagnostic round decisive.
No behavior change.
