Fixed

- A UDP flow reaching a group that names `detour:` now dials through that front instead of the node's own path. The group detour was resolved only on the TCP dial path, so every UDP flow — QUIC/HTTP3, DNS-over-QUIC, UDP associates — silently left through the node's direct connection even while TCP traffic on the same group was chained.
- MASQUE, Hysteria2, TUIC, Juicity, Trojan and AnyTLS now carry a group's detour on UDP. A detoured flow builds its own tunnel, QUIC client or session instead of borrowing a pooled or shared-source carrier opened over another path, and a MASQUE UDP socket now keeps its tunnel alive so reload pruning cannot delete the device from under a live flow. Protocols that cannot carry a detour refuse the dial rather than quietly going direct.
