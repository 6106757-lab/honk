Added

- A node may name the node it dials out through. A node written into the configuration carries it on its share link as `?dialer-proxy=front`; Clash subscriptions read `dialer-proxy`, and sing-box and JSON outbounds read `detour`. The stream protocols dial the path before TLS, and the QUIC protocols (Hysteria2, TUIC, Juicity) run over the framed UDP path the detour hands back instead of binding a socket of their own.
- A detour may name a policy group as well as a node. The group is resolved on each dial rather than when the generation is built, so the front follows the group's current choice: switching a selector, or a fallback failing over, moves the chain without a reload.
- `dialer-proxy` is now read from a share link written into the configuration, which is the one place an operator writes a node by hand. Previously only a subscription's nodes could name a detour.
