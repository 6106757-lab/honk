Added

- A node may name the node it dials out through. A node written into the configuration carries it on its share link as `?dialer-proxy=front`; Clash subscriptions read `dialer-proxy`, and sing-box and JSON outbounds read `detour`. Every protocol can ride one: the stream protocols dial the path before TLS, and the QUIC protocols (Hysteria2, TUIC, Juicity) run over the framed UDP path the detour hands back instead of binding a socket of their own.
- A configuration or subscription that points a node's detour at a group no longer leaves that node unusable: the name is dropped with a warning naming the node, so the configuration still loads and the node dials on its own path.
