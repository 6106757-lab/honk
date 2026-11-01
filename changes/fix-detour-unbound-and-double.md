Fixed

- A node whose detour is not bound in the running generation now fails its dial instead of leaving through the real interface as if nothing were configured.
- A node that names a detour is carried through it exactly once. MASQUE reads the same shared binding as every other protocol, so its own carrier no longer applies the path a second time.
- REALITY is refused on a detour, and so are Hysteria2 obfuscation and port hopping: each needs a socket of this node's own, so applying them through a detour would not do what the configuration asks.
- A detour that names a group is no longer discarded. It used to be dropped with a warning, on the grounds that nothing on the dial path could resolve a group, which meant a subscription carrying `dialer-proxy: <group>` silently configured nothing.
- A SOCKS5 or AnyTLS node that names a detour is now carried by it instead of ignoring it. Both dialled their own socket and never read the binding, so the traffic left through the real interface looking like an ordinary connection — the one thing a detour exists to rule out.
- A Shadowsocks node that names a detour now refuses the dial. Its ciphers are built around a real socket, so it cannot be carried; failing loudly is better than going direct without saying so.
