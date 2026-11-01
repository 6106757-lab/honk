Fixed

- A node whose detour is not bound in the running generation now fails its dial instead of leaving through the real interface as if nothing were configured.
- A node that names a detour is carried through it exactly once. MASQUE reads the same shared binding as every other protocol, so its own carrier no longer applies the path a second time.
- REALITY is refused on a detour, and so are Hysteria2 obfuscation and port hopping: each needs a socket of this node's own, so applying them through a detour would not do what the configuration asks.
