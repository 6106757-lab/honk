Added

- `masque://` share links now carry the parameters the node form writes: `network` (`h2`, or `h3`/`quic` for the QUIC carrier), `private-key`, `public-key`, `ip`, `ipv6`, `mtu`, `remote-dns-resolve` and `dns`, with `sni` / `insecure` handled by the shared TLS pass. Previously the parser read only the endpoint, so a hand-written or UI-generated MASQUE link arrived with no key material and no tunnel address.
- A MASQUE link enables TLS implicitly: the tunnel is always TLS, and a link that names no `security` must not end up dialling in the clear. An unknown `network` value keeps the protocol default rather than failing the node, and `h3` is accepted as another spelling of `quic`.
