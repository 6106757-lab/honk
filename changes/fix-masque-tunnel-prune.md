Fixed

- MASQUE tunnels that a reused runtime kept from an earlier generation are reclaimed on reload, so their TUN devices and routes no longer linger until a restart. Flows hold a reference to the tunnel they ride, so reloading does not tear an active connection's device away.
