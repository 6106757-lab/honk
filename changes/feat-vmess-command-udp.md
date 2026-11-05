Added

- VMess UDP through the protocol's command-UDP request (`0x02`): one association per destination, one AEAD body chunk per datagram in each direction. It is connected UDP, so a UDP flow over VMess works but is not a shared full-cone source.
- VMess follows the `network` field like Trojan: an explicit `network: tcp` keeps the node out of UDP selection, while an omitted value allows both TCP and UDP.
