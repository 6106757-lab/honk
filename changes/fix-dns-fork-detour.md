Fixed

- DNS upstreams that dial through a node which names `dialer-proxy` no
  longer fail with `detour ... is not bound in this generation`. The DNS
  runtime fork rebuilt every node runtime without the detour bindings,
  and since the fork is rebuilt on every boot, restarting did not help.
  The fork now carries the parent generation's bindings over.
