Fixed

- A VLESS node that names `dialer-proxy` now dials through it. The plain
  stream path ignored the node's own detour and every dial failed with
  `detour ... is not bound in this generation`; only a group's detour
  reached a VLESS member.
