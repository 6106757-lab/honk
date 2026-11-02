Fixed

- A node that names `dialer-proxy` no longer fails with
  `detour ... is not bound in this generation` right after a reload that
  added the detour: the connection pool still offered bare TCP sockets it
  had opened before, and the pooled path has no runtime to read the
  binding from. Nodes on a detour now skip the pools and dial through
  the generation that carries the binding.
