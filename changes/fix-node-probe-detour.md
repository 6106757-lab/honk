Fixed

- A manual HTTP or DNS probe of a node that names its own front
  (dialer-proxy) now rides that front the way real flows do, instead of
  failing with a generic `probe_failed`; the DNS probe over UDP rides it
  too, and a failed probe attempt logs the actual cause.
