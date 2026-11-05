Fixed

- A subscription that publishes an endpoint already written by hand in `config.dae` now loads: the hand-written node and the imported copy are two distinct outbounds instead of colliding on one node ID and rejecting the whole provider with `duplicate-node-id`.
- Two providers serving the same endpoint still share one identity, so the existing first-publisher-wins rule is unchanged.
