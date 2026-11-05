Fixed

- VLESS nodes imported from a subscription keep UDP enabled when the proxy omits `udp`, matching the same endpoint written as a local `node {}`. Only an explicit `udp: false` restricts the node, in both base64 share-link lists and mihomo/Clash YAML.
