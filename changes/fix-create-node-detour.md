Fixed

- `POST /api/v1/nodes` accepts a share link whose `dialer-proxy` names an existing node or group again. The entry was validated as a document holding only itself, so every detour it named was unresolvable and the create failed with "node detour must name a node, a group or direct"; the entry now runs only the checks that stand on one entry, and the assembled configuration still resolves the references when it activates.
