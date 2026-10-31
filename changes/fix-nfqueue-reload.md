Fixed

- When NFQUEUE is unavailable at startup, configuration writes and reloads are no longer refused because `global.nfqueue_enable` needs a restart; the reloaded configuration keeps NFQUEUE disabled.
