Security

- Clear RUSTSEC-2026-0385 by locking `ctutils` to 0.4.7, so AES-GCM mask generation and `u128` comparisons use constant-time helpers.
