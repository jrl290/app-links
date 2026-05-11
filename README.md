# app-links

`app-links` is a small support crate for higher-level Reticulum/LXMF applications.
It is not a standalone end-user app, daemon, or CLI on its own.

The crate centralizes app-link lifecycle management used by host applications,
including:

- path-race based liveness checks
- destination registry state
- the three-tier DIRECT delivery send hierarchy

Today it primarily exists to support integrations such as `lxmf-rust` and other
host apps that need shared app-link behavior without reimplementing the same
logic in multiple places.

## Dependency Position

Current dependency chain:

```text
lxmf-rust -> app-links -> Reticulum-rust
```

`app-links` deliberately does not depend on `lxmf-rust`.

## Building

This crate currently expects the sibling path dependency layout used by the
Reticulum workspace:

```text
parent/
├── Reticulum-rust/
└── app-links/
```

Then build normally:

```bash
cargo build
```