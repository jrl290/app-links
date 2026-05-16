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

## Concepts

AppLinks does not introduce a separate network-level link type. In both the
LXMF and non-LXMF cases, the underlying transport primitive is still the same
Reticulum `LinkHandle`.

What changes is AppLinks' responsibility above that transport link.

### LXMF Direct Delivery

For direct LXMF delivery, AppLinks acts as a send orchestrator.

- It owns the three-tier DIRECT send flow: inbound link, cached outbound link,
	then fresh outbound link.
- It tracks inbound delivery links opened by peers so later sends can reuse
	them as the first tier.
- It owns the 5-second propagation fallback trigger used when direct delivery
	has not completed.

In other words, for direct LXMF delivery AppLinks is not just keeping a link
alive. It decides how the send is attempted and which link path is used.

### Generic Reticulum App Destinations

For generic app destinations, AppLinks is primarily a lifecycle and liveness
layer.

- It watches announces and path availability.
- It opens an app-link in either `EphemeralLink` or `Persistent` mode.
- If a persistent link is requested, it owns creation and teardown of the held
	outbound link.

After that, the caller owns the application protocol that runs over the link.
AppLinks does not interpret request/response payloads for those destinations.

The current `lxmf.propagation` flow is the main example: AppLinks owns the
persistent propagation link, while `lxmf-rust` owns identify, message-list,
message-get, and acknowledgement requests sent over that link.

### `EphemeralLink`

`EphemeralLink` is the lifecycle mode behind `AppLinks::open()`.

- `open()` performs only path-race/liveness work.
- No outbound link is held open just because `open()` was called.
- A fresh outbound link may still be created later by the DIRECT tier-3 send
	path when an actual send needs one.
- If that tier-3 link succeeds, AppLinks may cache it for short-term reuse, but
	there is no persistent ownership contract.

This is the normal mode for direct LXMF delivery destinations.

### `Persistent`

`Persistent` is the lifecycle mode behind `AppLinks::open_persistent()`.

- AppLinks first races path readiness.
- Once a usable path exists, it creates and holds a real outbound link.
- That link remains AppLinks-owned until it closes or the destination is
	explicitly closed.
- Status callbacks may receive a live `LinkHandle` when the persistent link
	becomes active.

This mode is for app protocols that want a stable shared link instead of
on-demand send-time link creation.

### Practical Rule

- LXMF direct delivery: AppLinks sends for you.
- Generic Reticulum app destination: AppLinks gets you to Ready or to an active
	persistent link, and your protocol runs on top of it.

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