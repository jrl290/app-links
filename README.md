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
- How one tier hands over to the next depends on the message's size:
	- A message that fits one link packet: each tier fires, and the next
		fires `DIRECT_STAGGER_WAIT` (1 s) later unless the send has been
		delivered by then. The earlier packet stays in flight.
	- A message over the link MDU travels as a Resource. Each tier's Resource
		runs to its own outcome, and the next tier fires only on that tier's own
		failure event. That means the Resource concluding without COMPLETE,
		which is also how it ends when its link closes or when the receiver
		never answers its advertisement (RNS 1.5.2 `Resource.py`: the watchdog
		gives up after `MAX_ADV_RETRIES`). No clock hands a tier over: not the
		stagger, and not the outcome backstop below. A Resource queued behind
		another transfer on its link waits its turn, as the reference does. A
		stalled one is decided by its own RTT-scaled timeouts.
	- Since 2026-09-29. Before that, Resource tiers staggered by 1 s like
		packets, so a photo went out two or three times at once. On the iPad over
		the Bluetooth RTNode link it ran as two concurrent 3700-part Resources,
		each at half speed. Tiers 1 and 2 also reported no failure, so a tier-3
		path race or link that failed FAILED the message while tier 1's
		Resource was still moving.
- A send has one outcome. `on_delivered` fires once, from whichever tier
	delivers first. `on_failed` fires once, only when no tier is left to fire
	and every tier that fired has failed (or no tier could fire). Anything a
	tier reports after the outcome is logged and ignored, except a delivery
	after `on_failed`. That still reaches `on_delivered`, once, because the
	peer proved it holds the message. It is the same rule Reticulum-rust
	follows for a late proof (PARITY-AUDIT B35), and LXMF reports it as a late
	delivery.
- It tracks inbound delivery links opened by peers so later sends can reuse
	them as the first tier.
- It owns the 5-second propagation fallback trigger (Timer P) used when direct
	delivery has not completed. The 5 seconds count only time without transfer
	activity: a message over the link MDU travels as a Resource, and each
	request the receiver makes that brings more of it sent starts them again,
	so a transfer that is moving gets no propagated backup copy. The activity
	clock is shared across the tiers, so a Resource that fails on one tier and
	moves on the next is one transfer to Timer P. Each fired tier's outcome
	backstop (120 s) counts the same way. It only guards a lost callback. On
	a packet tier it counts the tier failed. On a Resource tier it only logs:
	a Resource that has not concluded can still deliver, so its own events
	decide it.
- Earlier on 2026-09-29 the backstop still failed a quiet Resource tier and
	handed it over. A photo queued for 120 s behind another photo on its link
	went out again on the next tier, beside the first, and the queued copy
	went too once its turn came. That change also swallowed a delivery that
	came after `on_failed`, so a message the peer had proved stayed FAILED.
	Both were fixed the same evening.
- It reports a Resource transfer's progress to the caller
	(`send_with_compression` / `send_on_held_link`, `SendProgressCallback`):
	the raw `Resource::get_progress` fraction after each request served, until
	delivery. A message that fits one link packet reports nothing.

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