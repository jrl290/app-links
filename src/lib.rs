//! App-link crate.
//!
//! Owns path-racing (liveness), the destination registry, the
//! three-tier send hierarchy for DIRECT LXMF delivery, and an optional
//! held-open outbound link mode for generic app destinations.
//!
//! Dependency chain: `lxmf-rust → app-links → reticulum-rust`
//! (no cycles; this crate does NOT depend on lxmf-rust).
//!
//! # Mental Model
//!
//! AppLinks does not define a separate wire-level link type. In every case the
//! transport primitive is still Reticulum's `LinkHandle`.
//!
//! The distinction is what AppLinks owns above that transport link.
//!
//! ## LXMF direct delivery
//!
//! For direct LXMF delivery, AppLinks is the send orchestrator.
//!
//! - It owns the three-tier DIRECT send flow.
//! - It tracks peer-initiated inbound delivery links for reuse.
//! - It fires the propagation fallback signal when direct delivery has not
//!   completed within the required window.
//!
//! In this mode, AppLinks is deciding *how* to send, not just whether a link
//! exists.
//!
//! ## Generic Reticulum app destinations
//!
//! For generic app destinations, AppLinks is mainly a liveness and lifecycle
//! layer.
//!
//! - It watches readiness and announce state.
//! - It opens either an `EphemeralLink` or a `Persistent` app-link lifecycle.
//! - It may hand the caller an active persistent `LinkHandle`.
//!
//! The caller then owns the application protocol spoken over that link. The
//! current `lxmf.propagation` flow is the reference example: AppLinks owns the
//! persistent link, while `lxmf-rust` owns identify/request/response handling.
//!
//! ## `EphemeralLink`
//!
//! `EphemeralLink` is the lifecycle mode used by [`AppLinks::open`]. It races
//! path readiness but does not hold an outbound link open merely because the
//! destination was registered. An outbound link may still be created later by
//! the tier-3 send path and cached for reuse, but AppLinks does not treat that
//! as a long-lived owned session.
//!
//! ## `Persistent`
//!
//! `Persistent` is the lifecycle mode used by [`AppLinks::open_persistent`].
//! AppLinks races path readiness, creates a real outbound link, and keeps that
//! link in the registry until it closes or the destination is explicitly
//! closed.
//!
//! # Send tiers  (see DESIGN_PRINCIPLES.md §1, §3, §5, §7)
//!
//! `AppLinks::send(dest, packed, on_delivered, on_propagation_needed, on_failed)` drives:
//!
//! Timer P starts in parallel the moment `send` is called.  It counts only
//! time WITHOUT transfer activity: `on_propagation_needed` fires once the
//! send has gone the 5 s liveness budget undelivered and without its
//! transfer moving, and never after delivery.  A message over the link MDU
//! travels as a Resource, and each request the receiver makes that brings
//! more of it sent is activity that restarts the 5 s; a transfer that is
//! making progress is not stuck, and a propagated backup copy of it would
//! upload the whole payload a second time.  (Until 2026-09-29 Timer P fired
//! 5 s after `send` whatever the transfer was doing: an iPad photo, 1708
//! parts over a Nearby RTNode Bluetooth link, got a backup copy 5 s into a
//! direct transfer that went on to deliver.)  The activity clock is shared
//! by every tier, so a Resource that fails on one tier and starts on the
//! next is one transfer to Timer P: only the quiet time counts, across the
//! handover.  When the current APP_LINK status is already `DISCONNECTED` it
//! fires immediately so propagation can start in parallel with the fresh
//! direct cascade.  This is independent of the tier chain.
//!
//!   * **Tier 1** — peer-initiated inbound link (they opened it to us).
//!   * **Tier 2** — cached outbound link (`STATE_ACTIVE`).
//!   * **Tier 3** — `expire_path` → `race_path` (≤5 s) → `Link::new_outbound`
//!     + `initiate` (≤5 s) → fire.  A setup failure (race, identity, link
//!     establishment) means tier 3 did not fire.
//!
//! How a tier hands over to the next depends on how the message travels
//! ([`link_representation`]):
//!
//!   * **One link packet** (up to the link MDU): each tier fires, and the
//!     next fires [`DIRECT_STAGGER_WAIT`] (1 s, Timer A / Timer B) later
//!     unless the send has been delivered by then.  The earlier packet stays
//!     in flight; its receipt (proof or RTT-scaled timeout) still counts.
//!   * **A Resource** (over the link MDU): each tier's Resource runs to its
//!     own outcome, and the next tier fires only on that tier's own failure
//!     event — its Resource concluding without COMPLETE.  That is also how a
//!     Resource ends when its link closes (RNS/Link.py `link_closed` cancels
//!     it) and when the receiver never starts the transfer (RNS/Resource.py
//!     watchdog: the advertisement unanswered through `MAX_ADV_RETRIES`).
//!     Never because a clock ran: not the stagger, and not the outcome
//!     backstop below.  A Resource QUEUED behind another transfer on its link
//!     waits its turn, as the reference does, and a stalled one is decided
//!     by its own RTT-scaled timeouts.
//!
//! Until 2026-09-29 every tier fired 1 s after the one before whatever the
//! payload, so a Resource went out two or three times at once: an iPad
//! photo over the Bluetooth RTNode link ran as two concurrent 3700-part
//! Resources, each at half the link's speed.  And tiers 1 and 2 reported no
//! failure, so tier 3 alone decided `on_failed`: a tier-3 path race or link
//! that failed FAILED the message while tier 1's Resource was still moving.
//!
//! One outcome per send (`SendOutcome`): `on_delivered` once, from whichever
//! tier delivers first; `on_failed` once, only when the chain will fire no
//! more tiers and every tier that fired has failed (or no tier could fire).
//! Anything a tier reports after the outcome is logged and ignored, except
//! a delivery after `on_failed`.  That still reaches `on_delivered`, once:
//! the peer proved it holds the message (Reticulum-rust's PARITY-AUDIT B35
//! rule for a late proof).  Each fired tier's outcome wait has the 120 s
//! backstop, which counts only time with neither an outcome nor transfer
//! activity.  It guards a lost callback.  On a packet tier it counts the tier
//! failed.  On a Resource tier it only logs, because a Resource that has not
//! concluded can still deliver.
//!
//! Earlier on 2026-09-29 the backstop still failed a quiet Resource tier and
//! handed it over.  A photo queued for 120 s behind another photo on its link
//! went out again on the next tier, beside the first, and the queued copy
//! went too once its turn came.  That change also swallowed a delivery that
//! came after `on_failed`, so a message the peer had proved stayed FAILED.
//!
//! `send_with_compression` and `send_on_held_link` take an optional progress
//! callback that hears the Resource's own fraction (`Resource::get_progress`,
//! RNS/Resource.py `get_progress`) after each request the receiver makes,
//! until delivery, and 0.0 once its advertisement has gone out.  A payload
//! that fits one link packet reports nothing.  The advertisement report is
//! for DESIGN_PRINCIPLES §1, bulk transfers: from the advertisement on, a
//! Resource must show progress at least every 5 s, and LXMF's send
//! assertion watches that from these reports (since 2026-10-01).
//!
//! Advancing to the next tier NEVER cancels or closes the packet or Resource
//! of an earlier tier.
//!
//! # Open / liveness
//!
//! `AppLinks::open()` races a path (liveness), marks the destination READY,
//! and fires `APP_LINK_ACTIVE(None)`.  **No link is built** by `open()`.
//!
//! `AppLinks::open_persistent()` uses the same path-race gate, then
//! establishes and holds an outbound `LinkHandle` in `Registry.links`.
//! The underlying `Link` actor owns keepalive and stale detection.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

use reticulum_rust::announce_log;
use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::link::{
    Link,
    LinkHandle,
    MODE_AES256_CBC,
    STATE_ACTIVE,
    STATE_HANDSHAKE,
    STATE_PENDING,
};
use reticulum_rust::packet::{self, Packet};
use reticulum_rust::transport::{AnnounceCallback, AnnounceHandler, Transport, BROADCAST};
use reticulum_rust::{hexrep, log, LOG_NOTICE};

// ─── Public status constants ─────────────────────────────────────────────
pub const APP_LINK_NONE: u8 = 0x00;
pub const APP_LINK_PATH_REQUESTED: u8 = 0x01;
pub const APP_LINK_ESTABLISHING: u8 = 0x02;
pub const APP_LINK_ACTIVE: u8 = 0x03;
pub const APP_LINK_DISCONNECTED: u8 = 0x04;

/// Tier-advance stagger for a message that fits ONE link packet: after a
/// tier fires its packet, the next tier fires this many seconds later unless
/// the send has been delivered by then.  The earlier packet stays in flight.
///
/// A message over the link MDU travels as a Resource and does not use this:
/// the next tier fires only on the earlier tier's own failure event (its
/// Resource concluding FAILED: rejected, the link closed, the advertisement
/// unanswered through its retries, a part or proof timed out), never because
/// this second passed, and never at the outcome backstop either.  Until
/// 2026-09-29 every tier fired its own full Resource 1 s after the one
/// before, so a photo went out two or three times at once and each copy ran
/// at a fraction of the link's speed.
///
/// Owned here because AppLinks drives all tier scheduling.
pub const DIRECT_STAGGER_WAIT: f64 = 1.0;

/// Settling window for dual-link disambiguation (seconds).
/// When both an outbound and an inbound link exist for the same destination,
/// the one whose most-recent inbound traffic is older than this value is
/// torn down.  2 × KEEPALIVE_MAX (360 s) protects healthy links.
pub const DUAL_LINK_SETTLING_SECS: u64 = 720;

/// Host lifecycle policy.  Gates which triggers are allowed to attempt
/// new path-races.  Set via [`AppLinks::set_policy`].
///
/// Default: [`LinkPolicy::Foreground`].
///
/// Trigger gate matrix (✓ = fires, ✗ = no-op):
///
/// | trigger                        | Foreground | Background | Suspended |
/// |--------------------------------|:----------:|:----------:|:---------:|
/// | `open()`                       |     ✓      |     ✓      |     ✗     |
/// | `announce_received()`          |     ✓      |     ✓      |     ✗     |
/// | `network_changed()`            |     ✓      |     ✗      |     ✗     |
/// | interface up-edge (Transport)  |     ✓      |     ✗      |     ✗     |
/// | post-ACTIVE auto-retry (close) |     ✓      |     ✗      |     ✗     |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkPolicy {
    Foreground,
    Background,
    Suspended,
}

impl Default for LinkPolicy {
    fn default() -> Self {
        LinkPolicy::Foreground
    }
}

/// Callback fired by the registry whenever an app-link's tracked state
/// changes.
///
/// `(dest_hash, status, link)` — `link` is `Some(handle)` only when a
/// real outbound `Link` is held in the registry (tier-3 just returned with
/// an established handle). For ephemeral-link open/status transitions it will be
/// `None`.
pub type AppLinkStatusCallback = Arc<dyn Fn(&[u8], u8, Option<LinkHandle>) + Send + Sync>;

/// Source of inbound DATA delivered to a named app destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundPacketSource {
    Transport,
    Link,
}

/// Shared callback used by generic app destinations that accept both plain
/// destination DATA and DATA arriving over an established link.
pub type InboundPacketCallback =
    Arc<dyn Fn(Vec<u8>, InboundPacketSource) + Send + Sync + 'static>;

/// Optional hook fired when a peer establishes a link to a destination that
/// has been wired via [`AppLinks::wire_inbound_destination`].
pub type InboundLinkEstablishedCallback = Arc<dyn Fn() + Send + Sync + 'static>;

/// Transfer progress of a send that travels as a Resource: the raw fraction
/// (0.0..=1.0) the sending Resource reports through `Resource::get_progress`
/// (RNS/Resource.py `get_progress`), called after each request the receiver
/// makes, until the send is delivered.  The caller maps it onto its own
/// scale (LXMF: 0.10 + 0.90 × fraction, LXMF/LXMessage.py
/// `__update_transfer_progress`).  When one tier's Resource fails and the
/// next tier's starts, the fraction starts again from that Resource's own
/// beginning, so the values need not rise monotonically.  A send that fits
/// one link packet reports nothing.
/// Each Resource also reports 0.0 once, when its advertisement has gone
/// out (after any wait behind another Resource on its link): every call is
/// an event of the transfer, the advertisement or a request served, and
/// LXMF's §1 send assertion counts the silence between them
/// (DESIGN_PRINCIPLES §1, bulk transfers).  On a fast link that report can
/// come after the first request's.
/// Keep it short: it runs on the thread serving the receiver's request,
/// with that Resource's lock held (the advertisement report: on the
/// advertise thread, with no lock held), and must never wait on the link.
pub type SendProgressCallback = Arc<dyn Fn(f64) + Send + Sync + 'static>;

/// Per-destination lifecycle mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum LinkMode {
    #[default]
    EphemeralLink,
    Persistent,
}

/// Per-destination state held by the registry.
#[derive(Clone)]
pub struct AppLinkSpec {
    pub app_name: String,
    pub aspects: Vec<String>,
    pub mode: LinkMode,
    /// True from the moment `establish` begins until the in-flight cycle
    /// resolves (path found or failed).  Prevents concurrent triggers from
    /// spawning duplicate races.
    pub attempt_in_flight: Arc<AtomicBool>,
    /// True once this destination has reached READY/ACTIVE at least once
    /// since open.
    pub ever_established: Arc<AtomicBool>,
    /// Arms a single deterministic close-triggered re-open for persistent
    /// links. Re-armed by an explicit trigger (open/announce/network change)
    /// or after a successful persistent establish. This prevents tight
    /// close→open loops while still honoring persistent-link ownership.
    pub reconnect_armed: Arc<AtomicBool>,
}

impl AppLinkSpec {
    pub fn new(app_name: impl Into<String>, aspects: Vec<String>) -> Self {
        Self {
            app_name: app_name.into(),
            aspects,
            mode: LinkMode::EphemeralLink,
            attempt_in_flight: Arc::new(AtomicBool::new(false)),
            ever_established: Arc::new(AtomicBool::new(false)),
            reconnect_armed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_mode(
        app_name: impl Into<String>,
        aspects: Vec<String>,
        mode: LinkMode,
    ) -> Self {
        Self {
            app_name: app_name.into(),
            aspects,
            mode,
            attempt_in_flight: Arc::new(AtomicBool::new(false)),
            ever_established: Arc::new(AtomicBool::new(false)),
            reconnect_armed: Arc::new(AtomicBool::new(mode == LinkMode::Persistent)),
        }
    }
}

struct Registry {
    specs: HashMap<Vec<u8>, AppLinkSpec>,
    /// Destinations that have completed a successful path-race.  Entry
    /// timestamp is for debug/tracing; liveness source-of-truth is
    /// `Transport::has_path`.
    ready: HashMap<Vec<u8>, Instant>,
    /// Cached outbound `LinkHandle`s populated by tier-3 sends.
    /// At most one entry per destination.
    links: HashMap<Vec<u8>, LinkHandle>,
    /// Peer-initiated (inbound) links.  Populated by
    /// [`AppLinks::register_inbound`] when a peer opens a link to us and
    /// identifies themselves.  Auto-removed by closed callback.
    inbound_links: HashMap<Vec<u8>, LinkHandle>,
    /// Destinations whose last direct send exhausted the normal 5 s Timer P
    /// budget and escalated to propagation. These stay logically red until a
    /// fresh path or link establishment succeeds.
    prop_fallback_disconnected: HashSet<Vec<u8>>,
    status_callbacks: Vec<AppLinkStatusCallback>,
    announce_handler_installed: bool,
    policy: LinkPolicy,
}

impl Registry {
    fn new() -> Self {
        Self {
            specs: HashMap::new(),
            ready: HashMap::new(),
            links: HashMap::new(),
            inbound_links: HashMap::new(),
            prop_fallback_disconnected: HashSet::new(),
            status_callbacks: Vec::new(),
            announce_handler_installed: false,
            policy: LinkPolicy::Foreground,
        }
    }
}

static REGISTRY: Lazy<Mutex<Registry>> = Lazy::new(|| Mutex::new(Registry::new()));

/// Public façade.
pub struct AppLinks;

impl AppLinks {
    fn emit_status(dest_hash: &[u8], status: u8, link: Option<LinkHandle>) {
        let cbs: Vec<AppLinkStatusCallback> = REGISTRY
            .lock()
            .map(|r| r.status_callbacks.clone())
            .unwrap_or_default();
        for cb in &cbs {
            cb(dest_hash, status, link.clone());
        }
    }

    fn mark_prop_fallback_disconnected(dest_hash: &[u8]) {
        let changed = REGISTRY
            .lock()
            .map(|mut reg| reg.prop_fallback_disconnected.insert(dest_hash.to_vec()))
            .unwrap_or(false);
        if !changed {
            return;
        }
        log(
            &format!(
                "[APP_LINK] Timer P latched DISCONNECTED for {}",
                hexrep(dest_hash, false)
            ),
            LOG_NOTICE,
            false,
            false,
        );
        Self::emit_status(dest_hash, APP_LINK_DISCONNECTED, None);
    }

    fn clear_prop_fallback_disconnected(dest_hash: &[u8]) {
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.prop_fallback_disconnected.remove(dest_hash);
        }
    }

    fn persistent_requires_verified_session_path(spec: &AppLinkSpec) -> bool {
        spec.app_name == "lxmf"
            && spec.aspects.len() == 1
            && spec.aspects[0] == "propagation"
    }

    fn ephemeral_requires_verified_session_path(spec: &AppLinkSpec) -> bool {
        spec.mode == LinkMode::EphemeralLink
    }

    fn outbound_link_live(dest_hash: &[u8]) -> bool {
        Self::get_handle(dest_hash)
            .map(|handle| {
                let status = handle.status();
                status == STATE_PENDING || status == STATE_HANDSHAKE || status == STATE_ACTIVE
            })
            .unwrap_or(false)
    }

    fn arm_reconnect_if_persistent(dest_hash: &[u8]) {
        if let Some(spec) = Self::spec(dest_hash) {
            if spec.mode == LinkMode::Persistent {
                spec.reconnect_armed.store(true, Ordering::Release);
            }
        }
    }

    fn consume_reconnect_arm(dest_hash: &[u8]) -> bool {
        Self::spec(dest_hash)
            .filter(|spec| spec.mode == LinkMode::Persistent)
            .map(|spec| spec.reconnect_armed.swap(false, Ordering::AcqRel))
            .unwrap_or(false)
    }

    pub fn get_preferred_handle(dest_hash: &[u8]) -> Option<LinkHandle> {
        Self::get_handle(dest_hash)
            .or_else(|| Self::get_inbound_handle(dest_hash))
    }

    fn remove_tracked_outbound_if_same(dest_hash: &[u8], closing: &LinkHandle) -> bool {
        if let Ok(mut reg) = REGISTRY.lock() {
            let should_remove = reg
                .links
                .get(dest_hash)
                .map(|tracked| tracked.same_link(closing))
                .unwrap_or(false);
            if should_remove {
                reg.links.remove(dest_hash);
                reg.ready.remove(dest_hash);
                return true;
            }
        }
        false
    }

    fn remove_tracked_inbound_if_same(dest_hash: &[u8], closing: &LinkHandle) -> bool {
        if let Ok(mut reg) = REGISTRY.lock() {
            let should_remove = reg
                .inbound_links
                .get(dest_hash)
                .map(|tracked| tracked.same_link(closing))
                .unwrap_or(false);
            if should_remove {
                reg.inbound_links.remove(dest_hash);
                return true;
            }
        }
        false
    }

    fn handle_tracked_outbound_closed(dest_hash: Vec<u8>, closing: LinkHandle) {
        let _ = Self::remove_tracked_outbound_if_same(&dest_hash, &closing);
        Self::invalidate_liveness(&dest_hash);
        log(
            &format!(
                "[APP_LINK] outbound link closed for {}",
                hexrep(&dest_hash, false)
            ),
            LOG_NOTICE,
            false,
            false,
        );
        if Self::contains(&dest_hash) {
            Self::emit_status(&dest_hash, APP_LINK_DISCONNECTED, None);
            if Self::policy() == LinkPolicy::Foreground
                && Self::consume_reconnect_arm(&dest_hash)
            {
                log(
                    &format!(
                        "[APP_LINK] persistent close trigger → re-open {}",
                        hexrep(&dest_hash, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                Self::request_reopen_internal(&dest_hash, false);
            }
        }
    }

    // ─── Host integration ─────────────────────────────────────────────

    /// Subscribe to status changes.  Multiple callbacks are supported.
    /// Callbacks are invoked synchronously from whichever thread the
    /// underlying link/race callback runs on.  Implementers MUST NOT block.
    pub fn register_status_callback(callback: AppLinkStatusCallback) {
        let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
        reg.status_callbacks.push(callback);
    }

    /// Wire a generic inbound app destination so the caller handles one
    /// packet callback regardless of whether DATA arrived directly on the
    /// destination or over a peer-established link.
    pub fn wire_inbound_destination(
        destination: &mut Destination,
        on_packet: InboundPacketCallback,
        on_link_established: Option<InboundLinkEstablishedCallback>,
    ) {
        let direct_packet_cb = on_packet.clone();
        destination.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
            direct_packet_cb(data.to_vec(), InboundPacketSource::Transport);
        })));

        let link_packet_cb = on_packet;
        let link_established_cb = on_link_established;
        destination.set_link_established_callback(Some(Arc::new(move |link: LinkHandle| {
            if let Some(callback) = &link_established_cb {
                callback();
            }

            let per_link_packet_cb = link_packet_cb.clone();
            link.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
                per_link_packet_cb(data.to_vec(), InboundPacketSource::Link);
            })));
        })));
    }

    /// Current host lifecycle policy.  Defaults to [`LinkPolicy::Foreground`].
    pub fn policy() -> LinkPolicy {
        REGISTRY
            .lock()
            .map(|r| r.policy)
            .unwrap_or(LinkPolicy::Foreground)
    }

    /// Update the host lifecycle policy.
    ///
    /// Side effects:
    ///   * Entering `Suspended` clears all READY entries and fires
    ///     `APP_LINK_DISCONNECTED` for each.
    ///   * Leaving `Suspended` fires a network-change-style attempt for
    ///     every registered destination.
    pub fn set_policy(policy: LinkPolicy) {
        let prev = {
            let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
            let prev = reg.policy;
            reg.policy = policy;
            prev
        };
        if prev == policy {
            return;
        }
        log(
            &format!("[APP_LINK] policy {:?} -> {:?}", prev, policy),
            LOG_NOTICE,
            false,
            false,
        );
        match policy {
            LinkPolicy::Suspended => {
                Self::clear_all_ready(/*notify*/ true);
            }
            LinkPolicy::Foreground | LinkPolicy::Background => {
                if prev == LinkPolicy::Suspended {
                    Self::resume_attempts();
                }
            }
        }
    }

    fn resume_attempts() {
        let candidates: Vec<Vec<u8>> = Self::destinations()
            .into_iter()
            .filter(|h| {
                let s = Self::status(h);
                s != APP_LINK_ACTIVE && s != APP_LINK_ESTABLISHING
            })
            .collect();
        if candidates.is_empty() {
            return;
        }
        log(
            &format!(
                "[APP_LINK] policy resume → attempting {} link(s)",
                candidates.len()
            ),
            LOG_NOTICE,
            false,
            false,
        );
        for dest in &candidates {
            Self::invalidate_liveness(dest);
            Self::establish(dest);
        }
    }

    /// True when `dest_hash` is currently registered as an app-link.
    pub fn contains(dest_hash: &[u8]) -> bool {
        REGISTRY
            .lock()
            .map(|r| r.specs.contains_key(dest_hash))
            .unwrap_or(false)
    }

    /// Snapshot of all currently-registered app-link destination hashes.
    pub fn destinations() -> Vec<Vec<u8>> {
        REGISTRY
            .lock()
            .map(|r| r.specs.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the `AppLinkSpec` for `dest_hash` if registered.  Cheap clone.
    pub fn spec(dest_hash: &[u8]) -> Option<AppLinkSpec> {
        REGISTRY
            .lock()
            .ok()
            .and_then(|r| r.specs.get(dest_hash).cloned())
    }

    /// Register `spec` for `dest_hash`.  A re-registration in the same mode
    /// keeps the in-flight guard of the spec it replaces: the attempt that
    /// guard covers is still running.  A fresh guard let the next trigger
    /// start a second attempt beside it — on 2026-09-25 a reconnect opened
    /// two links to the propagation node, and the one no longer tracked
    /// was never torn down.
    fn register_spec(dest_hash: &[u8], mut spec: AppLinkSpec) {
        let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
        if let Some(existing) = reg.specs.get(dest_hash) {
            if existing.mode == spec.mode {
                spec.attempt_in_flight = existing.attempt_in_flight.clone();
            }
        }
        reg.specs.insert(dest_hash.to_vec(), spec);
    }

    // ─── Public lifecycle ─────────────────────────────────────────────

    /// Register `dest_hash` for liveness tracking.  Races a path, marks
    /// READY, and fires `APP_LINK_ACTIVE(None)` once a path is found.
    ///
    /// No outbound `Link` is built by this call.  Links exist only during
    /// a tier-3 send (and are cached in the registry for tier-2 reuse).
    ///
    pub fn open(dest_hash: &[u8], app_name: &str, aspects: &[&str]) {
        Self::open_with_mode(dest_hash, app_name, aspects, LinkMode::EphemeralLink);
    }

    /// Open a held-open outbound link for `dest_hash`.
    ///
    /// This still begins with a path-race, but once a path is found it
    /// establishes an outbound `LinkHandle` and keeps that handle in the
    /// registry until the link closes or [`Self::close`] is called.
    pub fn open_persistent(dest_hash: &[u8], app_name: &str, aspects: &[&str]) {
        Self::open_with_mode(dest_hash, app_name, aspects, LinkMode::Persistent);
    }

    /// Open an app link in `mode`.
    pub fn open_with_mode(
        dest_hash: &[u8],
        app_name: &str,
        aspects: &[&str],
        mode: LinkMode,
    ) {
        Self::ensure_announce_handler();
        Self::ensure_interface_up_hook();

        let previous_status = Self::status(dest_hash);
        let previous_outbound_live = Self::outbound_link_live(dest_hash);

        let spec = AppLinkSpec::with_mode(
            app_name,
            aspects.iter().map(|s| (*s).to_string()).collect(),
            mode,
        );

        Self::register_spec(dest_hash, spec);

        Transport::watch_announce(dest_hash.to_vec());

        if Self::policy() == LinkPolicy::Suspended {
            return;
        }

        if mode == LinkMode::Persistent {
            Self::arm_reconnect_if_persistent(dest_hash);
        }

        match mode {
            LinkMode::EphemeralLink => {
                if previous_status == APP_LINK_ACTIVE
                    || previous_status == APP_LINK_ESTABLISHING
                    || previous_status == APP_LINK_PATH_REQUESTED
                {
                    return;
                }
            }
            LinkMode::Persistent => {
                if previous_outbound_live
                    || previous_status == APP_LINK_ESTABLISHING
                    || previous_status == APP_LINK_PATH_REQUESTED
                {
                    return;
                }
            }
        }

        Self::establish(dest_hash);
    }

    /// Explicit deterministic re-open trigger for a registered app link.
    ///
    /// Used by host callbacks and close-trigger handling for persistent
    /// links. This invalidates any cached liveness winner and runs the same
    /// path-race/link-establish flow as `open_with_mode`, without adding any
    /// timed retry loop.
    fn request_reopen_internal(dest_hash: &[u8], arm_reconnect: bool) {
        if !Self::contains(dest_hash) {
            return;
        }
        if Self::policy() == LinkPolicy::Suspended {
            return;
        }
        if arm_reconnect {
            Self::arm_reconnect_if_persistent(dest_hash);
        }
        Self::invalidate_liveness(dest_hash);
        Self::establish(dest_hash);
    }

    pub fn request_reopen(dest_hash: &[u8]) {
        Self::request_reopen_internal(dest_hash, true);
    }

    /// Close an app link.  Removes from registry, drops any held link and
    /// inbound link, fires `APP_LINK_NONE` callback.
    pub fn close(dest_hash: &[u8]) {
        let (was_registered, dropped_link, dropped_inbound) = {
            let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
            let removed = reg.specs.remove(dest_hash).is_some();
            reg.ready.remove(dest_hash);
            let dl = reg.links.remove(dest_hash);
            let di = reg.inbound_links.remove(dest_hash);
            reg.prop_fallback_disconnected.remove(dest_hash);
            (removed, dl, di)
        };
        if let Some(handle) = &dropped_link {
            handle.teardown();
        }
        if let Some(handle) = &dropped_inbound {
            handle.teardown();
        }
        drop(dropped_link);
        drop(dropped_inbound);
        if was_registered {
            let cbs: Vec<AppLinkStatusCallback> = REGISTRY
                .lock()
                .map(|r| r.status_callbacks.clone())
                .unwrap_or_default();
            for cb in &cbs {
                cb(dest_hash, APP_LINK_NONE, None);
            }
        }
    }

    /// Forget every registration and tear down every held link, outbound
    /// and inbound.
    ///
    /// The registry is process-global and outlives the Reticulum instance.
    /// A host that stops and starts the stack inside one process (Android
    /// `StackRuntime.restart` on 2026-09-24) otherwise leaves the new stack
    /// holding `STATE_ACTIVE` handles whose interfaces are gone: the router
    /// "sends" on them and nothing leaves the device. The host calls this
    /// from its stack shutdown; routers re-register their callbacks and
    /// persistent links when they come back.
    pub fn close_all() -> usize {
        let (outbound, inbound, dests) = {
            let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
            let dests: Vec<Vec<u8>> = reg.specs.keys().cloned().collect();
            reg.specs.clear();
            reg.ready.clear();
            reg.prop_fallback_disconnected.clear();
            let outbound: Vec<LinkHandle> = reg.links.drain().map(|(_, h)| h).collect();
            let inbound: Vec<LinkHandle> = reg.inbound_links.drain().map(|(_, h)| h).collect();
            (outbound, inbound, dests)
        };
        let torn_down = outbound.len() + inbound.len();
        for handle in outbound.iter().chain(inbound.iter()) {
            handle.teardown();
        }
        if let Ok(mut cache) = LIVENESS_CACHE.lock() {
            cache.clear();
        }
        let cbs: Vec<AppLinkStatusCallback> = REGISTRY
            .lock()
            .map(|mut r| std::mem::take(&mut r.status_callbacks))
            .unwrap_or_default();
        for dest in &dests {
            for cb in &cbs {
                cb(dest, APP_LINK_NONE, None);
            }
        }
        log(
            &format!(
                "[APP_LINK] close_all: {} registration(s) dropped, {} link(s) torn down",
                dests.len(),
                torn_down
            ),
            LOG_NOTICE,
            false,
            false,
        );
        torn_down
    }

    /// Tear down the held outbound link to `dest_hash` and keep its
    /// registration, so a persistent link re-opens under the normal
    /// close-triggered policy. This is what the reference does when a link
    /// packet's receipt times out (LXMF/LXMessage.py
    /// `__link_packet_timed_out`: `packet_receipt.destination.teardown()`).
    /// Returns `false` when no link is held.
    pub fn teardown_held_link(dest_hash: &[u8]) -> bool {
        let handle = REGISTRY
            .lock()
            .ok()
            .and_then(|r| r.links.get(dest_hash).cloned());
        match handle {
            Some(handle) => {
                Self::arm_reconnect_if_persistent(dest_hash);
                handle.teardown();
                true
            }
            None => false,
        }
    }

    /// Send `packed` over the held `STATE_ACTIVE` link to `dest_hash` and
    /// report the outcome the way the reference does for a propagation
    /// transfer (LXMF/LXMessage.py `send`, PROPAGATED): `on_delivered` when
    /// the link packet is proved or the Resource completes, `on_failed` when
    /// the packet receipt times out or the Resource fails. Nothing is raced,
    /// re-sent or timed here beyond the stack's own receipt timeout; the
    /// caller owns the message state.
    ///
    /// `on_progress` hears the Resource's fraction while a payload over the
    /// link MDU transfers, and its advertisement
    /// ([`SendProgressCallback`]); a packet reports nothing. Never on the
    /// calling thread, so the caller may hold a lock the callback takes.
    ///
    /// Returns `Err` when no active link is held or the packet could not be
    /// queued, in which case no callback fires.
    pub fn send_on_held_link(
        dest_hash: &[u8],
        packed: Vec<u8>,
        compress: bool,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_failed: Arc<dyn Fn() + Send + Sync + 'static>,
        on_progress: Option<SendProgressCallback>,
    ) -> Result<(), String> {
        let link = Self::get_handle(dest_hash)
            .filter(|handle| handle.status() == STATE_ACTIVE)
            .ok_or_else(|| format!("no active link held for {}", hexrep(dest_hash, false)))?;
        let delivered = Arc::new(AtomicBool::new(false));
        let watch = TransferWatch::new(on_progress);
        if Self::fire_on_link(&link, &packed, compress, delivered, on_delivered, Some(on_failed), &watch) {
            Ok(())
        } else {
            Err(format!("packet could not be queued on the link to {}", hexrep(dest_hash, false)))
        }
    }

    /// Current status for `dest_hash`.
    ///
    ///   * `APP_LINK_NONE`           — not registered.
    ///   * `APP_LINK_PATH_REQUESTED` — path-race in flight.
    ///   * `APP_LINK_ESTABLISHING`   — link handle exists, not yet `STATE_ACTIVE`
    ///                                 (propagation destinations only).
    ///   * `APP_LINK_ACTIVE`         — path known (ready) and still valid,
    ///                                 OR a held link is `STATE_ACTIVE`.
    ///   * `APP_LINK_DISCONNECTED`   — registered, no path, no race, OR
    ///                                 the last direct send had to escalate to
    ///                                 propagation and no fresh path/link
    ///                                 success has cleared that red latch yet.
    pub fn status(dest_hash: &[u8]) -> u8 {
        let (registered, in_flight, link, inbound, in_ready, prop_fallback_disconnected) = {
            let reg = match REGISTRY.lock() {
                Ok(g) => g,
                Err(_) => return APP_LINK_NONE,
            };
            let spec = reg.specs.get(dest_hash);
            let registered = spec.is_some();
            let in_flight = spec
                .map(|s| s.attempt_in_flight.load(Ordering::Acquire))
                .unwrap_or(false);
            let link = reg.links.get(dest_hash).cloned();
            let inbound = reg.inbound_links.get(dest_hash).cloned();
            let in_ready = reg.ready.contains_key(dest_hash);
            let prop_fallback_disconnected = reg.prop_fallback_disconnected.contains(dest_hash);
            (
                registered,
                in_flight,
                link,
                inbound,
                in_ready,
                prop_fallback_disconnected,
            )
        };
        if !registered {
            return APP_LINK_NONE;
        }
        if prop_fallback_disconnected {
            return APP_LINK_DISCONNECTED;
        }
        // Held link (propagation node, or recent tier-3 cached link).
        if let Some(handle) = link {
            if handle.status() == STATE_ACTIVE {
                return APP_LINK_ACTIVE;
            }
            return APP_LINK_ESTABLISHING;
        }
        if let Some(handle) = inbound {
            if handle.status() == STATE_ACTIVE {
                return APP_LINK_ACTIVE;
            }
        }
        if in_flight {
            return APP_LINK_PATH_REQUESTED;
        }
        // EphemeralLink: ACTIVE when ready entry exists and path is still valid.
        if in_ready {
            let candidates = liveness_candidate_interfaces();
            if cached_path_iface_is_live(dest_hash, &candidates, false).is_some() {
                return APP_LINK_ACTIVE;
            }
        }
        APP_LINK_DISCONNECTED
    }

    /// Live outbound `LinkHandle` from the registry, if any.
    pub fn get_handle(dest_hash: &[u8]) -> Option<LinkHandle> {
        REGISTRY
            .lock()
            .ok()
            .and_then(|r| r.links.get(dest_hash).cloned())
    }

    /// Register a peer-initiated (inbound) link for `dest_hash`.
    ///
    /// Called from the LXMF delivery-destination identify callback when a
    /// peer opens a link to our delivery destination and identifies
    /// themselves.  Installs a closed-callback that auto-removes the entry.
    ///
    /// Only stores if `dest_hash` is already registered via [`AppLinks::open`].
    pub fn register_inbound(dest_hash: &[u8], link: LinkHandle) {
        if !Self::contains(dest_hash) {
            return;
        }
        {
            let dest_owned = dest_hash.to_vec();
            link.set_link_closed_callback(Some(Arc::new(move |closing: LinkHandle| {
                AppLinks::remove_tracked_inbound_if_same(&dest_owned, &closing);
                log(
                    &format!(
                        "[APP_LINK] inbound link closed for {}",
                        hexrep(&dest_owned, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
            })));
        }
        log(
            &format!(
                "[APP_LINK] inbound link registered for {}",
                hexrep(dest_hash, false)
            ),
            LOG_NOTICE,
            false,
            false,
        );
        Self::clear_prop_fallback_disconnected(dest_hash);
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.inbound_links.insert(dest_hash.to_vec(), link);
        }
    }

    /// Returns the live inbound `LinkHandle` for `dest_hash`, if any.
    pub fn get_inbound_handle(dest_hash: &[u8]) -> Option<LinkHandle> {
        REGISTRY
            .lock()
            .ok()
            .and_then(|r| r.inbound_links.get(dest_hash).cloned())
    }

    /// True when an inbound link is tracked for `dest_hash`.
    pub fn has_inbound(dest_hash: &[u8]) -> bool {
        REGISTRY
            .lock()
            .map(|r| r.inbound_links.contains_key(dest_hash))
            .unwrap_or(false)
    }

    // ─── External triggers ────────────────────────────────────────────

    /// Trigger one fresh path-race on the strength of a fresh announce.
    /// No-op if no entry exists, already active, or race already running.
    pub fn announce_received(dest_hash: &[u8]) {
        if !Self::contains(dest_hash) {
            return;
        }
        if Self::policy() == LinkPolicy::Suspended {
            return;
        }
        if Self::status(dest_hash) == APP_LINK_ACTIVE {
            return;
        }
        Self::request_reopen(dest_hash);
    }

    /// Trigger one fresh attempt for every app-link not currently active.
    /// Call from the host on a network state change.
    pub fn network_changed() {
        Self::attempt_inactive_links("network-change trigger");
    }

    /// An interface came online (Transport's up-edge): one fresh attempt for
    /// every app-link not currently active, as for a network change. A link
    /// attempt that failed for want of an interface ("no usable interface")
    /// is not retried by design (§3), so without this a link stayed down
    /// after its interface came back — until 2026-09-25 an Android phone's
    /// RFed links stayed down after its TCP interface reconnected, until
    /// the app was restarted. A network change is not the only way an
    /// interface returns: a TCP reconnect after the peer restarted, or after
    /// the OS unblocked the app's network, changes no network.
    fn interface_online(name: &str) {
        Self::attempt_inactive_links(&format!("interface {} online", name));
    }

    /// One fresh attempt for every registered app-link that is neither
    /// active nor establishing, in the foreground only (see LinkPolicy).
    fn attempt_inactive_links(trigger: &str) {
        if Self::policy() != LinkPolicy::Foreground {
            return;
        }
        let candidates: Vec<Vec<u8>> = Self::destinations()
            .into_iter()
            .filter(|h| {
                let s = Self::status(h);
                s != APP_LINK_ACTIVE && s != APP_LINK_ESTABLISHING
            })
            .collect();
        if candidates.is_empty() {
            return;
        }
        log(
            &format!(
                "[APP_LINK] {} → attempting {} link(s)",
                trigger,
                candidates.len()
            ),
            LOG_NOTICE,
            false,
            false,
        );
        for dest in &candidates {
            Self::request_reopen(dest);
        }
    }

    // ─── Internals ────────────────────────────────────────────────────

    fn clear_all_ready(notify: bool) {
        let (notify_direct, dropped_links, dropped_inbound) = {
            let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
            let ready_keys: Vec<Vec<u8>> = reg.ready.keys().cloned().collect();
            let link_keys: Vec<Vec<u8>> = reg.links.keys().cloned().collect();
            let inbound_keys: Vec<Vec<u8>> = reg.inbound_links.keys().cloned().collect();
            reg.ready.clear();
            let dropped_links: Vec<LinkHandle> =
                reg.links.drain().map(|(_, h)| h).collect();
            let dropped_inbound: Vec<LinkHandle> =
                reg.inbound_links.drain().map(|(_, h)| h).collect();
            let mut notify_direct = Vec::new();
            for k in ready_keys.into_iter().chain(inbound_keys.into_iter()) {
                if !link_keys.contains(&k) && !notify_direct.contains(&k) {
                    notify_direct.push(k);
                }
            }
            (notify_direct, dropped_links, dropped_inbound)
        };
        for handle in &dropped_links {
            handle.teardown();
        }
        for handle in &dropped_inbound {
            handle.teardown();
        }
        drop(dropped_links);
        drop(dropped_inbound);
        if !notify || notify_direct.is_empty() {
            return;
        }
        let cbs: Vec<AppLinkStatusCallback> = REGISTRY
            .lock()
            .map(|r| r.status_callbacks.clone())
            .unwrap_or_default();
        for dest in &notify_direct {
            for cb in &cbs {
                cb(dest, APP_LINK_DISCONNECTED, None);
            }
        }
    }

    /// Idempotently spawn the global ready-watcher thread.
    /// Polls `Transport::has_path` for every READY entry and emits
    /// `APP_LINK_DISCONNECTED` when the path is gone.
    /// Single-use install of the global announce handler.  Idempotent.
    fn ensure_announce_handler() {
        {
            let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
            if reg.announce_handler_installed {
                return;
            }
            reg.announce_handler_installed = true;
        }
        let callback: AnnounceCallback = Arc::new(
            |destination_hash, _identity, _app_data, _announce_hash, _is_path_response| {
                if AppLinks::contains(destination_hash) {
                    AppLinks::announce_received(destination_hash);
                }
            },
        );
        Transport::register_announce_handler(AnnounceHandler {
            aspect_filter: None,
            receive_path_responses: true,
            callback,
        });
    }

    /// Single-use subscription to Transport's interface up-edge. Idempotent.
    fn ensure_interface_up_hook() {
        static HOOKED: std::sync::Once = std::sync::Once::new();
        HOOKED.call_once(|| {
            Transport::add_interface_up_listener(Arc::new(|name: &str| AppLinks::interface_online(name)));
        });
    }

    /// Drive a path-race for an already-registered destination.
    ///
    /// The `attempt_in_flight` CAS gate collapses concurrent triggers into a
    /// single in-flight race.  After the race:
    ///
    /// After a successful race, mark READY, fire `APP_LINK_ACTIVE(None)`,
    /// and release the gate. No Link is built.
    fn establish(dest_hash: &[u8]) {
        if Self::policy() == LinkPolicy::Suspended {
            return;
        }
        let spec = match Self::spec(dest_hash) {
            Some(s) => s,
            None => return,
        };
        if spec.mode == LinkMode::Persistent {
            Self::establish_persistent(dest_hash, spec);
            return;
        }
        if Self::status(dest_hash) == APP_LINK_ACTIVE {
            return;
        }
        if spec
            .attempt_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let cbs: Vec<AppLinkStatusCallback> = REGISTRY
            .lock()
            .map(|r| r.status_callbacks.clone())
            .unwrap_or_default();
        for cb in &cbs {
            cb(dest_hash, APP_LINK_PATH_REQUESTED, None);
        }

        log(
            &format!("[APP_LINK] path-race trigger for {}", hexrep(dest_hash, false)),
            LOG_NOTICE,
            false,
            false,
        );

        let dest_owned = dest_hash.to_vec();
        let in_flight = spec.attempt_in_flight.clone();
        let ever_established = spec.ever_established.clone();
        std::thread::Builder::new()
            .name("app_links_race".into())
            .spawn(move || {
                // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1, §2
                //
                // Do NOT call expire_path() here.
                //
                // expire_path() sets the path timestamp to 0, which causes the
                // transport cull to classify the entry as a same-as-new insert.
                // If the only PATH_RESPONSE that comes back (e.g., from a remote
                // relay) carries a worse hop count than the cached entry, the quality
                // gate CANNOT reject it because expire_path() + cull has already
                // deleted the cached entry (has_existing=false).  The result is that
                // every chat-open can silently degrade a good 2-hop path to a 12-hop
                // stale relay response, which then gets persisted to disk.
                //
                // expire_path() belongs in tier-3 of send(), AFTER tiers 1 and 2 have
                // both failed.  At that point we have direct evidence the cached path
                // is not working and forcing a fresh lookup is warranted.
                //
                // For ephemeral destinations, READY must mean the path has been
                // confirmed in this process. Disk-restored routes are not
                // sufficient because the first actual LRREQ would otherwise
                // discover staleness only after the user hits Send.
                let result = match if Self::ephemeral_requires_verified_session_path(&spec) {
                    liveness::race_path_verified_this_session(&dest_owned, LIVENESS_BUDGET)
                } else {
                    liveness::race_path(&dest_owned, LIVENESS_BUDGET)
                } {
                    Ok(iface) => Ok(iface),
                    Err(e) => Err(e),
                };

                let cbs: Vec<AppLinkStatusCallback> = REGISTRY
                    .lock()
                    .map(|r| r.status_callbacks.clone())
                    .unwrap_or_default();

                match result {
                    Ok(iface) => {
                        {
                            let mut reg = REGISTRY
                                .lock()
                                .expect("app_links registry mutex poisoned");
                            reg.prop_fallback_disconnected.remove(&dest_owned);
                            reg.ready.insert(dest_owned.clone(), Instant::now());
                        }
                        ever_established.store(true, Ordering::Relaxed);
                        if let Ok(mut cache) = LIVENESS_CACHE.lock() {
                            cache.insert(
                                dest_owned.clone(),
                                (iface.clone(), Instant::now()),
                            );
                        }
                        log(
                            &format!(
                                "[APP_LINK] READY (path via {}) for {}",
                                iface,
                                hexrep(&dest_owned, false)
                            ),
                            LOG_NOTICE,
                            false,
                            false,
                        );

                        in_flight.store(false, Ordering::Release);
                        for cb in &cbs {
                            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
                            // ACTIVE fires with None: no Link is held by AppLinks.
                            // The send tier hierarchy in AppLinks::send builds a
                            // Link only when needed (tier-3).
                            cb(&dest_owned, APP_LINK_ACTIVE, None);
                        }
                    }
                    Err(e) => {
                        in_flight.store(false, Ordering::Release);
                        log(
                            &format!(
                                "[APP_LINK] path-race failed for {}: {}",
                                hexrep(&dest_owned, false),
                                e
                            ),
                            LOG_NOTICE,
                            false,
                            false,
                        );
                        for cb in &cbs {
                            cb(&dest_owned, APP_LINK_DISCONNECTED, None);
                        }
                    }
                }
            })
            .expect("failed to spawn app_links race thread");
    }

    fn establish_persistent(dest_hash: &[u8], spec: AppLinkSpec) {
        if Self::policy() == LinkPolicy::Suspended {
            return;
        }
        if Self::outbound_link_live(dest_hash) {
            return;
        }
        if spec
            .attempt_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        Self::emit_status(dest_hash, APP_LINK_PATH_REQUESTED, None);
        log(
            &format!(
                "[APP_LINK] persistent path-race trigger for {}",
                hexrep(dest_hash, false)
            ),
            LOG_NOTICE,
            false,
            false,
        );

        let dest_owned = dest_hash.to_vec();
        let app_name = spec.app_name.clone();
        let aspects = spec.aspects.clone();
        let spec_for_open = spec.clone();
        std::thread::Builder::new()
            .name("app_links_persistent_open".into())
            .spawn(move || {
                let iface = match if Self::persistent_requires_verified_session_path(&spec_for_open) {
                    liveness::race_path_verified_this_session(&dest_owned, LIVENESS_BUDGET)
                } else {
                    liveness::race_path(&dest_owned, LIVENESS_BUDGET)
                } {
                    Ok(iface) => iface,
                    Err(e) => {
                        spec_for_open
                            .attempt_in_flight
                            .store(false, Ordering::Release);
                        log(
                            &format!(
                                "[APP_LINK] persistent race failed for {}: {}",
                                hexrep(&dest_owned, false),
                                e
                            ),
                            LOG_NOTICE,
                            false,
                            false,
                        );
                        AppLinks::emit_status(&dest_owned, APP_LINK_DISCONNECTED, None);
                        return;
                    }
                };

                if let Ok(mut cache) = LIVENESS_CACHE.lock() {
                    cache.insert(dest_owned.clone(), (iface.clone(), Instant::now()));
                }
                AppLinks::clear_prop_fallback_disconnected(&dest_owned);

                let identity = match Identity::recall(&dest_owned) {
                    Some(id) => id,
                    None => {
                        spec_for_open
                            .attempt_in_flight
                            .store(false, Ordering::Release);
                        log(
                            &format!(
                                "[APP_LINK] persistent open: no identity for {}",
                                hexrep(&dest_owned, false)
                            ),
                            LOG_NOTICE,
                            false,
                            false,
                        );
                        AppLinks::emit_status(&dest_owned, APP_LINK_DISCONNECTED, None);
                        return;
                    }
                };

                let destination = match Destination::new_outbound(
                    Some(identity),
                    DestinationType::Single,
                    app_name,
                    aspects,
                ) {
                    Ok(destination) => destination,
                    Err(e) => {
                        spec_for_open
                            .attempt_in_flight
                            .store(false, Ordering::Release);
                        log(
                            &format!(
                                "[APP_LINK] persistent open: destination build failed for {}: {}",
                                hexrep(&dest_owned, false),
                                e
                            ),
                            LOG_NOTICE,
                            false,
                            false,
                        );
                        AppLinks::emit_status(&dest_owned, APP_LINK_DISCONNECTED, None);
                        return;
                    }
                };

                let link = match Link::new_outbound(destination, MODE_AES256_CBC) {
                    Ok(link) => link,
                    Err(e) => {
                        spec_for_open
                            .attempt_in_flight
                            .store(false, Ordering::Release);
                        log(
                            &format!(
                                "[APP_LINK] persistent open: Link::new_outbound failed for {}: {}",
                                hexrep(&dest_owned, false),
                                e
                            ),
                            LOG_NOTICE,
                            false,
                            false,
                        );
                        AppLinks::emit_status(&dest_owned, APP_LINK_DISCONNECTED, None);
                        return;
                    }
                };

                let handle = LinkHandle::spawn(link);
                if let Ok(mut reg) = REGISTRY.lock() {
                    reg.ready.remove(&dest_owned);
                    reg.links.insert(dest_owned.clone(), handle.clone());
                }
                AppLinks::emit_status(&dest_owned, APP_LINK_ESTABLISHING, Some(handle.clone()));

                {
                    let dest_cb = dest_owned.clone();
                    let iface_cb = iface.clone();
                    let spec_cb = spec_for_open.clone();
                    handle.set_link_established_callback(Some(Arc::new(move |established_handle: LinkHandle| {
                        let still_tracked = REGISTRY
                            .lock()
                            .map(|reg| {
                                reg.links
                                    .get(&dest_cb)
                                    .map(|tracked| tracked.same_link(&established_handle))
                                    .unwrap_or(false)
                            })
                            .unwrap_or(false);
                        if !still_tracked {
                            return;
                        }

                        if let Ok(mut reg) = REGISTRY.lock() {
                            reg.links.insert(dest_cb.clone(), established_handle.clone());
                            reg.ready.insert(dest_cb.clone(), Instant::now());
                        }

                        {
                            let dest_closed = dest_cb.clone();
                            established_handle.set_link_closed_callback(Some(Arc::new(
                                move |closing: LinkHandle| {
                                    AppLinks::handle_tracked_outbound_closed(dest_closed.clone(), closing);
                                },
                            )));
                        }

                        spec_cb.ever_established.store(true, Ordering::Relaxed);
                        spec_cb.reconnect_armed.store(true, Ordering::Release);
                        spec_cb.attempt_in_flight.store(false, Ordering::Release);
                        log(
                            &format!(
                                "[APP_LINK] persistent outbound ACTIVE via {} for {}",
                                iface_cb,
                                hexrep(&dest_cb, false)
                            ),
                            LOG_NOTICE,
                            false,
                            false,
                        );
                        AppLinks::emit_status(&dest_cb, APP_LINK_ACTIVE, Some(established_handle));
                    })));
                }
                {
                    let dest_cb = dest_owned.clone();
                    let spec_cb = spec_for_open.clone();
                    handle.set_link_closed_callback(Some(Arc::new(move |closing: LinkHandle| {
                        let was_tracked = AppLinks::remove_tracked_outbound_if_same(&dest_cb, &closing);
                        spec_cb.attempt_in_flight.store(false, Ordering::Release);
                        if was_tracked {
                            log(
                                &format!(
                                    "[APP_LINK] persistent open: link closed before active for {}",
                                    hexrep(&dest_cb, false)
                                ),
                                LOG_NOTICE,
                                false,
                                false,
                            );
                            AppLinks::emit_status(&dest_cb, APP_LINK_DISCONNECTED, None);
                        }
                    })));
                }

                Transport::synthesize_tunnel_all_tcp();

                if let Err(e) = handle.initiate() {
                    AppLinks::remove_tracked_outbound_if_same(&dest_owned, &handle);
                    spec_for_open
                        .attempt_in_flight
                        .store(false, Ordering::Release);
                    log(
                        &format!(
                            "[APP_LINK] persistent open: initiate failed for {}: {:?}",
                            hexrep(&dest_owned, false),
                            e
                        ),
                        LOG_NOTICE,
                        false,
                        false,
                    );
                    AppLinks::emit_status(&dest_owned, APP_LINK_DISCONNECTED, None);
                    return;
                }
            })
            .expect("failed to spawn app_links persistent open thread");
    }

    // ─── Three-tier send ──────────────────────────────────────────────
    //
    // Send semantics (DESIGN_PRINCIPLES §1, §3, §7):
    //
    //   Tier 1 — inbound link (peer opened it to us).
    //   Tier 2 — cached outbound link from a previous tier-3 that is still
    //            STATE_ACTIVE.
    //   Tier 3 — expire_path + race_path + Link::new_outbound + send.
    //
    // A message that fits one link packet: the tiers fire at t=0, t=1s,
    // t=2s (Timer A/B, DIRECT_STAGGER_WAIT), each only while the send is
    // still undelivered.
    // A message over the link MDU travels as a Resource, and a tier hands
    // over to the next only on its OWN failure event (its Resource
    // concluding without COMPLETE: failed, rejected, its link closed, its
    // advertisement unanswered through MAX_ADV_RETRIES), never on a clock:
    // not the stagger, and not the outcome backstop, which only logs on a
    // Resource tier.
    // Until 2026-09-29 the Resource tiers staggered by 1 s like packets, and
    // a photo went out as two or three concurrent full Resources.
    //
    // One SendOutcome decides the send: on_delivered once, from the first
    // tier to deliver; on_failed once, when the chain fires no more tiers and
    // every tier that fired has failed (or none could fire). A delivery
    // after on_failed (a late proof) still reaches on_delivered. A parallel
    // Timer P fires on_propagation_needed once the send has gone 5 s
    // undelivered with no transfer activity on any tier (a Resource
    // reporting more of the message sent restarts the 5 s).
    // Advancing never cancels an earlier tier.
    //
    // Spawns a background thread; returns immediately (§7).

    /// Send `packed` bytes to `dest` via the best available link.
    ///
    /// Non-blocking.  Spawns a background thread; returns immediately.
    ///
    /// Callbacks (all MUST be idempotent and MUST NOT block):
    ///   `on_delivered`           — once, the first delivery proof (or
    ///                              Resource COMPLETE) from any tier.
    ///   `on_propagation_needed`  — Timer P: the send went
    ///                              [`PROP_FALLBACK_DELAY`] (5 s) undelivered
    ///                              with no transfer activity; caller should
    ///                              start a parallel propagation send.
    ///   `on_failed`              — once, when every tier that fired has
    ///                              failed by its own failure event (packet
    ///                              receipt timeout, Resource concluded
    ///                              without COMPLETE) and no tier is left to
    ///                              fire, or when no tier could fire at all.
    ///                              A fired packet tier that goes the 120 s
    ///                              outcome backstop with no outcome counts
    ///                              as failed; a Resource tier never does.
    ///                              Never while a fired tier is in flight.
    ///                              A delivery after it still calls
    ///                              `on_delivered`, once (a late proof).
    pub fn send(
        dest: &[u8],
        packed: Vec<u8>,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_propagation_needed: Arc<dyn Fn() + Send + Sync + 'static>,
        on_failed: Arc<dyn Fn() + Send + Sync + 'static>,
    ) {
        // No announce knowledge here: the reference assumes compression is
        // supported when the peer's app_data says nothing (LXMF/LXMF.py).
        Self::send_with_compression(dest, packed, true, on_delivered, on_propagation_needed, on_failed, None);
    }

    /// `send` with the peer's compression support decided by the caller
    /// (LXMF: `compression_support_from_app_data` on the peer's announce).
    /// A message over the link MDU travels as a Resource; `compress` is that
    /// Resource's auto-compress switch, and `on_progress` hears its
    /// advertisement and its fraction as it transfers
    /// ([`SendProgressCallback`]).
    pub fn send_with_compression(
        dest: &[u8],
        packed: Vec<u8>,
        compress: bool,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_propagation_needed: Arc<dyn Fn() + Send + Sync + 'static>,
        on_failed: Arc<dyn Fn() + Send + Sync + 'static>,
        on_progress: Option<SendProgressCallback>,
    ) {
        let dest_owned = dest.to_vec();
        std::thread::Builder::new()
            .name("app_links_send".into())
            .spawn(move || {
                Self::run_tier_chain(
                    &dest_owned,
                    packed,
                    compress,
                    on_delivered,
                    on_propagation_needed,
                    on_failed,
                    on_progress,
                );
            })
            .expect("failed to spawn app_links send thread");
    }

    /// Send a plain DATA packet via an ephemeral app-link using the supplied
    /// destination spec.
    ///
    /// Unlike [`Self::open`], this only registers the app/aspect mapping and
    /// announce watch needed for tier-3 destination construction. The actual
    /// path-race / link-establish / DATA send lifecycle remains owned by
    /// [`Self::send`].
    pub fn send_with_spec(
        dest: &[u8],
        app_name: &str,
        aspects: &[&str],
        packed: Vec<u8>,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_propagation_needed: Arc<dyn Fn() + Send + Sync + 'static>,
        on_failed: Arc<dyn Fn() + Send + Sync + 'static>,
    ) {
        Self::ensure_announce_handler();

        let spec = AppLinkSpec::with_mode(
            app_name,
            aspects.iter().map(|s| (*s).to_string()).collect(),
            LinkMode::EphemeralLink,
        );

        Self::register_spec(dest, spec);

        Transport::watch_announce(dest.to_vec());
        Self::send(dest, packed, on_delivered, on_propagation_needed, on_failed);
    }

    /// Drive the tier chain on the background send thread: the stack's own
    /// links ([`StackTiers`]) under production's clocks.
    fn run_tier_chain(
        dest: &[u8],
        packed: Vec<u8>,
        compress: bool,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_propagation_needed: Arc<dyn Fn() + Send + Sync + 'static>,
        on_failed: Arc<dyn Fn() + Send + Sync + 'static>,
        on_progress: Option<SendProgressCallback>,
    ) {
        let prop_delay = Self::prop_fallback_delay_for_status(Self::status(dest));
        let pacing = ChainPacing {
            stagger: Duration::from_secs_f64(DIRECT_STAGGER_WAIT),
            prop_delay,
            backstop: OUTCOME_BACKSTOP,
        };
        // Timer P firing turns the destination red, unless it was already
        // DISCONNECTED (the zero delay).
        let dest_p = dest.to_vec();
        let on_prop: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || {
            if prop_delay > Duration::ZERO {
                AppLinks::mark_prop_fallback_disconnected(&dest_p);
            }
            on_propagation_needed();
        });
        let outcome = SendOutcome::new(dest, on_delivered, on_failed);
        let links = StackTiers { dest, packed: &packed, compress };
        Self::drive_tier_chain(
            &links,
            link_representation(packed.len()),
            pacing,
            &outcome,
            on_prop,
            on_progress,
        );
    }

    /// The tier chain, over any [`TierLinks`]: the stack's own links in
    /// production, fakes in the tests. Runs on the send thread and returns
    /// once it has fired every tier it will fire and heard each fired tier's
    /// own outcome (or that tier's backstop); `outcome` decides the send.
    ///
    /// Timer P runs in parallel on its own thread. Tier advancement waits only
    /// when an earlier tier actually put something in flight, so empty tiers
    /// never burn direct-send budget before the first real LRREQ.
    fn drive_tier_chain(
        links: &impl TierLinks,
        representation: LinkRepresentation,
        pacing: ChainPacing,
        outcome: &Arc<SendOutcome>,
        on_propagation_needed: Arc<dyn Fn() + Send + Sync + 'static>,
        on_progress: Option<SendProgressCallback>,
    ) {
        // The send's delivered gate: set once, by the first tier to deliver.
        let delivered = outcome.delivered.clone();
        // Shared by every tier's Resource: the caller's progress callback and
        // the send's activity clock, which Timer P and every tier's outcome
        // backstop read so that they count only time without transfer
        // activity — on any tier, across the handover from one to the next.
        let watch = TransferWatch::new(on_progress);
        let prop_delay = pacing.prop_delay;

        // ── Timer P: propagation fallback ─────────────────────────────
        //
        // Fires on_propagation_needed once the send has gone the computed
        // propagation delay undelivered and WITHOUT transfer activity: a
        // Resource reporting more of the message sent restarts the delay, so
        // a transfer that is making progress gets no propagated backup copy
        // (a second upload of the whole payload). Never fires after delivery.
        // DISCONNECTED readiness means the UI is already red, so the delay
        // is collapsed to zero while the direct cascade still continues in
        // parallel. Runs on a separate thread so it is truly parallel with
        // all tiers.
        //
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        // This is the authoritative source of the propagation trigger delay.
        // The caller (lxm_router) handles the actual propagation mechanics.
        {
            let delivered_p = delivered.clone();
            let activity_p = watch.activity.clone();
            let on_prop = on_propagation_needed;
            std::thread::Builder::new()
                .name("app_links_prop_timer".into())
                .spawn(move || {
                    Self::run_prop_timer(prop_delay, &delivered_p, &activity_p, || on_prop());
                })
                .expect("failed to spawn app-links Timer P");
        }

        // How a tier hands over to the next (see "Send tiers" at the top of
        // this file): a Resource tier only on its own failure event, a packet
        // tier after the stagger.
        let resource = representation == LinkRepresentation::Resource;
        // Packet tiers still in flight when the chain moved on. Their own
        // receipt events (proof or timeout) still decide the send; the chain
        // hears them at the end, under the same backstop.
        let mut unheard: Vec<(Tier, std::sync::mpsc::Receiver<bool>)> = Vec::new();

        // ── Tier 1: inbound link ──────────────────────────────────────
        // Fires immediately when a peer-initiated inbound link already exists.
        let (report, tier1_rx) = outcome.arm(Tier::Inbound);
        let tier1_fired = links.fire(
            Tier::Inbound,
            report,
            &watch,
        );
        if tier1_fired {
            if resource {
                // The Resource runs to its own outcome. Tier 2 fires only if
                // it fails; a moving transfer gets no second copy.
                if Self::await_tier(outcome, Tier::Inbound, &tier1_rx, &watch, pacing.backstop, representation) {
                    return;
                }
            } else {
                // Timer A: only wait when tier 1 actually put a packet in flight.
                std::thread::sleep(pacing.stagger);
                if delivered.load(Ordering::Acquire) {
                    return;
                }
                unheard.push((Tier::Inbound, tier1_rx));
            }
        } else {
            outcome.not_fired(Tier::Inbound);
        }

        // ── Tier 2: cached outbound link ─────────────────────────────
        if delivered.load(Ordering::Acquire) {
            return;
        }
        let (report, tier2_rx) = outcome.arm(Tier::Cached);
        let tier2_fired = links.fire(
            Tier::Cached,
            report,
            &watch,
        );
        if tier2_fired {
            if resource {
                // As tier 1: tier 3 fires only if this Resource fails.
                if Self::await_tier(outcome, Tier::Cached, &tier2_rx, &watch, pacing.backstop, representation) {
                    return;
                }
            } else {
                // Timer B: only wait when tier 2 actually put a packet in flight.
                std::thread::sleep(pacing.stagger);
                if delivered.load(Ordering::Acquire) {
                    return;
                }
                unheard.push((Tier::Cached, tier2_rx));
            }
        } else {
            outcome.not_fired(Tier::Cached);
        }

        // ── Tier 3: path verification + new link + send ──────────────
        if delivered.load(Ordering::Acquire) {
            return;
        }
        let (report, tier3_rx) = outcome.arm(Tier::NewLink);
        let tier3_fired = links.fire(
            Tier::NewLink,
            report,
            &watch,
        );
        if !tier3_fired {
            // Its path race or link failed (logged in `run_tier3`). That
            // fails the send only if no earlier tier is still in flight.
            outcome.not_fired(Tier::NewLink);
        }
        // Nothing fires after tier 3: from here the last in-flight tier's own
        // failure fails the send — or it fails now, if every tier that fired
        // has already failed or none could fire.
        outcome.exhausted();
        if tier3_fired {
            Self::await_tier(outcome, Tier::NewLink, &tier3_rx, &watch, pacing.backstop, representation);
        }
        for (tier, rx) in unheard {
            if outcome.is_decided() {
                break;
            }
            Self::await_tier(outcome, tier, &rx, &watch, pacing.backstop, representation);
        }
    }

    /// Timer P's clock, on the Timer P thread: waits until the send has gone
    /// `delay` without transfer activity, then runs `fire` — unless the
    /// message was delivered, which ends the wait at its next deadline
    /// without firing. Each report of more of the message sent pushes the
    /// deadline to `delay` after it. Returns whether it fired.
    fn run_prop_timer(
        delay: Duration,
        delivered: &AtomicBool,
        activity: &TransferActivity,
        fire: impl FnOnce(),
    ) -> bool {
        loop {
            if delivered.load(Ordering::Acquire) {
                return false;
            }
            let due = activity.quiet_deadline(delay);
            let now = Instant::now();
            if now >= due {
                break;
            }
            std::thread::sleep(due - now);
        }
        fire();
        true
    }

    fn prop_fallback_delay_for_status(status: u8) -> Duration {
        if status == APP_LINK_DISCONNECTED {
            Duration::ZERO
        } else {
            PROP_FALLBACK_DELAY
        }
    }

    /// Tier 3: a fresh path race, a new outbound link, and the message fired
    /// on it, reporting through `report`. Returns whether the message was put
    /// in flight. Every setup failure (path race, identity, destination, link
    /// establishment) is logged here and means tier 3 did not fire: it fails
    /// the send only when no earlier tier is still in flight (`SendOutcome`).
    /// Until 2026-09-29 each of them called `on_failed` directly, and failed
    /// the message while tier 1's Resource was still moving.
    fn run_tier3(
        dest: &[u8],
        packed: &[u8],
        compress: bool,
        report: TierReport,
        watch: &TransferWatch,
    ) -> bool {
        log(
            &format!("[APP_LINK] send tier-3 (path race + new link) for {}", hexrep(dest, false)),
            LOG_NOTICE, false, false,
        );

        let iface = match if Transport::has_path(dest) && Transport::is_path_verified_this_session(dest) {
            liveness::race_path(dest, LIVENESS_BUDGET)
        } else {
            liveness::race_path_verified_this_session(dest, LIVENESS_BUDGET)
        } {
            Ok(i) => i,
            Err(e) => {
                log(
                    &format!(
                        "[APP_LINK] send tier-3 race failed for {}: {}",
                        hexrep(dest, false),
                        e
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                return false;
            }
        };

        // Pre-warm the liveness cache for future opens/sends.
        if let Ok(mut cache) = LIVENESS_CACHE.lock() {
            cache.insert(dest.to_vec(), (iface.clone(), Instant::now()));
        }

        // Resolve identity and build the destination.
        let identity = match Identity::recall(dest) {
            Some(id) => id,
            None => {
                log(
                    &format!(
                        "[APP_LINK] send tier-3: no identity for {}",
                        hexrep(dest, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                return false;
            }
        };

        let spec = Self::spec(dest);
        let (app_name, aspects) = spec
            .map(|s| (s.app_name.clone(), s.aspects.clone()))
            .unwrap_or_else(|| ("lxmf".to_string(), vec!["delivery".to_string()]));

        let destination = match Destination::new_outbound(
            Some(identity),
            DestinationType::Single,
            app_name,
            aspects,
        ) {
            Ok(d) => d,
            Err(e) => {
                log(
                    &format!(
                        "[APP_LINK] send tier-3: destination build failed for {}: {}",
                        hexrep(dest, false),
                        e
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                return false;
            }
        };

        let link = match Link::new_outbound(destination, MODE_AES256_CBC) {
            Ok(l) => l,
            Err(e) => {
                log(
                    &format!(
                        "[APP_LINK] send tier-3: Link::new_outbound failed for {}: {}",
                        hexrep(dest, false),
                        e
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                return false;
            }
        };

        let handle = LinkHandle::spawn(link);

        // Wait for link establishment via channel (§7: callback/channel,
        // not polling).
        let (est_tx, est_rx) = std::sync::mpsc::sync_channel::<Result<LinkHandle, ()>>(1);
        {
            let tx = est_tx.clone();
            handle.set_link_established_callback(Some(Arc::new(move |h: LinkHandle| {
                let _ = tx.send(Ok(h));
            })));
        }
        {
            let tx = est_tx;
            handle.set_link_closed_callback(Some(Arc::new(move |_: LinkHandle| {
                let _ = tx.send(Err(()));
            })));
        }

        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        // Refresh TCP tunnel bindings before LRREQ.
        Transport::synthesize_tunnel_all_tcp();

        if let Err(e) = handle.initiate() {
            log(
                &format!(
                    "[APP_LINK] send tier-3: initiate failed for {}: {:?}",
                    hexrep(dest, false),
                    e
                ),
                LOG_NOTICE,
                false,
                false,
            );
            return false;
        }

        let established_handle = match est_rx.recv_timeout(LIVENESS_BUDGET) {
            Ok(Ok(h)) => h,
            Ok(Err(())) => {
                log(
                    &format!(
                        "[APP_LINK] send tier-3: link closed before established for {}",
                        hexrep(dest, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                return false;
            }
            Err(_) => {
                log(
                    &format!(
                        "[APP_LINK] send tier-3: link establishment timed out for {}",
                        hexrep(dest, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                return false;
            }
        };

        // Cache the link for tier-2 reuse on future sends.
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.links.insert(dest.to_vec(), established_handle.clone());
        }
        // Also mark as ready so status() returns ACTIVE.
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.prop_fallback_disconnected.remove(dest);
            reg.ready.insert(dest.to_vec(), Instant::now());
        }

        // Register a deterministic teardown callback so the registry is
        // cleaned up when this tier-3 link closes.  This is the event-driven
        // replacement for the old poll-based ready-watcher.
        // NEVER REMOVE EVER — without this, reg.links and reg.ready leak
        // until the next send's expire_path clears them.
        {
            let dest_cb = dest.to_vec();
            established_handle.set_link_closed_callback(Some(Arc::new(move |closing: LinkHandle| {
                AppLinks::handle_tracked_outbound_closed(dest_cb.clone(), closing);
            })));
        }

        // A packet on an earlier tier may have been proved while this link
        // came up: then there is nothing left to send.
        if report.send_delivered.load(Ordering::Acquire) {
            log(
                &format!(
                    "[APP_LINK] send tier-3: already delivered by an earlier tier; nothing fired on the new link to {}",
                    hexrep(dest, false)
                ),
                LOG_NOTICE, false, false,
            );
            return false;
        }

        // Fire; the chain hears the outcome (`await_tier`).
        let fired = Self::fire_on_link(
            &established_handle,
            packed,
            compress,
            report.gate,
            report.delivered,
            Some(report.failed),
            watch,
        );
        if !fired {
            log(
                &format!(
                    "[APP_LINK] send tier-3: the message could not be put in flight on the new link to {}",
                    hexrep(dest, false)
                ),
                LOG_NOTICE, false, false,
            );
        }
        fired
    }

    /// Hear one fired tier's own outcome, as RNS/LXMF decide it: delivered
    /// (the link packet proved, or its Resource concluded COMPLETE) or failed
    /// (the packet receipt's RTT-scaled timeout, or its Resource concluding
    /// without COMPLETE). Returns whether that tier delivered; `outcome` has
    /// already heard it from the tier's own callbacks.
    ///
    /// The backstop only guards a lost callback: it counts time with neither
    /// an outcome nor transfer activity (`await_outcome`). A tier whose
    /// callbacks were all dropped unheard is counted as failed here. So is a
    /// packet tier that goes the whole backstop with no outcome: its receipt
    /// callback never came. A Resource tier is not. The backstop passing only
    /// logs, and the wait goes on for the Resource's own outcome. A Resource
    /// that has not concluded can still deliver: it may be QUEUED behind
    /// another transfer on its link (RNS 1.5.2 Resource.py waits there with
    /// no clock), or stalled inside its own give-up time (RTT × 4 × 16 + 78 s,
    /// past 120 s once the RTT is over 0.66 s). Its own watchdog, its link
    /// closing, or its being dropped unconcluded ends it. Handing it over
    /// here would put a second full copy on the air beside it. Until
    /// 2026-09-29 (evening) the backstop failed a Resource tier: a photo
    /// queued behind another photo for 120 s went out again on the next
    /// tier, and the queued copy went too once its turn came.
    ///
    /// Until 2026-09-23 tier 3 waited a fixed LIVENESS_BUDGET (5 s) after its
    /// link came up and then declared failure while a transfer was still in
    /// flight: on a 3 s RTT link a Resource cannot finish in 5 s, so every
    /// direct message over the MDU "failed" and went to propagation. The
    /// 5-second promise to the user is Timer P (propagation fallback), not
    /// this wait. Until 2026-09-29 the
    /// OUTCOME_BACKSTOP was the same mistake on a longer clock: 120 s after
    /// the fire it failed a Resource that was still moving (an iPad photo,
    /// ~4 minutes over Bluetooth, reported FAILED at 120 s and DELIVERED
    /// later). Since 2026-09-29 every fired tier is heard this way, not only
    /// tier 3. Interruptible: the tier's callbacks send on its channel, so
    /// this thread wakes at once. NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
    fn await_tier(
        outcome: &SendOutcome,
        tier: Tier,
        rx: &std::sync::mpsc::Receiver<bool>,
        watch: &TransferWatch,
        backstop: Duration,
        representation: LinkRepresentation,
    ) -> bool {
        loop {
            match Self::await_outcome(rx, &watch.activity, backstop) {
                OutcomeWait::Delivered => return true,
                OutcomeWait::Failed => return false,
                OutcomeWait::Quiet if representation == LinkRepresentation::Resource => {
                    log(
                        &format!(
                            "[APP_LINK] send tier-{}: no outcome and no transfer activity for {:?} for {}; its Resource has not concluded (queued behind another transfer on its link, or inside its own timeouts), so the tier stays in flight until it does",
                            tier.number(),
                            backstop,
                            hexrep(&outcome.dest, false)
                        ),
                        LOG_NOTICE, false, false,
                    );
                }
                OutcomeWait::Quiet => {
                    outcome.tier_failed(
                        tier,
                        &format!("no outcome from the stack and no transfer activity for {:?} (backstop)", backstop),
                    );
                    return false;
                }
                OutcomeWait::Dropped => {
                    outcome.tier_failed(tier, "the stack dropped the transfer without an outcome");
                    return false;
                }
            }
        }
    }

    /// One fired tier's outcome wait. Returns the stack's outcome for the transfer
    /// as soon as it arrives. Fails it (`Quiet`) only once a full `backstop`
    /// has passed since the later of the start of this wait and the last
    /// transfer activity: a transfer that keeps moving is not stuck, and its
    /// own RTT-scaled timeouts (packet receipt, Resource watchdog) decide it.
    /// `Dropped` when every callback holding the channel was dropped without
    /// reporting.
    fn await_outcome(
        outcome_rx: &std::sync::mpsc::Receiver<bool>,
        activity: &TransferActivity,
        backstop: Duration,
    ) -> OutcomeWait {
        use std::sync::mpsc::RecvTimeoutError;
        let started = Instant::now();
        let quiet_deadline = || activity.quiet_deadline(backstop).max(started + backstop);
        loop {
            let wait = quiet_deadline().saturating_duration_since(Instant::now());
            match outcome_rx.recv_timeout(wait) {
                Ok(true) => return OutcomeWait::Delivered,
                Ok(false) => return OutcomeWait::Failed,
                Err(RecvTimeoutError::Disconnected) => return OutcomeWait::Dropped,
                Err(RecvTimeoutError::Timeout) => {
                    if Instant::now() >= quiet_deadline() {
                        return OutcomeWait::Quiet;
                    }
                }
            }
        }
    }

    /// Fire `packed` on `link` — one link packet, or a Resource over the link
    /// MDU — and install its outcome callbacks.
    ///
    /// Returns `true` when the message was put in flight (packet receipt
    /// obtained, or Resource built and advertising).  `on_delivered` fires
    /// when the LRPROOF arrives or the Resource concludes COMPLETE, and
    /// `delivered` gates it: this attempt reports delivery once.  In the tier
    /// chain `delivered` is the tier's own gate (`TierReport::gate`) and
    /// `SendOutcome` decides between tiers.  `on_outcome_failed` hears this
    /// attempt's own failure event: the receipt's timeout, or the Resource
    /// concluding without COMPLETE.
    fn fire_on_link(
        link: &LinkHandle,
        packed: &[u8],
        compress: bool,
        delivered: Arc<AtomicBool>,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_outcome_failed: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
        watch: &TransferWatch,
    ) -> bool {
        if link_representation(packed.len()) == LinkRepresentation::Resource {
            return Self::fire_resource_on_link(link, packed, compress, delivered, on_delivered, on_outcome_failed, watch);
        }
        // One link packet: nothing to report until the proof (the reference
        // sets a fixed 0.50 here, LXMF/LXMessage.py `send`).
        let Ok(dest) = link.build_link_destination() else {
            return false;
        };
        let mut pkt = Packet::new(
            Some(dest),
            packed.to_vec(),
            packet::DATA,
            packet::NONE,
            BROADCAST,
            packet::HEADER_1,
            None,
            None,
            true,
            0,
        );
        let Ok(Some(mut receipt)) = pkt.send() else {
            return false;
        };
        let dcb: Arc<dyn Fn(&reticulum_rust::packet::PacketReceipt) + Send + Sync> =
            Arc::new(move |_| {
                if !delivered.swap(true, Ordering::AcqRel) {
                    on_delivered();
                }
            });
        receipt.set_delivery_callback(dcb.clone());
        Transport::set_receipt_delivery_callback(&receipt.hash, dcb);
        // The receipt's own RTT-scaled timeout (RNS/Packet.py PacketReceipt)
        // is the failure event for a link packet.
        if let Some(failed) = on_outcome_failed {
            let tcb: Arc<dyn Fn(&reticulum_rust::packet::PacketReceipt) + Send + Sync> =
                Arc::new(move |_| failed());
            receipt.set_timeout_callback(tcb.clone());
            Transport::set_receipt_timeout_callback(&receipt.hash, tcb);
        }
        true
    }

    /// The callback a delivery Resource concludes through. RNS/Resource.py
    /// runs a Resource's `callback(resource)` once, when it concludes, and
    /// the status says how: COMPLETE is delivery; anything else is this
    /// attempt's own failure event — FAILED when the receiver never answered
    /// the advertisement through `MAX_ADV_RETRIES` (the watchdog's ADVERTISED
    /// branch), when a part request or the proof timed out, or when the link
    /// closed under it (RNS/Link.py `link_closed` cancels it); REJECTED when
    /// the receiver refused it. The Resource's own RTT-scaled timeouts decide
    /// all of these; nothing here adds a clock.
    fn resource_concluded(
        delivered: Arc<AtomicBool>,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_outcome_failed: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
    ) -> Arc<dyn Fn(Arc<Mutex<reticulum_rust::resource::Resource>>) + Send + Sync> {
        use reticulum_rust::resource::ResourceStatus;
        Arc::new(move |resource| {
            let complete = resource
                .lock()
                .map(|r| matches!(r.status, ResourceStatus::Complete))
                .unwrap_or(false);
            if complete {
                if !delivered.swap(true, Ordering::AcqRel) {
                    on_delivered();
                }
            } else if let Some(failed) = &on_outcome_failed {
                failed();
            }
        })
    }

    /// Send `packed` as a Resource on `link` (LXMF/LXMessage.py: a message
    /// larger than the link MDU has the RESOURCE representation and is
    /// delivered by `RNS.Resource(packed, link)`; `__resource_concluded`
    /// marks it delivered when the status is COMPLETE). Until 2026-09-23
    /// every direct message left here as ONE link packet, so anything over
    /// the MDU never left the phone: the packet could not be built, the
    /// receipt timed out, and the 5-second fallback propagated it instead.
    ///
    /// The Resource's progress callback (RNS/Resource.py `request` →
    /// `progress_callback`, LXMF/LXMessage.py `__as_resource`) reports its
    /// fraction to the caller and marks transfer activity for Timer P and
    /// the outcome backstop (`TransferWatch::resource_progress`). Until
    /// 2026-09-29 it was `None`: the message sat at 5 % for the whole
    /// transfer and the timers took a moving transfer for a stuck one.
    /// The caller also hears the advertisement once it has gone out
    /// (`TransferWatch::advertised`, since 2026-10-01).
    fn fire_resource_on_link(
        link: &LinkHandle,
        packed: &[u8],
        compress: bool,
        delivered: Arc<AtomicBool>,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_outcome_failed: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
        watch: &TransferWatch,
    ) -> bool {
        use reticulum_rust::resource::{AutoCompressOption, Resource, ResourceData};
        if !link.is_active() {
            return false;
        }
        let progress = watch.resource_progress(delivered.clone());
        let advertised = watch.advertised(delivered.clone());
        let concluded = Self::resource_concluded(delivered, on_delivered, on_outcome_failed);
        match Resource::new_internal(
            Some(ResourceData::Bytes(packed.to_vec())),
            link.clone(),
            None,
            false,
            if compress { AutoCompressOption::Enabled } else { AutoCompressOption::Disabled },
            Some(concluded),
            Some(progress),
            None,
            1,
            None,
            None,
            false,
            0,
            None,
        ) {
            Ok(resource) => {
                // DESIGN_PRINCIPLES §1, bulk transfers: the caller watches
                // the transfer from its advertisement on, so it hears the
                // advertisement once it has gone out (after any wait behind
                // another Resource on the link), on the advertise thread:
                // send_on_held_link runs on the caller's thread, which may
                // hold the very lock the report takes.
                Resource::advertise_shared_then(Arc::new(Mutex::new(resource)), advertised);
                true
            }
            Err(e) => {
                log(
                    &format!("[APP_LINK] could not build the delivery Resource ({} B): {}", packed.len(), e),
                    LOG_NOTICE, false, false,
                );
                false
            }
        }
    }
}

/// How a packed LXMF message travels on a link: one packet up to the link
/// MDU, a Resource above it (LXMF/LXMessage.py pack(): `content_size <=
/// LINK_PACKET_MAX_CONTENT` chooses PACKET, else RESOURCE; the packed size
/// against `RNS.Link.MDU` is the same boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRepresentation {
    Packet,
    Resource,
}

pub fn link_representation(packed_len: usize) -> LinkRepresentation {
    if packed_len > reticulum_rust::link::MDU {
        LinkRepresentation::Resource
    } else {
        LinkRepresentation::Packet
    }
}

// ─── Liveness race ───────────────────────────────────────────────────────

/// Bitrate threshold below which an interface is considered "LoRa-class"
/// and excluded from the liveness race.  Units: bits per second.
pub const LORA_BITRATE_THRESHOLD: f64 = 50_000.0;

/// How long a successful liveness result is considered fresh.  Within this
/// window subsequent sends to the same destination skip the race entirely.
pub const LIVENESS_CACHE_TTL: Duration = Duration::from_secs(2);

/// 5-second deterministic upper bound for the liveness race.
/// (DESIGN_PRINCIPLES §1).  Late success past this point is a defect.
const LIVENESS_BUDGET: Duration = Duration::from_secs(5);

/// Backstop on each fired tier's outcome wait (`AppLinks::await_tier`; until
/// 2026-09-29 only tier 3 had one). The outcome itself comes from the
/// stack's own RTT-scaled timeouts (packet receipt, Resource); this only
/// guards against a lost callback. It counts only time with neither an
/// outcome nor transfer activity (`AppLinks::await_outcome`): each report of
/// more of a Resource sent restarts it. On a packet tier it counts the tier
/// failed, because the receipt callback never came. On a Resource tier it
/// only logs. The Resource's own events decide that tier, since a Resource
/// that has not concluded can still deliver. It may be queued behind
/// another transfer on its link, or stalled within its own give-up time,
/// which passes 120 s once the RTT is over 0.66 s. So the backstop never
/// hands a Resource tier over and never fails one. Until 2026-09-29 it
/// counted from the fire, and failed a ~4-minute Bluetooth photo transfer at
/// 120 s while it was still moving. Until that evening it still failed a
/// quiet Resource tier, so a photo queued behind another went out twice.
const OUTCOME_BACKSTOP: Duration = Duration::from_secs(120);

/// How long a send may go undelivered AND without transfer activity before
/// Timer P fires `on_propagation_needed`: measured from the send, and again
/// from each report of more of a Resource sent (`AppLinks::run_prop_timer`).
/// Matches §1's 5-second network-action limit. Until 2026-09-29 it was
/// measured from the send alone, so every transfer longer than 5 s got a
/// propagated backup copy — the whole payload uploaded a second time.
/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
pub const PROP_FALLBACK_DELAY: Duration = LIVENESS_BUDGET;

/// When one send's transfer last moved: the send's start, then each report
/// from a Resource carrying it that more of it has been sent. Timer P and
/// every tier's outcome backstop count from here, so they measure only time
/// WITHOUT transfer activity — a transfer that is making progress is not
/// stuck. Shared by every tier of the send, so the quiet time runs on across
/// the handover from a failed tier's Resource to the next tier's.
#[derive(Clone)]
struct TransferActivity {
    last: Arc<Mutex<Instant>>,
}

impl TransferActivity {
    fn new() -> Self {
        Self { last: Arc::new(Mutex::new(Instant::now())) }
    }

    /// The transfer moved: the quiet clocks start again from now.
    fn mark(&self) {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        *last = Instant::now();
    }

    /// The moment `window` without transfer activity will have passed.
    fn quiet_deadline(&self, window: Duration) -> Instant {
        *self.last.lock().unwrap_or_else(|p| p.into_inner()) + window
    }
}

/// What the Resources carrying one send report to: the caller's progress
/// callback and the send's activity clock.
#[derive(Clone)]
struct TransferWatch {
    activity: TransferActivity,
    on_progress: Option<SendProgressCallback>,
}

impl TransferWatch {
    fn new(on_progress: Option<SendProgressCallback>) -> Self {
        Self { activity: TransferActivity::new(), on_progress }
    }

    /// The reporter for one Resource: called with the fraction
    /// `Resource::get_progress` gives after each request the receiver makes.
    /// Until `delivered` is set (the gate of the attempt this Resource
    /// carries: in the tier chain, its tier's gate) it hands the caller that
    /// raw fraction, and marks transfer activity when this Resource's
    /// fraction has grown (a request that only brings resends is not
    /// progress). After delivery it does nothing.
    fn reporter(&self, delivered: Arc<AtomicBool>) -> impl Fn(f64) + Send + Sync + 'static {
        let watch = self.clone();
        let reached = Mutex::new(0.0f64);
        move |fraction: f64| {
            if delivered.load(Ordering::Acquire) {
                return;
            }
            let advanced = {
                let mut reached = reached.lock().unwrap_or_else(|p| p.into_inner());
                let advanced = fraction > *reached;
                if advanced {
                    *reached = fraction;
                }
                advanced
            };
            if advanced {
                watch.activity.mark();
            }
            if let Some(on_progress) = &watch.on_progress {
                on_progress(fraction);
            }
        }
    }

    /// The hook for one Resource carrying the send that runs once its
    /// advertisement has gone out (`Resource::advertise_shared_then`): until
    /// `delivered` is set it hands the caller the Resource's fraction then,
    /// 0.0. DESIGN_PRINCIPLES §1, bulk transfers: from the advertisement on
    /// the transfer must show progress at least every 5 s, and LXMF's send
    /// assertion starts that watch here (`transfer_progress_reporter`). It
    /// is also where LXMF/LXMessage.py puts a Resource send at 0.10, the
    /// fraction 0.0 on LXMF's scale.
    ///
    /// Not transfer activity: nothing of the message has been sent yet, so
    /// Timer P and the outcome backstop count on from the last time some
    /// was (`TransferActivity`), as before.
    fn advertised(&self, delivered: Arc<AtomicBool>) -> Box<dyn FnOnce() + Send + 'static> {
        let on_progress = self.on_progress.clone();
        Box::new(move || {
            if delivered.load(Ordering::Acquire) {
                return;
            }
            if let Some(on_progress) = on_progress {
                on_progress(0.0);
            }
        })
    }

    /// The `progress_callback` for one Resource carrying the send
    /// (RNS/Resource.py hands the Resource to it after each request it
    /// serves): reads the fraction and passes it to [`Self::reporter`].
    fn resource_progress(
        &self,
        delivered: Arc<AtomicBool>,
    ) -> Arc<dyn Fn(Arc<Mutex<reticulum_rust::resource::Resource>>) + Send + Sync> {
        let report = self.reporter(delivered);
        Arc::new(move |resource| {
            let fraction = resource.lock().map(|mut r| r.get_progress());
            if let Ok(fraction) = fraction {
                report(fraction);
            }
        })
    }
}

/// How one fired tier's outcome wait ended (`AppLinks::await_outcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeWait {
    /// The delivery proof, or the Resource concluded COMPLETE.
    Delivered,
    /// The stack's failure event: receipt timeout, or the Resource concluded
    /// without COMPLETE.
    Failed,
    /// The backstop passed with no outcome and no transfer activity.
    Quiet,
    /// Every callback that could report was dropped without reporting.
    Dropped,
}

// ─── One DIRECT send: its tiers and its outcome ──────────────────────────

/// The three tiers of a DIRECT send, in the order the chain tries them
/// (see "Send tiers" at the top of this file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    /// Tier 1: the peer's own (inbound) link to us.
    Inbound,
    /// Tier 2: our cached outbound link from an earlier tier 3.
    Cached,
    /// Tier 3: a fresh path race and a new outbound link.
    NewLink,
}

impl Tier {
    fn index(self) -> usize {
        match self {
            Tier::Inbound => 0,
            Tier::Cached => 1,
            Tier::NewLink => 2,
        }
    }

    fn number(self) -> usize {
        self.index() + 1
    }
}

/// The clocks of one tier chain. None of them decides whether a tier failed:
/// that is always the tier's own event.
#[derive(Debug, Clone, Copy)]
struct ChainPacing {
    /// A packet tier's head start before the next tier fires beside it
    /// ([`DIRECT_STAGGER_WAIT`]). Resource tiers do not use it.
    stagger: Duration,
    /// Timer P: time undelivered and without transfer activity before
    /// `on_propagation_needed` ([`PROP_FALLBACK_DELAY`], zero when the
    /// destination is already DISCONNECTED).
    prop_delay: Duration,
    /// The lost-callback guard on each fired tier's outcome wait
    /// ([`OUTCOME_BACKSTOP`]; quiet time only). It fails a packet tier; on a
    /// Resource tier it only logs.
    backstop: Duration,
}

/// One tier's line back to its send: the tier's link calls `delivered` or
/// `failed` on the stack's own events for the message it carries.
struct TierReport {
    /// This tier's own gate: its link's delivery callbacks pass it once.
    gate: Arc<AtomicBool>,
    /// The send's delivered gate: set once any tier has delivered.
    send_delivered: Arc<AtomicBool>,
    /// This tier delivered: its link packet was proved, or its Resource
    /// concluded COMPLETE.
    delivered: Arc<dyn Fn() + Send + Sync + 'static>,
    /// This tier's own failure event: its packet receipt timed out, or its
    /// Resource concluded without COMPLETE.
    failed: Arc<dyn Fn() + Send + Sync + 'static>,
}

/// How the tier chain reaches each tier's link: the stack's own links in
/// production ([`StackTiers`]), fakes in the tests.
trait TierLinks {
    /// Put the message in flight on `tier`'s link, reporting that tier's own
    /// outcome through `report`. Returns false when the tier has no usable
    /// link or put nothing in flight (for tier 3: its path race or link
    /// failed); `report` is then never called.
    fn fire(&self, tier: Tier, report: TierReport, watch: &TransferWatch) -> bool;
}

/// The tiers on the stack's own links: the registry's inbound and cached
/// outbound links, and tier 3's path race and new link (`run_tier3`).
struct StackTiers<'a> {
    dest: &'a [u8],
    packed: &'a [u8],
    compress: bool,
}

impl TierLinks for StackTiers<'_> {
    fn fire(&self, tier: Tier, report: TierReport, watch: &TransferWatch) -> bool {
        let dest = self.dest;
        let (handle, which) = match tier {
            Tier::NewLink => {
                return AppLinks::run_tier3(dest, self.packed, self.compress, report, watch);
            }
            Tier::Inbound => (AppLinks::get_inbound_handle(dest), "inbound link"),
            Tier::Cached => (
                REGISTRY.lock().ok().and_then(|r| r.links.get(dest).cloned()),
                "cached outbound link",
            ),
        };
        let Some(handle) = handle.filter(|h| h.status() == STATE_ACTIVE) else {
            return false;
        };
        let carried = match link_representation(self.packed.len()) {
            LinkRepresentation::Packet => "packet",
            LinkRepresentation::Resource => "Resource",
        };
        log(
            &format!(
                "[APP_LINK] send tier-{} ({}, {} of {} B) for {}",
                tier.number(),
                which,
                carried,
                self.packed.len(),
                hexrep(dest, false)
            ),
            LOG_NOTICE, false, false,
        );
        let fired = AppLinks::fire_on_link(
            &handle,
            self.packed,
            self.compress,
            report.gate,
            report.delivered,
            Some(report.failed),
            watch,
        );
        if !fired {
            log(
                &format!(
                    "[APP_LINK] send tier-{}: the message could not be put in flight on the {} to {}",
                    tier.number(),
                    which,
                    hexrep(dest, false)
                ),
                LOG_NOTICE, false, false,
            );
        }
        fired
    }
}

/// The one outcome of one DIRECT send, decided from its tiers' own events.
///
/// `on_delivered` fires once, from the first tier to deliver. `on_failed`
/// fires once, when the chain will fire no more tiers and every tier that
/// fired has failed — or no tier could fire. So neither a tier-3 setup
/// failure nor a later tier's failure can fail a send whose earlier tier is
/// still in flight. Whatever a tier reports after the outcome is logged and
/// ignored, except a delivery after `on_failed`: that still reaches
/// `on_delivered`, once ([`Self::tier_delivered`]). Until 2026-09-29 tiers 1
/// and 2 reported no failure at all and tier 3 alone decided `on_failed`.
struct SendOutcome {
    dest: Vec<u8>,
    /// The send's delivered gate: Timer P and the chain read it.
    delivered: Arc<AtomicBool>,
    state: Mutex<OutcomeState>,
    on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
    on_failed: Arc<dyn Fn() + Send + Sync + 'static>,
}

#[derive(Default)]
struct OutcomeState {
    /// Tiers armed to fire, or fired, whose own outcome has not arrived.
    in_flight: [bool; 3],
    /// Tiers that fired and failed, in the order they failed.
    failed: Vec<Tier>,
    /// The chain will fire no more tiers.
    exhausted: bool,
    /// The send's outcome once decided: `true` delivered, `false` failed.
    decided: Option<bool>,
}

impl OutcomeState {
    /// Fail the send when nothing can still deliver it: the chain fires no
    /// more tiers and no tier is in flight. Returns why, the once it does.
    fn settle(&mut self) -> Option<String> {
        if self.decided.is_some() || !self.exhausted || self.in_flight.iter().any(|t| *t) {
            return None;
        }
        self.decided = Some(false);
        if self.failed.is_empty() {
            return Some("no tier could fire".to_string());
        }
        let tiers: Vec<String> = self.failed.iter().map(|t| t.number().to_string()).collect();
        Some(format!("every tier that fired has failed (tier {})", tiers.join(", then ")))
    }
}

fn outcome_word(delivered: bool) -> &'static str {
    if delivered {
        "delivered"
    } else {
        "failed"
    }
}

impl SendOutcome {
    fn new(
        dest: &[u8],
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_failed: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Arc<Self> {
        Arc::new(Self {
            dest: dest.to_vec(),
            delivered: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(OutcomeState::default()),
            on_delivered,
            on_failed,
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, OutcomeState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `tier` is about to fire. It counts as in flight from now until its own
    /// outcome arrives (or [`Self::not_fired`]), so an outcome it reports
    /// while still being fired already counts. Returns the tier's report and
    /// the channel the chain hears its outcome on.
    fn arm(self: &Arc<Self>, tier: Tier) -> (TierReport, std::sync::mpsc::Receiver<bool>) {
        self.state().in_flight[tier.index()] = true;
        let (tx, rx) = std::sync::mpsc::sync_channel::<bool>(2);
        let this = self.clone();
        let delivered_tx = tx.clone();
        let delivered: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || {
            this.tier_delivered(tier);
            let _ = delivered_tx.try_send(true);
        });
        let this = self.clone();
        let failed: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || {
            this.tier_failed(
                tier,
                "the stack reported delivery failed (packet receipt timed out, or its Resource concluded without COMPLETE)",
            );
            let _ = tx.try_send(false);
        });
        let report = TierReport {
            gate: Arc::new(AtomicBool::new(false)),
            send_delivered: self.delivered.clone(),
            delivered,
            failed,
        };
        (report, rx)
    }

    /// `tier` had no usable link, or put nothing in flight.
    fn not_fired(&self, tier: Tier) {
        let failed = {
            let mut state = self.state();
            state.in_flight[tier.index()] = false;
            state.settle()
        };
        if let Some(why) = failed {
            self.fail(why);
        }
    }

    /// The chain fires no more tiers.
    fn exhausted(&self) {
        let failed = {
            let mut state = self.state();
            state.exhausted = true;
            state.settle()
        };
        if let Some(why) = failed {
            self.fail(why);
        }
    }

    fn is_decided(&self) -> bool {
        self.state().decided.is_some()
    }

    /// `tier` delivered: the send is delivered, unless it already was.
    ///
    /// A delivery after the send FAILED still reaches `on_delivered`, once.
    /// The peer has proved it holds the message, and telling the user it
    /// failed while holding that proof is wrong. This is the same rule as
    /// Reticulum-rust's `PacketReceipt::mark_delivered` (PARITY-AUDIT B35: a
    /// late proof delivers a receipt that timed out), and LXMF reports it as a
    /// late delivery (`report_late_delivery`). Delivery may follow a failure,
    /// never the reverse. Until 2026-09-29 (evening) this ignored it, so a
    /// message the peer had proved stayed FAILED.
    fn tier_delivered(&self, tier: Tier) {
        let after_failure = {
            let mut state = self.state();
            state.in_flight[tier.index()] = false;
            match state.decided {
                Some(true) => {
                    log(
                        &format!(
                            "[APP_LINK] send tier-{} delivered after the send had already been delivered for {}; ignored",
                            tier.number(),
                            hexrep(&self.dest, false)
                        ),
                        LOG_NOTICE, false, false,
                    );
                    return;
                }
                earlier => {
                    state.decided = Some(true);
                    earlier == Some(false)
                }
            }
        };
        self.delivered.store(true, Ordering::Release);
        if after_failure {
            log(
                &format!(
                    "[APP_LINK] send tier-{} delivered for {} after the send had failed; reporting the late delivery",
                    tier.number(),
                    hexrep(&self.dest, false)
                ),
                LOG_NOTICE, false, false,
            );
        } else {
            log(
                &format!("[APP_LINK] send delivered via tier-{} for {}", tier.number(), hexrep(&self.dest, false)),
                LOG_NOTICE, false, false,
            );
        }
        (self.on_delivered)();
    }

    /// `tier`'s own failure event (or its outcome wait's backstop). Fails the
    /// send when it was the last tier that could still deliver it.
    fn tier_failed(&self, tier: Tier, why: &str) {
        let failed = {
            let mut state = self.state();
            if !state.in_flight[tier.index()] {
                log(
                    &format!(
                        "[APP_LINK] send tier-{}: {} after its outcome was already in for {}; ignored",
                        tier.number(),
                        why,
                        hexrep(&self.dest, false)
                    ),
                    LOG_NOTICE, false, false,
                );
                return;
            }
            state.in_flight[tier.index()] = false;
            if let Some(earlier) = state.decided {
                log(
                    &format!(
                        "[APP_LINK] send tier-{} failed after the send had already {} for {}: {}; ignored",
                        tier.number(),
                        outcome_word(earlier),
                        hexrep(&self.dest, false),
                        why
                    ),
                    LOG_NOTICE, false, false,
                );
                return;
            }
            state.failed.push(tier);
            log(
                &format!("[APP_LINK] send tier-{} failed for {}: {}", tier.number(), hexrep(&self.dest, false), why),
                LOG_NOTICE, false, false,
            );
            state.settle()
        };
        if let Some(why) = failed {
            self.fail(why);
        }
    }

    fn fail(&self, why: String) {
        log(
            &format!("[APP_LINK] send failed for {}: {}", hexrep(&self.dest, false), why),
            LOG_NOTICE, false, false,
        );
        (self.on_failed)();
    }
}

/// Polling interval while waiting for a path to populate after firing
/// `request_path`.  20 ms keeps wake-up cost negligible.
///
/// Retained as a documented constant only. The race loop is now
/// event-driven via `Transport::wait_for_path` / `PATH_ADDED_NOTIFY`
/// (see DESIGN_PRINCIPLES.md §4 — no timeout tuning, no polling).
#[allow(dead_code)]
const LIVENESS_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Liveness cache entry: (winning iface name, when it was learned).
static LIVENESS_CACHE: Lazy<Mutex<HashMap<Vec<u8>, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Errors from [`liveness::race_path`] / [`AppLinks::send`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendErr {
    /// No online non-LoRa interfaces available.
    NoUsableInterface,
    /// Liveness race exceeded [`LIVENESS_BUDGET`] without a winner.
    LivenessTimeout,
    /// Dispatch returned an error.
    Dispatch(String),
}

impl std::fmt::Display for SendErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendErr::NoUsableInterface => {
                write!(f, "no usable (online, non-LoRa) interface")
            }
            SendErr::LivenessTimeout => write!(f, "liveness race timed out (>5s)"),
            SendErr::Dispatch(e) => write!(f, "dispatch failed: {}", e),
        }
    }
}

impl std::error::Error for SendErr {}

fn liveness_candidate_interfaces() -> Vec<String> {
    reticulum_rust::transport::get_state_snapshot()
        .interfaces
        .iter()
    .filter(|i| i.out && i.online && i.bitrate.map_or(true, |b| b >= LORA_BITRATE_THRESHOLD))
        .map(|i| i.name.clone())
        .collect()
}

fn path_iface_matches_candidates(path_iface: Option<&str>, candidates: &[String]) -> bool {
    path_iface
        .map(|iface| candidates.iter().any(|candidate| candidate == iface))
        .unwrap_or(false)
}

fn cached_path_iface_is_live(
    dest_hash: &[u8],
    candidates: &[String],
    require_verified_session: bool,
) -> Option<String> {
    if !Transport::has_path(dest_hash) {
        return None;
    }
    if require_verified_session && !Transport::is_path_verified_this_session(dest_hash) {
        return None;
    }
    let iface = Transport::next_hop_interface(dest_hash)?;
    if path_iface_matches_candidates(Some(&iface), candidates) {
        Some(iface)
    } else {
        None
    }
}

struct PathRaceLogWatch {
    dest_hash: Vec<u8>,
}

impl PathRaceLogWatch {
    fn new(dest_hash: &[u8]) -> Self {
        announce_log::watch_destination(dest_hash);
        Self {
            dest_hash: dest_hash.to_vec(),
        }
    }
}

impl Drop for PathRaceLogWatch {
    fn drop(&mut self) {
        announce_log::unwatch_destination(&self.dest_hash);
    }
}

/// Liveness race module.
pub mod liveness {
    use super::*;

    /// Race a path-request on every online, non-LoRa interface and return
    /// the name of the iface whose response landed first.
    ///
    /// Behaviour:
    ///   * Filters by `online && bitrate >= LORA_BITRATE_THRESHOLD`.
    ///   * Fires `Transport::request_path` per candidate (parallel,
    ///     fire-and-forget).
    ///   * Polls [`Transport::has_path`] every [`LIVENESS_POLL_INTERVAL`].
    ///   * (Updated) Now blocks on `Transport::wait_for_path`, which
    ///     wakes on the actual PATH_RESPONSE / announce event via the
    ///     `PATH_ADDED_NOTIFY` Condvar — no clock-poll loop.
    ///   * Returns `Transport::next_hop_interface` on first hit, or
    ///     `Err(SendErr::LivenessTimeout)` after `budget`.
    ///
    /// Does NOT consult cached path-table entries at all. Any pre-existing
    /// cache row for `dest_hash` is unconditionally expired before the race
    /// begins, so success requires a fresh PATH_RESPONSE / announce observed
    /// within `budget`.
    pub fn race_path(
        dest_hash: &[u8],
        budget: Duration,
    ) -> Result<String, SendErr> {
        let _watch = PathRaceLogWatch::new(dest_hash);
        let candidates = liveness_candidate_interfaces();

        if candidates.is_empty() {
            return Err(SendErr::NoUsableInterface);
        }

        // Drop any cached path before racing. Path Race must never benefit
        // from a stale path-table row: success has to come from a fresh
        // PATH_RESPONSE / announce arriving inside `budget`.
        Transport::expire_path(dest_hash);

        // Fire request_path on every candidate iface in parallel.
        for iface in &candidates {
            Transport::request_path(dest_hash, None, Some(iface.clone()), None, None);
        }

        // Block on the actual PATH_RESPONSE / announce event instead of
        // polling. `Transport::wait_for_path` returns as soon as the
        // path_table is mutated for `dest_hash` (Condvar-driven), or
        // after `budget` as a hard upper bound.
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §4: this is the
        // event-driven replacement for the previous sleep-poll loop.
        if Transport::wait_for_path(dest_hash, budget) {
            if let Some(iface) = cached_path_iface_is_live(dest_hash, &candidates, false) {
                return Ok(iface);
            }
        }

        Err(SendErr::LivenessTimeout)
    }

    /// Same as [`race_path`], but success requires a path verified by an
    /// inbound PATH_RESPONSE / announce in this process. Any cached path-
    /// table entry for `dest_hash` is unconditionally expired before the
    /// race begins, so the readiness gate can only be satisfied by a fresh
    /// in-session event.
    ///
    /// Used by persistent propagation links so LRREQ is sent only after the
    /// relay has proven it can reply on the current session.
    pub fn race_path_verified_this_session(
        dest_hash: &[u8],
        budget: Duration,
    ) -> Result<String, SendErr> {
        let _watch = PathRaceLogWatch::new(dest_hash);
        let candidates = liveness_candidate_interfaces();

        if candidates.is_empty() {
            return Err(SendErr::NoUsableInterface);
        }

        // Drop any cached path before racing — see `race_path` for rationale.
        Transport::expire_path(dest_hash);

        for iface in &candidates {
            Transport::request_path(dest_hash, None, Some(iface.clone()), None, None);
        }

        if Transport::wait_for_path_verified_this_session(dest_hash, budget) {
            if let Some(iface) = cached_path_iface_is_live(dest_hash, &candidates, true) {
                return Ok(iface);
            }
        }

        Err(SendErr::LivenessTimeout)
    }
}

impl AppLinks {
    /// Forget the cached liveness winner for `dest_hash`.  Call on known
    /// network-state changes to force re-racing on the next send.
    pub fn invalidate_liveness(dest_hash: &[u8]) {
        if let Ok(mut cache) = LIVENESS_CACHE.lock() {
            cache.remove(dest_hash);
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────
//
// These tests verify the orchestration constraints described in the send spec:
//   §O1 Timer P fires on_propagation_needed after PROP_FALLBACK_DELAY
//       without transfer activity.
//   §O2 Timer P does NOT fire if delivery happened before the delay.
//   §O3 The delivered gate fires on_delivered exactly once even when
//       multiple tiers fire concurrently.
//   §O4 on_propagation_needed and on_failed are independent — both can fire
//       on the same send (propagation starts while tier-3 still runs).
//   §O5 Tier advancement does not cancel prior in-flight tier packets
//       (the delivered gate remains settable from any tier at any time).
//   §O6 A Resource's progress reaches the caller until delivery, and marks
//       transfer activity when more of it has been sent. Its advertisement
//       reaches the caller too, once it has gone out (0.0), and is not
//       activity (DESIGN_PRINCIPLES §1, bulk transfers).
//   §O7 A transfer that keeps moving gets no Timer P backup and its outcome
//       wait does not go quiet; a silent one gets both.
//   §O8 A tier carrying a Resource hands over to the next tier only on its
//       own failure event (its Resource concluding FAILED, which covers its
//       link closing and an advertisement nobody answers), never on the
//       stagger and never on the outcome backstop (a Resource queued behind
//       another on its link, or stalled, waits past it); a tier carrying one
//       packet keeps the DIRECT_STAGGER_WAIT stagger.
//   §O9 One outcome per send: on_delivered once, from the first tier to
//       deliver; on_failed once, only after every tier that fired has
//       failed (a tier-3 setup failure never fails a send with a tier still
//       in flight, nor does the backstop on a Resource tier); anything later
//       is ignored, except a delivery after on_failed, which still reaches
//       on_delivered once (a late proof).
//
// §O8/§O9 drive the production tier chain (`drive_tier_chain`) over fake
// links (`FakeTiers`); §O8's advertisement case runs a real Resource's own
// watchdog. All tests use short delays (ms) so the suite completes quickly.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    static REGISTRY_TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn reset_registry_for_test() {
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.specs.clear();
            reg.ready.clear();
            reg.links.clear();
            reg.inbound_links.clear();
            reg.prop_fallback_disconnected.clear();
        }
        if let Ok(mut cache) = LIVENESS_CACHE.lock() {
            cache.clear();
        }
    }

    /// Spawn a Timer P with a custom delay for test speed, on production's
    /// clock (`run_prop_timer`), with no transfer activity.
    fn spawn_prop_timer(
        delay: Duration,
        delivered: Arc<AtomicBool>,
        on_prop: Arc<dyn Fn() + Send + Sync + 'static>,
    ) {
        spawn_prop_timer_watching(delay, delivered, TransferActivity::new(), on_prop);
    }

    /// Timer P on production's clock, watching `activity`. The handle
    /// yields whether it fired.
    fn spawn_prop_timer_watching(
        delay: Duration,
        delivered: Arc<AtomicBool>,
        activity: TransferActivity,
        on_prop: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> std::thread::JoinHandle<bool> {
        std::thread::spawn(move || AppLinks::run_prop_timer(delay, &delivered, &activity, || on_prop()))
    }

    /// The tier-3 outcome wait on production's code, on its own thread. The
    /// handle yields how it ended and when.
    fn spawn_outcome_wait(
        rx: mpsc::Receiver<bool>,
        activity: TransferActivity,
        backstop: Duration,
    ) -> std::thread::JoinHandle<(OutcomeWait, Instant)> {
        std::thread::spawn(move || {
            let outcome = AppLinks::await_outcome(&rx, &activity, backstop);
            (outcome, Instant::now())
        })
    }

    /// A sending Resource with `total_parts` parts on a bare link, carrying
    /// `progress` as its progress callback. Its data is never built (that
    /// needs an established link); `request` below serves requests on it the
    /// way the stack does and calls the callback the way the stack does.
    fn sending_resource(
        total_parts: usize,
        progress: Arc<dyn Fn(Arc<Mutex<reticulum_rust::resource::Resource>>) + Send + Sync>,
    ) -> reticulum_rust::resource::Resource {
        use reticulum_rust::destination::Destination;
        use reticulum_rust::resource::{AutoCompressOption, Resource, ResourceLinkContext};
        let link = LinkHandle::spawn(Link::new_inbound(Destination::default()).expect("test link"));
        let ctx = ResourceLinkContext {
            mtu: 500,
            rtt: Some(0.1),
            traffic_timeout_factor: 4.0,
            establishment_cost: 0,
            last_resource_window: None,
            last_resource_eifr: None,
        };
        let mut resource = Resource::new_internal(
            None, link, None, false, AutoCompressOption::Disabled,
            None, Some(progress), Some(0.0), 0, None, None, false, 0, Some(&ctx),
        )
        .expect("test resource");
        resource.initiator = true;
        resource.total_parts = total_parts;
        resource
    }

    /// The receiver asks for more and `sent` parts have now gone out:
    /// `Resource::request` serves the REQ and calls the progress callback.
    fn serve_request(resource: &mut reticulum_rust::resource::Resource, sent: usize) {
        resource.sent_parts = sent;
        let mut req = vec![0x00u8];
        req.extend_from_slice(&[0u8; 32]);
        resource.request(&req);
    }

    /// close_all drops every registration and tells the host so. The
    /// registry is process-global; a stack restarted in the same process
    /// must not inherit the previous stack's links.
    #[test]
    fn close_all_drops_registrations_and_reports_none() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_for_test();
        let a: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(7)).collect();
        let b: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(11)).collect();
        {
            let mut reg = REGISTRY.lock().unwrap();
            reg.specs.insert(a.clone(), AppLinkSpec::with_mode("lxmf", vec!["propagation".into()], LinkMode::Persistent));
            reg.specs.insert(b.clone(), AppLinkSpec::with_mode("lxmf", vec!["delivery".into()], LinkMode::EphemeralLink));
            reg.ready.insert(b.clone(), Instant::now());
            reg.prop_fallback_disconnected.insert(a.clone());
        }
        let seen: Arc<Mutex<Vec<(Vec<u8>, u8)>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = seen.clone();
        AppLinks::register_status_callback(Arc::new(move |dest, status, _| {
            seen_cb.lock().unwrap().push((dest.to_vec(), status));
        }));

        let torn_down = AppLinks::close_all();

        assert_eq!(torn_down, 0, "no handles were held");
        assert!(!AppLinks::contains(&a) && !AppLinks::contains(&b), "registrations must be gone");
        assert_eq!(AppLinks::status(&a), APP_LINK_NONE);
        assert_eq!(AppLinks::status(&b), APP_LINK_NONE);
        let mut reported = seen.lock().unwrap().clone();
        reported.sort();
        let mut expected = vec![(a.clone(), APP_LINK_NONE), (b.clone(), APP_LINK_NONE)];
        expected.sort();
        assert_eq!(reported, expected, "every dropped registration reports NONE once");
        {
            let reg = REGISTRY.lock().unwrap();
            assert!(reg.status_callbacks.is_empty(), "host callbacks belong to the stack that registered them");
            assert!(reg.prop_fallback_disconnected.is_empty());
        }
        reset_registry_for_test();
    }

    /// send_on_held_link fires no callback and reports the error when no
    /// active link is held: the caller keeps its message OUTBOUND.
    #[test]
    fn send_on_held_link_without_active_link_is_an_error() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_for_test();
        let dest: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(13)).collect();
        let fired = Arc::new(AtomicBool::new(false));
        let (f1, f2) = (fired.clone(), fired.clone());
        let f3 = fired.clone();
        let result = AppLinks::send_on_held_link(
            &dest,
            vec![1, 2, 3],
            true,
            Arc::new(move || f1.store(true, Ordering::Release)),
            Arc::new(move || f2.store(true, Ordering::Release)),
            Some(Arc::new(move |_| f3.store(true, Ordering::Release))),
        );
        assert!(result.is_err());
        assert!(!fired.load(Ordering::Acquire), "no callback without a send");
        assert!(!AppLinks::teardown_held_link(&dest), "nothing held to tear down");
        reset_registry_for_test();
    }

    // §O1 — Timer P fires on_propagation_needed when message not delivered.
    #[test]
    fn timer_p_fires_when_not_delivered() {
        let delivered = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<()>();
        spawn_prop_timer(
            Duration::from_millis(50),
            delivered,
            Arc::new(move || { let _ = tx.send(()); }),
        );
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_ok(),
            "Timer P must fire on_propagation_needed when not delivered"
        );
    }

    // §O2 — Timer P is suppressed when delivery already happened.
    #[test]
    fn timer_p_suppressed_when_already_delivered() {
        let delivered = Arc::new(AtomicBool::new(true)); // already delivered
        let (tx, rx) = mpsc::channel::<()>();
        spawn_prop_timer(
            Duration::from_millis(50),
            delivered,
            Arc::new(move || { let _ = tx.send(()); }),
        );
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "Timer P must NOT fire when delivery already happened"
        );
    }

    // §O2 (race) — delivery fires just before Timer P elapses.
    #[test]
    fn timer_p_suppressed_when_delivery_beats_timer() {
        let delivered = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<()>();
        spawn_prop_timer(
            Duration::from_millis(100),
            delivered.clone(),
            Arc::new(move || { let _ = tx.send(()); }),
        );
        // Mark delivered well before the timer fires.
        std::thread::sleep(Duration::from_millis(20));
        delivered.store(true, Ordering::Release);
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "Timer P must not fire when delivery beat it to the punch"
        );
    }

    #[test]
    fn disconnected_status_uses_immediate_prop_delay() {
        assert_eq!(
            AppLinks::prop_fallback_delay_for_status(APP_LINK_DISCONNECTED),
            Duration::ZERO,
            "DISCONNECTED readiness must trigger immediate propagation fallback"
        );
    }

    #[test]
    fn non_disconnected_status_uses_default_prop_delay() {
        for status in [
            APP_LINK_NONE,
            APP_LINK_PATH_REQUESTED,
            APP_LINK_ESTABLISHING,
            APP_LINK_ACTIVE,
        ] {
            assert_eq!(
                AppLinks::prop_fallback_delay_for_status(status),
                PROP_FALLBACK_DELAY,
                "Only DISCONNECTED readiness may collapse Timer P to zero"
            );
        }
    }

    #[test]
    fn prop_fallback_disconnect_latch_overrides_inflight_status() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_for_test();

        let dest = b"peer-a".to_vec();
        let spec = AppLinkSpec::new("lxmf", vec!["delivery".to_string()]);
        spec.attempt_in_flight.store(true, Ordering::Release);
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.specs.insert(dest.clone(), spec);
        }

        AppLinks::mark_prop_fallback_disconnected(&dest);

        assert_eq!(
            AppLinks::status(&dest),
            APP_LINK_DISCONNECTED,
            "Timer P red latch must override PATH_REQUESTED until a fresh success clears it"
        );

        reset_registry_for_test();
    }

    #[test]
    fn clearing_prop_fallback_disconnect_restores_inflight_status() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_for_test();

        let dest = b"peer-b".to_vec();
        let spec = AppLinkSpec::new("lxmf", vec!["delivery".to_string()]);
        spec.attempt_in_flight.store(true, Ordering::Release);
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.specs.insert(dest.clone(), spec);
            reg.prop_fallback_disconnected.insert(dest.clone());
        }

        AppLinks::clear_prop_fallback_disconnected(&dest);

        assert_eq!(
            AppLinks::status(&dest),
            APP_LINK_PATH_REQUESTED,
            "Fresh path resolution should be able to clear the red latch and expose live progress again"
        );

        reset_registry_for_test();
    }

    // A reconnect on 2026-09-25 opened two links to the propagation node:
    // a second open replaced the spec mid-attempt, and its fresh in-flight
    // guard let a second attempt start beside the first.
    #[test]
    fn reopening_a_link_mid_attempt_keeps_the_attempt_guard() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_for_test();

        let dest = b"prop-node".to_vec();
        let running = AppLinkSpec::with_mode("lxmf", vec!["propagation".into()], LinkMode::Persistent);
        running.attempt_in_flight.store(true, Ordering::Release);
        AppLinks::register_spec(&dest, running.clone());

        AppLinks::register_spec(
            &dest,
            AppLinkSpec::with_mode("lxmf", vec!["propagation".into()], LinkMode::Persistent),
        );
        let reopened = AppLinks::spec(&dest).expect("still registered");
        assert!(
            Arc::ptr_eq(&reopened.attempt_in_flight, &running.attempt_in_flight),
            "the running attempt's guard must carry over"
        );
        assert!(
            reopened
                .attempt_in_flight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err(),
            "a second attempt must be refused while the first runs"
        );

        // The attempt ends and clears the guard it holds: the next open sees it.
        running.attempt_in_flight.store(false, Ordering::Release);
        assert!(!AppLinks::spec(&dest).unwrap().attempt_in_flight.load(Ordering::Acquire));

        // A change of mode is a different attempt, with a guard of its own.
        running.attempt_in_flight.store(true, Ordering::Release);
        AppLinks::register_spec(&dest, AppLinkSpec::new("lxmf", vec!["propagation".into()]));
        assert!(!AppLinks::spec(&dest).unwrap().attempt_in_flight.load(Ordering::Acquire));

        let production = include_str!("lib.rs").split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            production.matches("reg.specs.insert(").count(),
            1,
            "every registration must go through register_spec"
        );

        reset_registry_for_test();
    }

    // §O3 — Delivered gate fires exactly once under concurrent tier delivery.
    #[test]
    fn delivered_gate_fires_exactly_once() {
        let delivered = Arc::new(AtomicBool::new(false));
        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let handles: Vec<_> = (0..3).map(|_| {
            let d = delivered.clone();
            let c = count.clone();
            std::thread::spawn(move || {
                if !d.swap(true, Ordering::AcqRel) {
                    c.fetch_add(1, Ordering::AcqRel);
                }
            })
        }).collect();
        for h in handles { h.join().unwrap(); }
        assert_eq!(
            count.load(Ordering::Acquire), 1,
            "on_delivered must fire exactly once regardless of concurrent tier deliveries"
        );
    }

    // §O4 — Timer P and on_failed are independent; both fire when tier-3
    // exhausts and delivery never happened.
    #[test]
    fn prop_and_failed_are_independent() {
        let delivered = Arc::new(AtomicBool::new(false));
        let (prop_tx, prop_rx) = mpsc::channel::<()>();
        let (fail_tx, fail_rx) = mpsc::channel::<()>();

        // Timer P fires at t=50ms.
        spawn_prop_timer(
            Duration::from_millis(50),
            delivered,
            Arc::new(move || { let _ = prop_tx.send(()); }),
        );

        // on_failed fires at t=150ms (tier-3 exhausted, always fires independently).
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            let _ = fail_tx.send(());
        });

        assert!(
            prop_rx.recv_timeout(Duration::from_millis(200)).is_ok(),
            "on_propagation_needed must fire independently of on_failed"
        );
        assert!(
            fail_rx.recv_timeout(Duration::from_millis(300)).is_ok(),
            "on_failed must fire independently of on_propagation_needed"
        );
    }

    #[test]
    fn a_message_over_the_link_mdu_travels_as_a_resource() {
        use super::{link_representation, LinkRepresentation};
        let mdu = reticulum_rust::link::MDU;
        assert_eq!(link_representation(1), LinkRepresentation::Packet);
        assert_eq!(link_representation(mdu), LinkRepresentation::Packet, "exactly the MDU still fits one packet");
        assert_eq!(link_representation(mdu + 1), LinkRepresentation::Resource, "one byte over the MDU is a Resource");
        assert_eq!(link_representation(1700), LinkRepresentation::Resource);
    }

    // §O5 — Tier-1 delivery is still accepted after tier-2 has started.
    // The delivered gate must remain open to any tier at any time.
    #[test]
    fn tier1_delivery_accepted_after_tier2_starts() {
        let delivered = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<()>();

        // Tier 1 "delivers" at t=80ms — after Timer A (50ms) so tier 2 has started.
        {
            let d = delivered.clone();
            let t = tx.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(80));
                if !d.swap(true, Ordering::AcqRel) {
                    let _ = t.send(());
                }
            });
        }

        // Tier 2 fires at t=50ms, "delivers" at t=120ms — but tier 1 wins.
        {
            let d = delivered.clone();
            let t = tx;
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(120));
                if !d.swap(true, Ordering::AcqRel) {
                    let _ = t.send(());
                }
            });
        }

        // Exactly one delivery notification must arrive.
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_ok(),
            "delivery must be notified"
        );
        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "delivery must not fire twice (delivered gate broken)"
        );
    }

    #[test]
    fn app_link_spec_preserves_requested_mode() {
        let spec = AppLinkSpec::with_mode(
            "rfed",
            vec!["channel".to_string()],
            LinkMode::Persistent,
        );
        assert_eq!(spec.mode, LinkMode::Persistent);
    }

    /// An interface coming back online re-attempts the links that are down,
    /// like a network change: every open subscribes AppLinks to Transport's
    /// up-edge, once, and both triggers share one foreground-gated path.
    #[test]
    fn an_interface_coming_online_reattempts_links_that_are_down() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        assert!(production.contains(
            "Transport::add_interface_up_listener(Arc::new(|name: &str| AppLinks::interface_online(name)));"
        ));
        assert!(production.contains("HOOKED.call_once("), "subscribed once per process");
        let open = production
            .split("pub fn open_with_mode(")
            .nth(1)
            .expect("open_with_mode")
            .split("let previous_status")
            .next()
            .unwrap();
        assert!(open.contains("Self::ensure_interface_up_hook();"), "every open subscribes");
        assert!(production.contains(
            "Self::attempt_inactive_links(&format!(\"interface {} online\", name));"
        ));
        assert!(production.contains("Self::attempt_inactive_links(\"network-change trigger\");"));
        let attempt = production
            .split("fn attempt_inactive_links(trigger: &str) {")
            .nth(1)
            .expect("attempt_inactive_links");
        assert!(
            attempt.trim_start().starts_with("if Self::policy() != LinkPolicy::Foreground {"),
            "foreground only, first"
        );
        assert!(
            !production.contains("app_links_reestablish"),
            "event-driven: no timed retry loop"
        );
    }

    #[test]
    fn persistent_mode_is_explicitly_wired() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        assert!(
            production.contains("Self::open_with_mode(dest_hash, app_name, aspects, LinkMode::Persistent);"),
            "open_persistent must register the persistent lifecycle mode"
        );
        assert!(
            production.contains("fn establish_persistent(dest_hash: &[u8], spec: AppLinkSpec)"),
            "persistent mode must have a dedicated establish path"
        );
        assert!(
            !production.contains("app_links_reestablish"),
            "persistent mode must remain event-driven; timed retry loops must not return"
        );
    }

    #[test]
    fn persistent_close_reopen_is_single_shot() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        assert!(
            production.contains("Self::request_reopen_internal(&dest_hash, false);"),
            "persistent close-triggered reopen must NOT re-arm itself"
        );
        assert!(
            production.contains("Self::request_reopen_internal(dest_hash, true);"),
            "external reopen requests must re-arm persistent links for one future close"
        );
    }

    #[test]
    fn persistent_establish_is_not_bounded_by_liveness_budget() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        let start = production
            .find("fn establish_persistent(dest_hash: &[u8], spec: AppLinkSpec)")
            .expect("persistent establish path must exist");
        let tail = &production[start..];
        let end = tail
            .find("// ─── Three-tier send")
            .expect("persistent establish fragment must end before send tiers");
        let fragment = &tail[..end];
        assert!(
            !fragment.contains("recv_timeout(LIVENESS_BUDGET)"),
            "persistent open must not abandon link establishment on the 5-second liveness budget"
        );
        assert!(
            fragment.contains("set_link_established_callback(Some"),
            "persistent open must remain callback-driven for activation"
        );
        assert!(
            fragment.contains("persistent open: link closed before active"),
            "persistent open must still surface deterministic close-before-active failures"
        );
    }

    #[test]
    fn direct_send_uses_fixed_stagger_scheduler() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        let start = production
            .find("fn run_tier_chain(")
            .expect("run_tier_chain must exist");
        let tail = &production[start..];
        let end = tail
            .find("fn run_tier3(")
            .expect("run_tier3 must exist after run_tier_chain");
        let fragment = &tail[..end];
        assert!(
            fragment.contains("if tier1_fired {")
                && fragment.contains("Duration::from_secs_f64(DIRECT_STAGGER_WAIT)"),
            "tier-2 must wait only when tier-1 actually queued a packet"
        );
        assert!(
            fragment.contains("if tier2_fired {")
                && fragment.contains("Duration::from_secs_f64(DIRECT_STAGGER_WAIT)"),
            "tier-3 must wait only when tier-2 actually queued a packet"
        );
        assert!(
            !fragment.contains("Duration::from_secs_f64(DIRECT_STAGGER_WAIT * 2.0)"),
            "tier-3 must not burn a fixed extra second when tier-2 never fired"
        );
        assert!(
            !fragment.contains("spawn_after(\n                \"app_links_tier2\""),
            "tier scheduling must not rely on detached fixed-delay worker threads"
        );
        // §O8: the stagger is for packets. A Resource tier is heard to its
        // own outcome instead, before the next tier may fire.
        for (tier, rx) in [("Inbound", "tier1_rx"), ("Cached", "tier2_rx")] {
            let heard = format!("Self::await_tier(outcome, Tier::{}, &{}, &watch, pacing.backstop, representation)", tier, rx);
            assert!(fragment.contains(&heard), "tier {} must hear its Resource's outcome: {}", tier, heard);
            let branch = fragment.split(&heard).next().expect("tier branch");
            let resource_branch = branch.rfind("if resource {").expect("each staggered tier branches on the representation");
            assert!(
                !branch[resource_branch..].contains("sleep("),
                "tier {} must not sleep the stagger before hearing its Resource's outcome",
                tier
            );
        }
        assert_eq!(fragment.matches("std::thread::sleep(pacing.stagger);").count(), 2, "Timer A and Timer B only");
    }

    #[test]
    fn ephemeral_open_requires_verified_session_path() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        let start = production
            .find("fn establish(dest_hash: &[u8])")
            .expect("ephemeral establish path must exist");
        let tail = &production[start..];
        let end = tail
            .find("fn establish_persistent(")
            .expect("ephemeral establish fragment must end before persistent path");
        let fragment = &tail[..end];
        assert!(
            fragment.contains("Self::ephemeral_requires_verified_session_path(&spec)")
                && fragment.contains("liveness::race_path_verified_this_session(&dest_owned, LIVENESS_BUDGET)"),
            "ephemeral app-link opens must require a path verified in this process"
        );
    }

    #[test]
    fn path_iface_must_match_live_candidates() {
        let candidates = vec!["Beleth".to_string(), "RPi TCP Transport".to_string()];
        assert!(path_iface_matches_candidates(Some("Beleth"), &candidates));
        assert!(!path_iface_matches_candidates(Some("rmap"), &candidates));
        assert!(!path_iface_matches_candidates(None, &candidates));
    }

    #[test]
    fn liveness_candidates_require_outbound_interfaces() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        assert!(
            production.contains(".filter(|i| i.out && i.online && i.bitrate.map_or(true, |b| b >= LORA_BITRATE_THRESHOLD))"),
            "AppLinks liveness races must ignore non-outbound transport interfaces when classifying READY paths"
        );
    }

    #[test]
    fn liveness_drops_cached_paths_before_racing() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        assert!(
            !production.contains("soft_expire_stale_cached_path"),
            "path races must not retain the soft-expire-by-candidate helper; cached paths are dropped unconditionally"
        );
        let race_start = production
            .find("pub fn race_path(")
            .expect("race_path must exist");
        let verified_start = production[race_start..]
            .find("pub fn race_path_verified_this_session(")
            .map(|idx| race_start + idx)
            .expect("race_path_verified_this_session must exist");
        let race_fragment = &production[race_start..verified_start];
        let verified_end = production[verified_start..]
            .find("}\n}\n\nimpl AppLinks")
            .map(|idx| verified_start + idx)
            .expect("verified race fragment must terminate before impl AppLinks");
        let verified_fragment = &production[verified_start..verified_end];

        let race_expire = race_fragment
            .find("Transport::expire_path(dest_hash);")
            .expect("race_path must unconditionally expire any cached path");
        let race_request = race_fragment
            .find("Transport::request_path(dest_hash, None, Some(iface.clone()), None, None);")
            .expect("race_path must issue request_path");
        assert!(
            race_expire < race_request,
            "race_path must drop cached paths before issuing fresh path requests"
        );

        let verified_expire = verified_fragment
            .find("Transport::expire_path(dest_hash);")
            .expect("race_path_verified_this_session must unconditionally expire any cached path");
        let verified_request = verified_fragment
            .find("Transport::request_path(dest_hash, None, Some(iface.clone()), None, None);")
            .expect("verified race must issue request_path");
        assert!(
            verified_expire < verified_request,
            "race_path_verified_this_session must drop cached paths before issuing fresh path requests"
        );

        assert!(
            production.contains("cached_path_iface_is_live(dest_hash, &candidates, false)")
                && production.contains("cached_path_iface_is_live(dest_hash, &candidates, true)"),
            "AppLinks must still validate the post-race iface against live candidates"
        );
    }

    #[test]
    fn path_races_install_transport_log_watch() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        assert!(
            production.contains("let _watch = PathRaceLogWatch::new(dest_hash);")
                && production.contains("announce_log::watch_destination(dest_hash);")
                && production.contains("announce_log::unwatch_destination(&self.dest_hash);") ,
            "path races must temporarily opt their destination into transport announce/path logging"
        );
    }

    #[test]
    fn path_races_do_not_short_circuit_on_cached_paths() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");

        let race_start = production
            .find("pub fn race_path(")
            .expect("race_path must exist");
        let verified_start = production[race_start..]
            .find("pub fn race_path_verified_this_session(")
            .map(|idx| race_start + idx)
            .expect("race_path_verified_this_session must exist");
        let race_fragment = &production[race_start..verified_start];

        let verified_end = production[verified_start..]
            .find("}\n}\n\nimpl AppLinks")
            .map(|idx| verified_start + idx)
            .expect("verified race fragment must terminate before impl AppLinks");
        let verified_fragment = &production[verified_start..verified_end];

        let race_request = race_fragment
            .find("Transport::request_path(dest_hash, None, Some(iface.clone()), None, None);")
            .expect("race_path must issue request_path");
        let race_wait = race_fragment
            .find("if Transport::wait_for_path(dest_hash, budget) {")
            .expect("race_path must wait for a fresh path event");
        let race_check = race_fragment
            .find("if let Some(iface) = cached_path_iface_is_live(dest_hash, &candidates, false) {")
            .expect("race_path must validate the resulting path");

        let verified_request = verified_fragment
            .find("Transport::request_path(dest_hash, None, Some(iface.clone()), None, None);")
            .expect("verified race must issue request_path");
        let verified_wait = verified_fragment
            .find("if Transport::wait_for_path_verified_this_session(dest_hash, budget) {")
            .expect("verified race must wait for a fresh verified path event");
        let verified_check = verified_fragment
            .find("if let Some(iface) = cached_path_iface_is_live(dest_hash, &candidates, true) {")
            .expect("verified race must validate the resulting verified path");

        assert!(
            race_request < race_wait
                && race_wait < race_check
                && verified_request < verified_wait
                && verified_wait < verified_check,
            "path races must not immediately accept cached paths before issuing a fresh path request"
        );
    }

    // §O6 — the Resource's own progress reaches the caller, raw, through
    // the stack's request path, and stops at delivery.
    #[test]
    fn a_resource_reports_its_progress_to_the_caller_until_delivery() {
        let seen: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = seen.clone();
        let watch = TransferWatch::new(Some(Arc::new(move |fraction| {
            seen_cb.lock().unwrap().push(fraction);
        })));
        let delivered = Arc::new(AtomicBool::new(false));
        let mut resource = sending_resource(4, watch.resource_progress(delivered.clone()));

        serve_request(&mut resource, 1);
        serve_request(&mut resource, 2);
        serve_request(&mut resource, 3);
        assert_eq!(*seen.lock().unwrap(), vec![0.25, 0.5, 0.75], "the raw Resource fraction, per request served");

        delivered.store(true, Ordering::Release);
        serve_request(&mut resource, 4);
        assert_eq!(seen.lock().unwrap().len(), 3, "nothing is reported after delivery");
    }

    // §O6 — the advertisement reaches the caller as 0.0 (LXMF's §1 watch on
    // the transfer starts there: DESIGN_PRINCIPLES §1, bulk transfers), until
    // delivery, and is not activity: nothing of the message has been sent.
    #[test]
    fn the_advertisement_reaches_the_caller_and_is_not_activity() {
        let seen: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = seen.clone();
        let watch = TransferWatch::new(Some(Arc::new(move |fraction| {
            seen_cb.lock().unwrap().push(fraction);
        })));
        let delivered = Arc::new(AtomicBool::new(false));
        let before = watch.activity.quiet_deadline(Duration::ZERO);

        std::thread::sleep(Duration::from_millis(5));
        (watch.advertised(delivered.clone()))();
        assert_eq!(*seen.lock().unwrap(), vec![0.0], "the advertisement, as the Resource's fraction then");
        assert_eq!(watch.activity.quiet_deadline(Duration::ZERO), before, "the advertisement is not activity");

        delivered.store(true, Ordering::Release);
        (watch.advertised(delivered))();
        assert_eq!(seen.lock().unwrap().len(), 1, "nothing is reported after delivery");
    }

    // §O6 — a Resource that is never advertised reports no advertisement.
    // A real Resource and its real advertise job, through the production
    // hook: its link is not ACTIVE, so `ensure_link` fails it before the
    // advertisement.
    #[test]
    fn a_resource_never_advertised_reports_no_advertisement() {
        use reticulum_rust::resource::{Resource, ResourceStatus};
        let seen: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = seen.clone();
        let watch = TransferWatch::new(Some(Arc::new(move |fraction| {
            seen_cb.lock().unwrap().push(fraction);
        })));
        let delivered = Arc::new(AtomicBool::new(false));
        let (tx, concluded) = mpsc::channel();
        let tx = Mutex::new(tx);
        let mut resource = sending_resource(4, watch.resource_progress(delivered.clone()));
        resource.callback = Some(Arc::new(move |r: Arc<Mutex<Resource>>| {
            let _ = tx.lock().unwrap().send(r.lock().map(|r| r.status).ok());
        }));
        Resource::advertise_shared_then(Arc::new(Mutex::new(resource)), watch.advertised(delivered));

        assert_eq!(
            concluded.recv_timeout(Duration::from_secs(5)).expect("it concludes"),
            Some(ResourceStatus::Failed),
            "a Resource on a link that is not ACTIVE fails before its advertisement"
        );
        std::thread::sleep(Duration::from_millis(50));
        assert!(seen.lock().unwrap().is_empty(), "no advertisement went out, so none is reported: {:?}", seen);
    }

    // §O6 — only more of the message sent is activity: a request that
    // brings only resends leaves the fraction where it was.
    #[test]
    fn only_more_of_the_transfer_sent_is_activity() {
        let watch = TransferWatch::new(None);
        let delivered = Arc::new(AtomicBool::new(false));
        let report = watch.reporter(delivered.clone());
        let at = |w: &TransferWatch| w.activity.quiet_deadline(Duration::ZERO);

        let start = at(&watch);
        std::thread::sleep(Duration::from_millis(5));
        report(0.5);
        let moved = at(&watch);
        assert!(moved > start, "more of the transfer sent restarts the quiet clock");

        std::thread::sleep(Duration::from_millis(5));
        report(0.5);
        report(0.25);
        assert_eq!(at(&watch), moved, "a resend-only request, or a lower fraction, is not activity");

        delivered.store(true, Ordering::Release);
        std::thread::sleep(Duration::from_millis(5));
        report(0.9);
        assert_eq!(at(&watch), moved, "nothing counts after delivery");
    }

    /// Feed `report` a rising fraction every `every` for `steps` steps.
    fn feed_progress(report: impl Fn(f64), steps: usize, every: Duration) {
        for step in 1..=steps {
            std::thread::sleep(every);
            report(step as f64 / (steps as f64 + 1.0));
        }
    }

    // §O7 — a transfer that keeps moving outlasts both Timer P's delay and
    // the tier-3 backstop several times over: no backup copy, no failure,
    // and delivery ends both.
    #[test]
    fn a_moving_transfer_gets_no_backup_and_is_not_failed_at_the_backstop() {
        let delay = Duration::from_millis(150);
        let backstop = Duration::from_millis(200);
        let watch = TransferWatch::new(None);
        let delivered = Arc::new(AtomicBool::new(false));
        let prop = Arc::new(AtomicBool::new(false));
        let prop_cb = prop.clone();
        let timer = spawn_prop_timer_watching(
            delay,
            delivered.clone(),
            watch.activity.clone(),
            Arc::new(move || prop_cb.store(true, Ordering::Release)),
        );
        let (tx, rx) = mpsc::sync_channel::<bool>(2);
        let wait = spawn_outcome_wait(rx, watch.activity.clone(), backstop);

        let started = Instant::now();
        feed_progress(watch.reporter(delivered.clone()), 60, Duration::from_millis(10));
        assert!(started.elapsed() > backstop * 2, "the transfer ran past both clocks");
        assert!(!prop.load(Ordering::Acquire), "no propagated backup while the transfer moves");

        // The Resource concludes COMPLETE: the delivered gate, then the outcome.
        delivered.store(true, Ordering::Release);
        tx.send(true).unwrap();
        let (outcome, _) = wait.join().unwrap();
        assert_eq!(outcome, OutcomeWait::Delivered, "the backstop must not fail a moving transfer");
        assert!(!timer.join().unwrap(), "Timer P never fires after delivery");
        assert!(!prop.load(Ordering::Acquire));
    }

    // §O7 — a silent transfer: Timer P fires after its delay, and the
    // backstop fails it after a full backstop from the start of the wait.
    #[test]
    fn a_silent_transfer_gets_the_backup_and_fails_at_the_backstop() {
        let delay = Duration::from_millis(60);
        let backstop = Duration::from_millis(120);
        let watch = TransferWatch::new(None);
        let delivered = Arc::new(AtomicBool::new(false));
        let (prop_tx, prop_rx) = mpsc::channel::<Instant>();
        let started = Instant::now();
        let timer = spawn_prop_timer_watching(
            delay,
            delivered.clone(),
            watch.activity.clone(),
            Arc::new(move || { let _ = prop_tx.send(Instant::now()); }),
        );
        let (_tx, rx) = mpsc::sync_channel::<bool>(2);
        let (outcome, ended) = spawn_outcome_wait(rx, watch.activity.clone(), backstop).join().unwrap();

        assert_eq!(outcome, OutcomeWait::Quiet);
        assert!(ended.duration_since(started) >= backstop, "never before a full backstop");
        let fired_at = prop_rx.recv_timeout(Duration::from_secs(2)).expect("Timer P fires");
        assert!(fired_at.duration_since(started) >= delay, "never before its delay");
        assert!(timer.join().unwrap());
    }

    // §O7 — the quiet clocks run from the LAST activity: a transfer that
    // stops moving gets the backup a delay later and fails a backstop later.
    #[test]
    fn a_transfer_that_stops_moving_is_failed_a_backstop_after_its_last_progress() {
        let delay = Duration::from_millis(100);
        let backstop = Duration::from_millis(150);
        let watch = TransferWatch::new(None);
        let delivered = Arc::new(AtomicBool::new(false));
        let (prop_tx, prop_rx) = mpsc::channel::<Instant>();
        let timer = spawn_prop_timer_watching(
            delay,
            delivered.clone(),
            watch.activity.clone(),
            Arc::new(move || { let _ = prop_tx.send(Instant::now()); }),
        );
        let (_tx, rx) = mpsc::sync_channel::<bool>(2);
        let wait = spawn_outcome_wait(rx, watch.activity.clone(), backstop);

        feed_progress(watch.reporter(delivered.clone()), 30, Duration::from_millis(10));
        let last = watch.activity.quiet_deadline(Duration::ZERO);

        let (outcome, ended) = wait.join().unwrap();
        assert_eq!(outcome, OutcomeWait::Quiet, "stuck after it stopped moving");
        assert!(ended.duration_since(last) >= backstop, "a full backstop after the last progress");
        let fired_at = prop_rx.recv_timeout(Duration::from_secs(2)).expect("Timer P fires once it stops moving");
        assert!(fired_at.duration_since(last) >= delay, "a full delay after the last progress");
        assert!(timer.join().unwrap());
    }

    // The stack's own outcome ends the wait at once, whatever the clocks say.
    #[test]
    fn the_stacks_outcome_ends_the_outcome_wait_at_once() {
        let backstop = Duration::from_secs(60);
        let (tx, rx) = mpsc::sync_channel::<bool>(2);
        tx.send(false).unwrap();
        assert_eq!(AppLinks::await_outcome(&rx, &TransferActivity::new(), backstop), OutcomeWait::Failed);
        tx.send(true).unwrap();
        assert_eq!(AppLinks::await_outcome(&rx, &TransferActivity::new(), backstop), OutcomeWait::Delivered);
        drop(tx);
        let started = Instant::now();
        assert_eq!(AppLinks::await_outcome(&rx, &TransferActivity::new(), backstop), OutcomeWait::Dropped);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    // The production send path is wired to all of the above: every Resource
    // it builds carries the progress callback, every tier shares one watch,
    // and Timer P and the tier-3 wait read its activity clock.
    #[test]
    fn the_send_path_reports_progress_and_counts_only_quiet_time() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        let between = |from: &str, to: &str| -> String {
            let start = production.find(from).unwrap_or_else(|| panic!("{} must exist", from));
            let tail = &production[start..];
            let end = tail.find(to).unwrap_or_else(|| panic!("{} must follow {}", to, from));
            tail[..end].to_string()
        };

        let resource = between("fn fire_resource_on_link(", "\n    }\n}");
        assert!(resource.contains("let progress = watch.resource_progress(delivered.clone());"));
        // DESIGN_PRINCIPLES §1, bulk transfers: the caller hears the
        // advertisement once it has gone out, from the advertise thread.
        assert!(resource.contains("let advertised = watch.advertised(delivered.clone());"));
        assert!(
            resource.contains("Resource::advertise_shared_then(Arc::new(Mutex::new(resource)), advertised);")
                && !resource.contains("Resource::advertise_shared("),
            "the delivery Resource is advertised through the hook that reports its advertisement"
        );
        assert!(
            resource.contains("Some(concluded),\n            Some(progress),"),
            "the delivery Resource's progress_callback (after `callback`) must be the watch's, not None"
        );

        let chain = between("fn run_tier_chain(", "fn run_prop_timer(");
        assert!(chain.contains("let watch = TransferWatch::new(on_progress);"));
        assert!(chain.contains("Self::run_prop_timer(prop_delay, &delivered_p, &activity_p, ||"));
        assert!(chain.contains("let activity_p = watch.activity.clone();"));
        assert_eq!(chain.matches("&watch,\n").count(), 3, "tiers 1, 2 and 3 share the watch");
        assert!(!chain.contains("spawn_after("), "Timer P is not a fixed-delay one-shot");

        // Every fired tier's outcome wait (tier 3's included) counts quiet
        // time only, with production's OUTCOME_BACKSTOP.
        let tier3 = between("fn run_tier3(", "fn await_outcome(");
        assert!(!tier3.contains("recv_timeout(OUTCOME_BACKSTOP)"), "the backstop counts quiet time only");
        let wait = between("fn await_tier(", "fn await_outcome(");
        assert!(wait.contains("Self::await_outcome(rx, &watch.activity, backstop)"));
        assert!(chain.contains("backstop: OUTCOME_BACKSTOP,"));
        assert_eq!(
            chain.matches("Self::await_tier(outcome, ").count(),
            4,
            "tiers 1 and 2 (as Resources), tier 3, and the packet tiers still unheard are all heard under it"
        );

        let held = between("pub fn send_on_held_link(", "pub fn status(");
        assert!(held.contains("let watch = TransferWatch::new(on_progress);"));
        assert!(held.contains("Some(on_failed), &watch)"));

        let send = between("pub fn send_with_compression(", "pub fn send_with_spec(");
        assert!(send.contains("on_progress,\n                );"), "the caller's callback reaches the tier chain");
    }

    // ── §O8/§O9: the production tier chain, over fake links ─────────────

    /// What one fake tier does when the chain fires it: put its message in
    /// flight and report through `report` later (true), or put nothing in
    /// flight (false: tier 3's path race or link failed).
    type FakeFire = Box<dyn Fn(TierReport, &TransferWatch) -> bool + Send + Sync>;

    /// The chain's links, faked. A tier that is `None` has no link. Records
    /// when the chain asked each tier to fire.
    struct FakeTiers {
        started: Instant,
        tiers: [Option<FakeFire>; 3],
        asked: Mutex<Vec<(Tier, Duration)>>,
    }

    impl FakeTiers {
        fn new(tier1: Option<FakeFire>, tier2: Option<FakeFire>, tier3: Option<FakeFire>) -> Self {
            Self { started: Instant::now(), tiers: [tier1, tier2, tier3], asked: Mutex::new(Vec::new()) }
        }

        fn asked(&self) -> Vec<Tier> {
            self.asked.lock().unwrap().iter().map(|(tier, _)| *tier).collect()
        }

        fn asked_at(&self, tier: Tier) -> Option<Duration> {
            self.asked.lock().unwrap().iter().find(|(t, _)| *t == tier).map(|(_, at)| *at)
        }
    }

    impl TierLinks for FakeTiers {
        fn fire(&self, tier: Tier, report: TierReport, watch: &TransferWatch) -> bool {
            self.asked.lock().unwrap().push((tier, self.started.elapsed()));
            match &self.tiers[tier.index()] {
                Some(fire) => fire(report, watch),
                None => false,
            }
        }
    }

    /// What the caller of one send heard, and when (from `FakeTiers::started`).
    #[derive(Default, Debug)]
    struct Heard {
        delivered: Vec<Duration>,
        failed: Vec<Duration>,
        propagation: Vec<Duration>,
    }

    /// Test clocks: a 50 ms packet stagger, Timer P out of the way, and a
    /// backstop no test reaches: the tiers' own events decide everything.
    fn test_pacing() -> ChainPacing {
        ChainPacing {
            stagger: Duration::from_millis(50),
            prop_delay: Duration::from_secs(30),
            backstop: Duration::from_secs(10),
        }
    }

    /// Run the production tier chain over `links` on this thread, as the send
    /// thread does, and return what the caller heard. Keeps listening for
    /// `linger` after the chain returns, for anything a tier reports late.
    fn drive(
        links: &FakeTiers,
        representation: LinkRepresentation,
        pacing: ChainPacing,
        linger: Duration,
    ) -> Heard {
        let heard = Arc::new(Mutex::new(Heard::default()));
        let started = links.started;
        let (delivered, failed, propagation) = (heard.clone(), heard.clone(), heard.clone());
        let outcome = SendOutcome::new(
            b"fake-peer",
            Arc::new(move || delivered.lock().unwrap().delivered.push(started.elapsed())),
            Arc::new(move || failed.lock().unwrap().failed.push(started.elapsed())),
        );
        AppLinks::drive_tier_chain(
            links,
            representation,
            pacing,
            &outcome,
            Arc::new(move || propagation.lock().unwrap().propagation.push(started.elapsed())),
            None,
        );
        std::thread::sleep(linger);
        let heard = std::mem::take(&mut *heard.lock().unwrap());
        heard
    }

    /// A tier whose Resource goes out and then, on its own thread, reports
    /// `steps` rising fractions `every` apart through the production
    /// reporter (as the stack's `request` does), and concludes: delivered, or
    /// its own failure event.
    fn moving(steps: usize, every: Duration, delivers: bool) -> Option<FakeFire> {
        Some(Box::new(move |report: TierReport, watch: &TransferWatch| {
            let progress = watch.reporter(report.gate.clone());
            std::thread::spawn(move || {
                feed_progress(progress, steps, every);
                if delivers { (report.delivered)() } else { (report.failed)() }
            });
            true
        }))
    }

    /// A tier whose message goes out and concludes `after`, with no progress
    /// on the way: a link packet's receipt, or a Resource nobody requests.
    fn silent(after: Duration, delivers: bool) -> Option<FakeFire> {
        Some(Box::new(move |report: TierReport, _: &TransferWatch| {
            std::thread::spawn(move || {
                std::thread::sleep(after);
                if delivers { (report.delivered)() } else { (report.failed)() }
            });
            true
        }))
    }

    /// Tier 3 whose path race or link establishment fails: nothing goes out.
    fn setup_fails() -> Option<FakeFire> {
        Some(Box::new(|_: TierReport, _: &TransferWatch| false))
    }

    fn unix_now() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }

    // §O8 (1) — a Resource moving on tier 1 is left to finish. However long
    // it runs against the stagger, tiers 2 and 3 are never fired (both have
    // links and would deliver at once), and delivery is heard once. Until
    // 2026-09-29 tier 2 fired its own full copy one stagger in.
    #[test]
    fn a_moving_resource_on_tier_1_gets_no_second_or_third_copy() {
        let links = FakeTiers::new(
            moving(30, Duration::from_millis(10), true),
            silent(Duration::ZERO, true),
            silent(Duration::ZERO, true),
        );
        let heard = drive(&links, LinkRepresentation::Resource, test_pacing(), Duration::from_millis(100));
        assert_eq!(links.asked(), vec![Tier::Inbound], "a moving Resource must not get a second copy: {:?}", heard);
        assert_eq!(heard.delivered.len(), 1, "delivered once: {:?}", heard);
        assert!(heard.delivered[0] >= Duration::from_millis(300), "by tier 1, when its Resource completed: {:?}", heard);
        assert!(heard.failed.is_empty(), "{:?}", heard);
    }

    // §O8 (2) — tier 1's Resource fails: tier 2 fires then, on that failure
    // event, and not when the stagger passes.
    #[test]
    fn a_failed_resource_hands_over_at_its_failure_not_at_the_stagger() {
        let pacing = test_pacing();
        let fails_at = Duration::from_millis(250);
        let links = FakeTiers::new(
            silent(fails_at, false),
            moving(5, Duration::from_millis(10), true),
            silent(Duration::ZERO, true),
        );
        let heard = drive(&links, LinkRepresentation::Resource, pacing, Duration::from_millis(100));
        let tier2 = links.asked_at(Tier::Cached).expect("tier 2 fires once tier 1's Resource has failed");
        assert!(
            tier2 >= fails_at,
            "tier 2 fired at {:?}, before tier 1's Resource failed at {:?} (the stagger is {:?})",
            tier2, fails_at, pacing.stagger
        );
        assert!(
            tier2 < fails_at * 2,
            "tier 2 fired at {:?}: at tier 1's failure event, not on the backstop ({:?})",
            tier2, pacing.backstop
        );
        assert_eq!(links.asked(), vec![Tier::Inbound, Tier::Cached], "tier 2 delivered: no tier 3");
        assert_eq!(heard.delivered.len(), 1, "{:?}", heard);
        assert!(heard.failed.is_empty(), "tier 1's failure alone does not fail the send: {:?}", heard);
    }

    // §O9 (3) — every tier that fired fails, one after another: on_failed
    // once, only after the last of them. A second failure after that is
    // ignored. A delivery after it is not: it reaches on_delivered, once,
    // after on_failed.
    #[test]
    fn on_failed_fires_once_after_the_last_fired_tier_fails() {
        let step = Duration::from_millis(80);
        let then_late: Option<FakeFire> = Some(Box::new(move |report: TierReport, _: &TransferWatch| {
            std::thread::spawn(move || {
                std::thread::sleep(step);
                (report.failed)();
                std::thread::sleep(Duration::from_millis(30));
                (report.failed)();
                (report.delivered)();
            });
            true
        }));
        let links = FakeTiers::new(silent(step, false), silent(step, false), then_late);
        let heard = drive(&links, LinkRepresentation::Resource, test_pacing(), Duration::from_millis(150));
        assert_eq!(links.asked(), vec![Tier::Inbound, Tier::Cached, Tier::NewLink]);
        assert!(links.asked_at(Tier::NewLink).unwrap() >= step * 2, "each tier fired on the failure of the one before");
        assert_eq!(heard.failed.len(), 1, "on_failed exactly once: {:?}", heard);
        assert!(heard.failed[0] >= step * 3, "only after tier 3, the last, failed: {:?}", heard);
        assert_eq!(heard.delivered.len(), 1, "a delivery after the send failed is reported, once: {:?}", heard);
        assert!(heard.delivered[0] > heard.failed[0], "{:?}", heard);
    }

    // §O9 (3) — a late proof (Reticulum-rust PARITY-AUDIT B35): tier 3's
    // packet receipt times out, which fails the send, and then the peer's
    // proof arrives. The caller hears on_failed and then on_delivered, each
    // once. Earlier on 2026-09-29 the delivery was swallowed and the message
    // stayed FAILED although the peer had proved it.
    #[test]
    fn a_proof_after_the_send_failed_still_reaches_on_delivered() {
        let times_out = Duration::from_millis(20);
        let proved = Duration::from_millis(60);
        let late_proof: Option<FakeFire> = Some(Box::new(move |report: TierReport, _: &TransferWatch| {
            std::thread::spawn(move || {
                std::thread::sleep(times_out);
                (report.failed)();
                std::thread::sleep(proved - times_out);
                (report.delivered)();
                (report.delivered)();
            });
            true
        }));
        let links = FakeTiers::new(None, None, late_proof);
        let heard = drive(&links, LinkRepresentation::Packet, test_pacing(), Duration::from_millis(150));
        assert_eq!(heard.failed.len(), 1, "{:?}", heard);
        assert!(heard.failed[0] >= times_out && heard.failed[0] < proved, "at the receipt's timeout: {:?}", heard);
        assert_eq!(heard.delivered.len(), 1, "the late proof is reported, once: {:?}", heard);
        assert!(heard.delivered[0] >= proved, "{:?}", heard);
    }

    // §O9 (3), packets — the tiers' packets are in flight together, so the
    // last to fail may be an early tier: on_failed waits for it. Until
    // 2026-09-29 tier 3's setup failure alone failed the send.
    #[test]
    fn a_packet_send_fails_only_after_its_last_outstanding_tier_fails() {
        let tier1_times_out = Duration::from_millis(400);
        let links = FakeTiers::new(
            silent(tier1_times_out, false),
            silent(Duration::from_millis(60), false),
            setup_fails(),
        );
        let heard = drive(&links, LinkRepresentation::Packet, test_pacing(), Duration::from_millis(100));
        assert_eq!(links.asked(), vec![Tier::Inbound, Tier::Cached, Tier::NewLink]);
        assert!(links.asked_at(Tier::NewLink).unwrap() < tier1_times_out);
        assert_eq!(heard.failed.len(), 1, "{:?}", heard);
        assert!(heard.failed[0] >= tier1_times_out, "not before tier 1's receipt timed out: {:?}", heard);
        assert!(heard.delivered.is_empty(), "{:?}", heard);
    }

    // §O9 (4) — tier 3 cannot set up (its path race or link fails) while
    // tier 1's Resource is moving: tier 3 is not even tried while it moves,
    // the send is not failed, and tier 1 delivers. Until 2026-09-29 tier 3
    // ran beside the moving Resource and its setup failure FAILED the
    // message.
    #[test]
    fn a_tier_3_setup_failure_cannot_fail_a_moving_tier_1_resource() {
        let links = FakeTiers::new(moving(30, Duration::from_millis(10), true), None, setup_fails());
        let heard = drive(&links, LinkRepresentation::Resource, test_pacing(), Duration::from_millis(100));
        assert_eq!(links.asked(), vec![Tier::Inbound], "{:?}", heard);
        assert!(heard.failed.is_empty(), "{:?}", heard);
        assert_eq!(heard.delivered.len(), 1, "{:?}", heard);
    }

    // §O9 (4), packets — tier 3 does run beside a packet still in flight on
    // tier 1; its setup failure leaves the send to tier 1's own outcome.
    #[test]
    fn a_tier_3_setup_failure_leaves_an_outstanding_tier_1_packet_to_deliver() {
        let delivers_at = Duration::from_millis(250);
        let links = FakeTiers::new(silent(delivers_at, true), None, setup_fails());
        let heard = drive(&links, LinkRepresentation::Packet, test_pacing(), Duration::from_millis(100));
        assert_eq!(links.asked(), vec![Tier::Inbound, Tier::Cached, Tier::NewLink]);
        assert!(
            links.asked_at(Tier::NewLink).unwrap() < delivers_at,
            "tier 3's setup failed while tier 1's packet was in flight"
        );
        assert!(heard.failed.is_empty(), "{:?}", heard);
        assert_eq!(heard.delivered.len(), 1, "{:?}", heard);
        assert!(heard.delivered[0] >= delivers_at, "{:?}", heard);
    }

    // §O8 (5) — the receiver never starts the transfer: nobody answers tier
    // 1's advertisement. The Resource's own watchdog fails it when its last
    // advertisement goes unanswered (RNS/Resource.py: ADVERTISED past
    // adv_sent + timeout + PROCESSING_GRACE with no retries left → cancel →
    // FAILED → callback), and that is when tier 2 fires. The real watchdog
    // runs here, with the production conclusion callback; the Resource starts
    // on its last advertisement (retries_left 0) so the test takes one
    // PROCESSING_GRACE rather than MAX_ADV_RETRIES + 1 of them.
    #[test]
    fn an_advertisement_nobody_answers_hands_over_on_the_resources_own_failure() {
        use reticulum_rust::resource::{Resource, ResourceStatus};
        let built: Arc<Mutex<Option<Arc<Mutex<Resource>>>>> = Arc::new(Mutex::new(None));
        let built_by_tier1 = built.clone();
        let advertised: Option<FakeFire> = Some(Box::new(move |report: TierReport, watch: &TransferWatch| {
            let mut resource = sending_resource(8, watch.resource_progress(report.gate.clone()));
            resource.callback = Some(AppLinks::resource_concluded(
                report.gate.clone(),
                report.delivered.clone(),
                Some(report.failed.clone()),
            ));
            resource.status = ResourceStatus::Advertised;
            resource.adv_sent = unix_now();
            resource.retries_left = 0;
            let resource = Arc::new(Mutex::new(resource));
            *built_by_tier1.lock().unwrap() = Some(resource.clone());
            Resource::start_watchdog(resource);
            true
        }));
        let links = FakeTiers::new(advertised, silent(Duration::ZERO, true), None);
        let heard = drive(&links, LinkRepresentation::Resource, test_pacing(), Duration::from_millis(50));

        let grace = Duration::from_secs_f64(Resource::PROCESSING_GRACE);
        let tier2 = links.asked_at(Tier::Cached).expect("tier 2 fires on tier 1's advertisement failure");
        assert!(
            tier2 + Duration::from_millis(20) >= grace,
            "tier 2 fired at {:?}, before tier 1's advertisement could go unanswered ({:?})",
            tier2, grace
        );
        assert!(
            tier2 < grace * 2,
            "tier 2 fired at {:?}: on the Resource's own failure, not on the chain's backstop ({:?})",
            tier2, test_pacing().backstop
        );
        let resource = built.lock().unwrap().clone().expect("tier 1 built its Resource");
        let resource = resource.lock().unwrap();
        assert_eq!(resource.status, ResourceStatus::Failed, "failed by its own watchdog");
        assert_ne!(
            resource.link.status(),
            reticulum_rust::link::STATE_CLOSED,
            "the advertisement failed, not the link: it is still open"
        );
        assert_eq!(heard.delivered.len(), 1, "tier 2 delivered: {:?}", heard);
        assert!(heard.failed.is_empty(), "{:?}", heard);
    }

    // §O8 (5b) — tier 1's Resource is QUEUED behind another transfer on its
    // link. RNS 1.5.2 Resource.py waits there with no clock, however long the
    // transfer ahead takes, and so does the chain. Several backstops pass with
    // no outcome and no activity, and tier 2, which would deliver at once, is
    // not fired. Tier 2 fires when tier 1's Resource fails by its own path.
    // Here its link closes, the Resource finds the link is not active
    // (`ensure_link`), and it concludes FAILED. The test uses a real Resource
    // and its real advertise job, on a real link. The transfer ahead is a
    // second Resource registered on that link. Earlier on 2026-09-29 the
    // backstop handed tier 1 over while it was queued, so a photo sent behind
    // another photo went out twice.
    #[test]
    fn a_resource_queued_behind_another_on_its_link_is_not_handed_over_at_the_backstop() {
        use reticulum_rust::resource::{Resource, ResourceStatus};
        let pacing = ChainPacing { backstop: Duration::from_millis(100), ..test_pacing() };
        let queued_for = pacing.backstop * 6;
        let status_at_close: Arc<Mutex<Option<ResourceStatus>>> = Arc::new(Mutex::new(None));
        let seen = status_at_close.clone();
        let queued: Option<FakeFire> = Some(Box::new(move |report: TierReport, watch: &TransferWatch| {
            let mut resource = sending_resource(8, watch.resource_progress(report.gate.clone()));
            resource.callback = Some(AppLinks::resource_concluded(
                report.gate.clone(),
                report.delivered.clone(),
                Some(report.failed.clone()),
            ));
            let link = resource.link.clone();
            let ahead = sending_resource(8, Arc::new(|_: Arc<Mutex<Resource>>| {}));
            link.register_outgoing_resource(Arc::new(Mutex::new(ahead)));
            let resource = Arc::new(Mutex::new(resource));
            Resource::advertise_shared(resource.clone());
            let seen = seen.clone();
            std::thread::spawn(move || {
                std::thread::sleep(queued_for);
                *seen.lock().unwrap() = resource.lock().ok().map(|r| r.status);
                link.teardown();
            });
            true
        }));
        let links = FakeTiers::new(queued, silent(Duration::ZERO, true), silent(Duration::ZERO, true));
        let heard = drive(&links, LinkRepresentation::Resource, pacing, Duration::from_millis(50));

        assert_eq!(
            *status_at_close.lock().unwrap(),
            Some(ResourceStatus::Queued),
            "tier 1's Resource was still queued behind the transfer ahead when its link closed"
        );
        let tier2 = links.asked_at(Tier::Cached).expect("tier 2 fires once tier 1's Resource has failed");
        assert!(
            tier2 >= queued_for,
            "tier 2 fired at {:?}, while tier 1's Resource was queued (backstop {:?})",
            tier2, pacing.backstop
        );
        assert_eq!(links.asked(), vec![Tier::Inbound, Tier::Cached], "tier 2 delivered: no tier 3");
        assert_eq!(heard.delivered.len(), 1, "{:?}", heard);
        assert!(heard.failed.is_empty(), "{:?}", heard);
    }

    // §O8 (5c) — tier 1's Resource moves, stalls for several backstops, and
    // resumes to deliver. It is still inside its own give-up time (RNS 1.5.2
    // Resource.py, transferring: RTT × 4 × 16 + 78 s, past 120 s once the RTT
    // is over 0.66 s). The backstop neither hands it over nor fails it. Tier
    // 3, whose path race would fail, is never tried, and the send is
    // delivered. Earlier on 2026-09-29 the backstop failed tier 1 here. Tier
    // 3's setup failure then failed the send while tier 1 could still
    // deliver, and tier 1's delivery was ignored.
    #[test]
    fn a_resource_stalled_past_the_backstop_is_neither_handed_over_nor_failed() {
        let pacing = ChainPacing { backstop: Duration::from_millis(100), ..test_pacing() };
        let stalls_for = pacing.backstop * 4;
        let stalls: Option<FakeFire> = Some(Box::new(move |report: TierReport, watch: &TransferWatch| {
            let progress = watch.reporter(report.gate.clone());
            std::thread::spawn(move || {
                progress(0.25);
                std::thread::sleep(stalls_for);
                progress(0.5);
                progress(0.75);
                (report.delivered)();
            });
            true
        }));
        let links = FakeTiers::new(stalls, None, setup_fails());
        let heard = drive(&links, LinkRepresentation::Resource, pacing, Duration::from_millis(50));
        assert_eq!(links.asked(), vec![Tier::Inbound], "{:?}", heard);
        assert!(heard.failed.is_empty(), "{:?}", heard);
        assert_eq!(heard.delivered.len(), 1, "{:?}", heard);
        assert!(heard.delivered[0] >= stalls_for, "{:?}", heard);
    }

    // §O9 (3) — the only tier that fired carries a Resource that goes quiet
    // past the backstop and then fails by its own event: on_failed comes at
    // that failure, not at the backstop. A packet tier whose receipt callback
    // never comes is still failed at the backstop: that is the lost callback
    // it guards.
    #[test]
    fn the_backstop_fails_a_quiet_packet_tier_but_never_a_resource_tier() {
        let pacing = ChainPacing { backstop: Duration::from_millis(100), ..test_pacing() };
        let fails_at = pacing.backstop * 4;
        let links = FakeTiers::new(None, None, silent(fails_at, false));
        let heard = drive(&links, LinkRepresentation::Resource, pacing, Duration::from_millis(50));
        assert_eq!(heard.failed.len(), 1, "{:?}", heard);
        assert!(
            heard.failed[0] >= fails_at,
            "at the Resource's own failure, not at the backstop ({:?}): {:?}",
            pacing.backstop, heard
        );
        assert!(heard.delivered.is_empty(), "{:?}", heard);

        let never: Option<FakeFire> = Some(Box::new(move |report: TierReport, _: &TransferWatch| {
            std::thread::spawn(move || {
                std::thread::sleep(fails_at);
                drop(report);
            });
            true
        }));
        let links = FakeTiers::new(None, None, never);
        let heard = drive(&links, LinkRepresentation::Packet, pacing, Duration::from_millis(50));
        assert_eq!(heard.failed.len(), 1, "{:?}", heard);
        assert!(
            heard.failed[0] >= pacing.backstop && heard.failed[0] < fails_at,
            "a packet tier with no outcome fails at the backstop: {:?}",
            heard
        );
    }

    // §O8 (6) — a message that fits one link packet keeps the stagger as it
    // was: tier 2 fires one stagger after tier 1 even though tier 1's receipt
    // has already timed out, tier 3 one stagger later, and the earlier
    // packets stay in flight (tier 2's proof, after tier 3's, is ignored).
    #[test]
    fn packet_payloads_keep_the_stagger() {
        let pacing = ChainPacing { stagger: Duration::from_millis(100), ..test_pacing() };
        let links = FakeTiers::new(
            silent(Duration::from_millis(10), false),
            silent(Duration::from_millis(300), true),
            silent(Duration::from_millis(20), true),
        );
        let heard = drive(&links, LinkRepresentation::Packet, pacing, Duration::from_millis(250));
        let tier2 = links.asked_at(Tier::Cached).unwrap();
        let tier3 = links.asked_at(Tier::NewLink).unwrap();
        assert!(
            tier2 >= pacing.stagger && tier2 < pacing.stagger * 2,
            "tier 2 at {:?}: one stagger after tier 1, not at tier 1's failure (10 ms)",
            tier2
        );
        assert!(tier3 >= pacing.stagger * 2 && tier3 < pacing.stagger * 3, "tier 3 at {:?}", tier3);
        assert_eq!(heard.delivered.len(), 1, "{:?}", heard);
        assert!(heard.delivered[0] >= tier3, "by tier 3's proof: {:?}", heard);
        assert!(heard.failed.is_empty(), "{:?}", heard);
    }

    // §O9 (7) — Timer P counts only quiet time across the whole chain: a
    // Resource that moves on tier 1, fails, and moves on tier 2 until it
    // delivers is never quiet for Timer P's delay, however long it all
    // takes, so it gets no propagated copy.
    #[test]
    fn timer_p_sees_one_transfer_across_a_tier_handover() {
        let pacing = ChainPacing { prop_delay: Duration::from_millis(100), ..test_pacing() };
        let links = FakeTiers::new(
            moving(20, Duration::from_millis(10), false),
            moving(20, Duration::from_millis(10), true),
            None,
        );
        let heard = drive(&links, LinkRepresentation::Resource, pacing, pacing.prop_delay * 2);
        assert_eq!(heard.delivered.len(), 1, "{:?}", heard);
        assert!(heard.delivered[0] >= pacing.prop_delay * 4, "the transfer outlasted Timer P's delay: {:?}", heard);
        assert!(
            heard.propagation.is_empty(),
            "the transfer never went {:?} without moving: {:?}",
            pacing.prop_delay, heard
        );
    }

    // §O9 (7) — and the quiet time runs on across a handover: tier 1's
    // Resource stops moving and only fails later. Timer P fires one delay
    // after its last progress, while the chain is still on tier 1.
    #[test]
    fn timer_p_fires_on_quiet_time_across_a_tier_handover() {
        let pacing = ChainPacing { prop_delay: Duration::from_millis(100), ..test_pacing() };
        let stalls: Option<FakeFire> = Some(Box::new(|report: TierReport, watch: &TransferWatch| {
            let progress = watch.reporter(report.gate.clone());
            std::thread::spawn(move || {
                feed_progress(progress, 10, Duration::from_millis(10));
                std::thread::sleep(Duration::from_millis(250));
                (report.failed)();
            });
            true
        }));
        let links = FakeTiers::new(stalls, moving(5, Duration::from_millis(10), true), None);
        let heard = drive(&links, LinkRepresentation::Resource, pacing, Duration::ZERO);
        let tier2 = links.asked_at(Tier::Cached).expect("tier 2 fires once tier 1 fails");
        assert_eq!(heard.propagation.len(), 1, "{:?}", heard);
        assert!(
            heard.propagation[0] >= Duration::from_millis(100) + pacing.prop_delay,
            "a full delay after tier 1's last progress: {:?}",
            heard
        );
        assert!(heard.propagation[0] < tier2, "while the chain was still on tier 1 (tier 2 at {:?}): {:?}", tier2, heard);
        assert_eq!(heard.delivered.len(), 1, "{:?}", heard);
    }
}
