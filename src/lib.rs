//! App-link crate.
//!
//! Owns path-racing (liveness), the destination registry, and the
//! three-tier send hierarchy for DIRECT LXMF delivery.
//!
//! Dependency chain: `lxmf-rust → app-links → reticulum-rust`
//! (no cycles; this crate does NOT depend on lxmf-rust).
//!
//! # Send tiers  (see DESIGN_PRINCIPLES.md §1, §3, §7)
//!
//! `AppLinks::send(dest, packed, on_delivered, on_propagation_needed, on_failed)` drives:
//!
//! Timer P (5 s) starts in parallel the moment `send` is called.  If the
//! message is not delivered by then, `on_propagation_needed` fires once.
//! This is independent of the tier chain.
//!
//!   * **Tier 1** — peer-initiated inbound link (they opened it to us):
//!     fire the packed bytes, wait ≤1 s (Timer A) for delivery proof.
//!     DO NOT tear down the in-flight packet if Timer A expires.
//!   * **Tier 2** — cached outbound link (`STATE_ACTIVE`): fire, wait ≤1 s
//!     (Timer B).  DO NOT tear down tier-1's in-flight packet.
//!   * **Tier 3** — `expire_path` → `race_path` (≤5 s) → `Link::new_outbound`
//!     + `initiate` (≤5 s) → fire packet → wait for delivery proof (≤5 s).
//!     `on_failed` fires only when tier 3 exhausts all protocol timeouts.
//!
//! All tiers share an `AtomicBool` delivered gate — the first delivery proof
//! from any tier wins and the others are silently ignored (idempotent).
//! All tiers are independent: advancing to the next tier NEVER cancels or
//! closes resources belonging to the previous tier.
//!
//! # Open / liveness
//!
//! `AppLinks::open()` races a path (liveness), marks the destination READY
//! and fires `APP_LINK_ACTIVE(None)`.  **No link is built** by open.
//! Links exist only while a tier-3 send is in progress or its resulting
//! link is still cached (in `Registry.links`).
//!
//! Propagation-node destinations (aspect == "propagation") are the sole
//! exception: they still build a persistent outbound Link so the LXMF
//! propagation pull can reuse it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::link::{Link, LinkHandle, MODE_AES256_CBC, STATE_ACTIVE};
use reticulum_rust::packet::{self, Packet};
use reticulum_rust::transport::{AnnounceCallback, AnnounceHandler, Transport, BROADCAST};
use reticulum_rust::{hexrep, log, LOG_NOTICE};

// ─── Public status constants ─────────────────────────────────────────────
pub const APP_LINK_NONE: u8 = 0x00;
pub const APP_LINK_PATH_REQUESTED: u8 = 0x01;
pub const APP_LINK_ESTABLISHING: u8 = 0x02;
pub const APP_LINK_ACTIVE: u8 = 0x03;
pub const APP_LINK_DISCONNECTED: u8 = 0x04;

/// Tier-advance stagger.  After tier-1 fires, tier-2 fires this many
/// seconds later (if tier-1 has not delivered within that window).
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
/// real outbound `Link` is held in the registry (propagation destinations,
/// or tier-3 just returned with an established handle).  For path-race
/// open/status transitions it will be `None`.
pub type AppLinkStatusCallback = Arc<dyn Fn(&[u8], u8, Option<LinkHandle>) + Send + Sync>;

/// Internal marker.  Kept as a type so call sites that pass a `mode`
/// argument continue to compile.  The only variant that builds a persistent
/// Link is the propagation-node path (aspect == "propagation"); all other
/// destinations use path-race-only semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum LinkMode {
    #[default]
    PersistentLink,
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
}

impl AppLinkSpec {
    pub fn new(app_name: impl Into<String>, aspects: Vec<String>) -> Self {
        Self {
            app_name: app_name.into(),
            aspects,
            mode: LinkMode::PersistentLink,
            attempt_in_flight: Arc::new(AtomicBool::new(false)),
            ever_established: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Retained for call-site compatibility; mode is always `PersistentLink`.
    pub fn with_mode(
        app_name: impl Into<String>,
        aspects: Vec<String>,
        _mode: LinkMode,
    ) -> Self {
        Self::new(app_name, aspects)
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
    // ─── Host integration ─────────────────────────────────────────────

    /// Subscribe to status changes.  Multiple callbacks are supported.
    /// Callbacks are invoked synchronously from whichever thread the
    /// underlying link/race callback runs on.  Implementers MUST NOT block.
    pub fn register_status_callback(callback: AppLinkStatusCallback) {
        let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
        reg.status_callbacks.push(callback);
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

    // ─── Public lifecycle ─────────────────────────────────────────────

    /// Register `dest_hash` for liveness tracking.  Races a path, marks
    /// READY, and fires `APP_LINK_ACTIVE(None)` once a path is found.
    ///
    /// No outbound `Link` is built by this call.  Links exist only during
    /// a tier-3 send (and are cached in the registry for tier-2 reuse).
    ///
    /// Exception: destinations with aspect `"propagation"` still build and
    /// hold a persistent outbound `Link` (needed for LXMF pull requests).
    pub fn open(dest_hash: &[u8], app_name: &str, aspects: &[&str]) {
        Self::open_with_mode(dest_hash, app_name, aspects, LinkMode::PersistentLink);
    }

    /// Alias for [`Self::open`].
    pub fn open_persistent(dest_hash: &[u8], app_name: &str, aspects: &[&str]) {
        Self::open(dest_hash, app_name, aspects);
    }

    /// Open an app link in `mode`.  `mode` is ignored for non-propagation
    /// destinations (call-site compatibility only).
    pub fn open_with_mode(
        dest_hash: &[u8],
        app_name: &str,
        aspects: &[&str],
        mode: LinkMode,
    ) {
        Self::ensure_announce_handler();

        let spec = AppLinkSpec::with_mode(
            app_name,
            aspects.iter().map(|s| (*s).to_string()).collect(),
            mode,
        );

        let als_before = Self::status(dest_hash);

        {
            let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
            reg.specs.insert(dest_hash.to_vec(), spec);
        }

        Transport::watch_announce(dest_hash.to_vec());

        if Self::policy() == LinkPolicy::Suspended {
            return;
        }

        if als_before == APP_LINK_ACTIVE
            || als_before == APP_LINK_ESTABLISHING
            || als_before == APP_LINK_PATH_REQUESTED
        {
            return;
        }

        Self::establish(dest_hash);
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
            (removed, dl, di)
        };
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

    /// Current status for `dest_hash`.
    ///
    ///   * `APP_LINK_NONE`           — not registered.
    ///   * `APP_LINK_PATH_REQUESTED` — path-race in flight.
    ///   * `APP_LINK_ESTABLISHING`   — link handle exists, not yet `STATE_ACTIVE`
    ///                                 (propagation destinations only).
    ///   * `APP_LINK_ACTIVE`         — path known (ready) and still valid,
    ///                                 OR a held link is `STATE_ACTIVE`.
    ///   * `APP_LINK_DISCONNECTED`   — registered, no path, no race.
    pub fn status(dest_hash: &[u8]) -> u8 {
        let (registered, in_flight, link, in_ready) = {
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
            let in_ready = reg.ready.contains_key(dest_hash);
            (registered, in_flight, link, in_ready)
        };
        if !registered {
            return APP_LINK_NONE;
        }
        // Held link (propagation node, or recent tier-3 cached link).
        if let Some(handle) = link {
            if handle.status() == STATE_ACTIVE {
                return APP_LINK_ACTIVE;
            }
            return APP_LINK_ESTABLISHING;
        }
        if in_flight {
            return APP_LINK_PATH_REQUESTED;
        }
        // Path-race-only: ACTIVE when ready entry exists and path is still valid.
        if in_ready && Transport::has_path(dest_hash) {
            return APP_LINK_ACTIVE;
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
            link.set_link_closed_callback(Some(Arc::new(move |_: LinkHandle| {
                if let Ok(mut reg) = REGISTRY.lock() {
                    reg.inbound_links.remove(&dest_owned);
                }
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
        Self::establish(dest_hash);
    }

    /// Trigger one fresh attempt for every app-link not currently active.
    /// Call from the host on a network state change.
    pub fn network_changed() {
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
                "[APP_LINK] network-change trigger → attempting {} link(s)",
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

    // ─── Internals ────────────────────────────────────────────────────

    fn clear_all_ready(notify: bool) {
        let (dropped, dropped_links, dropped_inbound) = {
            let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
            let ready_keys: Vec<Vec<u8>> = reg.ready.keys().cloned().collect();
            let link_keys: Vec<Vec<u8>> = reg.links.keys().cloned().collect();
            reg.ready.clear();
            let dropped_links: Vec<LinkHandle> =
                reg.links.drain().map(|(_, h)| h).collect();
            let dropped_inbound: Vec<LinkHandle> =
                reg.inbound_links.drain().map(|(_, h)| h).collect();
            let mut union: Vec<Vec<u8>> = ready_keys;
            for k in link_keys {
                if !union.contains(&k) {
                    union.push(k);
                }
            }
            (union, dropped_links, dropped_inbound)
        };
        drop(dropped_links);
        drop(dropped_inbound);
        if !notify || dropped.is_empty() {
            return;
        }
        let cbs: Vec<AppLinkStatusCallback> = REGISTRY
            .lock()
            .map(|r| r.status_callbacks.clone())
            .unwrap_or_default();
        for dest in &dropped {
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

    /// Drive a path-race for an already-registered destination.
    ///
    /// The `attempt_in_flight` CAS gate collapses concurrent triggers into a
    /// single in-flight race.  After the race:
    ///
    ///   * **Propagation destinations** (aspect == "propagation"): call
    ///     `start_persistent_link` to build and hold a real outbound `Link`,
    ///     matching the LXMF pull-request pattern.
    ///   * **All other destinations**: mark READY, fire `APP_LINK_ACTIVE(None)`,
    ///     release the gate.  No Link is built.
    fn establish(dest_hash: &[u8]) {
        if Self::policy() == LinkPolicy::Suspended {
            return;
        }
        let spec = match Self::spec(dest_hash) {
            Some(s) => s,
            None => return,
        };
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
        let app_name = spec.app_name.clone();
        let aspects = spec.aspects.clone();

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
                // Here in appLinkOpen we use has_path fast-path: if a valid path
                // already exists (from disk or a recent announce), return it
                // immediately.  If not, fire PATH_REQ on all interfaces and wait for
                // the best response, subject to LIVENESS_BUDGET.  The quality gate in
                // the announce handler then guards against worse inbound paths.
                let is_propagation = aspects.contains(&"propagation".to_string());
                let result = if is_propagation {
                    // Propagation-node LRREQ depends on the relay having proven
                    // bidirectional readiness in THIS process. A disk-cached
                    // path is useful for chat-open debugging, but it is not a
                    // server-ready signal for a persistent propagation link.
                    // Require a fresh PATH_RESPONSE / announce before building
                    // the Link and sending LRREQ.
                    // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §5.
                    liveness::race_path_verified_this_session(&dest_owned, LIVENESS_BUDGET)
                } else {
                    liveness::race_path(&dest_owned, LIVENESS_BUDGET)
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

                        // Propagation destinations build a persistent Link so
                        // LXMF pull requests can reuse it.  All others just
                        // mark READY and fire ACTIVE(None).
                        if is_propagation {
                            Self::start_persistent_link(
                                dest_owned,
                                app_name,
                                aspects,
                                in_flight,
                                cbs,
                            );
                        } else {
                            in_flight.store(false, Ordering::Release);
                            for cb in &cbs {
                                // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
                                // ACTIVE fires with None: no Link is held for non-propagation
                                // destinations.  The send tier hierarchy in AppLinks::send
                                // builds a Link only when needed (tier-3).
                                cb(&dest_owned, APP_LINK_ACTIVE, None);
                            }
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

    /// Build and hold a persistent outbound `Link` for `dest`.
    ///
    /// Used by propagation-node destinations only.  The `in_flight` gate
    /// stays armed until the link reaches `STATE_ACTIVE` or closes.
    fn start_persistent_link(
        dest: Vec<u8>,
        app_name: String,
        aspects: Vec<String>,
        in_flight: Arc<AtomicBool>,
        cbs: Vec<AppLinkStatusCallback>,
    ) {
        let identity = match Identity::recall(&dest) {
            Some(id) => id,
            None => {
                log(
                    &format!(
                        "[APP_LINK] PersistentLink: no identity for {} → DISCONNECTED",
                        hexrep(&dest, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                in_flight.store(false, Ordering::Release);
                for cb in &cbs {
                    cb(&dest, APP_LINK_DISCONNECTED, None);
                }
                return;
            }
        };

        let destination = match Destination::new_outbound(
            Some(identity),
            DestinationType::Single,
            app_name.clone(),
            aspects.clone(),
        ) {
            Ok(d) => d,
            Err(e) => {
                log(
                    &format!(
                        "[APP_LINK] PersistentLink: new_outbound failed for {}: {}",
                        hexrep(&dest, false),
                        e
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                in_flight.store(false, Ordering::Release);
                for cb in &cbs {
                    cb(&dest, APP_LINK_DISCONNECTED, None);
                }
                return;
            }
        };

        let link = match Link::new_outbound(destination, MODE_AES256_CBC) {
            Ok(l) => l,
            Err(e) => {
                log(
                    &format!(
                        "[APP_LINK] PersistentLink: Link::new_outbound failed for {}: {}",
                        hexrep(&dest, false),
                        e
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                in_flight.store(false, Ordering::Release);
                for cb in &cbs {
                    cb(&dest, APP_LINK_DISCONNECTED, None);
                }
                return;
            }
        };

        let handle = LinkHandle::spawn(link);

        {
            let dest_cb = dest.clone();
            let in_flight_cb = in_flight.clone();
            let cbs_cb = cbs.clone();
            handle.set_link_established_callback(Some(Arc::new(move |h: LinkHandle| {
                log(
                    &format!(
                        "[APP_LINK] PersistentLink ACTIVE for {}",
                        hexrep(&dest_cb, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                in_flight_cb.store(false, Ordering::Release);
                for cb in &cbs_cb {
                    cb(&dest_cb, APP_LINK_ACTIVE, Some(h.clone()));
                }
            })));
        }

        {
            let dest_cb = dest.clone();
            let in_flight_cb = in_flight.clone();
            let cbs_cb = cbs.clone();
            handle.set_link_closed_callback(Some(Arc::new(move |_: LinkHandle| {
                let dropped = {
                    let mut reg =
                        REGISTRY.lock().expect("app_links registry mutex poisoned");
                    reg.ready.remove(&dest_cb);
                    reg.links.remove(&dest_cb)
                };
                drop(dropped);
                in_flight_cb.store(false, Ordering::Release);
                log(
                    &format!(
                        "[APP_LINK] PersistentLink CLOSED for {}",
                        hexrep(&dest_cb, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                for cb in &cbs_cb {
                    cb(&dest_cb, APP_LINK_DISCONNECTED, None);
                }
                // Do NOT re-establish here. Link closure is the deterministic
                // failure event for this persistent-link cycle; immediately
                // spawning another `establish` is an application-level retry.
                // A later fresh announce / PATH_RESPONSE may trigger a new
                // cycle via `announce_received`, but this callback must only
                // surface DISCONNECTED.
                // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §3.
            })));
        }

        {
            let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
            reg.links.insert(dest.clone(), handle.clone());
        }

        for cb in &cbs {
            cb(&dest, APP_LINK_ESTABLISHING, Some(handle.clone()));
        }

        let dest_thread = dest.clone();
        std::thread::Builder::new()
            .name("app_links_link_initiate".into())
            .spawn(move || {
                // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
                // Refresh the tunnel binding on every TCP backbone before
                // sending the LRREQ so stale tunnel entries don't silently
                // drop the LINK_PROOF.
                Transport::synthesize_tunnel_all_tcp();
                if let Err(e) = handle.initiate() {
                    log(
                        &format!(
                            "[APP_LINK] PersistentLink initiate failed for {}: {:?}",
                            hexrep(&dest_thread, false),
                            e
                        ),
                        LOG_NOTICE,
                        false,
                        false,
                    );
                }
            })
            .expect("failed to spawn app_links link-initiate thread");
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
    // Each tier fires at t=0, t=1s, t=2s respectively (Timer A/B).  A
    // parallel Timer P fires on_propagation_needed at t=5s if not delivered.
    // All tiers share an AtomicBool gate; advancing never cancels prior tiers.
    //
    // Spawns a background thread; returns immediately (§7).

    /// Send `packed` bytes to `dest` via the best available link.
    ///
    /// Non-blocking.  Spawns a background thread; returns immediately.
    ///
    /// Callbacks (all MUST be idempotent and MUST NOT block):
    ///   `on_delivered`           — first delivery proof from any tier.
    ///   `on_propagation_needed`  — 5 s elapsed without delivery; caller
    ///                              should start a parallel propagation send.
    ///   `on_failed`              — tier 3 exhausted all protocol timeouts
    ///                              without delivery.
    pub fn send(
        dest: &[u8],
        packed: Vec<u8>,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_propagation_needed: Arc<dyn Fn() + Send + Sync + 'static>,
        on_failed: Arc<dyn Fn() + Send + Sync + 'static>,
    ) {
        let dest_owned = dest.to_vec();
        std::thread::Builder::new()
            .name("app_links_send".into())
            .spawn(move || {
                Self::run_tier_chain(
                    &dest_owned,
                    packed,
                    on_delivered,
                    on_propagation_needed,
                    on_failed,
                );
            })
            .expect("failed to spawn app_links send thread");
    }

    /// Drive the tier chain synchronously.  Runs on the background thread
    /// spawned by [`AppLinks::send`].
    fn run_tier_chain(
        dest: &[u8],
        packed: Vec<u8>,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_propagation_needed: Arc<dyn Fn() + Send + Sync + 'static>,
        on_failed: Arc<dyn Fn() + Send + Sync + 'static>,
    ) {
        // Shared delivered gate.  The first delivery proof from any tier wins.
        let delivered = Arc::new(AtomicBool::new(false));

        // ── Timer P: propagation fallback ─────────────────────────────
        //
        // Fires on_propagation_needed after PROP_FALLBACK_DELAY if the message
        // has not been delivered by then.  Runs on a separate thread so it is
        // truly parallel with all tiers.
        //
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        // This is the authoritative source of the 5-second propagation trigger.
        // The caller (lxm_router) handles the actual propagation mechanics.
        {
            let delivered_p = delivered.clone();
            let on_prop = on_propagation_needed;
            std::thread::Builder::new()
                .name("app_links_prop_timer".into())
                .spawn(move || {
                    std::thread::sleep(PROP_FALLBACK_DELAY);
                    if !delivered_p.load(Ordering::Acquire) {
                        on_prop();
                    }
                })
                .expect("failed to spawn propagation fallback timer");
        }

        // ── Tier 1: inbound link ──────────────────────────────────────
        // Timer A (1 s before tier 2) is owned by tier 2, not tier 1.
        // Tier 1 fires and immediately falls through; it does not wait.
        let inbound = Self::get_inbound_handle(dest)
            .filter(|h| h.status() == STATE_ACTIVE);

        let tier1_fired = if let Some(handle) = inbound {
            log(
                &format!("[APP_LINK] send tier-1 (inbound link) for {}", hexrep(dest, false)),
                LOG_NOTICE, false, false,
            );
            Self::fire_on_link(
                &handle,
                &packed,
                delivered.clone(),
                on_delivered.clone(),
            );
            true
        } else {
            false
        };

        // ── Tier 2: cached outbound link ─────────────────────────────
        // Timer A: wait 1 s before firing, but ONLY if tier 1 actually sent a
        // packet that needs time to prove delivery.  If tier 1 had no link,
        // there is nothing to wait for and we proceed immediately.
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        if tier1_fired {
            std::thread::sleep(Duration::from_secs(1));
            if delivered.load(Ordering::Acquire) {
                log(
                    &format!("[APP_LINK] send delivered via tier-1 for {}", hexrep(dest, false)),
                    LOG_NOTICE, false, false,
                );
                return;
            }
        }

        let outbound = REGISTRY
            .lock()
            .ok()
            .and_then(|r| r.links.get(dest).cloned())
            .filter(|h| h.status() == STATE_ACTIVE);

        let tier2_fired = if let Some(handle) = outbound {
            log(
                &format!("[APP_LINK] send tier-2 (cached outbound link) for {}", hexrep(dest, false)),
                LOG_NOTICE, false, false,
            );
            Self::fire_on_link(
                &handle,
                &packed,
                delivered.clone(),
                on_delivered.clone(),
            );
            true
        } else {
            false
        };

        // ── Tier 3: expire + race + new link + send ───────────────────
        // Timer B: wait 1 s before firing, but ONLY if tier 2 actually sent a
        // packet that needs time to prove delivery.  If tier 2 had no link,
        // there is nothing to wait for and we proceed immediately.
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        if tier2_fired {
            std::thread::sleep(Duration::from_secs(1));
            if delivered.load(Ordering::Acquire) {
                log(
                    &format!("[APP_LINK] send delivered via tier-2 for {}", hexrep(dest, false)),
                    LOG_NOTICE, false, false,
                );
                return;
            }
        }

        log(
            &format!("[APP_LINK] send tier-3 (path race + new link) for {}", hexrep(dest, false)),
            LOG_NOTICE, false, false,
        );

        // Expire any stale disk-cached path so the race resolves via the
        // relay that *currently* has a route to the destination.
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        Transport::expire_path(dest);

        let iface = match liveness::race_path(dest, LIVENESS_BUDGET) {
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
                on_failed();
                return;
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
                on_failed();
                return;
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
                on_failed();
                return;
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
                on_failed();
                return;
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
            on_failed();
            return;
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
                on_failed();
                return;
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
                on_failed();
                return;
            }
        };

        // Cache the link for tier-2 reuse on future sends.
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.links.insert(dest.to_vec(), established_handle.clone());
        }
        // Also mark as ready so status() returns ACTIVE.
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.ready.insert(dest.to_vec(), Instant::now());
        }

        // Register a deterministic teardown callback so the registry is
        // cleaned up when this tier-3 link closes.  This is the event-driven
        // replacement for the old poll-based ready-watcher.
        // NEVER REMOVE EVER — without this, reg.links and reg.ready leak
        // until the next send's expire_path clears them.
        {
            let dest_cb = dest.to_vec();
            let cbs: Vec<AppLinkStatusCallback> = REGISTRY
                .lock()
                .map(|r| r.status_callbacks.clone())
                .unwrap_or_default();
            established_handle.set_link_closed_callback(Some(Arc::new(move |_: LinkHandle| {
                {
                    let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
                    reg.ready.remove(&dest_cb);
                    reg.links.remove(&dest_cb);
                }
                AppLinks::invalidate_liveness(&dest_cb);
                log(
                    &format!("[APP_LINK] tier-3 link closed for {} → DISCONNECTED", hexrep(&dest_cb, false)),
                    LOG_NOTICE, false, false,
                );
                for cb in &cbs {
                    cb(&dest_cb, APP_LINK_DISCONNECTED, None);
                }
            })));
        }

        // Fire and wait for LRPROOF.
        // Interruptible proof wait: the delivery callback sends on proof_tx so
        // this thread wakes immediately when the proof arrives rather than
        // sleeping the full LIVENESS_BUDGET.
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        let (proof_tx, proof_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let proof_on_delivered = on_delivered.clone();
        let proof_cb: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || {
            proof_on_delivered();
            let _ = proof_tx.send(());
        });

        let fired = Self::fire_on_link(
            &established_handle,
            &packed,
            delivered.clone(),
            proof_cb,
        );
        if !fired {
            on_failed();
            return;
        }

        // Block until proof arrives or the budget expires.
        // recv_timeout wakes immediately on proof; no wasted sleep.
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        match proof_rx.recv_timeout(LIVENESS_BUDGET) {
            Ok(()) => {
                log(
                    &format!(
                        "[APP_LINK] send delivered via tier-3 for {}",
                        hexrep(dest, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
            }
            Err(_) => {
                log(
                    &format!(
                        "[APP_LINK] send tier-3: delivery proof timed out for {}",
                        hexrep(dest, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                on_failed();
            }
        }
    }

    /// Fire `packed` as a Packet on `link` and install delivery callback.
    ///
    /// Returns `true` when the packet was successfully queued (receipt
    /// obtained).  The `on_delivered` callback fires when LRPROOF arrives.
    /// The delivered `AtomicBool` gates all callbacks — first LRPROOF wins.
    fn fire_on_link(
        link: &LinkHandle,
        packed: &[u8],
        delivered: Arc<AtomicBool>,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> bool {
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
        true
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

/// How long to wait before firing `on_propagation_needed`.
/// Matches §1's 5-second network-action limit.
/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
pub const PROP_FALLBACK_DELAY: Duration = LIVENESS_BUDGET;

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

/// Liveness race module.
pub mod liveness {
    use super::*;
    use reticulum_rust::transport::get_state_snapshot;

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
    /// Does NOT consult the liveness cache — callers check the cache first.
    pub fn race_path(
        dest_hash: &[u8],
        budget: Duration,
    ) -> Result<String, SendErr> {
        let snap = get_state_snapshot();
        let candidates: Vec<String> = snap
            .interfaces
            .iter()
            .filter(|i| {
                i.online && i.bitrate.map_or(true, |b| b >= LORA_BITRATE_THRESHOLD)
            })
            .map(|i| i.name.clone())
            .collect();

        if candidates.is_empty() {
            return Err(SendErr::NoUsableInterface);
        }

        // Fast path: path already exists.
        if Transport::has_path(dest_hash) {
            if let Some(iface) = Transport::next_hop_interface(dest_hash) {
                return Ok(iface);
            }
        }

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
            if let Some(iface) = Transport::next_hop_interface(dest_hash) {
                return Ok(iface);
            }
        }

        Err(SendErr::LivenessTimeout)
    }

    /// Same as [`race_path`], but success requires a path verified by an
    /// inbound PATH_RESPONSE / announce in this process. Cached path-table
    /// entries from disk do not satisfy the readiness gate.
    ///
    /// Used by persistent propagation links so LRREQ is sent only after the
    /// relay has proven it can reply on the current session.
    pub fn race_path_verified_this_session(
        dest_hash: &[u8],
        budget: Duration,
    ) -> Result<String, SendErr> {
        let snap = get_state_snapshot();
        let candidates: Vec<String> = snap
            .interfaces
            .iter()
            .filter(|i| {
                i.online && i.bitrate.map_or(true, |b| b >= LORA_BITRATE_THRESHOLD)
            })
            .map(|i| i.name.clone())
            .collect();

        if candidates.is_empty() {
            return Err(SendErr::NoUsableInterface);
        }

        if Transport::has_path(dest_hash) && Transport::is_path_verified_this_session(dest_hash) {
            if let Some(iface) = Transport::next_hop_interface(dest_hash) {
                return Ok(iface);
            }
        }

        for iface in &candidates {
            Transport::request_path(dest_hash, None, Some(iface.clone()), None, None);
        }

        if Transport::wait_for_path_verified_this_session(dest_hash, budget) {
            if let Some(iface) = Transport::next_hop_interface(dest_hash) {
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
//   §O1 Timer P fires on_propagation_needed after PROP_FALLBACK_DELAY.
//   §O2 Timer P does NOT fire if delivery happened before the delay.
//   §O3 The delivered gate fires on_delivered exactly once even when
//       multiple tiers fire concurrently.
//   §O4 on_propagation_needed and on_failed are independent — both can fire
//       on the same send (propagation starts while tier-3 still runs).
//   §O5 Tier advancement does not cancel prior in-flight tier packets
//       (the delivered gate remains settable from any tier at any time).
//
// All tests use short delays (ms) so the suite completes quickly.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// Spawn a Timer P with a custom delay for test speed.
    fn spawn_prop_timer(
        delay: Duration,
        delivered: Arc<AtomicBool>,
        on_prop: Arc<dyn Fn() + Send + Sync + 'static>,
    ) {
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            if !delivered.load(Ordering::Acquire) {
                on_prop();
            }
        });
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
    fn propagation_open_requires_session_verified_path() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("race_path_verified_this_session(&dest_owned, LIVENESS_BUDGET)"),
            "propagation AppLinks establishment must require a current-session PATH_RESPONSE / announce before LRREQ"
        );
        assert!(
            src.contains("Transport::wait_for_path_verified_this_session(dest_hash, budget)"),
            "verified propagation path-race must wake from the transport path-added event, not a sleep-poll loop"
        );
    }

    #[test]
    fn persistent_link_close_does_not_auto_reopen() {
        let src = include_str!("lib.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix must exist");
        let close_log = production
            .find("[APP_LINK] PersistentLink CLOSED")
            .expect("persistent close callback must remain present");
        let tail = &production[close_log..];
        let next_section = tail
            .find("{\n            let mut reg = REGISTRY")
            .unwrap_or(tail.len());
        let close_callback = &tail[..next_section];
        assert!(
            !close_callback.contains("AppLinks::establish"),
            "PersistentLink CLOSED callback must surface DISCONNECTED, not retry by calling establish"
        );
        assert!(
            !production.contains("app_links_reestablish"),
            "removed retry thread name must not return"
        );
    }
}
