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
//! `AppLinks::send(dest, packed, on_delivered, on_all_tiers_failed)` drives:
//!
//!   * **Tier 1** — peer-initiated inbound link (they opened it to us):
//!     fire the packed bytes, wait ≤1 s for LRPROOF.
//!   * **Tier 2** — cached outbound link from a previous tier-3 send that
//!     is still `STATE_ACTIVE`: fire, wait ≤1 s.
//!   * **Tier 3** — `expire_path` (NEVER REMOVE EVER) → `race_path`
//!     (≤5 s budget) → `Link::new_outbound` + `initiate` → fire packet →
//!     wait for LRPROOF.
//!
//! All tiers share an `AtomicBool` delivered gate — the first LRPROOF from
//! any tier wins and the others are silently ignored (idempotent).
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

// ─── Watcher poll cadence ────────────────────────────────────────────────
//
// The ready-watcher thread scans for path expiry every 5 s.  Exactness is
// not required — this is a background liveness hint, not a hard signal.
const READY_WATCH_INTERVAL: Duration = Duration::from_secs(5);

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
    ready_watcher_installed: bool,
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
            ready_watcher_installed: false,
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
    fn ensure_ready_watcher() {
        {
            let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
            if reg.ready_watcher_installed {
                return;
            }
            reg.ready_watcher_installed = true;
        }
        std::thread::Builder::new()
            .name("app_links_ready_watch".into())
            .spawn(|| loop {
                std::thread::sleep(READY_WATCH_INTERVAL);
                let to_check: Vec<Vec<u8>> = REGISTRY
                    .lock()
                    .map(|r| r.ready.keys().cloned().collect())
                    .unwrap_or_default();
                if to_check.is_empty() {
                    continue;
                }
                let mut expired: Vec<Vec<u8>> = Vec::new();
                for dest in &to_check {
                    if !Transport::has_path(dest) {
                        expired.push(dest.clone());
                    }
                }
                if expired.is_empty() {
                    continue;
                }
                let cbs: Vec<AppLinkStatusCallback> = {
                    let mut reg =
                        REGISTRY.lock().expect("app_links registry mutex poisoned");
                    for dest in &expired {
                        reg.ready.remove(dest);
                    }
                    let dropped_links: Vec<LinkHandle> = expired
                        .iter()
                        .filter_map(|d| reg.links.remove(d))
                        .collect();
                    let cbs = reg.status_callbacks.clone();
                    drop(reg);
                    drop(dropped_links);
                    cbs
                };
                for dest in &expired {
                    log(
                        &format!(
                            "[APP_LINK] path expired for {} → DISCONNECTED",
                            hexrep(dest, false)
                        ),
                        LOG_NOTICE,
                        false,
                        false,
                    );
                    AppLinks::invalidate_liveness(dest);
                    for cb in &cbs {
                        cb(dest, APP_LINK_DISCONNECTED, None);
                    }
                }
            })
            .expect("failed to spawn app_links ready watcher");
    }

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

        Self::ensure_ready_watcher();

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
                // Expire any stale disk-cached path so race_path resolves via
                // the relay that *currently* has a route to the destination.
                // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
                Transport::expire_path(&dest_owned);

                let result = liveness::race_path(&dest_owned, LIVENESS_BUDGET);

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
                        let is_propagation =
                            aspects.contains(&"propagation".to_string());

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
                // Re-establish immediately if still registered.
                // NEVER REMOVE EVER — see DESIGN_PRINCIPLES §1
                let dest_re = dest_cb.clone();
                std::thread::Builder::new()
                    .name("app_links_reestablish".into())
                    .spawn(move || {
                        AppLinks::establish(&dest_re);
                    })
                    .ok();
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
    // Each tier advances after 1 s if no LRPROOF has arrived.  A shared
    // AtomicBool delivered gate makes all callbacks idempotent: the first
    // LRPROOF from any tier wins; subsequent proofs are silent no-ops.
    //
    // Spawns a background thread; returns immediately (§7).

    /// Send `packed` bytes to `dest` via the best available link.
    ///
    /// Non-blocking.  Spawns a background thread to drive the 3-tier
    /// hierarchy and returns immediately.
    ///
    /// `on_delivered` fires exactly once when an LRPROOF is received.
    /// `on_all_tiers_failed` fires exactly once when all tiers have been
    /// attempted and none produced an LRPROOF.  Both callbacks MUST be
    /// idempotent and MUST NOT block.
    ///
    /// If `dest` is not registered via [`AppLinks::open`] the call still
    /// works — tier-3 fires regardless.  Tier-1 and tier-2 simply have no
    /// links to try.
    pub fn send(
        dest: &[u8],
        packed: Vec<u8>,
        on_delivered: Arc<dyn Fn() + Send + Sync + 'static>,
        on_all_tiers_failed: Arc<dyn Fn() + Send + Sync + 'static>,
    ) {
        let dest_owned = dest.to_vec();
        std::thread::Builder::new()
            .name("app_links_send".into())
            .spawn(move || {
                Self::run_tier_chain(
                    &dest_owned,
                    packed,
                    on_delivered,
                    on_all_tiers_failed,
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
        on_all_tiers_failed: Arc<dyn Fn() + Send + Sync + 'static>,
    ) {
        // Shared delivered gate.  The first LRPROOF from any tier wins.
        let delivered = Arc::new(AtomicBool::new(false));

        // ── Tier 1: inbound link ──────────────────────────────────────
        let inbound = Self::get_inbound_handle(dest)
            .filter(|h| h.status() == STATE_ACTIVE);

        if let Some(handle) = inbound {
            log(
                &format!("[APP_LINK] send tier-1 (inbound link) for {}", hexrep(dest, false)),
                LOG_NOTICE, false, false,
            );
            let fired = Self::fire_on_link(
                &handle,
                &packed,
                delivered.clone(),
                on_delivered.clone(),
            );
            if fired {
                // Advance timer: 1 s to prove delivery before tier-2.
                std::thread::sleep(Duration::from_secs(1));
                if delivered.load(Ordering::Acquire) {
                    log(
                        &format!("[APP_LINK] send delivered via tier-1 for {}", hexrep(dest, false)),
                        LOG_NOTICE, false, false,
                    );
                    return;
                }
            }
        }

        // ── Tier 2: cached outbound link ─────────────────────────────
        let outbound = REGISTRY
            .lock()
            .ok()
            .and_then(|r| r.links.get(dest).cloned())
            .filter(|h| h.status() == STATE_ACTIVE);

        if let Some(handle) = outbound {
            log(
                &format!("[APP_LINK] send tier-2 (cached outbound link) for {}", hexrep(dest, false)),
                LOG_NOTICE, false, false,
            );
            let fired = Self::fire_on_link(
                &handle,
                &packed,
                delivered.clone(),
                on_delivered.clone(),
            );
            if fired {
                std::thread::sleep(Duration::from_secs(1));
                if delivered.load(Ordering::Acquire) {
                    log(
                        &format!("[APP_LINK] send delivered via tier-2 for {}", hexrep(dest, false)),
                        LOG_NOTICE, false, false,
                    );
                    return;
                }
            }
        }

        // ── Tier 3: expire + race + new link + send ───────────────────
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
                on_all_tiers_failed();
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
                on_all_tiers_failed();
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
                on_all_tiers_failed();
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
                on_all_tiers_failed();
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
            on_all_tiers_failed();
            return;
        }

        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        // Do NOT use recv_timeout(LIVENESS_BUDGET) here.  LIVENESS_BUDGET is 5s,
        // but link establishment timeout scales with hop count (6s × hops, up to
        // ~78s for 12-hop paths).  A 5s cutoff abandons every multi-hop link
        // before the transport's own timer can fire, causing all direct sends to
        // distant peers to fail spuriously.
        //
        // The deterministic event here is the link's own established/closed
        // callback, driven by the transport's per-hop timer.  We wait for it
        // unconditionally; recv() returns Err only if both senders are dropped
        // (actor panic), which we treat as failure.
        let established_handle = match est_rx.recv() {
            Ok(Ok(h)) => h,
            Ok(Err(())) | Err(_) => {
                log(
                    &format!(
                        "[APP_LINK] send tier-3: link closed/timed out before established for {}",
                        hexrep(dest, false)
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                on_all_tiers_failed();
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

        // Fire and wait for LRPROOF.
        let fired = Self::fire_on_link(
            &established_handle,
            &packed,
            delivered.clone(),
            on_delivered.clone(),
        );
        if !fired {
            on_all_tiers_failed();
            return;
        }

        // Wait for LRPROOF (§7: blocking only this background thread).
        std::thread::sleep(LIVENESS_BUDGET);
        if !delivered.load(Ordering::Acquire) {
            log(
                &format!(
                    "[APP_LINK] send tier-3: LRPROOF timed out for {}",
                    hexrep(dest, false)
                ),
                LOG_NOTICE,
                false,
                false,
            );
            on_all_tiers_failed();
        } else {
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

/// Polling interval while waiting for a path to populate after firing
/// `request_path`.  20 ms keeps wake-up cost negligible.
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

        // Poll until a path appears or budget is exhausted.
        let started = Instant::now();
        while started.elapsed() < budget {
            if Transport::has_path(dest_hash) {
                if let Some(iface) = Transport::next_hop_interface(dest_hash) {
                    return Ok(iface);
                }
            }
            std::thread::sleep(LIVENESS_POLL_INTERVAL);
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
