//! Interop harness for held addresses: the Rust end.
//!
//! `tests/interop/held_address_interop.py run` (through
//! `tests/interop/held_address_run.sh`) drives this binary and a Python
//! reference peer through a Python reference transport node over loopback
//! TCP. See that script for the scenarios.
//!
//!   held_address_interop node <config_dir> <state_dir>
//!
//! The process holds two addresses under one new identity, as an offline
//! distro device does (RFed-rust SPEC §17.15): `rfed.distro.direct.<random>`,
//! with ratchets, taking single packets and `/distro/direct` requests, and
//! `rfed.distro.direct`, which accepts no links.
//!
//! Commands on stdin, one per line; every reply is a line starting `@@`
//! (everything else on stdout is the stack's log):
//!
//!   ANNOUNCE             announce the offline address on every interface up -> @@ANNOUNCED n=<count>
//!   WAITPATH <hash>      wait (15 s at most) until a path to it is known    -> @@HASPATH | @@NOPATH
//!   SETBACK              its app_data becomes [random, true]                -> @@SET
//!   SENDPKT <hash> <tag> one packet to the peer's `interop.peer`            -> @@PROVED <tag> | @@UNPROVED <tag> | @@SENDERR <tag> <why>
//!   REQUEST <hash> <tag> one `/echo` request with bin <tag>                 -> @@ANSWER <tag> <hex> | @@REQFAILED <tag> | @@SENDERR <tag> <why>
//!   QUIT
//!
//! Unprompted: `@@DEST offline=<hash> lookup=<hash> identity=<hash>` once
//! both are held, `@@RX <text>` for each packet the offline address takes
//! (it proves those whose text starts with `take`), and `@@REQ <hex>` for
//! each request's data as it arrived.

use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Arc;

use app_links::{AppLinks, HeldAddress, HeldPacketHandler, HeldRequestHandler};
use reticulum_rust::identity::Identity;
use reticulum_rust::reticulum::Reticulum;

/// The offline address's random part (16 lowercase hex characters).
const RANDOM: &str = "0123456789abcdef";

fn say(line: String) {
    println!("@@{line}");
}

fn hex(b: &[u8]) -> String {
    reticulum_rust::hexrep(b, false)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// msgpack fixstr (under 32 bytes).
fn fixstr(s: &str) -> Vec<u8> {
    assert!(s.len() < 32);
    let mut v = vec![0xa0 | s.len() as u8];
    v.extend_from_slice(s.as_bytes());
    v
}

/// msgpack bin8.
fn bin8(b: &[u8]) -> Vec<u8> {
    assert!(b.len() < 256);
    let mut v = vec![0xc4, b.len() as u8];
    v.extend_from_slice(b);
    v
}

/// The offline address's app_data: msgpack [ str random, bool back ].
fn offline_app_data(back: bool) -> Vec<u8> {
    let mut v = vec![0x92];
    v.extend(fixstr(RANDOM));
    v.push(if back { 0xc3 } else { 0xc2 });
    v
}

/// The lookup address's app_data: msgpack [ str random ].
fn lookup_app_data() -> Vec<u8> {
    let mut v = vec![0x91];
    v.extend(fixstr(RANDOM));
    v
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("node") if args.len() == 4 => node(PathBuf::from(&args[2]), PathBuf::from(&args[3])),
        _ => {
            eprintln!("usage: node <config_dir> <state_dir>");
            std::process::exit(2);
        }
    }
}

fn node(config_dir: PathBuf, state_dir: PathBuf) {
    Reticulum::init(Some(config_dir), None, None, None, false, None).expect("Reticulum init");
    reticulum_rust::set_loglevel(reticulum_rust::LOG_NOTICE);
    std::fs::create_dir_all(&state_dir).expect("state dir");

    let identity = Identity::new(true);
    let identity_hash = identity.hash.clone().expect("identity hash");
    let on_packet: HeldPacketHandler = Arc::new(|plaintext: &[u8]| {
        let text = String::from_utf8_lossy(plaintext).to_string();
        say(format!("RX {text}"));
        text.starts_with("take")
    });
    let on_request: HeldRequestHandler = Arc::new(|data: &[u8]| {
        say(format!("REQ {}", hex(data)));
        vec![0x92, 0xc3, 0xc2]
    });
    let offline = AppLinks::hold_address(HeldAddress {
        identity: identity.clone(),
        app_name: "rfed".into(),
        aspects: vec!["distro".into(), "direct".into(), RANDOM.into()],
        ratchets_path: Some(state_dir.join("ratchets").to_string_lossy().into_owned()),
        accepts_links: true,
        default_app_data: Some(offline_app_data(false)),
        on_packet: Some(on_packet),
        requests: vec![("/distro/direct".into(), on_request)],
    })
    .expect("hold the offline address");
    let lookup = AppLinks::hold_address(HeldAddress {
        identity,
        app_name: "rfed".into(),
        aspects: vec!["distro".into(), "direct".into()],
        ratchets_path: None,
        accepts_links: false,
        default_app_data: Some(lookup_app_data()),
        on_packet: None,
        requests: vec![],
    })
    .expect("hold the lookup address");
    say(format!("DEST offline={} lookup={} identity={}", hex(&offline), hex(&lookup), hex(&identity_hash)));

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["ANNOUNCE"] => {
                let up: Vec<String> = reticulum_rust::transport::get_state_snapshot()
                    .interfaces
                    .iter()
                    .filter(|i| i.out && i.online)
                    .map(|i| i.name.clone())
                    .collect();
                match AppLinks::announce_held(&offline, None, &up) {
                    Ok(n) => say(format!("ANNOUNCED n={n}")),
                    Err(e) => say(format!("ERROR {e}")),
                }
            }
            ["WAITPATH", dest] => {
                // A harness wait, not the library's: the peer's announce has
                // to reach this process before a send to it can start.
                let Some(dest) = unhex(dest) else {
                    say("NOPATH bad hash".into());
                    continue;
                };
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
                while !reticulum_rust::transport::Transport::has_path(&dest) && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                if reticulum_rust::transport::Transport::has_path(&dest) {
                    say("HASPATH".into());
                } else {
                    say("NOPATH".into());
                }
            }
            ["SETBACK"] => match AppLinks::set_held_app_data(&offline, Some(offline_app_data(true))) {
                Ok(()) => say("SET".into()),
                Err(e) => say(format!("ERROR {e}")),
            },
            ["SENDPKT", dest, tag] | ["REQUEST", dest, tag] => {
                let tag = tag.to_string();
                let Some(dest) = unhex(dest) else {
                    say(format!("SENDERR {tag} bad hash"));
                    continue;
                };
                let Some(peer) = Identity::recall(&dest) else {
                    say(format!("SENDERR {tag} identity not recalled"));
                    continue;
                };
                let aspects = vec!["peer".to_string()];
                let started = if words[0] == "SENDPKT" {
                    let (t1, t2) = (tag.clone(), tag.clone());
                    AppLinks::send_packet_to(
                        &peer,
                        "interop",
                        &aspects,
                        tag.as_bytes(),
                        Arc::new(move || say(format!("PROVED {t1}"))),
                        Arc::new(move || say(format!("UNPROVED {t2}"))),
                    )
                } else {
                    let (t1, t2) = (tag.clone(), tag.clone());
                    AppLinks::request_once(
                        &peer,
                        "interop",
                        &aspects,
                        "/echo",
                        bin8(tag.as_bytes()),
                        Arc::new(move |answer: Vec<u8>| say(format!("ANSWER {t1} {}", hex(&answer)))),
                        Arc::new(move || say(format!("REQFAILED {t2}"))),
                    )
                };
                if let Err(e) = started {
                    say(format!("SENDERR {tag} {e}"));
                }
            }
            ["QUIT"] => std::process::exit(0),
            _ => say(format!("ERROR unknown command {line}")),
        }
    }
}
