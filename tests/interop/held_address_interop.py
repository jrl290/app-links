#!/usr/bin/env python3
"""Held addresses against the Python reference (rns 1.5.2 in ../.venv).

The Rust end is examples/held_address_interop.rs. Run through
tests/interop/held_address_run.sh, which builds it and calls `run` here.

  held_address_interop.py run  <rust_binary> <work_dir>   the orchestrator
  held_address_interop.py hub  <config_dir>               a bare reference transport node
  held_address_interop.py peer <config_dir>               the Python reference peer

Both ends are TCP clients of a Python reference transport node (the hub, in
gateway mode so it searches for paths it does not know), so every exchange
crosses a real transport hop. The Rust end holds an offline address and a
lookup address as RFed-rust SPEC §17.15 describes. Scenarios, each decided on
an event; ceilings only turn a missing event into a FAIL, and a proof later
than 5 s is a FAIL too (DESIGN_PRINCIPLES §1):

  a  The offline address announces once on the one interface it has; the
     peer hears it with app_data msgpack [random, false] and a ratchet.
  b  A packet the Rust host takes ("take-1") is proved.
  c  A packet the Rust host refuses ("refuse-1") is never proved: the peer's
     receipt times out.
  d  A `/distro/direct` request on a link reaches the Rust host with its data
     exactly as the peer sent it, and the host's answer, msgpack [true,
     false], comes back as it was made.
  e  A path request for the lookup address, never announced, is answered by
     the Rust end itself with its app_data, msgpack [random].
  f  A link to the lookup address never comes up.
  g  The sending side: Rust sends one packet to a Python destination and gets
     its proof.
  h  Rust sends one `/echo` request on a link of its own and gets the answer,
     the bin it sent.

Exit 0 only if every scenario passes.
"""
import os
import re
import subprocess
import sys
import threading
import time

RANDOM = "0123456789abcdef"
PROOF_LATE_S = 5.0     # DESIGN_PRINCIPLES §1: a later proof is a failure
EVENT_CEILING_S = 15   # a missing event becomes a FAIL after this
REFUSED_RECEIPT_S = 6  # the peer's receipt timeout for the refused packet
START_CEILING_S = 60   # interpreter start + RNS init


def emit(line):
    print(line, flush=True)


# ── hub and peer (the Python reference ends) ────────────────────────────────

def hub(config_dir):
    import RNS
    RNS.Reticulum(config_dir)
    emit("HUB ready")
    servers = [i for i in RNS.Transport.interfaces if type(i).__name__ == "TCPServerInterface"]
    last = None
    while True:
        n = sum(len(s.spawned_interfaces or []) for s in servers)
        if n != last:
            emit(f"@@PEERS {n}")
            last = n
        time.sleep(0.1)


def peer(config_dir):
    import RNS
    import RNS.vendor.umsgpack as umsgpack
    RNS.Reticulum(config_dir)
    emit("@@READY")
    watch = {"identity": None}

    class Handler:
        aspect_filter = None
        receive_path_responses = True

        def received_announce(self, destination_hash, announced_identity, app_data, announce_packet_hash, is_path_response):
            if watch["identity"] and announced_identity and announced_identity.hash == watch["identity"]:
                ratchet = RNS.Identity.get_ratchet(destination_hash)
                emit(f"@@HEARD {destination_hash.hex()} app_data={(app_data or b'').hex()} "
                     f"ratchet={'yes' if ratchet else 'none'} path_response={int(bool(is_path_response))}")

    RNS.Transport.register_announce_handler(Handler())

    def offline_destination(dest_hash):
        identity = RNS.Identity.recall(dest_hash)
        app_data = RNS.Identity.recall_app_data(dest_hash)
        if identity is None or not app_data:
            return None
        random_part = umsgpack.unpackb(app_data)[0]
        dest = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "rfed", "distro", "direct", random_part)
        return dest if dest.hash == dest_hash else None

    in_dest = None
    for line in sys.stdin:
        words = line.split()
        if not words:
            continue
        cmd = words[0]
        if cmd == "WATCH":
            watch["identity"] = bytes.fromhex(words[1])
            emit("@@WATCHING")
        elif cmd == "SENDPKT":
            tag = words[2]
            dest = offline_destination(bytes.fromhex(words[1]))
            if dest is None:
                emit(f"@@UNPROVEN {tag} no destination")
                continue
            started = time.time()
            receipt = RNS.Packet(dest, tag.encode()).send()
            if not receipt:
                emit(f"@@UNPROVEN {tag} no receipt")
                continue
            receipt.set_timeout(REFUSED_RECEIPT_S if tag.startswith("refuse") else EVENT_CEILING_S)
            receipt.set_delivery_callback(lambda r, tag=tag, started=started: emit(f"@@PROVEN {tag} ms={int((time.time() - started) * 1000)}"))
            receipt.set_timeout_callback(lambda r, tag=tag: emit(f"@@UNPROVEN {tag} receipt timed out"))
        elif cmd == "LINKREQ":
            tag = words[2]
            dest = offline_destination(bytes.fromhex(words[1]))
            if dest is None:
                emit(f"@@REQFAILED {tag} no destination")
                continue

            def up(link, tag=tag):
                link.request(
                    "/distro/direct",
                    data=[b"sealed-" + tag.encode(), b"stamp"],
                    response_callback=lambda r: (emit(f"@@ANSWER {tag} {umsgpack.packb(r.response).hex()}"), link.teardown()),
                    failed_callback=lambda r: (emit(f"@@REQFAILED {tag}"), link.teardown()),
                )

            RNS.Link(dest, established_callback=up)
        elif cmd == "PATH":
            h = bytes.fromhex(words[1])
            RNS.Transport.request_path(h)
            deadline = time.time() + EVENT_CEILING_S
            while not RNS.Transport.has_path(h) and time.time() < deadline:
                time.sleep(0.1)
            if RNS.Transport.has_path(h):
                emit(f"@@PATH {h.hex()} app_data={(RNS.Identity.recall_app_data(h) or b'').hex()}")
            else:
                emit(f"@@NOPATH {h.hex()}")
        elif cmd == "LINKLOOKUP":
            h = bytes.fromhex(words[1])
            identity = RNS.Identity.recall(h)
            dest = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "rfed", "distro", "direct")
            if dest.hash != h:
                emit("@@LOOKUPLINK wrong hash")
                continue
            state = {"up": False}

            def lookup_up(link, state=state):
                state["up"] = True
                emit("@@LOOKUPLINK up")
                link.teardown()

            def lookup_closed(link, state=state):
                if not state["up"]:
                    emit("@@LOOKUPLINK refused")

            RNS.Link(dest, established_callback=lookup_up, closed_callback=lookup_closed)
        elif cmd == "INDEST":
            in_dest = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, "interop", "peer")
            in_dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
            in_dest.set_packet_callback(lambda data, packet: emit(f"@@INRX {data.decode(errors='replace')}"))
            in_dest.register_request_handler(
                "/echo",
                response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: data,
                allow=RNS.Destination.ALLOW_ALL,
            )
            in_dest.announce()
            emit(f"@@INDEST {in_dest.hash.hex()}")
        elif cmd == "QUIT":
            os._exit(0)
        else:
            emit(f"@@ERROR unknown command {line.strip()}")


# ── orchestrator ────────────────────────────────────────────────────────────

class Fail(Exception):
    pass


# The same port registry Reticulum-rust's interop harness uses, so the two
# can run side by side.
REGISTRY = os.path.join(os.environ.get("TMPDIR", "/tmp"), "reticulum-interop-ports")


def claim_port():
    """A free 127.0.0.1 port in 20000-31999, claimed in the registry."""
    import fcntl
    import random
    import socket

    def alive(pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def free(port):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
        finally:
            s.close()
        c = socket.socket()
        c.settimeout(0.5)
        try:
            return c.connect_ex(("127.0.0.1", port)) != 0
        finally:
            c.close()

    with open(REGISTRY, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        entries = [l.split() for l in f.read().splitlines()]
        entries = [(int(p), r) for p, r in (e for e in entries if len(e) == 2) if alive(int(r))]
        taken = {p for p, _ in entries}
        for port in random.sample(range(20000, 32000), 12000):
            if port not in taken and free(port):
                break
        else:
            raise Fail("no free port in 20000-31999")
        entries.append((port, str(os.getpid())))
        f.seek(0)
        f.truncate()
        f.write("".join(f"{p} {r}\n" for p, r in entries))
    return port


def release_ports():
    import fcntl
    try:
        with open(REGISTRY, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            keep = [l for l in f.read().splitlines() if len(l.split()) == 2 and l.split()[1] != str(os.getpid())]
            f.seek(0)
            f.truncate()
            f.write("".join(k + "\n" for k in keep))
    except OSError:
        pass


def config(path, port, transport, mode=None):
    os.makedirs(path, exist_ok=True)
    if transport:
        iface = f"type = TCPServerInterface\n    listen_ip = 127.0.0.1\n    listen_port = {port}"
    else:
        iface = f"type = TCPClientInterface\n    target_host = 127.0.0.1\n    target_port = {port}"
    if mode:
        # `mode`, not `interface_mode`: rns 1.5.2 reads c["mode"] for "gateway".
        iface += f"\n    mode = {mode}"
    with open(os.path.join(path, "config"), "w") as f:
        f.write(f"""[reticulum]
  enable_transport = {'true' if transport else 'false'}
  share_instance = false

[logging]
  loglevel = {os.environ.get('INTEROP_LOGLEVEL', '3')}

[interfaces]
  [[Interop]]
    {iface}
    enabled = true
""")


class Proc:
    """A child process whose stdout lines are kept, in order, for expect()."""

    def __init__(self, name, cmd, log_dir):
        self.name = name
        self.lines = []
        self.cursor = 0
        self.cond = threading.Condition()
        self.out_path = os.path.join(log_dir, f"{name}.out")
        self.err = open(os.path.join(log_dir, f"{name}.err"), "w")
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err, text=True, bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        with open(self.out_path, "w") as out:
            for line in self.p.stdout:
                out.write(line)
                out.flush()
                with self.cond:
                    self.lines.append(line.rstrip("\n"))
                    self.cond.notify_all()
        with self.cond:
            self.cond.notify_all()

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def expect(self, pattern, what, ceiling=EVENT_CEILING_S, fail_pattern=None):
        rx = re.compile(pattern)
        frx = re.compile(fail_pattern) if fail_pattern else None
        deadline = time.time() + ceiling
        with self.cond:
            while True:
                while self.cursor < len(self.lines):
                    line = self.lines[self.cursor]
                    self.cursor += 1
                    if frx and frx.search(line):
                        raise Fail(f"{what}: {self.name} printed {line!r}")
                    m = rx.search(line)
                    if m:
                        return m
                if self.p.poll() is not None:
                    raise Fail(f"{what}: {self.name} exited ({self.p.returncode}) first")
                left = deadline - time.time()
                if left <= 0:
                    raise Fail(f"{what}: not seen from {self.name} within {ceiling} s")
                self.cond.wait(min(left, 0.5))

    def stop(self):
        if self.p.poll() is None:
            try:
                self.send("QUIT")
            except (BrokenPipeError, OSError):
                pass
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.terminate()
                try:
                    self.p.wait(5)
                except subprocess.TimeoutExpired:
                    self.p.kill()
                    self.p.wait()
        self.err.close()

    def tail(self, n=25):
        with self.cond:
            return self.lines[-n:]


def run(rust_bin, work):
    import RNS.vendor.umsgpack as umsgpack
    python = sys.executable
    me = os.path.abspath(__file__)
    procs = []
    results = []

    def scenario(name, fn):
        try:
            fn()
            results.append((name, None))
            emit(f"PASS {name}")
        except Fail as e:
            results.append((name, str(e)))
            emit(f"FAIL {name}: {e}")

    try:
        port = claim_port()
        config(os.path.join(work, "hub"), port, transport=True, mode="gateway")
        hub_p = Proc("hub", [python, me, "hub", os.path.join(work, "hub")], work)
        procs.append(hub_p)
        hub_p.expect(r"^HUB ready", "hub start", START_CEILING_S)

        config(os.path.join(work, "rust"), port, transport=False)
        rust = Proc("rust", [rust_bin, "node", os.path.join(work, "rust"), os.path.join(work, "rust_state")], work)
        procs.append(rust)
        m = rust.expect(r"^@@DEST offline=(\w+) lookup=(\w+) identity=(\w+)", "rust start", START_CEILING_S)
        offline, lookup, identity = m.group(1), m.group(2), m.group(3)

        config(os.path.join(work, "peer"), port, transport=False)
        py = Proc("peer", [python, me, "peer", os.path.join(work, "peer")], work)
        procs.append(py)
        py.expect(r"^@@READY", "peer start", START_CEILING_S)
        hub_p.expect(r"^@@PEERS 2", "both ends attached", START_CEILING_S)
        py.send(f"WATCH {identity}")
        py.expect(r"^@@WATCHING", "watch")

        expected_app_data = umsgpack.packb([RANDOM, False]).hex()

        def a():
            rust.send("ANNOUNCE")
            rust.expect(r"^@@ANNOUNCED n=1$", "announced on its one interface")
            m = py.expect(rf"^@@HEARD {offline} app_data=(\w*) ratchet=(\w+) path_response=0", "announce heard")
            if m.group(1) != expected_app_data:
                raise Fail(f"app_data {m.group(1)}, expected {expected_app_data}")
            if m.group(2) != "yes":
                raise Fail("the announce carried no ratchet")

        def b():
            py.send(f"SENDPKT {offline} take-1")
            rust.expect(r"^@@RX take-1$", "taken packet received")
            m = py.expect(r"^@@(PROVEN|UNPROVEN) take-1(?: ms=(\d+))?", "taken packet's proof")
            if m.group(1) != "PROVEN":
                raise Fail("a packet the host took was not proved")
            if int(m.group(2)) > PROOF_LATE_S * 1000:
                raise Fail(f"proof took {m.group(2)} ms")

        def c():
            py.send(f"SENDPKT {offline} refuse-1")
            rust.expect(r"^@@RX refuse-1$", "refused packet received")
            m = py.expect(r"^@@(PROVEN|UNPROVEN) refuse-1", "refused packet's outcome", REFUSED_RECEIPT_S + EVENT_CEILING_S)
            if m.group(1) != "UNPROVEN":
                raise Fail("a packet the host refused was proved")

        def d():
            py.send(f"LINKREQ {offline} r1")
            sent = umsgpack.packb([b"sealed-r1", b"stamp"]).hex()
            m = rust.expect(r"^@@REQ (\w+)$", "request received", 2 * EVENT_CEILING_S)
            if m.group(1) != sent:
                raise Fail(f"request data {m.group(1)}, sent {sent}")
            m = py.expect(r"^@@(ANSWER|REQFAILED) r1 ?(\w*)", "request answered", 2 * EVENT_CEILING_S)
            if m.group(1) != "ANSWER" or m.group(2) != "92c3c2":
                raise Fail(f"answer {m.group(0)!r}, expected 92c3c2")

        def e():
            py.send(f"PATH {lookup}")
            m = py.expect(rf"^@@(PATH|NOPATH) {lookup}(?: app_data=(\w*))?", "lookup path answered", 2 * EVENT_CEILING_S)
            if m.group(1) != "PATH":
                raise Fail("no answer for the lookup address")
            if m.group(2) != umsgpack.packb([RANDOM]).hex():
                raise Fail(f"lookup app_data {m.group(2)}")

        def f():
            py.send(f"LINKLOOKUP {lookup}")
            m = py.expect(r"^@@LOOKUPLINK (\w+)", "link to the lookup address", 4 * EVENT_CEILING_S)
            if m.group(1) != "refused":
                raise Fail(f"link to the lookup address: {m.group(1)}")

        def g():
            py.send("INDEST")
            dest = py.expect(r"^@@INDEST (\w+)", "peer destination").group(1)
            rust.send(f"WAITPATH {dest}")
            if rust.expect(r"^@@(HASPATH|NOPATH)", "path to the peer").group(1) != "HASPATH":
                raise Fail("Rust never learned a path to the peer")
            rust.send(f"SENDPKT {dest} hello-1")
            py.expect(r"^@@INRX hello-1$", "peer received the packet")
            m = rust.expect(r"^@@(PROVED|UNPROVED|SENDERR) hello-1", "Rust packet's proof")
            if m.group(1) != "PROVED":
                raise Fail(f"Rust packet: {m.group(0)!r}")
            g.dest = dest

        def h():
            rust.send(f"REQUEST {g.dest} ping-1")
            m = rust.expect(r"^@@(ANSWER|REQFAILED|SENDERR) ping-1 ?(\w*)", "Rust request answered", 2 * EVENT_CEILING_S)
            want = umsgpack.packb(b"ping-1").hex()
            if m.group(1) != "ANSWER" or m.group(2) != want:
                raise Fail(f"Rust request: {m.group(0)!r}, expected answer {want}")

        for name, fn in (("a announce", a), ("b proved on yes", b), ("c unproved on no", c),
                         ("d request unwrapped", d), ("e lookup answered", e), ("f lookup takes no links", f),
                         ("g Rust packet proved", g), ("h Rust one-off request", h)):
            scenario(name, fn)
    except Fail as e:
        results.append(("setup", str(e)))
        emit(f"FAIL setup: {e}")
    finally:
        for p in procs:
            p.stop()
        release_ports()

    failed = [r for r in results if r[1]]
    if failed:
        for p in procs:
            emit(f"--- last lines from {p.name}:")
            for line in p.tail():
                emit(f"    {line}")
    emit(f"{len(results) - len(failed)} of {len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "hub" and len(sys.argv) == 3:
        hub(sys.argv[2])
    elif cmd == "peer" and len(sys.argv) == 3:
        peer(sys.argv[2])
    elif cmd == "run" and len(sys.argv) == 4:
        sys.exit(run(os.path.abspath(sys.argv[2]), os.path.abspath(sys.argv[3])))
    else:
        sys.exit(__doc__)
