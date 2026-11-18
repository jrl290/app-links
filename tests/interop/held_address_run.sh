#!/usr/bin/env bash
# Held addresses against the Python reference (rns in ../.venv, 1.5.2): an
# offline address and a lookup address held by the Rust end, and the Rust
# sending side, all through a Python reference transport node over loopback
# TCP. The scenarios are in the header of tests/interop/held_address_interop.py.
#
#   tests/interop/held_address_run.sh
#
#   PYTHON=...            interpreter for the Python ends (default ../.venv/bin/python)
#   INTEROP_LOGLEVEL=n    RNS loglevel written into every Python config (default 3)
#   INTEROP_KEEP=dir      keep every process's config, state and logs there
#
# Exit 0 only if every scenario passes.
set -u
cd "$(dirname "$0")/../.."
PY="${PYTHON:-../.venv/bin/python}"
cargo build --quiet --example held_address_interop || exit 1
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
"$PY" tests/interop/held_address_interop.py run target/debug/examples/held_address_interop "$WORK"
status=$?
if [ -n "${INTEROP_KEEP:-}" ]; then
  mkdir -p "$INTEROP_KEEP" && cp -r "$WORK"/. "$INTEROP_KEEP"/ && echo "logs kept in $INTEROP_KEEP"
fi
exit $status
