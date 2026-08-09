"""Broker startup self-probe prototype for the M4B-2 ECH boundary.

SPIKE CODE — not production. Standard-library only.

Converts the residual "ECH is inert on this stack" argument from an
environmental assumption into a measured, fail-closed startup invariant.
The production broker would run this before accepting readiness; any
failure must prevent NETWORK_BROKER_READY.

Three checks:
  1. Gate self-test: a synthetic ECH-bearing ClientHello must be rejected
     and a synthetic clean ClientHello must be accepted by the actual gate
     instance (proves the enforcement code path is live).
  2. Environment pin: the OpenSSL actually linked into this Python process
     must match the recorded, reviewed version, and the loaded libssl must
     export no ECH acceptance machinery (SSL_ech_*/SSL_CTX_set1_echstore
     symbols) — ECH can never be *acted on* in this process.
  3. Report (not enforce in this spike) whether the process inherited an
     OPENSSL_CONF that could alter TLS behavior.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import chgen  # noqa: E402
from ech_gate import ClientHelloGate, Decision  # noqa: E402

# Recorded on the approved spike host. Production must treat any mismatch
# as a different, unmeasured stack and fail closed.
PINNED_OPENSSL_VERSION = "OpenSSL 3.5.5 27 Jan 2026"

# Symbols that would indicate ECH acceptance machinery in the loaded libssl.
ECH_SYMBOLS = (
    "SSL_CTX_set1_echstore",
    "SSL_ech_get1_status",
    "SSL_ech_set1_echconfig",
    "OSSL_ech_get1_helper",
)


class StartupProbeError(Exception):
    pass


def check_gate_self_test() -> None:
    ech_bytes = chgen.make_client_hello(b"approved.example.test", ech=True)
    gate = ClientHelloGate()
    if gate.feed(ech_bytes) is not Decision.REJECT:
        raise StartupProbeError("gate accepted an ECH-bearing ClientHello")
    if "0xfe0d" not in gate.reason:
        raise StartupProbeError(f"gate rejected ECH for wrong reason: "
                                f"{gate.reason}")
    clean = chgen.make_client_hello(b"approved.example.test")
    gate2 = ClientHelloGate()
    if gate2.feed(clean) is not Decision.ACCEPT:
        raise StartupProbeError(f"gate rejected a clean ClientHello: "
                                f"{gate2.reason}")
    if gate2.accepted_bytes != clean:
        raise StartupProbeError("gate replay is not verbatim")


def check_openssl_pin() -> None:
    if ssl.OPENSSL_VERSION != PINNED_OPENSSL_VERSION:
        raise StartupProbeError(
            f"unmeasured OpenSSL: {ssl.OPENSSL_VERSION!r} "
            f"(pinned {PINNED_OPENSSL_VERSION!r})")


def check_no_ech_machinery() -> None:
    path = ctypes.util.find_library("ssl")
    if path is None:
        raise StartupProbeError("libssl not found")
    lib = ctypes.CDLL(path)
    present = [s for s in ECH_SYMBOLS if hasattr(lib, s)]
    if present:
        raise StartupProbeError(
            f"loaded libssl exports ECH machinery: {present}")


def run_startup_probe() -> dict:
    check_gate_self_test()
    check_openssl_pin()
    check_no_ech_machinery()
    return {
        "gate_self_test": "pass",
        "openssl_version": ssl.OPENSSL_VERSION,
        "ech_machinery": "absent",
        "openssl_conf": os.environ.get("OPENSSL_CONF"),
    }


if __name__ == "__main__":
    print(run_startup_probe())
