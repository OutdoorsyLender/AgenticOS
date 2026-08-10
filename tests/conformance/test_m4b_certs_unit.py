"""Unit tests for the M4B-2 task-scoped certificate helper and sealed transport.

Covers Corpus F minus broker-integration items: distinct CA/leaf keypairs,
exact-hostname SAN leaves, chain verification, digest-bound sealed memfd
transport, fail-closed binding/context verification, /proc/self/fd/N TLS
context loading, helper subprocess lifetime, and a real end-to-end TLS
handshake. All tests require Linux (memfd sealing); the module skips elsewhere.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 certificate helper requires Linux", allow_module_level=True)

import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from agenticos.sandbox import cert_helper as ch


TASK_CONTEXT = {
    "task_id": "task-certs",
    "task_generation": 3,
    "launch_nonce": "ab" * 16,
    "hostnames": ("approved.example.test",),
    "policy_digest": "cd" * 32,
}

_OTHER_CONTEXT = {
    "task_id": "task-other",
    "task_generation": 9,
    "launch_nonce": "ef" * 16,
    "hostnames": ("other.example.test",),
    "policy_digest": "01" * 32,
}

_REQUIRED_SEALS = (
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
)

_HANDSHAKE_TIMEOUT = 5.0


@pytest.fixture(scope="module")
def material():
    """One genuine helper-produced material set shared by read-only tests."""
    generated = ch.generate_task_material(**TASK_CONTEXT)
    yield generated
    generated.close()


@pytest.fixture(scope="module")
def other_material():
    """A second, fully independent task generation for cross-material tests."""
    generated = ch.generate_task_material(**_OTHER_CONTEXT)
    yield generated
    generated.close()


@pytest.fixture(scope="module")
def verified(material):
    return ch.verify_task_material(**_material_fds(material), **TASK_CONTEXT)


def _material_fds(m):
    return {
        "ca_cert_fd": m.ca_cert_fd,
        "leaf_cert_fd": m.leaf_cert_fd,
        "leaf_key_fd": m.leaf_key_fd,
        "binding_fd": m.binding_fd,
    }


def _read_fd_payload(fd):
    size = os.fstat(fd).st_size
    return os.pread(fd, size, 0)


def _sealed_memfd(name, payload):
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, payload)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _REQUIRED_SEALS)
        os.lseek(fd, 0, os.SEEK_SET)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _parse_cert(pem):
    return x509.load_pem_x509_certificate(pem)


def _public_key_pem(cert):
    return cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _client_context(ca_pem):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cadata=ca_pem.decode("ascii"))
    return context


def _handshake(server_context, client_context, server_hostname):
    """Run one real TLS handshake over a socket pair; return (client, error)."""
    left, right = socket.socketpair()
    left.settimeout(_HANDSHAKE_TIMEOUT)
    right.settimeout(_HANDSHAKE_TIMEOUT)
    server_errors = []

    def serve():
        try:
            server_socket = server_context.wrap_socket(left, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            server_errors.append(exc)
            left.close()
            return
        server_socket.close()

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    client_socket = None
    error = None
    try:
        client_socket = client_context.wrap_socket(
            right, server_hostname=server_hostname
        )
    except (ssl.SSLError, OSError) as exc:
        error = exc
        right.close()
    server.join(_HANDSHAKE_TIMEOUT * 2)
    return client_socket, error, server_errors


# -- dependency gate: broker-side module import stays stdlib-only ---------------


def test_broker_module_import_is_stdlib_only():
    src_root = Path(ch.__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src_root)
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import agenticos.sandbox.cert_helper;"
            "assert 'cryptography' not in sys.modules",
        ],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


# -- keypair and certificate shape ----------------------------------------------


def test_ca_and_leaf_keypairs_are_distinct(verified):
    ca_cert = _parse_cert(verified.ca_cert_pem)
    leaf_cert = _parse_cert(verified.leaf_cert_pem)
    assert _public_key_pem(ca_cert) != _public_key_pem(leaf_cert)


def test_leaf_san_is_exactly_approved_hostname(verified):
    leaf_cert = _parse_cert(verified.leaf_cert_pem)
    san_extension = leaf_cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    )
    entries = list(san_extension.value)
    assert len(entries) == 1
    assert san_extension.value.get_values_for_type(x509.DNSName) == list(
        TASK_CONTEXT["hostnames"]
    )
    assert "*" not in entries[0].value


def test_ca_and_leaf_certificates_are_distinct_per_task(material, other_material):
    first = ch.verify_task_material(**_material_fds(material), **TASK_CONTEXT)
    second = ch.verify_task_material(
        **_material_fds(other_material), **_OTHER_CONTEXT
    )
    assert first.ca_cert_pem != second.ca_cert_pem
    assert first.leaf_cert_pem != second.leaf_cert_pem
    ca_one = _public_key_pem(_parse_cert(first.ca_cert_pem))
    ca_two = _public_key_pem(_parse_cert(second.ca_cert_pem))
    assert ca_one != ca_two


# -- sealing ---------------------------------------------------------------------


def test_all_material_fds_are_fully_sealed(material):
    for name, fd in material.fds().items():
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        assert seals & _REQUIRED_SEALS == _REQUIRED_SEALS, name


def test_material_fds_deny_mutation_after_sealing(material):
    for name, fd in material.fds().items():
        with pytest.raises(OSError):
            os.write(fd, b"x")
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        assert seals & _REQUIRED_SEALS == _REQUIRED_SEALS, name


def test_binding_digest_is_canonical(material):
    binding = material.binding
    assert ch.binding_digest(binding) == hashlib.sha256(binding.to_bytes()).hexdigest()
    assert json.loads(binding.to_bytes().decode("ascii"))["version"] == "AOSCERT/1"


# -- binding / context verification ------------------------------------------------


def test_verify_accepts_genuine_material(material, verified):
    assert verified.binding == material.binding
    assert verified.binding.hostnames == TASK_CONTEXT["hostnames"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("task_id", "task-wrong"),
        ("task_generation", 4),
        ("launch_nonce", "00" * 16),
        ("policy_digest", "11" * 32),
    ],
)
def test_stale_context_is_denied(material, field, value):
    context = dict(TASK_CONTEXT)
    context[field] = value
    with pytest.raises(ch.CertHelperError):
        ch.verify_task_material(**_material_fds(material), **context)


def test_wrong_hostname_is_denied(material):
    context = dict(TASK_CONTEXT, hostnames=("evil.example.test",))
    with pytest.raises(ch.CertHelperError):
        ch.verify_task_material(**_material_fds(material), **context)


def test_swapped_ca_cert_fd_is_denied(material, other_material):
    fds = _material_fds(material)
    fds["ca_cert_fd"] = other_material.ca_cert_fd
    with pytest.raises(ch.CertHelperError):
        ch.verify_task_material(**fds, **TASK_CONTEXT)


def test_tampered_sealed_payload_is_detected_by_digest_binding(material):
    genuine = _read_fd_payload(material.leaf_cert_fd)
    flipped = bytearray(genuine)
    flipped[len(flipped) // 2] ^= 0x01
    tampered_fd = _sealed_memfd("aos-test-tampered-leaf", bytes(flipped))
    try:
        fds = _material_fds(material)
        fds["leaf_cert_fd"] = tampered_fd
        with pytest.raises(ch.CertHelperError):
            ch.verify_task_material(**fds, **TASK_CONTEXT)
    finally:
        os.close(tampered_fd)


def test_tampered_binding_record_is_denied(material):
    forged = dataclasses.replace(material.binding, task_id="task-forged")
    forged_fd = _sealed_memfd("aos-test-forged-binding", forged.to_bytes())
    try:
        fds = _material_fds(material)
        fds["binding_fd"] = forged_fd
        with pytest.raises(ch.CertHelperError):
            ch.verify_task_material(**fds, **TASK_CONTEXT)
    finally:
        os.close(forged_fd)


# -- CA private key absence --------------------------------------------------------


def test_ca_private_key_is_absent_from_helper_outputs(material, verified):
    ca_public = _public_key_pem(_parse_cert(verified.ca_cert_pem))
    for name, fd in material.fds().items():
        payload = _read_fd_payload(fd)
        if name == "leaf_key":
            assert b"PRIVATE KEY" in payload
            key = serialization.load_pem_private_key(payload, password=None)
            leaf_public = key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            assert leaf_public != ca_public, "leaf key must not be the CA key"
        else:
            assert b"PRIVATE KEY" not in payload, name
    assert set(material.fds()) == {"ca_cert", "leaf_cert", "leaf_key", "binding"}


def test_helper_exited_before_return_and_is_reaped(material):
    assert material.helper_pid > 0
    assert not Path(f"/proc/{material.helper_pid}").exists()


def test_helper_spawns_no_descendants_and_exits_cleanly():
    fds = {name: ch._create_sealable_memfd(ch._MEMFD_NAMES[name]) for name in ch._MATERIAL_FD_NAMES}
    try:
        request = {
            "version": "AOSCERTREQ/1",
            **TASK_CONTEXT,
            "fds": dict(fds),
        }
        payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        process = ch._spawn_helper(request, fds)
        process.stdin.write(payload)
        process.stdin.close()
        process.stdin = None
        samples = 0
        while process.poll() is None:
            children = Path(f"/proc/{process.pid}/task/{process.pid}/children")
            if children.exists():
                assert not children.read_text().split(), "helper spawned a child"
                samples += 1
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr
        assert stdout == b"" and stderr == b""
        assert not Path(f"/proc/{process.pid}").exists()
        verified = ch.verify_task_material(
            ca_cert_fd=fds["ca_cert"],
            leaf_cert_fd=fds["leaf_cert"],
            leaf_key_fd=fds["leaf_key"],
            binding_fd=fds["binding"],
            **TASK_CONTEXT,
        )
        assert verified.binding.task_id == TASK_CONTEXT["task_id"]
    finally:
        for fd in fds.values():
            os.close(fd)


def test_helper_failure_is_fail_closed():
    fds = {name: ch._create_sealable_memfd(ch._MEMFD_NAMES[name]) for name in ch._MATERIAL_FD_NAMES}
    os.close(fds["binding"])  # child gets an invalid fd number
    try:
        request = {
            "version": "AOSCERTREQ/1",
            **TASK_CONTEXT,
            "fds": dict(fds),
        }
        payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        process = ch._spawn_helper(request, fds)
        process.communicate(payload, timeout=30)
        assert process.returncode != 0
    finally:
        for name, fd in fds.items():
            if name != "binding":
                os.close(fd)


# -- broker-side loader -------------------------------------------------------------


def test_loader_builds_ssl_context_from_sealed_fds(material):
    context = ch.load_leaf_ssl_context(**_material_fds(material), **TASK_CONTEXT)
    assert isinstance(context, ssl.SSLContext)


def test_loader_fails_closed_with_wrong_expected_hostname(material):
    context = dict(TASK_CONTEXT, hostnames=("evil.example.test",))
    with pytest.raises(ch.CertHelperError):
        ch.load_leaf_ssl_context(**_material_fds(material), **context)


def test_loader_rejects_mismatched_leaf_key_even_with_consistent_binding(
    material, other_material
):
    """A test double with a self-consistent binding but broken crypto fails."""
    leaf_cert = _read_fd_payload(material.leaf_cert_fd)
    wrong_key = _read_fd_payload(other_material.leaf_key_fd)
    ca_cert = _read_fd_payload(material.ca_cert_fd)
    binding = ch.CertBinding(
        version="AOSCERT/1",
        task_id=TASK_CONTEXT["task_id"],
        task_generation=TASK_CONTEXT["task_generation"],
        launch_nonce=TASK_CONTEXT["launch_nonce"],
        hostnames=TASK_CONTEXT["hostnames"],
        policy_digest=TASK_CONTEXT["policy_digest"],
        ca_cert_sha256=hashlib.sha256(ca_cert).hexdigest(),
        leaf_cert_sha256=hashlib.sha256(leaf_cert).hexdigest(),
        leaf_key_sha256=hashlib.sha256(wrong_key).hexdigest(),
    )
    fds = {
        "ca_cert_fd": _sealed_memfd("aos-test-ca", ca_cert),
        "leaf_cert_fd": _sealed_memfd("aos-test-leaf", leaf_cert),
        "leaf_key_fd": _sealed_memfd("aos-test-key", wrong_key),
        "binding_fd": _sealed_memfd("aos-test-binding", binding.to_bytes()),
    }
    try:
        with pytest.raises(ch.CertHelperError):
            ch.load_leaf_ssl_context(**fds, **TASK_CONTEXT)
    finally:
        for fd in fds.values():
            os.close(fd)


def test_loader_rejects_wrong_ca_even_with_consistent_binding(
    material, other_material
):
    """The crypto path must fail even when a test double's digests agree."""
    wrong_ca = _read_fd_payload(other_material.ca_cert_fd)
    leaf_cert = _read_fd_payload(material.leaf_cert_fd)
    leaf_key = _read_fd_payload(material.leaf_key_fd)
    binding = ch.CertBinding(
        version="AOSCERT/1",
        task_id=TASK_CONTEXT["task_id"],
        task_generation=TASK_CONTEXT["task_generation"],
        launch_nonce=TASK_CONTEXT["launch_nonce"],
        hostnames=TASK_CONTEXT["hostnames"],
        policy_digest=TASK_CONTEXT["policy_digest"],
        ca_cert_sha256=hashlib.sha256(wrong_ca).hexdigest(),
        leaf_cert_sha256=hashlib.sha256(leaf_cert).hexdigest(),
        leaf_key_sha256=hashlib.sha256(leaf_key).hexdigest(),
    )
    fds = {
        "ca_cert_fd": _sealed_memfd("aos-test-ca", wrong_ca),
        "leaf_cert_fd": _sealed_memfd("aos-test-leaf", leaf_cert),
        "leaf_key_fd": _sealed_memfd("aos-test-key", leaf_key),
        "binding_fd": _sealed_memfd("aos-test-binding", binding.to_bytes()),
    }
    try:
        with pytest.raises(ch.CertHelperError):
            ch.load_leaf_ssl_context(**fds, **TASK_CONTEXT)
    finally:
        for fd in fds.values():
            os.close(fd)


def test_loaded_context_does_not_retain_source_fds():
    material = ch.generate_task_material(**TASK_CONTEXT)
    verified = ch.verify_task_material(**_material_fds(material), **TASK_CONTEXT)
    context = ch.load_leaf_ssl_context(**_material_fds(material), **TASK_CONTEXT)
    ca_pem = verified.ca_cert_pem
    material.close()
    for fd in material.fds().values():
        with pytest.raises(OSError):
            os.fstat(fd)
    client, error, server_errors = _handshake(
        context, _client_context(ca_pem), TASK_CONTEXT["hostnames"][0]
    )
    assert error is None, error
    assert not server_errors
    client.close()


# -- end-to-end ---------------------------------------------------------------------


def test_end_to_end_exact_hostname_handshake(material, verified):
    server_context = ch.load_leaf_ssl_context(
        **_material_fds(material), **TASK_CONTEXT
    )
    trusting_only_task_ca = _client_context(verified.ca_cert_pem)
    client, error, server_errors = _handshake(
        server_context, trusting_only_task_ca, TASK_CONTEXT["hostnames"][0]
    )
    assert error is None, error
    assert not server_errors
    peer = client.getpeercert()
    assert tuple(peer["subjectAltName"]) == (
        ("DNS", TASK_CONTEXT["hostnames"][0]),
    )
    client.close()


def test_end_to_end_wrong_hostname_client_fails(material, verified):
    server_context = ch.load_leaf_ssl_context(
        **_material_fds(material), **TASK_CONTEXT
    )
    client, error, _server_errors = _handshake(
        server_context,
        _client_context(verified.ca_cert_pem),
        "evil.example.test",
    )
    assert client is None
    assert isinstance(error, ssl.SSLError)


def test_end_to_end_client_trusting_wrong_ca_fails(material, other_material):
    server_context = ch.load_leaf_ssl_context(
        **_material_fds(material), **TASK_CONTEXT
    )
    other_ca = ch.verify_task_material(
        **_material_fds(other_material), **_OTHER_CONTEXT
    ).ca_cert_pem
    client, error, _server_errors = _handshake(
        server_context, _client_context(other_ca), TASK_CONTEXT["hostnames"][0]
    )
    assert client is None
    assert isinstance(error, ssl.SSLError)
