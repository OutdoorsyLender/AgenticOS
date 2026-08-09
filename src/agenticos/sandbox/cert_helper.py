"""M4B-2 task-scoped certificate helper, sealed transport, and broker loader.

A trusted controller invokes a SHORT-LIVED helper subprocess that generates a
per-task CA keypair and a DISTINCT leaf keypair, issues a leaf certificate
valid only for the exact approved hostname, and returns all material as fully
sealed memfds. The CA private key is never serialized, never leaves the
helper's address space, and the helper exits before any hostile worker
execution. See docs/phase-zero/dependency-review-m4b2.md for the dependency
gate and the process-model rationale.

This module is standard-library-only at import time: ``cryptography`` is
imported exclusively inside the helper child code path, so the long-lived
broker runtime may import this module without taking the dependency.

Transport contract (mirrors network_identity.py / host_qualification.py):

- Four memfds are created by the controller with MFD_ALLOW_SEALING and passed
  to the helper via subprocess pass_fds (the controller copies stay CLOEXEC).
- The helper writes each payload, then applies F_SEAL_WRITE | F_SEAL_GROW |
  F_SEAL_SHRINK | F_SEAL_SEAL and VERIFIES the seals and write denial.
- A binding record (canonical JSON + SHA-256, following network_models.py)
  binds the material to task_id, task_generation, launch_nonce, the approved
  hostname, the policy digest, and the payload digests; it is carried in its
  own sealed memfd and re-verified against the payload memfds on every load.
- Broker-side verification fails closed on any stale or mismatched material.
"""

from __future__ import annotations

import fcntl
import gc
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Any

from .host_qualification import verify_memfd_sealed


_BINDING_VERSION = "AOSCERT/1"
_REQUEST_VERSION = "AOSCERTREQ/1"
_MAX_UNSIGNED_64 = (1 << 64) - 1
_MAX_CERT_BYTES = 16384
_MAX_KEY_BYTES = 16384
_MAX_BINDING_BYTES = 4096
_MAX_REQUEST_BYTES = 4096
_MAX_STDERR_BYTES = 4096
_TASK_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LOWER_HEX_32_RE = re.compile(r"[0-9a-f]{32}\Z")
_LOWER_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_HOSTNAME_LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z")
_REQUIRED_SEALS = (
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
)
_MATERIAL_FD_NAMES = ("ca_cert", "leaf_cert", "leaf_key", "binding")
_MEMFD_NAMES = {
    "ca_cert": "aos-task-ca-cert",
    "leaf_cert": "aos-task-leaf-cert",
    "leaf_key": "aos-task-leaf-key",
    "binding": "aos-task-cert-binding",
}
_DEFAULT_HELPER_TIMEOUT_SECONDS = 15.0
_AUDIT_TIMEOUT_SECONDS = 5.0


class CertHelperError(RuntimeError):
    """Task certificate material failed closed generation or verification."""


@dataclass(frozen=True)
class CertBinding:
    """Canonical binding between sealed certificate material and one task."""

    version: str
    task_id: str
    task_generation: int
    launch_nonce: str
    hostname: str
    policy_digest: str
    ca_cert_sha256: str
    leaf_cert_sha256: str
    leaf_key_sha256: str

    def __post_init__(self) -> None:
        if type(self.version) is not str or self.version != _BINDING_VERSION:
            raise CertHelperError(f"version must be {_BINDING_VERSION}")
        _require_task_context(
            self.task_id,
            self.task_generation,
            self.launch_nonce,
            self.policy_digest,
        )
        _require_hostname(self.hostname)
        for name in ("ca_cert_sha256", "leaf_cert_sha256", "leaf_key_sha256"):
            value = getattr(self, name)
            if type(value) is not str or not _LOWER_HEX_64_RE.fullmatch(value):
                raise CertHelperError(f"{name} must be lowercase hexadecimal")

    def to_bytes(self) -> bytes:
        payload = {
            "version": self.version,
            "task_id": self.task_id,
            "task_generation": self.task_generation,
            "launch_nonce": self.launch_nonce,
            "hostname": self.hostname,
            "policy_digest": self.policy_digest,
            "ca_cert_sha256": self.ca_cert_sha256,
            "leaf_cert_sha256": self.leaf_cert_sha256,
            "leaf_key_sha256": self.leaf_key_sha256,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        if not 0 < len(encoded) <= _MAX_BINDING_BYTES:
            raise CertHelperError("certificate binding record is empty or oversized")
        return encoded

    @classmethod
    def from_bytes(cls, payload: bytes) -> CertBinding:
        decoded = _require_exact_fields(
            _decode_json(payload, maximum=_MAX_BINDING_BYTES, label="cert binding"),
            {
                "version",
                "task_id",
                "task_generation",
                "launch_nonce",
                "hostname",
                "policy_digest",
                "ca_cert_sha256",
                "leaf_cert_sha256",
                "leaf_key_sha256",
            },
            "cert binding",
        )
        try:
            binding = cls(
                version=decoded["version"],
                task_id=decoded["task_id"],
                task_generation=decoded["task_generation"],
                launch_nonce=decoded["launch_nonce"],
                hostname=decoded["hostname"],
                policy_digest=decoded["policy_digest"],
                ca_cert_sha256=decoded["ca_cert_sha256"],
                leaf_cert_sha256=decoded["leaf_cert_sha256"],
                leaf_key_sha256=decoded["leaf_key_sha256"],
            )
        except CertHelperError:
            raise
        except (TypeError, ValueError) as exc:
            raise CertHelperError("cert binding fields are invalid") from exc
        if binding.to_bytes() != payload:
            raise CertHelperError("cert binding encoding is not canonical")
        return binding


def binding_digest(binding: CertBinding) -> str:
    """Return the lowercase SHA-256 digest of the canonical binding bytes."""
    if type(binding) is not CertBinding:
        raise CertHelperError("binding must be a CertBinding")
    return hashlib.sha256(binding.to_bytes()).hexdigest()


# -- strict input validation ----------------------------------------------------


def _require_positive_u64(name: str, value: object) -> None:
    if type(value) is not int or not 0 < value <= _MAX_UNSIGNED_64:
        raise CertHelperError(f"{name} must be a positive unsigned 64-bit integer")


def _require_hostname(value: object) -> None:
    if type(value) is not str or not value.isascii() or not 1 <= len(value) <= 253:
        raise CertHelperError("hostname must be a bounded ASCII DNS name")
    labels = value.split(".")
    if any(_HOSTNAME_LABEL_RE.fullmatch(label) is None for label in labels):
        raise CertHelperError("hostname must be lowercase LDH labels, no wildcard")


def _require_task_context(
    task_id: object, generation: object, nonce: object, digest: object
) -> None:
    if type(task_id) is not str or not _TASK_ID_RE.fullmatch(task_id):
        raise CertHelperError("task_id must be a bounded ASCII identifier")
    _require_positive_u64("task_generation", generation)
    if type(nonce) is not str or not _LOWER_HEX_32_RE.fullmatch(nonce):
        raise CertHelperError("launch_nonce must be lowercase hexadecimal")
    if type(digest) is not str or not _LOWER_HEX_64_RE.fullmatch(digest):
        raise CertHelperError("policy_digest must be lowercase hexadecimal")


def _require_exact_fields(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise CertHelperError(f"{label} has missing or unknown fields")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CertHelperError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise CertHelperError(f"non-finite JSON number is forbidden: {value}")


def _decode_json(payload: bytes, *, maximum: int, label: str) -> dict[str, Any]:
    if type(payload) is not bytes or not 0 < len(payload) <= maximum:
        raise CertHelperError(f"{label} is empty or oversized")
    try:
        text = payload.decode("ascii")
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except CertHelperError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CertHelperError(f"{label} is not strict ASCII JSON") from exc
    if type(decoded) is not dict:
        raise CertHelperError(f"{label} must be a JSON object")
    return decoded


# -- sealed memfd primitives -----------------------------------------------------


def _write_exact(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise CertHelperError("short write to sealed certificate object")
        offset += written


def _duplicate_cloexec(fd: int, label: str) -> int:
    if type(fd) is not int or fd < 0:
        raise CertHelperError(f"{label} must be a non-negative descriptor")
    duplicate: int | None = None
    completed = False
    try:
        duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
        if not fcntl.fcntl(duplicate, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            raise CertHelperError(f"duplicated {label} is not close-on-exec")
        completed = True
        return duplicate
    except CertHelperError:
        raise
    except OSError as exc:
        raise CertHelperError(f"could not securely duplicate {label}") from exc
    finally:
        if duplicate is not None and not completed:
            try:
                os.close(duplicate)
            except OSError:
                pass


def _read_sealed_fd_payload(fd: int, label: str, maximum: int) -> bytes:
    """Duplicate, re-verify seals and kernel identity, and return the payload."""
    duplicate: int | None = None
    try:
        duplicate = _duplicate_cloexec(fd, label)
        before = os.fstat(duplicate)
        if not stat.S_ISREG(before.st_mode):
            raise CertHelperError(f"{label} is not a regular memfd-like object")
        if before.st_dev <= 0 or before.st_ino <= 0:
            raise CertHelperError(f"{label} lacks positive kernel identity")
        if not 0 < before.st_size <= maximum:
            raise CertHelperError(f"{label} is empty or oversized")
        seals_before = fcntl.fcntl(duplicate, fcntl.F_GET_SEALS)
        if seals_before & _REQUIRED_SEALS != _REQUIRED_SEALS:
            raise CertHelperError(f"{label} is not fully sealed")

        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(duplicate, before.st_size - offset, offset)
            if not chunk:
                raise CertHelperError(f"{label} read ended early")
            chunks.append(chunk)
            offset += len(chunk)
        if os.pread(duplicate, 1, before.st_size):
            raise CertHelperError(f"{label} exceeded its verified size")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise CertHelperError(f"{label} read length changed")

        after = os.fstat(duplicate)
        seals_after = fcntl.fcntl(duplicate, fcntl.F_GET_SEALS)
        if seals_after & _REQUIRED_SEALS != _REQUIRED_SEALS:
            raise CertHelperError(f"{label} seals changed during verification")
        if (
            after.st_dev,
            after.st_ino,
            stat.S_IFMT(after.st_mode),
            after.st_size,
        ) != (
            before.st_dev,
            before.st_ino,
            stat.S_IFMT(before.st_mode),
            before.st_size,
        ):
            raise CertHelperError(f"{label} kernel identity changed during verification")
        return payload
    except CertHelperError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise CertHelperError(f"{label} verification failed") from exc
    finally:
        if duplicate is not None:
            os.close(duplicate)


# -- broker-side verification ----------------------------------------------------


@dataclass(frozen=True)
class VerifiedTaskMaterial:
    """Sealed certificate material authenticated against one task context."""

    binding: CertBinding
    ca_cert_pem: bytes
    leaf_cert_pem: bytes


def verify_task_material(
    *,
    ca_cert_fd: int,
    leaf_cert_fd: int,
    leaf_key_fd: int,
    binding_fd: int,
    task_id: str,
    task_generation: int,
    launch_nonce: str,
    hostname: str,
    policy_digest: str,
) -> VerifiedTaskMaterial:
    """Fail closed unless the sealed fds carry material for exactly this task.

    Rejects stale or mismatched material: wrong task, generation, nonce,
    hostname, or policy digest, and any payload whose digest diverges from the
    sealed binding record.
    """
    _require_task_context(task_id, task_generation, launch_nonce, policy_digest)
    _require_hostname(hostname)
    ca_cert_pem = _read_sealed_fd_payload(ca_cert_fd, "ca certificate", _MAX_CERT_BYTES)
    leaf_cert_pem = _read_sealed_fd_payload(
        leaf_cert_fd, "leaf certificate", _MAX_CERT_BYTES
    )
    leaf_key_pem = _read_sealed_fd_payload(
        leaf_key_fd, "leaf private key", _MAX_KEY_BYTES
    )
    binding_payload = _read_sealed_fd_payload(
        binding_fd, "cert binding", _MAX_BINDING_BYTES
    )
    binding = CertBinding.from_bytes(binding_payload)
    if (
        binding.task_id != task_id
        or binding.task_generation != task_generation
        or binding.launch_nonce != launch_nonce
        or binding.hostname != hostname
        or binding.policy_digest != policy_digest
    ):
        raise CertHelperError("certificate material context did not authenticate")
    if (
        binding.ca_cert_sha256 != hashlib.sha256(ca_cert_pem).hexdigest()
        or binding.leaf_cert_sha256 != hashlib.sha256(leaf_cert_pem).hexdigest()
        or binding.leaf_key_sha256 != hashlib.sha256(leaf_key_pem).hexdigest()
    ):
        raise CertHelperError("certificate material payload digests do not authenticate")
    return VerifiedTaskMaterial(
        binding=binding, ca_cert_pem=ca_cert_pem, leaf_cert_pem=leaf_cert_pem
    )


# -- broker-side TLS context loader ----------------------------------------------


def _run_server_handshake(
    server_context: ssl.SSLContext, raw_socket: socket.socket, errors: list
) -> None:
    try:
        server_socket = server_context.wrap_socket(raw_socket, server_side=True)
    except (ssl.SSLError, OSError) as exc:
        errors.append(exc)
        try:
            raw_socket.close()
        except OSError:
            pass
    else:
        try:
            server_socket.unwrap()
        except (ssl.SSLError, OSError):
            pass
        finally:
            server_socket.close()


def _audit_handshake(
    server_context: ssl.SSLContext, ca_cert_pem: bytes, hostname: str
) -> None:
    """Prove the loaded leaf serves the exact hostname under only the task CA.

    A standard-library client that trusts ONLY the CA certificate payload
    performs a real TLS handshake against ``server_context`` over a socket
    pair, with hostname checking enabled for ``hostname``. Any failure —
    wrong key, broken chain, SAN mismatch — fails closed. The peer's SAN set
    must then be exactly the approved hostname (no wildcard, no extra SANs).
    """
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    client_context.verify_mode = ssl.CERT_REQUIRED
    client_context.check_hostname = True
    try:
        client_context.load_verify_locations(cadata=ca_cert_pem.decode("ascii"))
    except (UnicodeDecodeError, ssl.SSLError) as exc:
        raise CertHelperError("sealed CA certificate is not valid PEM") from exc

    left, right = socket.socketpair()
    server_errors: list = []
    server = threading.Thread(
        target=_run_server_handshake,
        args=(server_context, left, server_errors),
        daemon=True,
    )
    client_socket: ssl.SSLSocket | None = None
    try:
        right.settimeout(_AUDIT_TIMEOUT_SECONDS)
        server.start()
        client_socket = client_context.wrap_socket(right, server_hostname=hostname)
        peer = client_socket.getpeercert()
        if not peer:
            raise CertHelperError("audit handshake returned no peer certificate")
        san = peer.get("subjectAltName", ())
        if tuple(san) != (("DNS", hostname),):
            raise CertHelperError(
                "leaf SAN set is not exactly the approved hostname"
            )
    except CertHelperError:
        raise
    except (ssl.SSLError, OSError) as exc:
        raise CertHelperError(
            "leaf does not authenticate under the sealed task CA"
        ) from exc
    finally:
        if client_socket is not None:
            client_socket.close()
        else:
            try:
                right.close()
            except OSError:
                pass
        server.join(_AUDIT_TIMEOUT_SECONDS * 2)
    if server_errors:
        raise CertHelperError(
            "leaf does not authenticate under the sealed task CA"
        ) from server_errors[0]
    if server.is_alive():
        raise CertHelperError("audit handshake did not finish in bounded time")


def load_leaf_ssl_context(
    *,
    ca_cert_fd: int,
    leaf_cert_fd: int,
    leaf_key_fd: int,
    binding_fd: int,
    task_id: str,
    task_generation: int,
    launch_nonce: str,
    hostname: str,
    policy_digest: str,
) -> ssl.SSLContext:
    """Build a server SSLContext from the sealed FDs, retaining none of them.

    The chain and key are loaded through the ``/proc/self/fd/N`` path form
    from short-lived CLOEXEC duplicates; ``load_cert_chain`` itself fails
    unless the leaf private key corresponds to the leaf certificate public
    key. A self-audit handshake then proves the leaf chains to the sealed
    task CA and that its SAN set is exactly the approved hostname. Once this
    function returns, the caller may close every source fd; the context
    holds the material in OpenSSL memory only.
    """
    verified = verify_task_material(
        ca_cert_fd=ca_cert_fd,
        leaf_cert_fd=leaf_cert_fd,
        leaf_key_fd=leaf_key_fd,
        binding_fd=binding_fd,
        task_id=task_id,
        task_generation=task_generation,
        launch_nonce=launch_nonce,
        hostname=hostname,
        policy_digest=policy_digest,
    )
    cert_duplicate = _duplicate_cloexec(leaf_cert_fd, "leaf certificate")
    key_duplicate: int | None = None
    context: ssl.SSLContext | None = None
    try:
        key_duplicate = _duplicate_cloexec(leaf_key_fd, "leaf private key")
        candidate = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        candidate.minimum_version = ssl.TLSVersion.TLSv1_2
        candidate.load_cert_chain(
            certfile=f"/proc/self/fd/{cert_duplicate}",
            keyfile=f"/proc/self/fd/{key_duplicate}",
        )
        context = candidate
    except (ssl.SSLError, OSError) as exc:
        raise CertHelperError(
            "sealed leaf certificate/key could not be loaded"
        ) from exc
    finally:
        os.close(cert_duplicate)
        if key_duplicate is not None:
            os.close(key_duplicate)
    _audit_handshake(context, verified.ca_cert_pem, hostname)
    return context


# -- controller-side helper invocation --------------------------------------------


@dataclass
class SealedTaskMaterial:
    """Owned sealed certificate material returned by the helper subprocess."""

    ca_cert_fd: int
    leaf_cert_fd: int
    leaf_key_fd: int
    binding_fd: int
    binding: CertBinding
    helper_pid: int
    _closed: bool = False

    def fds(self) -> dict[str, int]:
        return {
            "ca_cert": self.ca_cert_fd,
            "leaf_cert": self.leaf_cert_fd,
            "leaf_key": self.leaf_key_fd,
            "binding": self.binding_fd,
        }

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for fd in self.fds().values():
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self) -> SealedTaskMaterial:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _create_sealable_memfd(name: str) -> int:
    fd: int | None = None
    completed = False
    try:
        fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        if seals != 0:
            raise CertHelperError("new certificate memfd is unexpectedly sealed")
        completed = True
        return fd
    except CertHelperError:
        raise
    except (AttributeError, OSError) as exc:
        raise CertHelperError("could not create sealable certificate memfd") from exc
    finally:
        if fd is not None and not completed:
            try:
                os.close(fd)
            except OSError:
                pass


def _helper_environment() -> dict[str, str]:
    """Child environment: inherit, but guarantee the agenticos source root."""
    env = dict(os.environ)
    src_root = str(Path(__file__).resolve().parents[2])
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        src_root if not existing else src_root + os.pathsep + existing
    )
    return env


def _spawn_helper(request: dict[str, Any], fds: dict[str, int]) -> subprocess.Popen:
    """Spawn the short-lived helper child; the caller bounds its lifetime."""
    try:
        return subprocess.Popen(
            [sys.executable, "-m", "agenticos.sandbox.cert_helper"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=tuple(fds.values()),
            env=_helper_environment(),
        )
    except (OSError, ValueError) as exc:
        raise CertHelperError("could not spawn the certificate helper") from exc


def generate_task_material(
    *,
    task_id: str,
    task_generation: int,
    launch_nonce: str,
    hostname: str,
    policy_digest: str,
    timeout_seconds: float = _DEFAULT_HELPER_TIMEOUT_SECONDS,
) -> SealedTaskMaterial:
    """Generate per-task certificate material in a short-lived subprocess.

    The helper child generates the CA and leaf keypairs, seals every output
    memfd, destroys the CA private key in its own address space, and exits
    before this function returns. The controller then re-verifies seals,
    binding, and payload digests before accepting the material.
    """
    _require_task_context(task_id, task_generation, launch_nonce, policy_digest)
    _require_hostname(hostname)
    if (
        type(timeout_seconds) not in (int, float)
        or not 0 < timeout_seconds <= 120
    ):
        raise CertHelperError("helper timeout must be a bounded positive number")

    fds: dict[str, int] = {}
    try:
        for name in _MATERIAL_FD_NAMES:
            fds[name] = _create_sealable_memfd(_MEMFD_NAMES[name])
        request = {
            "version": _REQUEST_VERSION,
            "task_id": task_id,
            "task_generation": task_generation,
            "launch_nonce": launch_nonce,
            "hostname": hostname,
            "policy_digest": policy_digest,
            "fds": {name: fds[name] for name in _MATERIAL_FD_NAMES},
        }
        payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        if not 0 < len(payload) <= _MAX_REQUEST_BYTES:
            raise CertHelperError("helper request is empty or oversized")

        process = _spawn_helper(request, fds)
        try:
            stdout, stderr = process.communicate(payload, timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise CertHelperError("certificate helper exceeded its time bound") from exc
        if process.returncode != 0:
            detail = stderr[:_MAX_STDERR_BYTES].decode("ascii", errors="replace")
            raise CertHelperError(
                f"certificate helper failed with status {process.returncode}: "
                f"{detail.strip()}"
            )
        if stdout or stderr:
            raise CertHelperError("certificate helper produced unexpected output")

        verified = verify_task_material(
            ca_cert_fd=fds["ca_cert"],
            leaf_cert_fd=fds["leaf_cert"],
            leaf_key_fd=fds["leaf_key"],
            binding_fd=fds["binding"],
            task_id=task_id,
            task_generation=task_generation,
            launch_nonce=launch_nonce,
            hostname=hostname,
            policy_digest=policy_digest,
        )
        return SealedTaskMaterial(
            ca_cert_fd=fds["ca_cert"],
            leaf_cert_fd=fds["leaf_cert"],
            leaf_key_fd=fds["leaf_key"],
            binding_fd=fds["binding"],
            binding=verified.binding,
            helper_pid=process.pid,
        )
    except BaseException:
        for fd in fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        raise


# -- helper child entry point ------------------------------------------------------


def _child_build_material(
    *,
    task_id: str,
    task_generation: int,
    launch_nonce: str,
    hostname: str,
    policy_digest: str,
) -> dict[str, bytes]:
    """Generate keys/certs and return the four sealed payload byte strings.

    Runs ONLY inside the short-lived helper child. The CA private key is
    referenced only transiently for signing, is never serialized, and its
    reference is dropped before this function returns.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(seconds=300)
    ca_not_after = now + datetime.timedelta(hours=24)
    leaf_not_after = now + datetime.timedelta(hours=12)

    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    leaf_private_key = ec.generate_private_key(ec.SECP256R1())

    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AgenticOS M4B-2 task CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(ca_not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    leaf_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "AgenticOS M4B-2 task leaf")]
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(leaf_not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_private_key.public_key()
            ),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    # The CA private key is destroyed here: never serialized, never written,
    # and its last reference is dropped before any payload is emitted.
    del ca_private_key
    gc.collect()

    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    leaf_cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    leaf_key_pem = leaf_private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    del leaf_private_key

    binding = CertBinding(
        version=_BINDING_VERSION,
        task_id=task_id,
        task_generation=task_generation,
        launch_nonce=launch_nonce,
        hostname=hostname,
        policy_digest=policy_digest,
        ca_cert_sha256=hashlib.sha256(ca_cert_pem).hexdigest(),
        leaf_cert_sha256=hashlib.sha256(leaf_cert_pem).hexdigest(),
        leaf_key_sha256=hashlib.sha256(leaf_key_pem).hexdigest(),
    )
    return {
        "ca_cert": ca_cert_pem,
        "leaf_cert": leaf_cert_pem,
        "leaf_key": leaf_key_pem,
        "binding": binding.to_bytes(),
    }


def _child_write_and_seal(fd: int, payload: bytes, label: str) -> None:
    status = os.fstat(fd)
    if not stat.S_ISREG(status.st_mode) or status.st_size != 0:
        raise CertHelperError(f"{label} output object is not a fresh memfd")
    if fcntl.fcntl(fd, fcntl.F_GET_SEALS) != 0:
        raise CertHelperError(f"{label} output object is unexpectedly sealed")
    if not 0 < len(payload) <= _MAX_CERT_BYTES:
        raise CertHelperError(f"{label} payload is empty or oversized")
    _write_exact(fd, payload)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _REQUIRED_SEALS)
    try:
        verify_memfd_sealed(fd)
    except Exception as exc:
        raise CertHelperError(f"{label} did not acquire full sealing") from exc
    os.lseek(fd, 0, os.SEEK_SET)


def _run_helper_child() -> None:
    if sys.argv[1:]:
        raise CertHelperError("helper accepts no command-line arguments")
    raw = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
    request = _require_exact_fields(
        _decode_json(raw, maximum=_MAX_REQUEST_BYTES, label="helper request"),
        {
            "version",
            "task_id",
            "task_generation",
            "launch_nonce",
            "hostname",
            "policy_digest",
            "fds",
        },
        "helper request",
    )
    if request["version"] != _REQUEST_VERSION:
        raise CertHelperError(f"helper request version must be {_REQUEST_VERSION}")
    _require_task_context(
        request["task_id"],
        request["task_generation"],
        request["launch_nonce"],
        request["policy_digest"],
    )
    _require_hostname(request["hostname"])
    fds = _require_exact_fields(
        request["fds"], set(_MATERIAL_FD_NAMES), "helper request fds"
    )
    for name, fd in fds.items():
        if type(fd) is not int or fd < 0:
            raise CertHelperError(f"helper fd {name} must be a non-negative integer")
    if len(set(fds.values())) != len(_MATERIAL_FD_NAMES):
        raise CertHelperError("helper fds must be distinct")

    payloads = _child_build_material(
        task_id=request["task_id"],
        task_generation=request["task_generation"],
        launch_nonce=request["launch_nonce"],
        hostname=request["hostname"],
        policy_digest=request["policy_digest"],
    )
    for name in _MATERIAL_FD_NAMES:
        _child_write_and_seal(fds[name], payloads[name], name)
    gc.collect()


def _helper_main() -> int:
    try:
        _run_helper_child()
    except CertHelperError as exc:
        message = f"cert-helper: {exc}"
        sys.stderr.write(message[:256] + "\n")
        return 2
    except Exception as exc:  # fail closed without leaking internals
        sys.stderr.write(f"cert-helper: internal {type(exc).__name__}\n")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(_helper_main())


__all__ = [
    "CertBinding",
    "CertHelperError",
    "SealedTaskMaterial",
    "VerifiedTaskMaterial",
    "binding_digest",
    "generate_task_material",
    "load_leaf_ssl_context",
    "verify_task_material",
]
