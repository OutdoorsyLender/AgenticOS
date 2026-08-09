"""M4B-2 host qualification manifest and fail-closed host verification.

M4B-2 security claims (exact-hostname authenticated HTTPS, ECH denial,
sealed immutable policy) depend on exact host properties — never on version
strings alone. This module computes a canonical, digest-able *host
qualification manifest* covering the security-relevant identity classes of
every component the broker boundary relies on, and verifies the current host
against a recorded manifest, failing closed on ANY divergence and reporting
exactly which field changed.

Identity classes recorded per component:

- ``upstream_version``     — the component's own version identity.
- ``distro_revision``      — the dpkg package revision, where dpkg owns the
                             artifact (carries the distro security revision).
- ``artifacts``            — SHA-256 digest of each runtime executable or
                             shared library that is actually loaded/used.
- ``security_patch_coverage`` — where USN/security-patch coverage is
                             recorded (the dpkg revision, or curl's reported
                             "security patched" suffix), or "not-recordable".
- ``compiled_features``    — compile-time posture, e.g. whether the loaded
                             libssl exports ECH acceptance machinery.
- ``behavior_probes``      — authoritative runtime probes (fail-closed).

The recorded host has TWO independent TLS client stacks: curl uses
libcurl/OpenSSL while Git HTTPS (git-remote-https) uses libcurl-gnutls/
GnuTLS. Both are qualified independently; qualifying curl never qualifies
git.

All probing is strictly read-only: no system modification, no package
installation, no network mutation (the curl ECH probe targets
127.0.0.1:1 and is rejected during option parsing before any connection;
the resolver probe uses the local "localhost." name only).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Optional

from .capabilities import parse_wsl_version

HOST_QUALIFICATION_VERSION = "AOSHOSTQUAL/1"

_MAX_STRING_LENGTH = 1024

COMPONENT_NAMES = (
    "python",
    "python_ssl",
    "openssl_runtime",
    "curl",
    "git_https",
    "gnutls",
    "bubblewrap",
    "kernel_wsl",
    "ca_certificates",
)

# Symbols whose presence in the loaded libssl would indicate ECH acceptance
# machinery (mirrors the M4B-2 ECH spike startup probe).
ECH_MACHINERY_SYMBOLS = (
    "SSL_CTX_set1_echstore",
    "SSL_ech_get1_status",
    "SSL_ech_set1_echconfig",
    "OSSL_ech_get1_helper",
)

_LDD_LINE_RE = re.compile(r"\s*(\S+)\s+=>\s+(/\S+)\s+\(0x[0-9a-f]+\)\s*\Z")
_LDCONFIG_LINE_RE = re.compile(r"\s*(\S+)\s+\([^)]*\)\s+=>\s+(/\S+)\s*\Z")


class HostQualificationError(Exception):
    """The current host cannot be qualified; a probe failed closed."""


class HostQualificationMismatchError(HostQualificationError):
    """The observed host diverges from the recorded qualification manifest."""

    def __init__(self, mismatches: list[str]) -> None:
        self.mismatches = tuple(mismatches)
        message = f"host qualification mismatch: {self.mismatches[0]}"
        if len(self.mismatches) > 1:
            message += f" (+{len(self.mismatches) - 1} more)"
        super().__init__(message)


# -- small probe helpers (all read-only) -------------------------------------


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=5.0, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HostQualificationError(
            f"probe command {argv[0]!r} failed: {type(exc).__name__}"
        ) from exc


def _require_output(completed: subprocess.CompletedProcess, what: str) -> str:
    if completed.returncode != 0:
        raise HostQualificationError(
            f"{what} probe exited with status {completed.returncode}"
        )
    return completed.stdout


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact(path: os.PathLike | str, what: str) -> dict:
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise HostQualificationError(f"{what} artifact missing: {resolved}")
    try:
        return {"path": str(resolved), "sha256": _sha256_path(resolved)}
    except OSError as exc:
        raise HostQualificationError(
            f"{what} artifact unreadable: {resolved}: {type(exc).__name__}"
        ) from exc


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise HostQualificationError(f"required tool {name!r} not found on PATH")
    return path


def _dpkg_query(*args: str) -> Optional[str]:
    exe = shutil.which("dpkg-query")
    if exe is None:
        return None
    try:
        completed = subprocess.run(
            [exe, *args], capture_output=True, text=True, timeout=5.0, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _dpkg_revision_for_path(path: os.PathLike | str) -> Optional[str]:
    """Return the owning dpkg package revision for an artifact, if owned."""
    resolved = str(Path(path).resolve())
    owner = _dpkg_query("-S", resolved)
    if owner is None:
        return None
    # `dpkg-query -S` output: "pkg: /path" or "pkg1, pkg2: /path".
    package = owner.split(":", 1)[0].split(",")[0].strip()
    if not package:
        return None
    return _dpkg_query("-W", "-f=${Version}", package)


def _dpkg_revision_for_package(package: str) -> Optional[str]:
    return _dpkg_query("-W", "-f=${Version}", package)


def _ldd_libraries(path: os.PathLike | str) -> dict[str, str]:
    """Map soname -> absolute library path from ldd output (host binaries only)."""
    output = _require_output(_run(["ldd", str(path)]), f"ldd({path})")
    libraries: dict[str, str] = {}
    for line in output.splitlines():
        match = _LDD_LINE_RE.match(line)
        if match:
            libraries[match.group(1)] = match.group(2)
    return libraries


def _ldconfig_path(soname: str) -> Optional[Path]:
    output = _require_output(_run(["ldconfig", "-p"]), "ldconfig -p")
    for line in output.splitlines():
        match = _LDCONFIG_LINE_RE.match(line)
        if match and match.group(1) == soname:
            return Path(match.group(2))
    return None


def _loaded_tls_libraries() -> dict[str, Path]:
    """Resolve the libssl/libcrypto actually loaded into this process."""
    found: dict[str, Path] = {}
    try:
        maps = Path("/proc/self/maps").read_text(errors="replace")
    except OSError as exc:
        raise HostQualificationError("/proc/self/maps unreadable") from exc
    for line in maps.splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[-1].startswith("/"):
            continue
        name = parts[-1].rsplit("/", 1)[-1]
        for key in ("libssl", "libcrypto"):
            if name.startswith(f"{key}.so") and key not in found:
                found[key] = Path(parts[-1]).resolve()
    missing = {"libssl", "libcrypto"} - found.keys()
    if missing:
        raise HostQualificationError(
            f"TLS libraries not loaded in this process: {sorted(missing)}"
        )
    return found


# -- behavior probes (fail-closed) --------------------------------------------


def verify_memfd_sealed(fd: int) -> None:
    """Require all four immutable seals present and writes denied on ``fd``."""
    import fcntl

    required = (
        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    )
    seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
    if seals & required != required:
        raise HostQualificationError(
            f"memfd is missing required seals: seals={seals:#x} required={required:#x}"
        )
    try:
        os.write(fd, b"x")
    except OSError:
        return
    raise HostQualificationError("write succeeded on a fully sealed memfd")


def probe_memfd_full_sealing() -> None:
    """Prove memfd_create + full sealing + write denial works on this kernel."""
    if not hasattr(os, "memfd_create"):
        raise HostQualificationError("os.memfd_create is not available")
    import fcntl

    flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    try:
        fd = os.memfd_create("aos-hostqual-seal-probe", flags)
    except OSError as exc:
        raise HostQualificationError(
            f"memfd_create failed: {type(exc).__name__}"
        ) from exc
    try:
        os.write(fd, b"aos-hostqual")
        fcntl.fcntl(
            fd,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        verify_memfd_sealed(fd)
    finally:
        os.close(fd)


def _probe_python_ssl_behavior() -> dict:
    probes: dict[str, str] = {}
    if not hasattr(ssl, "OP_NO_RENEGOTIATION"):
        raise HostQualificationError("ssl.OP_NO_RENEGOTIATION is not exposed")
    probes["op_no_renegotiation_exposed"] = "pass"
    if not hasattr(ssl, "MemoryBIO") or not hasattr(ssl, "SSLObject"):
        raise HostQualificationError("ssl.MemoryBIO/SSLObject are not available")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.set_alpn_protocols(["http/1.1"])
        tls_object = context.wrap_bio(
            ssl.MemoryBIO(),
            ssl.MemoryBIO(),
            server_side=False,
            server_hostname="approved.example.test",
        )
        if not isinstance(tls_object, ssl.SSLObject):
            raise HostQualificationError("wrap_bio did not return an SSLObject")
        tls_object.selected_alpn_protocol()
    except (ssl.SSLError, ValueError) as exc:
        raise HostQualificationError(
            f"ALPN set/get probe failed: {type(exc).__name__}"
        ) from exc
    probes["memory_bio_ssl_object"] = "pass"
    probes["alpn_set_get"] = "pass"
    return probes


def _probe_curl_ech_absent(curl_path: str) -> None:
    """Require that this curl/libcurl cannot emit ECH (fail-closed)."""
    completed = _run(
        [curl_path, "--ech", "false", "--max-time", "2", "https://127.0.0.1:1/"]
    )
    if "does not support this" not in completed.stderr:
        raise HostQualificationError(
            "curl did not refuse ECH; this libcurl may be able to emit ECH"
        )


def _probe_getaddrinfo_terminal_dot() -> str:
    """Record (only) whether flags=0 resolution of a terminal-dot name works."""
    try:
        socket.getaddrinfo("localhost.", 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError:
        return "unsupported"
    return "supported"


# -- component qualification ---------------------------------------------------


def _component_python() -> dict:
    executable = Path(sys.executable).resolve()
    revision = _dpkg_revision_for_path(executable)
    build = platform.python_build()
    return {
        "upstream_version": platform.python_version(),
        "distro_revision": revision,
        "security_patch_coverage": revision or "not-recordable",
        "artifacts": {"executable": _artifact(executable, "python interpreter")},
        "compiled_features": {
            "hexversion": sys.hexversion,
            "build": f"{build[0]} {build[1]}",
        },
        "behavior_probes": {},
    }


def _component_python_ssl(tls_libraries: Mapping[str, Path]) -> dict:
    import _ssl

    revision = _dpkg_revision_for_path(tls_libraries["libssl"])
    return {
        "upstream_version": ssl.OPENSSL_VERSION,
        "distro_revision": revision,
        "security_patch_coverage": revision or "not-recordable",
        "artifacts": {
            "_ssl_extension": _artifact(_ssl.__file__, "_ssl extension"),
            "libssl": _artifact(tls_libraries["libssl"], "loaded libssl"),
            "libcrypto": _artifact(tls_libraries["libcrypto"], "loaded libcrypto"),
        },
        "compiled_features": {"openssl_version": ssl.OPENSSL_VERSION},
        "behavior_probes": _probe_python_ssl_behavior(),
    }


def _component_openssl_runtime(tls_libraries: Mapping[str, Path]) -> dict:
    libssl_path = tls_libraries["libssl"]
    library = ctypes.CDLL(str(libssl_path))
    library.OpenSSL_version.restype = ctypes.c_char_p
    version = library.OpenSSL_version(0).decode("ascii", errors="strict")
    present = sorted(
        symbol for symbol in ECH_MACHINERY_SYMBOLS if hasattr(library, symbol)
    )
    if present:
        raise HostQualificationError(
            f"loaded libssl exports ECH acceptance machinery: {present}"
        )
    revision = _dpkg_revision_for_path(libssl_path)
    return {
        "upstream_version": version,
        "distro_revision": revision,
        "security_patch_coverage": revision or "not-recordable",
        "artifacts": {
            "libssl": _artifact(libssl_path, "libssl"),
            "libcrypto": _artifact(tls_libraries["libcrypto"], "libcrypto"),
        },
        "compiled_features": {
            "ech_machinery": "absent",
            "ech_symbols_present": [],
        },
        "behavior_probes": {"ech_symbol_absence": "pass"},
    }


def _component_curl() -> dict:
    exe = _require_tool("curl")
    output = _require_output(_run([exe, "--version"]), "curl --version")
    lines = output.splitlines()
    tokens = lines[0].split()
    if len(tokens) < 2 or tokens[0] != "curl":
        raise HostQualificationError(f"unrecognized curl --version line: {lines[0]!r}")
    upstream_version = tokens[1]
    tls_backend = "unidentified"
    for index, token in enumerate(tokens):
        if token.startswith("libcurl/") and index + 1 < len(tokens):
            tls_backend = tokens[index + 1]
            break
    if tls_backend == "unidentified":
        raise HostQualificationError("curl TLS backend could not be identified")
    security_patched = None
    for line in lines[1:]:
        marker = "security patched:"
        if marker in line:
            security_patched = line.split(marker, 1)[1].strip()
            break
    libraries = _ldd_libraries(Path(exe).resolve())
    libcurl = next(
        (path for soname, path in libraries.items() if soname.startswith("libcurl.so")),
        None,
    )
    if libcurl is None:
        raise HostQualificationError("libcurl not found in curl linkage")
    _probe_curl_ech_absent(exe)
    revision = _dpkg_revision_for_path(exe)
    return {
        "upstream_version": upstream_version,
        "distro_revision": revision,
        "security_patch_coverage": security_patched or revision or "not-recordable",
        "artifacts": {
            "curl": _artifact(exe, "curl"),
            "libcurl": _artifact(libcurl, "libcurl"),
        },
        "compiled_features": {"tls_backend": tls_backend, "ech_support": "absent"},
        "behavior_probes": {"ech_cannot_emit": "pass"},
    }


def _component_git_https() -> dict:
    git = _require_tool("git")
    version_output = _require_output(_run([git, "--version"]), "git --version")
    tokens = version_output.split()
    if len(tokens) < 3 or tokens[:2] != ["git", "version"]:
        raise HostQualificationError(
            f"unrecognized git --version line: {version_output!r}"
        )
    exec_path = _require_output(_run([git, "--exec-path"]), "git --exec-path").strip()
    remote_helper = Path(exec_path) / "git-remote-https"
    if not remote_helper.exists():
        raise HostQualificationError(f"git-remote-https missing: {remote_helper}")
    libraries = _ldd_libraries(remote_helper.resolve())
    libcurl_entry = next(
        ((soname, path) for soname, path in libraries.items()
         if soname.startswith("libcurl")),
        None,
    )
    if libcurl_entry is None:
        raise HostQualificationError("git-remote-https does not link libcurl")
    gnutls = next(
        (path for soname, path in libraries.items() if soname.startswith("libgnutls")),
        None,
    )
    openssl = next(
        (path for soname, path in libraries.items() if soname.startswith("libssl")),
        None,
    )
    if "gnutls" in libcurl_entry[0] and gnutls is not None:
        tls_backend = "gnutls-via-libcurl-gnutls"
        tls_library = gnutls
    elif openssl is not None and gnutls is None:
        tls_backend = "openssl-via-libcurl"
        tls_library = openssl
    else:
        raise HostQualificationError(
            "git-remote-https TLS stack could not be identified fail-closed"
        )
    revision = _dpkg_revision_for_path(remote_helper)
    return {
        "upstream_version": tokens[2],
        "distro_revision": revision,
        "security_patch_coverage": revision or "not-recordable",
        "artifacts": {
            "git_remote_https": _artifact(remote_helper, "git-remote-https"),
            "libcurl": _artifact(libcurl_entry[1], "git libcurl"),
            "tls_library": _artifact(tls_library, "git TLS library"),
        },
        "compiled_features": {"tls_backend": tls_backend},
        "behavior_probes": {},
    }


def _component_gnutls(git_tls_library: Optional[Path]) -> dict:
    if git_tls_library is not None:
        library_path = git_tls_library
    else:
        soname = ctypes.util.find_library("gnutls")
        candidate = _ldconfig_path(soname) if soname else None
        if candidate is None:
            raise HostQualificationError("libgnutls could not be located")
        library_path = candidate
    library_path = Path(library_path).resolve()
    library = ctypes.CDLL(str(library_path))
    library.gnutls_check_version.restype = ctypes.c_char_p
    library.gnutls_check_version.argtypes = [ctypes.c_char_p]
    version = library.gnutls_check_version(None)
    if not version:
        raise HostQualificationError("gnutls_check_version returned no version")
    revision = _dpkg_revision_for_path(library_path)
    return {
        "upstream_version": version.decode("ascii", errors="strict"),
        "distro_revision": revision,
        "security_patch_coverage": revision or "not-recordable",
        "artifacts": {"libgnutls": _artifact(library_path, "libgnutls")},
        "compiled_features": {},
        "behavior_probes": {},
    }


def _component_bubblewrap() -> dict:
    exe = _require_tool("bwrap")
    resolved = Path(exe).resolve()
    observed = resolved.stat()
    import stat as stat_module

    if not stat_module.S_ISREG(observed.st_mode):
        raise HostQualificationError("bubblewrap is not a regular file")
    if observed.st_uid != 0 or observed.st_gid != 0:
        raise HostQualificationError(
            f"bubblewrap must be root-owned, observed uid={observed.st_uid} "
            f"gid={observed.st_gid}"
        )
    mode = stat_module.S_IMODE(observed.st_mode)
    if mode != 0o755:
        raise HostQualificationError(f"bubblewrap mode must be 0755, observed {mode:#o}")
    if observed.st_mode & (stat_module.S_ISUID | stat_module.S_ISGID):
        raise HostQualificationError("bubblewrap setuid/setgid bits are present")
    file_capabilities = ""
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        raise HostQualificationError("os.getxattr unavailable; cannot verify file caps")
    try:
        raw = getxattr(resolved, "security.capability")
        file_capabilities = "security.capability=" + bytes(raw).hex() if raw else ""
    except OSError as exc:
        if exc.errno in {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}:
            file_capabilities = ""
        else:
            raise HostQualificationError(
                f"bubblewrap file capabilities could not be verified: {exc.errno}"
            ) from exc
    if file_capabilities:
        raise HostQualificationError("bubblewrap file capabilities are present")
    version_output = _require_output(
        _run([str(resolved), "--version"]), "bwrap --version"
    ).strip()
    revision = _dpkg_revision_for_path(resolved)
    return {
        "upstream_version": version_output.split()[-1],
        "distro_revision": revision,
        "security_patch_coverage": revision or "not-recordable",
        "artifacts": {"bwrap": _artifact(resolved, "bubblewrap")},
        "compiled_features": {
            "version_output": version_output,
            "setuid": False,
            "setgid": False,
            "file_capabilities": "",
        },
        "behavior_probes": {"identity_pin": "pass"},
    }


def _component_kernel_wsl() -> dict:
    try:
        proc_version = Path("/proc/version").read_text(errors="replace")
    except OSError as exc:
        raise HostQualificationError("/proc/version unreadable") from exc
    wsl = parse_wsl_version(proc_version)
    probe_memfd_full_sealing()
    return {
        "upstream_version": platform.release(),
        "distro_revision": None,
        "security_patch_coverage": "not-recordable",
        "artifacts": {},
        "compiled_features": {
            "wsl": wsl or "not-wsl",
            "machine": platform.machine(),
        },
        "behavior_probes": {
            "memfd_full_sealing": "pass",
            "getaddrinfo_terminal_dot": _probe_getaddrinfo_terminal_dot(),
        },
    }


def _component_ca_certificates() -> dict:
    verify_paths = ssl.get_default_verify_paths()
    if verify_paths.cafile is None:
        raise HostQualificationError("no default CA bundle file is configured")
    bundle = Path(verify_paths.cafile).resolve()
    revision = _dpkg_revision_for_package("ca-certificates")
    return {
        "upstream_version": revision or "not-recordable",
        "distro_revision": revision,
        "security_patch_coverage": revision or "not-recordable",
        "artifacts": {"ca_bundle": _artifact(bundle, "CA bundle")},
        "compiled_features": {"configured_cafile": verify_paths.cafile},
        "behavior_probes": {"bundle_readable": "pass"},
    }


# -- manifest computation, canonical form, verification ------------------------


def compute_host_manifest() -> dict:
    """Compute the host qualification manifest for the current host.

    Fail-closed: any failed security-relevant probe raises
    ``HostQualificationError`` instead of recording a weaker result.
    """
    if not sys.platform.startswith("linux"):
        raise HostQualificationError("host qualification requires Linux")
    tls_libraries = _loaded_tls_libraries()
    git_https = _component_git_https()
    git_tls_library = Path(git_https["artifacts"]["tls_library"]["path"])
    gnutls: dict
    if git_https["compiled_features"]["tls_backend"] == "gnutls-via-libcurl-gnutls":
        gnutls = _component_gnutls(git_tls_library)
    else:
        gnutls = _component_gnutls(None)
    components = {
        "python": _component_python(),
        "python_ssl": _component_python_ssl(tls_libraries),
        "openssl_runtime": _component_openssl_runtime(tls_libraries),
        "curl": _component_curl(),
        "git_https": git_https,
        "gnutls": gnutls,
        "bubblewrap": _component_bubblewrap(),
        "kernel_wsl": _component_kernel_wsl(),
        "ca_certificates": _component_ca_certificates(),
    }
    return {
        "version": HOST_QUALIFICATION_VERSION,
        "components": components,
    }


def _validate_canonical(value: object, path: str) -> None:
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if value < 0:
            raise ValueError(f"{path}: negative integers are not canonical")
        return
    if type(value) is str:
        if not value.isascii():
            raise ValueError(f"{path}: non-ASCII strings are not canonical")
        if len(value) > _MAX_STRING_LENGTH:
            raise ValueError(f"{path}: string exceeds the canonical bound")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or not key:
                raise ValueError(f"{path}: manifest keys must be non-empty strings")
            _validate_canonical(item, f"{path}.{key}")
        return
    if type(value) in (list, tuple):
        for index, item in enumerate(value):
            _validate_canonical(item, f"{path}[{index}]")
        return
    raise TypeError(f"{path}: unsupported manifest value type {type(value).__name__}")


def canonical_manifest_bytes(manifest: Mapping) -> bytes:
    """Return the deterministic, canonical serialization of ``manifest``."""
    if type(manifest) is not dict:
        raise TypeError("manifest must be a dict")
    _validate_canonical(manifest, "manifest")
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def manifest_digest(manifest: Mapping) -> str:
    """Return the lowercase SHA-256 digest of the canonical manifest bytes."""
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def _short(value: object) -> str:
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


def diff_manifests(recorded: Mapping, observed: Mapping) -> list[str]:
    """Return dotted-path descriptions of every divergence, empty when equal."""
    mismatches: list[str] = []
    _diff_node(recorded, observed, "manifest", mismatches)
    return mismatches


def _diff_node(
    recorded: object, observed: object, path: str, mismatches: list[str]
) -> None:
    if type(recorded) is not type(observed):
        mismatches.append(
            f"{path}: type changed "
            f"({type(recorded).__name__} -> {type(observed).__name__})"
        )
        return
    if type(recorded) is dict:
        for key in sorted(recorded.keys() - observed.keys()):
            mismatches.append(f"{path}.{key}: recorded field missing on observed host")
        for key in sorted(observed.keys() - recorded.keys()):
            mismatches.append(f"{path}.{key}: unexpected field on observed host")
        for key in sorted(recorded.keys() & observed.keys()):
            _diff_node(recorded[key], observed[key], f"{path}.{key}", mismatches)
        return
    if recorded != observed:
        mismatches.append(
            f"{path}: recorded {_short(recorded)} != observed {_short(observed)}"
        )


def verify_host_manifest(recorded: Mapping, observed: Mapping) -> None:
    """Fail closed unless ``observed`` matches ``recorded`` exactly.

    Raises ``HostQualificationMismatchError`` listing every divergent field.
    """
    canonical_manifest_bytes(recorded)
    canonical_manifest_bytes(observed)
    mismatches = diff_manifests(recorded, observed)
    if mismatches:
        raise HostQualificationMismatchError(mismatches)


def verify_current_host(recorded: Mapping) -> dict:
    """Compute the current manifest and fail closed on any divergence."""
    observed = compute_host_manifest()
    verify_host_manifest(recorded, observed)
    return observed


__all__ = [
    "COMPONENT_NAMES",
    "ECH_MACHINERY_SYMBOLS",
    "HOST_QUALIFICATION_VERSION",
    "HostQualificationError",
    "HostQualificationMismatchError",
    "canonical_manifest_bytes",
    "compute_host_manifest",
    "diff_manifests",
    "manifest_digest",
    "probe_memfd_full_sealing",
    "verify_current_host",
    "verify_host_manifest",
    "verify_memfd_sealed",
]
