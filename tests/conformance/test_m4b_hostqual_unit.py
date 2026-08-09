"""Unit tests for the M4B-2 host qualification manifest.

Structure, canonicalization, digest, and verification tests use synthetic
manifests and run on any platform. Seal-verification and real-host probe
tests require Linux and skip elsewhere.
"""

from __future__ import annotations

import copy
import sys

import pytest

from agenticos.sandbox import host_qualification as hq

LINUX_ONLY = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="requires Linux host probes"
)


def _synthetic_manifest():
    """A bounded synthetic manifest exercising every identity class."""
    return {
        "version": hq.HOST_QUALIFICATION_VERSION,
        "components": {
            "python": {
                "upstream_version": "3.14.4",
                "distro_revision": "3.14.4-1ubuntu0.1",
                "security_patch_coverage": "3.14.4-1ubuntu0.1",
                "artifacts": {
                    "executable": {
                        "path": "/usr/bin/python3.14",
                        "sha256": "aa" * 32,
                    }
                },
                "compiled_features": {"hexversion": 51118192, "build": "main t0"},
                "behavior_probes": {},
            },
            "openssl_runtime": {
                "upstream_version": "OpenSSL 3.5.5 27 Jan 2026",
                "distro_revision": "3.5.5-1ubuntu3",
                "security_patch_coverage": "3.5.5-1ubuntu3",
                "artifacts": {
                    "libssl": {
                        "path": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
                        "sha256": "bb" * 32,
                    },
                    "libcrypto": {
                        "path": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
                        "sha256": "cc" * 32,
                    },
                },
                "compiled_features": {
                    "ech_machinery": "absent",
                    "ech_symbols_present": [],
                },
                "behavior_probes": {"ech_symbol_absence": "pass"},
            },
        },
    }


def _flip(manifest, dotted_path, new_value):
    flipped = copy.deepcopy(manifest)
    node = flipped
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = new_value
    return flipped


# -- canonical encoding and digest ----------------------------------------------


def test_canonical_bytes_are_stable_and_order_independent():
    manifest = _synthetic_manifest()
    first = hq.canonical_manifest_bytes(manifest)
    assert hq.canonical_manifest_bytes(manifest) == first
    reordered = {
        "components": manifest["components"],
        "version": manifest["version"],
    }
    assert hq.canonical_manifest_bytes(reordered) == first
    assert first.startswith(b'{"components":')


def test_canonical_bytes_reject_unknown_types():
    manifest = _synthetic_manifest()
    for bad_value in (b"bytes", {"set"}, 1.5, object()):
        flipped = _flip(manifest, "components.python.upstream_version", bad_value)
        with pytest.raises((TypeError, ValueError)):
            hq.canonical_manifest_bytes(flipped)


def test_canonical_bytes_reject_unbounded_or_non_ascii_strings():
    manifest = _synthetic_manifest()
    too_long = _flip(
        manifest, "components.python.upstream_version", "x" * 2048
    )
    with pytest.raises(ValueError):
        hq.canonical_manifest_bytes(too_long)
    non_ascii = _flip(
        manifest, "components.python.upstream_version", "3.14.4-é"
    )
    with pytest.raises(ValueError):
        hq.canonical_manifest_bytes(non_ascii)


def test_manifest_digest_is_deterministic_and_covers_every_field():
    manifest = _synthetic_manifest()
    digest = hq.manifest_digest(manifest)
    assert digest == hq.manifest_digest(manifest)
    assert len(digest) == 64
    flipped = _flip(
        manifest, "components.openssl_runtime.artifacts.libssl.sha256", "dd" * 32
    )
    assert hq.manifest_digest(flipped) != digest


# -- fail-closed verification against recorded manifests ------------------------


def test_identical_manifest_verifies():
    manifest = _synthetic_manifest()
    hq.verify_host_manifest(manifest, copy.deepcopy(manifest))
    assert hq.diff_manifests(manifest, copy.deepcopy(manifest)) == []


@pytest.mark.parametrize(
    "dotted_path,new_value",
    [
        # upstream version
        ("components.python.upstream_version", "3.14.5"),
        # distro package revision
        ("components.python.distro_revision", "3.14.4-1ubuntu0.2"),
        # security patch / USN coverage
        ("components.python.security_patch_coverage", "not-recordable"),
        # runtime artifact digest (one byte of the recorded digest)
        (
            "components.openssl_runtime.artifacts.libssl.sha256",
            "ab" + "bb" * 31,
        ),
        # compiled features (ECH posture)
        ("components.openssl_runtime.compiled_features.ech_machinery", "present"),
        (
            "components.openssl_runtime.compiled_features.ech_symbols_present",
            ["SSL_ech_get1_status"],
        ),
        # behavior probes
        ("components.openssl_runtime.behavior_probes.ech_symbol_absence", "fail"),
    ],
)
def test_flipped_field_fails_closed_with_exact_field_identified(
    dotted_path, new_value
):
    manifest = _synthetic_manifest()
    flipped = _flip(manifest, dotted_path, new_value)
    with pytest.raises(hq.HostQualificationMismatchError) as excinfo:
        hq.verify_host_manifest(manifest, flipped)
    expected_path = f"manifest.{dotted_path}"
    assert any(
        mismatch.startswith(expected_path) for mismatch in excinfo.value.mismatches
    ), excinfo.value.mismatches


def test_flipped_top_level_version_fails_closed():
    manifest = _synthetic_manifest()
    flipped = _flip(manifest, "version", "AOSHOSTQUAL/2")
    with pytest.raises(hq.HostQualificationMismatchError) as excinfo:
        hq.verify_host_manifest(manifest, flipped)
    assert any(m.startswith("manifest.version") for m in excinfo.value.mismatches)


def test_missing_component_fails_closed():
    manifest = _synthetic_manifest()
    degraded = copy.deepcopy(manifest)
    del degraded["components"]["openssl_runtime"]
    with pytest.raises(hq.HostQualificationMismatchError) as excinfo:
        hq.verify_host_manifest(manifest, degraded)
    assert any(
        m.startswith("manifest.components.openssl_runtime")
        for m in excinfo.value.mismatches
    )


def test_extra_component_fails_closed():
    manifest = _synthetic_manifest()
    mutated = copy.deepcopy(manifest)
    mutated["components"]["surprise"] = {"upstream_version": "0.0.0"}
    with pytest.raises(hq.HostQualificationMismatchError) as excinfo:
        hq.verify_host_manifest(manifest, mutated)
    assert any(
        m.startswith("manifest.components.surprise") for m in excinfo.value.mismatches
    )


def test_field_type_change_fails_closed():
    manifest = _synthetic_manifest()
    flipped = _flip(
        manifest,
        "components.openssl_runtime.compiled_features.ech_machinery",
        ["absent"],
    )
    with pytest.raises(hq.HostQualificationMismatchError) as excinfo:
        hq.verify_host_manifest(manifest, flipped)
    assert any(
        "type changed" in m
        and m.startswith(
            "manifest.components.openssl_runtime.compiled_features.ech_machinery"
        )
        for m in excinfo.value.mismatches
    )


def test_all_divergences_are_reported_not_just_the_first():
    manifest = _synthetic_manifest()
    flipped = _flip(manifest, "components.python.upstream_version", "3.14.5")
    flipped = _flip(flipped, "components.python.distro_revision", "9.9.9")
    with pytest.raises(hq.HostQualificationMismatchError) as excinfo:
        hq.verify_host_manifest(manifest, flipped)
    assert len(excinfo.value.mismatches) == 2


# -- memfd seal verification (Linux) --------------------------------------------


@LINUX_ONLY
def test_fully_sealed_memfd_passes():
    hq.probe_memfd_full_sealing()
    import fcntl
    import os

    fd = os.memfd_create("aos-hostqual-test", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, b"payload")
        fcntl.fcntl(
            fd,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        hq.verify_memfd_sealed(fd)
    finally:
        os.close(fd)


@LINUX_ONLY
def test_unsealed_memfd_fails_verification():
    import os

    fd = os.memfd_create("aos-hostqual-test", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, b"payload")
        with pytest.raises(hq.HostQualificationError):
            hq.verify_memfd_sealed(fd)
    finally:
        os.close(fd)


@LINUX_ONLY
def test_partially_sealed_memfd_fails_verification():
    import fcntl
    import os

    fd = os.memfd_create("aos-hostqual-test", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, b"payload")
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE)
        with pytest.raises(hq.HostQualificationError):
            hq.verify_memfd_sealed(fd)
    finally:
        os.close(fd)


# -- real-host qualification probe (Linux) ---------------------------------------


@LINUX_ONLY
def test_real_host_manifest_qualifies_and_verifies():
    manifest = hq.compute_host_manifest()

    assert set(manifest["components"]) == set(hq.COMPONENT_NAMES)
    assert len(manifest["components"]) == 9
    assert manifest["version"] == hq.HOST_QUALIFICATION_VERSION

    openssl = manifest["components"]["openssl_runtime"]
    assert openssl["compiled_features"]["ech_machinery"] == "absent"
    assert openssl["compiled_features"]["ech_symbols_present"] == []
    assert openssl["behavior_probes"]["ech_symbol_absence"] == "pass"

    # The recorded host has two independent TLS client stacks; both are
    # qualified independently (qualifying curl never qualifies git).
    curl = manifest["components"]["curl"]
    assert curl["compiled_features"]["tls_backend"].startswith("OpenSSL/")
    assert curl["behavior_probes"]["ech_cannot_emit"] == "pass"
    git_https = manifest["components"]["git_https"]
    assert git_https["compiled_features"]["tls_backend"] == (
        "gnutls-via-libcurl-gnutls"
    )

    assert manifest["components"]["kernel_wsl"]["behavior_probes"][
        "memfd_full_sealing"
    ] == "pass"

    digest = hq.manifest_digest(manifest)
    assert len(digest) == 64

    fresh = hq.compute_host_manifest()
    hq.verify_host_manifest(manifest, fresh)

    # One byte changed in a recorded digest fails closed on the exact field.
    tampered = copy.deepcopy(manifest)
    sha256 = tampered["components"]["python"]["artifacts"]["executable"]["sha256"]
    tampered["components"]["python"]["artifacts"]["executable"]["sha256"] = (
        ("0" if sha256[0] != "0" else "1") + sha256[1:]
    )
    with pytest.raises(hq.HostQualificationMismatchError) as excinfo:
        hq.verify_host_manifest(manifest, tampered)
    assert any(
        m.startswith("manifest.components.python.artifacts.executable.sha256")
        for m in excinfo.value.mismatches
    )
