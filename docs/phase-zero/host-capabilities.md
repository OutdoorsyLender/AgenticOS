# Phase Zero — Host Capability Detection

> Capability detection is **read-only** and reports *observations*, not
> guarantees. Uncertain results are `UNVERIFIED`, never upgraded to
> `SUPPORTED`.

## 1. What it is

`agenticos.sandbox.capabilities.HostCapabilityDetector` probes the current
host for the Linux features later AgenticOS milestones will need, and returns
a typed, JSON-serializable `HostCapabilityReport`:

```json
{
  "schema_version": "0.1.0",
  "collected_at": "2026-08-07T04:00:00+00:00",
  "platform_system": "Linux",
  "kernel_release": "5.15.90.1-microsoft-standard-WSL2",
  "capabilities": {
    "cgroup_v2_mounted": {
      "name": "cgroup_v2_mounted",
      "status": "SUPPORTED",
      "evidence": "/sys/fs/cgroup/cgroup.controllers exists"
    }
  }
}
```

Statuses: `SUPPORTED` · `UNSUPPORTED` · `UNVERIFIED` · `PERMISSION_DENIED` ·
`ERROR`. Every capability carries a short evidence string. Evidence never
contains usernames, home paths, machine ids, or environment dumps.

## 2. Capability inventory

| Capability | Probe (read-only) |
|---|---|
| `host_platform_linux` | `platform.system()` |
| `wsl_detected` / `wsl_version` | Microsoft/WSL markers in `/proc/version`; `WSL_DISTRO_NAME` env |
| `procfs_available` | `/proc/self/stat` readable |
| `process_groups_available` | `os.setsid` / `os.killpg` / `os.getpgid` present |
| `pidfd_available` | `os.pidfd_open(self)` actually succeeds |
| `systemd_available` | `systemctl` on PATH |
| `systemd_running` | `/proc/1/comm` == `systemd` |
| `systemd_user_bus` | `/run/user/<uid>/bus` socket exists |
| `systemd_scope_creation` | **always `UNVERIFIED` here** — see §3 |
| `cgroup_version` / `cgroup_v2_mounted` | `cgroup.controllers` + `cgroup2` mount entry |
| `cgroup_kill_available` | `cgroup.kill` in a dynamically discovered non-root cgroup (kernel ≥ 5.14) |
| `cgroup_events_available` | `cgroup.events` in a dynamically discovered non-root cgroup |
| `user_namespaces_observed` | `/proc/sys/user/max_user_namespaces` > 0 |
| `landlock_abi` | `landlock_create_ruleset` **version query only** via ctypes syscall; any positive ABI is detected as `SUPPORTED`, `ENOSYS` is unsupported, `EOPNOTSUPP` disabled, other errno `ERROR`; platforms where no query can run remain `UNVERIFIED`; the M3B runtime gate separately rejects ABI <3 |
| `repo_on_linux_filesystem` | repo path must not be under `/mnt/<drive>` (drvfs) |

## 3. System capability vs current-user permission

"systemd exists" does **not** imply "this process may create cgroups". The
detector therefore never claims `systemd_scope_creation` — it stays
`UNVERIFIED` until `CgroupProcessRunner.probe()` actually creates and
collects a trivial transient user scope (`systemd-run --user --scope
--collect -- ... /usr/bin/true`). Only that runtime probe distinguishes
SYSTEM CAPABILITY from CURRENT USER PERMISSION. The probe creates nothing
persistent.

## 4. Observed vs guaranteed

A `SUPPORTED` result means "this probe observed the feature just now". It is
not a contract: WSL kernel updates, distro changes, or policy changes can
invalidate it. Runners re-gate on the report at startup, and integration
tests skip with concrete reasons rather than faking success.

## 5. Supported / unsupported hosts

- **Verified target (Milestone 2B, observed)**: Ubuntu 26.04 LTS on WSL2,
  kernel `6.6.87.2-microsoft-standard-WSL2`, systemd 259 as PID 1,
  systemd user manager + bus operational, unified cgroup v2 at
  `/sys/fs/cgroup` (`nsdelegate`), Landlock ABI v3 detected and separately
  enforced by the Milestone 3B runtime probe,
  pidfd available, repo on the Linux filesystem. All capability probes and
  the real containment suite pass on this environment.
- **Plain Linux with systemd**: expected to work identically (not observed).
- **Windows (native)**: containment capabilities report
  `UNSUPPORTED`/`UNVERIFIED`; `CgroupProcessRunner.run()` raises
  `ContainmentUnavailableError` with reasons. Unit tests still prove the
  detection and cancellation logic via synthetic fixtures and fake backends.
- **WSL1**: no real cgroup v2; reports `UNSUPPORTED`.

### cgroup.events / cgroup.kill detection semantics (corrected in 2B)

These files exist **only in non-root cgroups** — the hierarchy root never
exposes them, so probing `/sys/fs/cgroup/cgroup.events` directly is a false
negative (observed on the real host). The detector now discovers an existing
non-root cgroup dynamically: first the current process's own cgroup from
`/proc/self/cgroup`, then PID 1's, then (last resort) the first direct child
of the cgroup root exposing `cgroup.events`. No path is hard-coded, nothing
is created to answer detection, and the probe stays read-only. Presence of
`cgroup.kill` means the kernel exposes the feature; whether AgenticOS may
*use* it on a task scope (`cgroup_kill_usable`) is only proven at runtime by
actually writing to a task cgroup — system capability and current-user
permission remain separate facts.

## 6. Known WSL caveats

- systemd must be enabled in the distro (`/etc/wsl.conf`) by the user —
  AgenticOS never edits it.
- Non-login shells (e.g. `wsl -- bash -c ...`) may lack
  `XDG_RUNTIME_DIR`/`DBUS_SESSION_BUS_ADDRESS`; the backend defaults them to
  `/run/user/<uid>` when that directory exists.
- The Docker Desktop `docker-desktop` distro is **not** a viable host: no
  systemd (`PID 1` is Docker's init), no `systemctl`, no Python.
- Repos under `/mnt/c` (drvfs) are reported `UNSUPPORTED` for
  `repo_on_linux_filesystem` — keep the checkout on the Linux filesystem.

## 7. Test procedure

```
# any host — unit + fake-backend tests:
python -m pytest

# Ubuntu WSL2 — real containment integration tests:
python -m pytest tests/conformance/test_cgroup_integration.py -v
```

Integration tests are marked `cgroup_linux` and skip with the exact missing
capability when the host cannot run them.

## 8. Milestone 3B runtime gate

`HostCapabilityDetector` remains observation-only. Before starting a native
filesystem task, `NativeLandlockRunner` performs both the ABI query and the
separate real enforcement probe. Capability evidence is recorded separately
from the later per-task `FILESYSTEM_POLICY_APPLIED` evidence. Unknown probe
errors, ABI below 3, or a failed enforcement probe prevent scope creation and
worker execution; there is no fallback to the experimental shim or to an
unsafe runner.

## 9. Milestone 4A runtime gate

M4A additionally pins `/usr/bin/bwrap` by exact path, version, SHA-256,
root ownership, mode 0755, absent setuid/setgid bits, and absent file
capabilities. Its bounded behavior probe must demonstrate the explicit
user/mount/PID/network/IPC/UTS namespace configuration, FD binds, JSON status,
`--block-fd`, and nested-userns denial. The accepted recorded-host result is
documented in [runtime-boundary.md](runtime-boundary.md). Capability discovery
remains observation; every task re-gates before scope creation.

## 10. Milestone 4B-2 host qualification manifest

`agenticos.sandbox.host_qualification` converts the M4B-2 security claims
from environmental assumptions into a canonical, digest-able **host
qualification manifest** (`compute_host_manifest()`), plus a fail-closed
verifier (`verify_host_manifest(recorded, observed)` /
`verify_current_host(recorded)`) that rejects ANY divergence and reports
exactly which dotted-path field changed (`HostQualificationMismatchError.mismatches`).
There is no "log and continue" path.

Each of the nine qualified components — `python`, `python_ssl`,
`openssl_runtime`, `curl`, `git_https`, `gnutls`, `bubblewrap`, `kernel_wsl`,
`ca_certificates` — records every applicable identity class, never a version
string alone:

- upstream version (e.g. `OpenSSL 3.5.5 27 Jan 2026`),
- distro package revision (`dpkg-query` version, carrying the distro
  security revision; Ubuntu exposes no offline machine-readable USN list, so
  `security_patch_coverage` records the dpkg revision, or curl's own
  `security patched:` suffix, and `not-recordable` where neither exists),
- SHA-256 digest of each runtime executable/shared library actually used
  (the loaded libssl/libcrypto are resolved from `/proc/self/maps`, not from
  a guessed path; `git-remote-https` is resolved through its symlink),
- compiled features — notably the loaded libssl's ECH posture: a ctypes
  symbol probe requires that no `SSL_ech_*`/`SSL_CTX_set1_echstore`/
  `OSSL_ech_get1_helper` acceptance machinery is exported
  (`ech_machinery: absent`), failing closed at compute time otherwise,
- behavior probes, fail-closed where authoritative: `ssl.OP_NO_RENEGOTIATION`
  exposure, `MemoryBIO`/`SSLObject` availability, ALPN set/get, curl's
  inability to emit ECH (`--ech false` must be refused by libcurl), full
  memfd sealing (`F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL`
  verified present via `F_GET_SEALS` plus a denied write attempt), and the
  bubblewrap identity pin mirroring §9 (root-owned 0755, no setuid/setgid,
  no file capabilities). The terminal-dot `getaddrinfo` behavior is recorded
  as a capability only, with no network mutation.

**Dual TLS stacks.** On the recorded host, curl HTTPS and Git HTTPS are two
independent TLS client stacks: curl links `libcurl.so.4`/OpenSSL, while
`git-remote-https` links `libcurl-gnutls.so.4`/GnuTLS (`libgnutls.so.30`).
They are qualified as separate components (`curl` vs `git_https` + `gnutls`);
qualifying curl never qualifies git.

The manifest canonicalizes to sorted compact ASCII JSON
(`canonical_manifest_bytes()`) with a SHA-256 digest (`manifest_digest()`),
following the `network_models.py` canonical-policy pattern. All probing is
read-only: no system modification, no package installation, no network
mutation (the curl ECH probe targets `127.0.0.1:1` and is refused during
option parsing; the resolver probe uses only the local `localhost.` name).
