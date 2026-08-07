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
| `cgroup_kill_available` | `cgroup.kill` exists (kernel ≥ 5.14) |
| `cgroup_events_available` | `cgroup.events` exists |
| `user_namespaces_observed` | `/proc/sys/user/max_user_namespaces` > 0 |
| `landlock_abi` | `landlock_create_ruleset` **version query only** via ctypes syscall — detection, never enforcement |
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

- **Target**: Ubuntu on WSL2 (systemd enabled), repo on the Linux filesystem
  (e.g. `~/src/AgenticOS`).
- **Plain Linux with systemd**: expected to work identically.
- **Windows (native)**: containment capabilities report
  `UNSUPPORTED`/`UNVERIFIED`; `CgroupProcessRunner.run()` raises
  `ContainmentUnavailableError` with reasons. Unit tests still prove the
  detection and cancellation logic via synthetic fixtures and fake backends.
- **WSL1**: no real cgroup v2; reports `UNSUPPORTED`.

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
