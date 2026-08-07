"""Read-only Linux/WSL host capability detection for AgenticOS Phase Zero.

Every probe in this module is strictly READ-ONLY: it reads procfs/sysfs
files, inspects the process environment, and (for Landlock) performs a
purely informational syscall-version query. Nothing here creates, mounts,
writes, or configures anything on the host.

Uncertain observations are reported as UNVERIFIED — never upgraded to
SUPPORTED. Each capability carries a short evidence string. Evidence avoids
host-identifying detail (no usernames, no home paths, no machine ids).

System capability is reported separately from current-user permission:
e.g. cgroup v2 can be SUPPORTED while ``systemd_scope_creation`` remains
UNVERIFIED until something actually tries to create a transient scope
(see ``agenticos.sandbox.containment.CgroupProcessRunner.probe``).
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional

from .models import utc_now_iso

CAPABILITIES_SCHEMA_VERSION = "0.1.0"

LANDLOCK_SYSCALL_NR = {"x86_64": 444, "aarch64": 444, "riscv64": 444}
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0


class CapabilityStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    UNVERIFIED = "UNVERIFIED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    ERROR = "ERROR"


@dataclass
class HostCapability:
    name: str
    status: str  # CapabilityStatus value
    evidence: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HostCapabilityReport:
    schema_version: str
    collected_at: str
    platform_system: str
    kernel_release: Optional[str]
    capabilities: dict[str, HostCapability] = field(default_factory=dict)

    def status_of(self, name: str) -> CapabilityStatus:
        cap = self.capabilities.get(name)
        if cap is None:
            return CapabilityStatus.UNVERIFIED
        return CapabilityStatus(cap.status)

    def add(self, name: str, status: CapabilityStatus, evidence: str) -> None:
        self.capabilities[name] = HostCapability(name, status.value, evidence)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "collected_at": self.collected_at,
            "platform_system": self.platform_system,
            "kernel_release": self.kernel_release,
            "capabilities": {k: v.to_dict() for k, v in self.capabilities.items()},
        }


def parse_mounts(mounts_text: str) -> list[tuple[str, str, str]]:
    """Parse /proc/self/mounts content into (device, mountpoint, fstype)."""
    entries = []
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            entries.append((parts[0], parts[1], parts[2]))
    return entries


def parse_wsl_version(proc_version: str) -> Optional[str]:
    """Classify WSL from /proc/version content. None if not WSL."""
    text = proc_version.lower()
    if "wsl2" in text or "microsoft-standard" in text:
        return "WSL2"
    if "microsoft" in text or "wsl" in text:
        return "WSL1-or-unknown"
    return None


def parse_cgroup_events(events_text: str) -> dict[str, int]:
    """Parse cgroup.events content, e.g. 'populated 0\\nfrozen 0'."""
    out: dict[str, int] = {}
    for line in events_text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                continue
    return out


def parse_proc_cgroup(text: str) -> Optional[str]:
    """Extract the cgroup v2 path from /proc/<pid>/cgroup content.

    v2 content is a single '0::/path' line; the path is '/' when the process
    sits in the hierarchy root. Returns None when no unified entry exists.
    """
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
            return parts[2] or "/"
    return None


class HostCapabilityDetector:
    """Read-only host capability probes.

    ``proc_root`` / ``cgroup_root`` / ``environ`` are injectable so unit
    tests can point the detector at synthetic fixture trees.
    """

    def __init__(
        self,
        proc_root: str | Path = "/proc",
        cgroup_root: str | Path = "/sys/fs/cgroup",
        environ: Optional[Mapping[str, str]] = None,
        repo_path: Optional[str | Path] = None,
    ) -> None:
        self.proc_root = Path(proc_root)
        self.cgroup_root = Path(cgroup_root)
        self.environ = dict(os.environ if environ is None else environ)
        self.repo_path = Path(repo_path) if repo_path is not None else Path.cwd()

    # -- small read-only helpers ------------------------------------------

    def _read(self, path: Path) -> Optional[str]:
        try:
            return path.read_text(errors="replace")
        except OSError:
            return None

    # -- main entry point ---------------------------------------------------

    def detect(self) -> HostCapabilityReport:
        report = HostCapabilityReport(
            schema_version=CAPABILITIES_SCHEMA_VERSION,
            collected_at=utc_now_iso(),
            platform_system=platform.system() or "unknown",
            kernel_release=platform.release() or None,
        )
        self._check_host_platform(report)
        self._check_wsl(report)
        self._check_procfs(report)
        self._check_process_groups(report)
        self._check_pidfd(report)
        self._check_systemd(report)
        self._check_cgroups(report)
        self._check_user_namespaces(report)
        self._check_landlock(report)
        self._check_sandbox_helpers(report)
        self._check_repo_location(report)
        return report

    # -- individual probes (all read-only) ---------------------------------

    def _check_host_platform(self, report: HostCapabilityReport) -> None:
        system = report.platform_system
        status = (
            CapabilityStatus.SUPPORTED
            if system == "Linux"
            else CapabilityStatus.UNSUPPORTED
        )
        report.add("host_platform_linux", status, f"platform.system()={system!r}")

    def _check_wsl(self, report: HostCapabilityReport) -> None:
        version_text = self._read(self.proc_root / "version")
        if version_text is None:
            report.add(
                "wsl_detected", CapabilityStatus.UNVERIFIED,
                f"{self.proc_root}/version unreadable (non-Linux host?)",
            )
            report.add("wsl_version", CapabilityStatus.UNVERIFIED, "no /proc/version evidence")
            return
        wsl = parse_wsl_version(version_text)
        if wsl is None:
            report.add("wsl_detected", CapabilityStatus.UNSUPPORTED,
                       "/proc/version contains no Microsoft/WSL marker")
            report.add("wsl_version", CapabilityStatus.UNSUPPORTED, "not a WSL kernel")
        else:
            report.add("wsl_detected", CapabilityStatus.SUPPORTED,
                       "/proc/version contains Microsoft/WSL marker")
            report.add("wsl_version", CapabilityStatus.SUPPORTED, f"environment={wsl}")
        distro = self.environ.get("WSL_DISTRO_NAME")
        if distro:
            report.add("wsl_distro_env", CapabilityStatus.SUPPORTED,
                       "WSL_DISTRO_NAME is set")

    def _check_procfs(self, report: HostCapabilityReport) -> None:
        stat = self._read(self.proc_root / "self" / "stat")
        if stat is not None:
            report.add("procfs_available", CapabilityStatus.SUPPORTED,
                       f"{self.proc_root}/self/stat readable")
        else:
            report.add("procfs_available", CapabilityStatus.UNSUPPORTED,
                       f"{self.proc_root}/self/stat unreadable")

    def _check_process_groups(self, report: HostCapabilityReport) -> None:
        ok = (
            os.name == "posix"
            and hasattr(os, "setsid")
            and hasattr(os, "killpg")
            and hasattr(os, "getpgid")
        )
        report.add(
            "process_groups_available",
            CapabilityStatus.SUPPORTED if ok else CapabilityStatus.UNSUPPORTED,
            "os.setsid/os.killpg/os.getpgid present" if ok else "POSIX process-group APIs missing",
        )

    def _check_pidfd(self, report: HostCapabilityReport) -> None:
        if not hasattr(os, "pidfd_open"):
            report.add("pidfd_available", CapabilityStatus.UNSUPPORTED,
                       "os.pidfd_open not provided by this Python/platform")
            return
        try:
            fd = os.pidfd_open(os.getpid())
            os.close(fd)
            report.add("pidfd_available", CapabilityStatus.SUPPORTED,
                       "os.pidfd_open(self) succeeded")
        except OSError as exc:
            report.add("pidfd_available", CapabilityStatus.UNSUPPORTED,
                       f"os.pidfd_open raised {type(exc).__name__}")

    def _check_systemd(self, report: HostCapabilityReport) -> None:
        systemctl = shutil.which("systemctl")
        report.add(
            "systemd_available",
            CapabilityStatus.SUPPORTED if systemctl else CapabilityStatus.UNSUPPORTED,
            "systemctl found on PATH" if systemctl else "systemctl not found on PATH",
        )
        comm = (self._read(self.proc_root / "1" / "comm") or "").strip()
        if comm == "systemd":
            report.add("systemd_running", CapabilityStatus.SUPPORTED,
                       "/proc/1/comm is 'systemd'")
        elif comm:
            report.add("systemd_running", CapabilityStatus.UNSUPPORTED,
                       f"/proc/1/comm is {comm!r}")
        else:
            report.add("systemd_running", CapabilityStatus.UNVERIFIED,
                       f"{self.proc_root}/1/comm unreadable")

        # User-manager / session-bus evidence (read-only; does not prove the
        # current context may create scopes — that is what probe() is for).
        uid = os.getuid() if hasattr(os, "getuid") else None
        bus = Path(f"/run/user/{uid}/bus") if uid is not None else None
        if bus is not None and bus.exists():
            report.add("systemd_user_bus", CapabilityStatus.SUPPORTED,
                       f"/run/user/<uid>/bus exists")
        else:
            xdg = self.environ.get("XDG_RUNTIME_DIR")
            hint = "XDG_RUNTIME_DIR set but bus socket missing" if xdg else "no /run/user/<uid>/bus socket"
            report.add("systemd_user_bus", CapabilityStatus.UNVERIFIED, hint)

        report.add(
            "systemd_scope_creation",
            CapabilityStatus.UNVERIFIED,
            "read-only detection only; verified at runtime by CgroupProcessRunner.probe()",
        )

    def _discover_nonroot_cgroup(self) -> tuple[Optional[Path], str]:
        """Find an existing non-root cgroup directory, read-only.

        Preference order: the current process's own cgroup (from
        /proc/self/cgroup), then PID 1's cgroup, then — as a last resort —
        the first direct child of the cgroup root exposing cgroup.events.
        Never creates a cgroup; never assumes a distro-specific path.
        Returns (path, source_description).
        """
        for proc_file, label in (
            (self.proc_root / "self" / "cgroup", "/proc/self/cgroup"),
            (self.proc_root / "1" / "cgroup", "/proc/1/cgroup"),
        ):
            rel = parse_proc_cgroup(self._read(proc_file) or "")
            if rel and rel != "/":
                candidate = self.cgroup_root / rel.lstrip("/")
                if candidate.is_dir():
                    return candidate, f"{label} entry {rel!r}"
        try:
            for child in sorted(self.cgroup_root.iterdir()):
                if child.is_dir() and (child / "cgroup.events").exists():
                    return child, "direct child of cgroup root"
        except OSError:
            pass
        return None, "no non-root cgroup found"

    def _check_cgroups(self, report: HostCapabilityReport) -> None:
        controllers = self.cgroup_root / "cgroup.controllers"
        mounts_text = self._read(self.proc_root / "self" / "mounts") or ""
        fstypes = {fs for _, _, fs in parse_mounts(mounts_text)}

        if controllers.exists():
            report.add("cgroup_version", CapabilityStatus.SUPPORTED, "v2")
            report.add("cgroup_v2_mounted", CapabilityStatus.SUPPORTED,
                       f"{controllers} exists")
        elif "cgroup" in fstypes:
            report.add("cgroup_version", CapabilityStatus.SUPPORTED, "v1 (legacy)")
            report.add("cgroup_v2_mounted", CapabilityStatus.UNSUPPORTED,
                       "only cgroup v1 mounts found")
        else:
            report.add("cgroup_version", CapabilityStatus.UNVERIFIED,
                       "no cgroup controllers file and no cgroup mounts observed")
            report.add("cgroup_v2_mounted", CapabilityStatus.UNVERIFIED,
                       f"{controllers} missing")
        if "cgroup2" in fstypes and not controllers.exists():
            report.add("cgroup_v2_mounted", CapabilityStatus.UNVERIFIED,
                       "cgroup2 mount present but controllers file missing at detection root")

        v2 = controllers.exists()
        if not v2:
            if "cgroup" in fstypes:
                note = "cgroup.kill/cgroup.events are cgroup v2 features; host is v1"
                report.add("cgroup_kill_available", CapabilityStatus.UNSUPPORTED, note)
                report.add("cgroup_events_available", CapabilityStatus.UNSUPPORTED, note)
            else:
                note = "cgroup v2 not detected; cannot assess"
                report.add("cgroup_kill_available", CapabilityStatus.UNVERIFIED, note)
                report.add("cgroup_events_available", CapabilityStatus.UNVERIFIED, note)
            return

        kill_probe, kill_source = self._discover_nonroot_cgroup()
        if kill_probe is None:
            report.add("cgroup_kill_available", CapabilityStatus.UNVERIFIED,
                       f"no existing non-root cgroup discoverable ({kill_source})")
            report.add("cgroup_events_available", CapabilityStatus.UNVERIFIED,
                       f"no existing non-root cgroup discoverable ({kill_source})")
        else:
            # cgroup.events / cgroup.kill exist only in NON-ROOT cgroups
            # (kernel design); probing the hierarchy root is a false negative.
            kill = kill_probe / "cgroup.kill"
            report.add(
                "cgroup_kill_available",
                CapabilityStatus.SUPPORTED if kill.exists() else CapabilityStatus.UNSUPPORTED,
                f"cgroup.kill {'present' if kill.exists() else 'absent'} in non-root "
                f"cgroup {kill_probe.name!r} (via {kill_source})"
                + ("" if kill.exists() else " — kernel < 5.14 or not applicable"),
            )
            events = kill_probe / "cgroup.events"
            report.add(
                "cgroup_events_available",
                CapabilityStatus.SUPPORTED if events.exists() else CapabilityStatus.UNSUPPORTED,
                f"cgroup.events {'present' if events.exists() else 'absent'} in non-root "
                f"cgroup {kill_probe.name!r} (via {kill_source})",
            )

    def _check_user_namespaces(self, report: HostCapabilityReport) -> None:
        raw = self._read(self.proc_root / "sys" / "user" / "max_user_namespaces")
        if raw is None:
            report.add("user_namespaces_observed", CapabilityStatus.UNVERIFIED,
                       "max_user_namespaces unreadable")
            return
        try:
            count = int(raw.strip())
        except ValueError:
            report.add("user_namespaces_observed", CapabilityStatus.ERROR,
                       "max_user_namespaces not an integer")
            return
        report.add(
            "user_namespaces_observed",
            CapabilityStatus.SUPPORTED if count > 0 else CapabilityStatus.UNSUPPORTED,
            f"max_user_namespaces={count}",
        )

    def _check_landlock(self, report: HostCapabilityReport) -> None:
        """Detection only. Queries the Landlock ABI version via a version
        syscall that creates nothing and enforces nothing."""
        machine = platform.machine()
        nr = LANDLOCK_SYSCALL_NR.get(machine)
        if report.platform_system != "Linux" or nr is None:
            report.add("landlock_abi", CapabilityStatus.UNVERIFIED,
                       f"no Landlock syscall number for {report.platform_system}/{machine}")
            return
        try:
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            abi = libc.syscall(nr, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
            if abi > 0:
                report.add("landlock_abi", CapabilityStatus.SUPPORTED,
                           f"landlock_create_ruleset ABI v{abi} (detection only, not enforced)")
            else:
                err = ctypes.get_errno()
                report.add("landlock_abi", CapabilityStatus.UNSUPPORTED,
                           f"landlock_create_ruleset version query failed, errno={err}")
        except Exception as exc:  # noqa: BLE001 - detection must never crash
            report.add("landlock_abi", CapabilityStatus.UNVERIFIED,
                       f"ABI probe raised {type(exc).__name__}: {exc}")

    def _check_sandbox_helpers(self, report: HostCapabilityReport) -> None:
        """Presence only — NOT usability. Usability requires a real bounded
        probe (see agenticos.sandbox.isolation probes)."""
        bwrap = shutil.which("bwrap")
        report.add(
            "bubblewrap_available",
            CapabilityStatus.SUPPORTED if bwrap else CapabilityStatus.UNSUPPORTED,
            "bwrap found on PATH" if bwrap else "bwrap not found on PATH",
        )
        unshare = shutil.which("unshare")
        report.add(
            "unshare_available",
            CapabilityStatus.SUPPORTED if unshare else CapabilityStatus.UNSUPPORTED,
            "unshare found on PATH" if unshare else "unshare not found on PATH",
        )

    def _check_repo_location(self, report: HostCapabilityReport) -> None:
        """The repo must run from a Linux filesystem, not /mnt/<drive>."""
        try:
            resolved = self.repo_path.resolve()
        except OSError:
            resolved = self.repo_path
        text = str(resolved)
        if report.platform_system != "Linux":
            report.add("repo_on_linux_filesystem", CapabilityStatus.UNSUPPORTED,
                       "host is not Linux; repository must run inside WSL/Ubuntu")
            return
        parts = resolved.parts
        if len(parts) >= 3 and parts[1] == "mnt" and len(parts[2]) == 1:
            report.add("repo_on_linux_filesystem", CapabilityStatus.UNSUPPORTED,
                       f"repository is under /mnt/{parts[2]} (Windows-backed drvfs); "
                       "move it to the Linux filesystem (e.g. ~/src/AgenticOS)")
            return
        if text.startswith("/mnt/"):
            report.add("repo_on_linux_filesystem", CapabilityStatus.UNVERIFIED,
                       f"repository is under /mnt (unrecognized mount): {parts[:3]}")
            return
        report.add("repo_on_linux_filesystem", CapabilityStatus.SUPPORTED,
                   "repository path is on the Linux filesystem")
