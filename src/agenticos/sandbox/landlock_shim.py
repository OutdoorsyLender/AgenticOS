#!/usr/bin/env python3
"""EXPERIMENTAL Landlock filesystem-policy shim (standalone, stdlib only).

Reads a policy from the AOS_LANDLOCK_POLICY environment variable (base64
JSON: {"rules": [{"path": ..., "access": "rw" | "ro"}]}), restricts the
current thread with Landlock, then execs the command after `--`:

    python landlock_shim.py -- <argv...>

Landlock is inherited across fork/exec, so every descendant of the exec'd
process keeps the restriction. Any policy-application error is FAIL-CLOSED:
the target command never runs. Not a security sandbox by itself — this is a
Phase Zero experiment composed under cgroup process containment.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import sys

_SYS_LANDLOCK_CREATE_RULESET = 444  # x86_64 / aarch64 / riscv64
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446
_PR_SET_NO_NEW_PRIVS = 38
_LANDLOCK_RULE_PATH_BENEATH = 1

# linux/landlock.h access rights (ABI v1 bits 0..12, v2 REFER, v3 TRUNCATE)
_EXECUTE = 1 << 0
_WRITE_FILE = 1 << 1
_READ_FILE = 1 << 2
_READ_DIR = 1 << 3
_REMOVE_DIR = 1 << 4
_REMOVE_FILE = 1 << 5
_MAKE_CHAR = 1 << 6
_MAKE_DIR = 1 << 7
_MAKE_REG = 1 << 8
_MAKE_SOCK = 1 << 9
_MAKE_FIFO = 1 << 10
_MAKE_BLOCK = 1 << 11
_MAKE_SYM = 1 << 12
_REFER = 1 << 13
_TRUNCATE = 1 << 14

ACCESS_RO = _READ_FILE | _READ_DIR | _EXECUTE
ACCESS_RW = (
    _EXECUTE | _WRITE_FILE | _READ_FILE | _READ_DIR | _REMOVE_DIR | _REMOVE_FILE
    | _MAKE_CHAR | _MAKE_DIR | _MAKE_REG | _MAKE_SOCK | _MAKE_FIFO | _MAKE_BLOCK
    | _MAKE_SYM | _REFER | _TRUNCATE
)
ACCESS_BY_NAME = {"ro": ACCESS_RO, "rw": ACCESS_RW}

# Rights meaningful on non-directory paths; granting directory-only rights
# (READ_DIR, MAKE_*, REMOVE_DIR) on a regular file makes add_rule fail EINVAL.
_FILE_RIGHTS = _EXECUTE | _READ_FILE | _WRITE_FILE | _REMOVE_FILE | _REFER | _TRUNCATE


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]


def _fail_closed(message: str) -> "NoReturn":  # noqa: F821
    print(json.dumps({"shim": "landlock", "applied": False, "error": message}))
    sys.exit(2)


def main() -> None:
    libc = ctypes.CDLL(None, use_errno=True)

    raw = os.environ.get("AOS_LANDLOCK_POLICY")
    if not raw:
        _fail_closed("AOS_LANDLOCK_POLICY not set")
    try:
        policy = json.loads(base64.b64decode(raw))
        rules = policy["rules"]
    except Exception as exc:  # noqa: BLE001
        _fail_closed(f"bad policy: {exc}")

    try:
        sep = sys.argv.index("--")
        target_argv = sys.argv[sep + 1:]
    except ValueError:
        _fail_closed("missing '--' separator")
    if not target_argv:
        _fail_closed("empty target argv")

    # Handled rights: everything we might grant — anything NOT granted by a
    # path-beneath rule is denied for the whole filesystem.
    handled = ACCESS_RW
    attr = _RulesetAttr(handled)
    ruleset_fd = libc.syscall(_SYS_LANDLOCK_CREATE_RULESET,
                              ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if ruleset_fd < 0:
        _fail_closed(f"create_ruleset failed, errno={ctypes.get_errno()}")

    for rule in rules:
        access = ACCESS_BY_NAME.get(rule.get("access"))
        if access is None:
            _fail_closed(f"unknown access {rule.get('access')!r}")
        try:
            path_fd = os.open(rule["path"], os.O_PATH)
        except OSError as exc:
            _fail_closed(f"cannot open rule path {rule['path']!r}: {exc}")
        # Directory-only rights on a regular file are rejected (EINVAL).
        if not os.path.isdir(rule["path"]):
            access &= _FILE_RIGHTS
        pb = _PathBeneathAttr(access & handled, path_fd)
        rc = libc.syscall(_SYS_LANDLOCK_ADD_RULE, ruleset_fd,
                          _LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(pb), 0)
        os.close(path_fd)
        if rc != 0:
            _fail_closed(f"add_rule failed for {rule['path']!r}, "
                         f"errno={ctypes.get_errno()}")

    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        _fail_closed(f"prctl(NO_NEW_PRIVS) failed, errno={ctypes.get_errno()}")
    if libc.syscall(_SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
        _fail_closed(f"restrict_self failed, errno={ctypes.get_errno()}")
    os.close(ruleset_fd)

    os.execvpe(target_argv[0], target_argv, os.environ)
    _fail_closed("exec returned")  # unreachable


if __name__ == "__main__":
    main()
