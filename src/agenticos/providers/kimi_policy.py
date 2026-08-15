"""Fail-closed policy for the one passively qualified Kimi Planner artifact."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final


PINNED_VERSION: Final = "0.36.1"
PINNED_TAG: Final = "@moonshot-ai/kimi-code@0.36.1"
PINNED_SOURCE_COMMIT: Final = "13d86f8b7bb2443a3b8222e7d94deb0a66429f8e"
PINNED_ARCHIVE_SHA256: Final = "c5af089d5ad34c27f2f26d5f93588ba3f656bf771911e5d43c85be95d3e1cbd4"
PINNED_EXECUTABLE_SHA256: Final = "78c07b255e0bdc8dfe90d0cbd3204a3d862957394a08ca99c6e31144732451c7"
PINNED_MODE: Final = 0o555
GLOBAL_TOOL_SENTINEL: Final = "AgenticOSPlannerNoToolSentinel"
_CREDENTIAL_TRANSIENT_NAME: Final = re.compile(
    r"kimi-code\.json\.tmp\.[1-9][0-9]*\.[0-9a-f]{8}\Z"
)

_ARTIFACT_FIELDS: Final = {
    "schema",
    "version",
    "tag",
    "tag_object",
    "source_commit",
    "release_url",
    "release_published_at",
    "archive_name",
    "archive_size",
    "archive_sha256",
    "archive_url",
    "checksum_url",
    "checksum_sha256",
    "manifest_url",
    "manifest_sha256",
    "executable_name",
    "executable_size",
    "executable_sha256",
    "elf_build_id",
    "platform",
    "runtime_requirements",
    "required_mode",
}


class KimiPolicyError(ValueError):
    """One stable rejection code for qualification-policy drift."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise KimiPolicyError("DUPLICATE_JSON_KEY", name)
        result[name] = value
    return result


@dataclass(frozen=True, slots=True)
class KimiPinnedArtifact:
    version: str
    tag: str
    source_commit: str
    archive_sha256: str
    executable_sha256: str
    executable_size: int
    required_mode: int

    def __post_init__(self) -> None:
        exact = (
            (self.version, PINNED_VERSION, "WRONG_VERSION"),
            (self.tag, PINNED_TAG, "WRONG_TAG"),
            (self.source_commit, PINNED_SOURCE_COMMIT, "WRONG_SOURCE_COMMIT"),
            (self.archive_sha256, PINNED_ARCHIVE_SHA256, "WRONG_ARCHIVE_HASH"),
            (
                self.executable_sha256,
                PINNED_EXECUTABLE_SHA256,
                "WRONG_EXECUTABLE_HASH_PIN",
            ),
        )
        for actual, expected, code in exact:
            if actual != expected:
                raise KimiPolicyError(code)
        if type(self.executable_size) is not int or self.executable_size < 1:
            raise KimiPolicyError("INVALID_EXECUTABLE_SIZE")
        if self.required_mode != PINNED_MODE:
            raise KimiPolicyError("WRONG_REQUIRED_MODE")

    @classmethod
    def from_json(cls, path: Path) -> KimiPinnedArtifact:
        try:
            raw = json.loads(
                path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise KimiPolicyError("ARTIFACT_UNREADABLE") from exc
        if type(raw) is not dict or set(raw) != _ARTIFACT_FIELDS:
            raise KimiPolicyError("ARTIFACT_FIELDS")
        if raw["schema"] != "AOS_KIMI_PIN/1":
            raise KimiPolicyError("ARTIFACT_SCHEMA")
        _validate_provenance(raw)
        mode = raw["required_mode"]
        if mode != "0555":
            raise KimiPolicyError("WRONG_REQUIRED_MODE")
        return cls(
            version=raw["version"],
            tag=raw["tag"],
            source_commit=raw["source_commit"],
            archive_sha256=raw["archive_sha256"],
            executable_sha256=raw["executable_sha256"],
            executable_size=raw["executable_size"],
            required_mode=int(mode, 8),
        )


def _validate_provenance(raw: dict[str, object]) -> None:
    exact = {
        "tag_object": "336fed3b5f265c986d4f43808da98f3c6b4bbd16",
        "release_published_at": "2026-08-14T12:53:36Z",
        "archive_name": "kimi-code-linux-x64.zip",
        "archive_size": 64_621_491,
        "checksum_sha256": "428ca7c07c64fa266d86ee372a2689ceeb063ab5724221e8e1e729b1f96748b5",
        "manifest_sha256": "b1c89cc44b3e4401125ac86a5ac4c9cc324f856e902c7b859049fc3578c2af66",
        "executable_name": "kimi",
        "elf_build_id": "5e67bdf95c7646325b62decd0ca8d375d325ea19",
        "platform": "linux-x64",
        "release_url": "https://github.com/MoonshotAI/kimi-code/releases/tag/%40moonshot-ai%2Fkimi-code%400.36.1",
        "archive_url": "https://github.com/MoonshotAI/kimi-code/releases/download/%40moonshot-ai/kimi-code%400.36.1/kimi-code-linux-x64.zip",
        "checksum_url": "https://github.com/MoonshotAI/kimi-code/releases/download/%40moonshot-ai/kimi-code%400.36.1/kimi-code-linux-x64.zip.sha256",
        "manifest_url": "https://github.com/MoonshotAI/kimi-code/releases/download/%40moonshot-ai/kimi-code%400.36.1/manifest.json",
    }
    for name, expected in exact.items():
        if raw[name] != expected:
            raise KimiPolicyError("ARTIFACT_PROVENANCE_DRIFT", name)
    requirements = raw["runtime_requirements"]
    if type(requirements) is not list or requirements != [
        "ELF x86-64",
        "/lib64/ld-linux-x86-64.so.2",
        "glibc",
        "libstdc++",
        "libgcc_s",
    ]:
        raise KimiPolicyError("RUNTIME_REQUIREMENTS_DRIFT")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pinned_runtime(
    executable: Path,
    artifact: KimiPinnedArtifact,
    *,
    expected_uid: int,
) -> None:
    try:
        info = executable.lstat()
    except FileNotFoundError as exc:
        raise KimiPolicyError("MISSING_EXECUTABLE") from exc
    if stat.S_ISLNK(info.st_mode):
        raise KimiPolicyError("EXECUTABLE_SYMLINK")
    if not stat.S_ISREG(info.st_mode):
        raise KimiPolicyError("EXECUTABLE_NOT_REGULAR")
    if info.st_size != artifact.executable_size:
        raise KimiPolicyError("WRONG_EXECUTABLE_SIZE")
    if info.st_uid != expected_uid:
        raise KimiPolicyError("WRONG_EXECUTABLE_OWNER")
    if stat.S_IMODE(info.st_mode) != artifact.required_mode:
        raise KimiPolicyError("WRONG_EXECUTABLE_MODE")
    if sha256_file(executable) != artifact.executable_sha256:
        raise KimiPolicyError("WRONG_EXECUTABLE_HASH")


def verify_reported_version(reported: str) -> None:
    if type(reported) is not str or re.fullmatch(r"(?:kimi\s+)?0\.36\.1", reported.strip()) is None:
        raise KimiPolicyError("WRONG_REPORTED_VERSION")


def build_kimi_environment() -> dict[str, str]:
    """Return the whole provider environment; never inherit ``os.environ``."""

    return {
        "HOME": "/home/aos",
        "KIMI_CODE_HOME": "/home/aos/kimi",
        "KIMI_CODE_NO_AUTO_UPDATE": "1",
        "KIMI_DISABLE_CRON": "1",
        "KIMI_DISABLE_TELEMETRY": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/opt/agenticos/kimi/bin:/usr/bin",
        "PWD": "/workspace",
        "TMPDIR": "/tmp",
    }


def validate_qualification_bundle(root: Path) -> KimiPinnedArtifact:
    expected = {
        "artifact.json",
        "config.toml",
        "data-root-policy.json",
        "agents/agent.md",
    }
    try:
        actual = {
            str(path.relative_to(root)).replace(os.sep, "/")
            for path in root.rglob("*")
            if path.is_file() or path.is_symlink()
        }
    except OSError as exc:
        raise KimiPolicyError("BUNDLE_UNREADABLE") from exc
    if actual != expected:
        raise KimiPolicyError("UNEXPECTED_QUALIFICATION_FILE")
    for relative in expected:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise KimiPolicyError("QUALIFICATION_FILE_TYPE", relative)

    artifact = KimiPinnedArtifact.from_json(root / "artifact.json")
    _validate_config(root / "config.toml")
    _validate_data_root_policy(root / "data-root-policy.json")
    _validate_profile(root / "agents" / "agent.md")
    return artifact


def _validate_data_root_policy(path: Path) -> None:
    expected = {
        "schema": "AOS_KIMI_DATA_ROOT_POLICY/1",
        "credential_storage_key": "oauth/kimi-code",
        "future_persistent_paths": ["credentials/"],
        "future_credential_directory_mode": "0700",
        "future_credential_file_mode": "0600",
        "future_credential_final_entries": ["kimi-code.json"],
        "future_credential_transient_pattern": "kimi-code.json.tmp.<pid>.<8-lowercase-hex>",
        "ephemeral_categories": ["CACHE", "LOG", "MUTABLE_NONSECRET_STATE"],
        "workspace_authority": "NONE",
        "unknown_state_policy": "FAIL_CLOSED",
        "real_authentication": "NOT_AUTHENTICATED",
        "real_provider_execution": "REAL_PROVIDER_DISABLED",
    }
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KimiPolicyError("DATA_ROOT_POLICY_UNREADABLE") from exc
    if raw != expected:
        raise KimiPolicyError("DATA_ROOT_POLICY_DRIFT")


def validate_future_credential_directory(
    root: Path,
    *,
    trusted_state_root: Path,
    allow_transient: bool = False,
    expected_uid: int | None = None,
) -> None:
    """Fail closed over the complete future persistent credential submount."""

    if (
        not isinstance(root, Path)
        or not isinstance(trusted_state_root, Path)
        or type(allow_transient) is not bool
    ):
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_ARGUMENT")
    if (
        not root.is_absolute()
        or not trusted_state_root.is_absolute()
        or root != trusted_state_root / "credentials"
    ):
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_PATH")
    if expected_uid is None:
        expected_uid = os.getuid()
    if type(expected_uid) is not int or expected_uid < 0:
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_ARGUMENT")
    try:
        trusted_stat = trusted_state_root.lstat()
        trusted_resolved = trusted_state_root.resolve(strict=True)
    except OSError as exc:
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_PATH") from exc
    if (
        not stat.S_ISDIR(trusted_stat.st_mode)
        or trusted_state_root.is_symlink()
        or trusted_resolved != trusted_state_root
    ):
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_PATH")
    if trusted_stat.st_uid != expected_uid:
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_OWNER")
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_TYPE") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or root.is_symlink():
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_TYPE")
    if stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_MODE")
    if root_stat.st_uid != expected_uid:
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_OWNER")
    try:
        if root.resolve(strict=True) != root:
            raise KimiPolicyError("CREDENTIAL_DIRECTORY_PATH")
    except OSError as exc:
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_PATH") from exc

    try:
        entries = sorted(root.iterdir(), key=lambda entry: entry.name)
    except OSError as exc:
        raise KimiPolicyError("CREDENTIAL_DIRECTORY_UNREADABLE") from exc
    for entry in entries:
        is_final = entry.name == "kimi-code.json"
        is_transient = _CREDENTIAL_TRANSIENT_NAME.fullmatch(entry.name) is not None
        if not is_final and not is_transient:
            raise KimiPolicyError("CREDENTIAL_ENTRY_NAME", entry.name)
        if is_transient and not allow_transient:
            raise KimiPolicyError("CREDENTIAL_TRANSIENT_PRESENT", entry.name)
        try:
            entry_stat = entry.lstat()
        except OSError as exc:
            raise KimiPolicyError("CREDENTIAL_ENTRY_TYPE", entry.name) from exc
        if not stat.S_ISREG(entry_stat.st_mode) or entry.is_symlink():
            raise KimiPolicyError("CREDENTIAL_ENTRY_TYPE", entry.name)
        if entry_stat.st_nlink != 1:
            raise KimiPolicyError("CREDENTIAL_FILE_LINK_COUNT", entry.name)
        if stat.S_IMODE(entry_stat.st_mode) != 0o600:
            raise KimiPolicyError("CREDENTIAL_FILE_MODE", entry.name)
        if entry_stat.st_uid != expected_uid:
            raise KimiPolicyError("CREDENTIAL_FILE_OWNER", entry.name)


def _validate_config(path: Path) -> None:
    try:
        raw_text = path.read_text(encoding="utf-8")
        config = tomllib.loads(raw_text)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise KimiPolicyError("CONFIG_UNREADABLE") from exc
    allowed = {
        "default_model",
        "default_permission_mode",
        "default_plan_mode",
        "merge_all_available_skills",
        "builtin_product_skills",
        "telemetry",
        "background",
        "tools",
        "providers",
        "models",
    }
    if set(config) != allowed:
        raise KimiPolicyError("CONFIG_FIELDS")
    exact_scalars = {
        "default_model": "kimi-code/kimi-for-coding",
        "default_permission_mode": "manual",
        "default_plan_mode": True,
        "merge_all_available_skills": False,
        "builtin_product_skills": False,
        "telemetry": False,
    }
    for name, expected in exact_scalars.items():
        if config.get(name) != expected:
            codes = {
                "merge_all_available_skills": "SKILLS_NOT_DISABLED",
                "builtin_product_skills": "BUILTIN_SKILLS_NOT_DISABLED",
                "telemetry": "TELEMETRY_NOT_DISABLED",
            }
            raise KimiPolicyError(codes.get(name, "CONFIG_SCALAR_DRIFT"), name)
    if config["background"] != {"max_running_tasks": 1, "keep_alive_on_exit": False}:
        raise KimiPolicyError("BACKGROUND_POLICY_DRIFT")
    if config["tools"] != {"enabled": [GLOBAL_TOOL_SENTINEL]}:
        raise KimiPolicyError("GLOBAL_TOOL_SENTINEL_DRIFT")
    providers = config["providers"]
    expected_provider = {
        "type": "kimi",
        "base_url": "https://api.kimi.com/coding/v1",
        "api_key": "",
        "oauth": {"storage": "file", "key": "oauth/kimi-code"},
    }
    if providers != {"managed:kimi-code": expected_provider}:
        if isinstance(providers, dict) and any(
            isinstance(value, dict) and value.get("api_key") not in (None, "")
            for value in providers.values()
        ):
            raise KimiPolicyError("API_KEY_CONFIGURED")
        raise KimiPolicyError("PROVIDER_POLICY_DRIFT")
    expected_model = {
        "provider": "managed:kimi-code",
        "model": "kimi-for-coding",
        "max_context_size": 262144,
        "capabilities": ["thinking", "always_thinking"],
    }
    if config["models"] != {"kimi-code/kimi-for-coding": expected_model}:
        raise KimiPolicyError("MODEL_POLICY_DRIFT")
    forbidden = ("KIMI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "env =", "[hooks", "[mcp")
    if any(item in raw_text for item in forbidden):
        raise KimiPolicyError("FORBIDDEN_CONFIG_AUTHORITY")


def _validate_profile(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise KimiPolicyError("PROFILE_UNREADABLE") from exc
    if "${" in text:
        raise KimiPolicyError("PROFILE_TEMPLATE_EXPANSION")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise KimiPolicyError("PROFILE_FRONTMATTER")
    header, body = text[4:].split("\n---\n", 1)
    if re.search(r"^tools:\s*$", header, re.MULTILINE):
        raise KimiPolicyError("PROFILE_TOOLS_NOT_EMPTY")
    if re.search(r"^subagents:\s*$", header, re.MULTILINE):
        raise KimiPolicyError("PROFILE_SUBAGENTS_NOT_EMPTY")
    fields: dict[str, str] = {}
    for line in header.splitlines():
        if ":" not in line:
            raise KimiPolicyError("PROFILE_FRONTMATTER")
        name, value = line.split(":", 1)
        name = name.strip()
        if name in fields:
            raise KimiPolicyError("PROFILE_DUPLICATE_FIELD", name)
        fields[name] = value.strip()
    if set(fields) != {"name", "description", "override", "tools", "subagents"}:
        raise KimiPolicyError("PROFILE_FIELDS")
    checks = (
        (fields["name"] == "agent", "PROFILE_WRONG_NAME"),
        (fields["override"] == "true", "PROFILE_NOT_OVERRIDE"),
        (fields["tools"] == "[]", "PROFILE_TOOLS_NOT_EMPTY"),
        (fields["subagents"] == "[]", "PROFILE_SUBAGENTS_NOT_EMPTY"),
    )
    for accepted, code in checks:
        if not accepted:
            raise KimiPolicyError(code)
    required = (
        "exactly one AOSPLAN/1",
        "untrusted data",
        "Do not invoke tools, subagents, files, commands, plugins, skills, hooks, or background work.",
    )
    if any(fragment not in body for fragment in required):
        raise KimiPolicyError("PROFILE_PROMPT_DRIFT")
