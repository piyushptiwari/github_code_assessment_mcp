"""Utility helpers shared by scanner adapters and MCP tools."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from typing import Any

from .config import ALLOWED_GIT_HOSTS, COMMAND_VERSION_TIMEOUT_S, SCAN_TIMEOUT_S


SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "MEDIUM",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def host_of(url: str) -> str:
    match = re.match(r"https?://([^/]+)/", url if url.endswith("/") else url + "/")
    return (match.group(1).lower() if match else "").split("@")[-1]


def validate_repo_url(url: str) -> None:
    if not url.startswith("https://"):
        raise ValueError("repo_url must be an https:// URL")
    if host_of(url) not in ALLOWED_GIT_HOSTS:
        raise ValueError(f"host not allowed; permitted: {sorted(ALLOWED_GIT_HOSTS)}")


def count_files(root: str) -> int:
    total = 0
    for directory, _subdirectories, files in os.walk(root):
        normalized = directory.replace("\\", "/")
        if "/.git" in normalized or normalized.endswith("/.git"):
            continue
        total += len(files)
    return total


def directory_size_mb(root: str) -> float:
    total = 0
    for directory, _subdirectories, files in os.walk(root):
        for filename in files:
            try:
                total += os.path.getsize(os.path.join(directory, filename))
            except OSError:
                continue
    return total / (1024 * 1024)


def run_command(command: list[str], cwd: str | None = None, timeout: int = SCAN_TIMEOUT_S) -> tuple[subprocess.CompletedProcess, float]:
    started = time.monotonic()
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return completed, round(time.monotonic() - started, 3)


def command_version(command: list[str]) -> str:
    try:
        completed, _duration = run_command(command, timeout=COMMAND_VERSION_TIMEOUT_S)
    except Exception:
        return ""
    text = (completed.stdout or completed.stderr or "").strip()
    return text.splitlines()[0][:120] if text else ""


def stderr_tail(text: str, limit: int = 1200) -> str:
    return (text or "")[-limit:]


def cwe_from(tags: Any) -> str:
    text = json.dumps(tags) if not isinstance(tags, str) else tags
    match = re.search(r"CWE-\d+", text or "")
    return match.group(0) if match else ""


def owasp_from(tags: Any) -> str:
    text = json.dumps(tags) if not isinstance(tags, str) else tags
    match = re.search(r"A\d{2}:20\d\d", text or "")
    return match.group(0) if match else ""


def load_json_output(text: str) -> Any:
    stripped = (text or "").strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        starts = [index for index in (stripped.find("{"), stripped.find("[")) if index >= 0]
        if not starts:
            raise
        return json.loads(stripped[min(starts):])


def repo_relative(path: str, root: str) -> str:
    if not path:
        return ""
    try:
        relative = os.path.relpath(path, root) if os.path.isabs(path) else path
    except ValueError:
        relative = path
    return relative.replace("\\", "/")


def sort_findings(findings: list) -> list:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(getattr(finding, "severity", "INFO"), 99),
            getattr(finding, "scanner", ""),
            getattr(finding, "path", ""),
            getattr(finding, "start_line", 0),
            getattr(finding, "rule_id", ""),
        ),
    )


def clean_table_text(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ").strip()
