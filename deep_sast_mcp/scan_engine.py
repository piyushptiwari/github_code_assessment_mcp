"""Repository cloning and scanner orchestration."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
import uuid
from typing import Any, Callable

from .config import CLONE_DEPTH, DEFAULT_SCANNERS, MAX_REPO_MB, SCANNER_ALIASES
from .models import Scan, ScannerOutput, ScannerRun, utc_now
from .scanners import checkov, gitleaks, osv, semgrep, trivy
from .storage import SCANS, ensure_report_dir
from .utils import command_version, count_files, directory_size_mb, run_command, stderr_tail, validate_repo_url


ScannerAdapter = Callable[[str, int, str], ScannerOutput]
SCANNER_ADAPTERS: dict[str, ScannerAdapter] = {
    "semgrep": semgrep.scan,
    "gitleaks": gitleaks.scan,
    "osv": osv.scan,
    "checkov": checkov.scan,
    "trivy": trivy.scan,
}
VERSION_COMMANDS = {
    "semgrep": ["semgrep", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "osv": ["osv-scanner", "--version"],
    "checkov": ["checkov", "--version"],
    "trivy": ["trivy", "--version"],
}


def coerce_scanners(scanners: Any) -> list[str]:
    """Accept None, a list, or a comma/space-separated string and return scanner names."""
    if scanners is None or scanners == "":
        return list(DEFAULT_SCANNERS)
    if isinstance(scanners, str):
        cleaned = scanners.strip()
        if cleaned.lower() == "all":
            return list(DEFAULT_SCANNERS)
        tokens = re.split(r"[\s,]+", cleaned.strip("[]").replace('"', "").replace("'", ""))
    elif isinstance(scanners, (list, tuple, set)):
        tokens = [str(token) for token in scanners]
    else:
        tokens = [str(scanners)]

    ordered: dict[str, None] = {}
    for token in tokens:
        canonical = SCANNER_ALIASES.get(token.strip().lower())
        if canonical == "all":
            return list(DEFAULT_SCANNERS)
        if canonical:
            ordered.setdefault(canonical, None)
    return list(ordered) or list(DEFAULT_SCANNERS)


def start_scan(repo_url: str, ref: str = "HEAD", scanners: Any = None) -> Scan:
    selected = coerce_scanners(scanners)
    validate_repo_url(repo_url)
    scan_id = uuid.uuid4().hex
    workdir = tempfile.mkdtemp(prefix=f"sast-{scan_id}-")
    scan = Scan(
        scan_id=scan_id,
        repo_url=repo_url,
        ref=ref or "HEAD",
        workdir=workdir,
        reports_dir=ensure_report_dir(scan_id),
        selected_scanners=selected,
    )
    SCANS[scan_id] = scan
    do_scan(scan, selected)
    return scan


def do_scan(scan: Scan, scanners: list[str]) -> None:
    started = time.monotonic()
    try:
        scan.state = "cloning"
        clone_command = ["git", "clone", "--depth", CLONE_DEPTH]
        if scan.ref not in ("", "HEAD"):
            clone_command.extend(["--branch", scan.ref])
        clone_command.extend([scan.repo_url, scan.workdir])
        completed, clone_duration = run_command(clone_command)
        if completed.returncode != 0:
            raise ValueError(f"git clone failed: {stderr_tail(completed.stderr, 1800)}")

        size_mb = directory_size_mb(scan.workdir)
        if size_mb > MAX_REPO_MB:
            raise ValueError(f"repo too large: {size_mb:.0f}MB > {MAX_REPO_MB}MB cap")

        scan.total_files = count_files(scan.workdir)
        scan.state = "scanning"
        scan.scanner_versions = collect_versions(scanners)
        scan.scanner_runs.append(
            ScannerRun(
                scanner="git-clone",
                status="ok",
                duration_seconds=clone_duration,
                return_code=completed.returncode,
                version=command_version(["git", "--version"]),
            )
        )

        seed = 0
        for scanner_name in scanners:
            adapter = SCANNER_ADAPTERS.get(scanner_name)
            if adapter is None:
                scan.scanner_runs.append(ScannerRun(scanner=scanner_name, status="skipped", error="unknown scanner"))
                continue
            output = adapter(scan.workdir, seed, scan.scanner_versions.get(scanner_name, ""))
            scan.findings.extend(output.findings)
            scan.dependencies.extend(output.dependencies)
            if output.run:
                scan.scanner_runs.append(output.run)
            seed += max(len(output.findings), len(output.dependencies), 1) + 1000

        scan.files_scanned = scan.total_files
        scan.state = "done"
    except subprocess.TimeoutExpired:
        scan.state = "error"
        scan.error = "scan exceeded timeout"
    except Exception as exc:  # noqa: BLE001
        scan.state = "error"
        scan.error = str(exc)
    finally:
        scan.completed_at = utc_now()
        scan.duration_seconds = round(time.monotonic() - started, 3)


def collect_versions(scanners: list[str]) -> dict[str, str]:
    versions: dict[str, str] = {}
    for scanner in scanners:
        command = VERSION_COMMANDS.get(scanner)
        if command:
            versions[scanner] = command_version(command)
    return versions
