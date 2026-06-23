"""Repository cloning and scanner orchestration."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from .config import CLONE_DEPTH, DEFAULT_SCANNERS, MAX_FINDINGS_PER_SCANNER, MAX_REPO_MB, SCANNER_ALIASES
from .models import CoverageLedger, Scan, ScannerOutput, ScannerRun, utc_now
from .scanners import checkov, gitleaks, osv, semgrep, trivy
from .selection import select_files
from .storage import SCANS, ensure_report_dir, evict_if_needed
from .utils import command_version, directory_size_mb, run_command, stderr_tail, validate_repo_url


ScannerAdapter = Callable[..., ScannerOutput]
SEED_BLOCK = 100000
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


def start_scan(repo_url: str, ref: str = "HEAD", scanners: Any = None, wait: bool = False) -> Scan:
    """Create a scan and run it in a background thread.

    Returns immediately with state ``queued`` so the MCP/A2A call does not block
    (the synchronous version timed out the platform's agent turn on large repos).
    Callers poll ``get_scan_status`` for progress. Pass ``wait=True`` for tests.
    """
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
        state="queued",
        current_stage="queued",
        scanners_total=len(selected),
        started_monotonic=time.monotonic(),
    )
    SCANS[scan_id] = scan
    evict_if_needed()
    if wait:
        do_scan(scan, selected)
    else:
        thread = threading.Thread(target=do_scan, args=(scan, selected), name=f"scan-{scan_id[:8]}", daemon=True)
        thread.start()
    return scan


def do_scan(scan: Scan, scanners: list[str]) -> None:
    started = time.monotonic()
    scan.started_monotonic = started
    try:
        scan.state = "cloning"
        scan.current_stage = "cloning repository"
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

        scan.current_stage = "selecting in-scope files"
        selection = select_files(scan.workdir)
        scan.coverage = CoverageLedger(
            total_discovered=selection.total_discovered,
            in_scope=selection.in_scope,
            scanned=selection.in_scope,
            skipped=dict(selection.skipped),
            languages=dict(selection.languages),
            lockfiles=len(selection.lockfiles),
            used_git=selection.used_git,
        )
        exclude_dirs = selection.exclude_dirs
        scan.total_files = selection.in_scope
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

        runnable: list[tuple[str, ScannerAdapter]] = []
        for scanner_name in scanners:
            adapter = SCANNER_ADAPTERS.get(scanner_name)
            if adapter is None:
                scan.scanner_runs.append(ScannerRun(scanner=scanner_name, status="skipped", error="unknown scanner"))
            else:
                runnable.append((scanner_name, adapter))

        scan.scanners_total = len(runnable)
        scan.scanners_completed = 0
        scan.current_stage = f"scanning 0/{len(runnable)} ({', '.join(name for name, _ in runnable)})"

        # Run scanners in parallel: wall-clock time becomes the slowest single
        # scanner instead of the sum, which keeps most scans within budget. Only
        # the orchestrator thread mutates `scan`, so no per-field locks are needed.
        with ThreadPoolExecutor(max_workers=max(1, len(runnable))) as executor:
            future_to_name = {
                executor.submit(adapter, scan.workdir, index * SEED_BLOCK, scan.scanner_versions.get(name, ""), exclude_dirs): name
                for index, (name, adapter) in enumerate(runnable)
            }
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    output = future.result()
                except Exception as exc:  # noqa: BLE001
                    scan.scanner_runs.append(ScannerRun(scanner=name, status="error", error=str(exc)))
                else:
                    findings = output.findings[:MAX_FINDINGS_PER_SCANNER]
                    if output.run and len(output.findings) > MAX_FINDINGS_PER_SCANNER:
                        output.run.error = (output.run.error + f"; truncated to {MAX_FINDINGS_PER_SCANNER} findings").strip("; ")
                    scan.findings.extend(findings)
                    scan.dependencies.extend(output.dependencies)
                    if output.run:
                        scan.scanner_runs.append(output.run)
                scan.scanners_completed += 1
                scan.current_stage = f"scanning {scan.scanners_completed}/{scan.scanners_total} ({name} done)"

        scan.files_scanned = scan.coverage.scanned
        scan.current_stage = "completed"
        scan.state = "done"
    except subprocess.TimeoutExpired:
        scan.state = "error"
        scan.current_stage = "error: timeout"
        scan.error = "scan exceeded timeout"
    except Exception as exc:  # noqa: BLE001
        scan.state = "error"
        scan.current_stage = "error"
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
