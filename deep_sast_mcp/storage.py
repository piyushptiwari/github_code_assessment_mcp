"""In-memory scan registry plus report path helpers."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from .config import MAX_RETAINED_SCANS, REPORTS_ROOT, SCAN_TTL_S
from .models import ReportArtifact, Scan


SCANS: dict[str, Scan] = {}
REPORTS: dict[str, ReportArtifact] = {}


def ensure_report_dir(scan_id: str) -> str:
    path = os.path.join(REPORTS_ROOT, scan_id)
    os.makedirs(path, exist_ok=True)
    return path


def _free_workspace(scan: Scan) -> None:
    """Delete a scan's clone workspace to release disk and memory pressure."""
    if scan.workdir and os.path.isdir(scan.workdir):
        shutil.rmtree(scan.workdir, ignore_errors=True)
    scan.workdir = ""


def evict_if_needed() -> int:
    """Bound the registry by TTL and count. Reports are preserved; only the clone
    workspace of old finished scans is released, and the oldest finished scans are
    dropped once the count exceeds MAX_RETAINED_SCANS. In-flight scans are never evicted."""
    evicted = 0
    now = time.monotonic()

    for scan in list(SCANS.values()):
        if scan.state in {"done", "error"} and scan.workdir and scan.started_monotonic:
            if now - scan.started_monotonic > SCAN_TTL_S:
                _free_workspace(scan)
                evicted += 1

    if len(SCANS) > MAX_RETAINED_SCANS:
        ordered = sorted(SCANS.values(), key=lambda item: item.started_monotonic)
        for scan in ordered[: len(SCANS) - MAX_RETAINED_SCANS]:
            if scan.state in {"queued", "cloning", "scanning"}:
                continue
            _free_workspace(scan)
            SCANS.pop(scan.scan_id, None)
            evicted += 1
    return evicted


def reports_for_scan(scan_id: str) -> list[ReportArtifact]:
    return [report for report in REPORTS.values() if report.scan_id == scan_id]


def safe_report_path(scan_id: str, filename: str) -> str | None:
    root = Path(REPORTS_ROOT, scan_id).resolve()
    candidate = (root / filename).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return str(candidate)


def remove_reports(scan_id: str) -> int:
    removed = 0
    for report in list(reports_for_scan(scan_id)):
        REPORTS.pop(report.report_id, None)
        try:
            os.remove(report.path)
            removed += 1
        except OSError:
            pass
    shutil.rmtree(os.path.join(REPORTS_ROOT, scan_id), ignore_errors=True)
    return removed
