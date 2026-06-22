"""In-memory scan registry plus report path helpers."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .config import REPORTS_ROOT
from .models import ReportArtifact, Scan


SCANS: dict[str, Scan] = {}
REPORTS: dict[str, ReportArtifact] = {}


def ensure_report_dir(scan_id: str) -> str:
    path = os.path.join(REPORTS_ROOT, scan_id)
    os.makedirs(path, exist_ok=True)
    return path


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
