"""Shared scanner adapter helpers."""

from __future__ import annotations

from ..models import ScannerRun
from ..utils import stderr_tail


def ok_run(scanner: str, completed, duration: float, version: str, findings_count: int = 0, dependency_findings: int = 0) -> ScannerRun:
    status = "ok" if completed.returncode in (0, 1) else "warning"
    return ScannerRun(
        scanner=scanner,
        status=status,
        findings_count=findings_count,
        dependency_findings=dependency_findings,
        duration_seconds=duration,
        return_code=completed.returncode,
        version=version,
        stderr_tail=stderr_tail(completed.stderr),
    )


def parse_error_run(scanner: str, completed, duration: float, version: str, exc: Exception) -> ScannerRun:
    return ScannerRun(
        scanner=scanner,
        status="error",
        duration_seconds=duration,
        return_code=completed.returncode,
        version=version,
        error=f"failed to parse {scanner} JSON: {exc}",
        stderr_tail=stderr_tail(completed.stderr),
    )
