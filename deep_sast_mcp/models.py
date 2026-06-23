"""Shared data models for scans, findings, scanner runs, and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class Finding:
    id: str
    scanner: str
    rule_id: str
    title: str
    severity: str
    owasp: str
    cwe: str
    path: str
    start_line: int
    end_line: int
    snippet: str
    fix_hint: str = ""
    confidence: str = "medium"
    details: str = ""


@dataclass
class ScannerRun:
    scanner: str
    status: str
    findings_count: int = 0
    dependency_findings: int = 0
    duration_seconds: float = 0.0
    return_code: int | None = None
    version: str = ""
    error: str = ""
    stderr_tail: str = ""


@dataclass
class ScannerOutput:
    findings: list[Finding] = field(default_factory=list)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    run: ScannerRun | None = None


@dataclass
class CoverageLedger:
    """Honest reconciliation of every discovered file.

    Invariant: ``in_scope + sum(skipped.values()) == total_discovered``.
    """

    total_discovered: int = 0
    in_scope: int = 0
    scanned: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    languages: dict[str, int] = field(default_factory=dict)
    lockfiles: int = 0
    used_git: bool = False

    @property
    def coverage_percent(self) -> float:
        if self.in_scope == 0:
            return 100.0 if self.scanned == 0 else 0.0
        return round((self.scanned / self.in_scope) * 100, 2)

    @property
    def reconciles(self) -> bool:
        return self.in_scope + sum(self.skipped.values()) == self.total_discovered


@dataclass
class ReportArtifact:
    report_id: str
    scan_id: str
    format: str
    filename: str
    path: str
    download_url: str
    media_type: str
    size_bytes: int
    sha256: str
    created_at: str = field(default_factory=utc_now)


@dataclass
class Scan:
    scan_id: str
    repo_url: str
    ref: str
    workdir: str
    reports_dir: str
    state: str = "pending"
    selected_scanners: list[str] = field(default_factory=list)
    total_files: int = 0
    files_scanned: int = 0
    coverage: "CoverageLedger" = field(default_factory=lambda: CoverageLedger())
    findings: list[Finding] = field(default_factory=list)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    scanner_runs: list[ScannerRun] = field(default_factory=list)
    scanner_versions: dict[str, str] = field(default_factory=dict)
    reports: list[ReportArtifact] = field(default_factory=list)
    error: str | None = None
    current_stage: str = "pending"
    scanners_total: int = 0
    scanners_completed: int = 0
    started_monotonic: float = 0.0
    started_at: str = field(default_factory=utc_now)
    completed_at: str = ""
    duration_seconds: float = 0.0
