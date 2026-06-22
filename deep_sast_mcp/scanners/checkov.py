"""Checkov IaC and OpenAPI scanner adapter."""

from __future__ import annotations

from .shared import ok_run, parse_error_run
from ..models import Finding, ScannerOutput
from ..utils import SEVERITY_MAP, load_json_output, run_command


def scan(workdir: str, seed: int, version: str = "") -> ScannerOutput:
    completed, duration = run_command(["checkov", "-d", workdir, "--quiet", "--compact", "-o", "json"])
    try:
        raw = load_json_output(completed.stdout)
    except Exception as exc:  # noqa: BLE001
        return ScannerOutput(run=parse_error_run("checkov", completed, duration, version, exc))

    findings = normalize(raw, seed)
    return ScannerOutput(findings=findings, run=ok_run("checkov", completed, duration, version, findings_count=len(findings)))


def normalize(raw, seed: int) -> list[Finding]:
    blocks = raw if isinstance(raw, list) else [raw]
    findings: list[Finding] = []
    index = 0
    for block in blocks:
        if not isinstance(block, dict):
            continue
        failed_checks = (block.get("results", {}) or {}).get("failed_checks", [])
        for result in failed_checks:
            line_range = result.get("file_line_range") or [0, 0]
            findings.append(
                Finding(
                    id=f"ck-{seed + index:05d}",
                    scanner="checkov",
                    rule_id=result.get("check_id", ""),
                    title=(result.get("check_name") or result.get("check_id", ""))[:160],
                    severity=SEVERITY_MAP.get(str(result.get("severity") or "MEDIUM").upper(), "MEDIUM"),
                    owasp="A05:2021",
                    cwe="",
                    path=(result.get("file_path") or "").lstrip("/"),
                    start_line=line_range[0] or 0,
                    end_line=line_range[-1] or 0,
                    snippet="",
                    fix_hint=(result.get("guideline") or "")[:600],
                    confidence="medium",
                    details=(result.get("bc_check_id") or "")[:120],
                )
            )
            index += 1
    return findings
