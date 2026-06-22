"""gitleaks secret scanner adapter."""

from __future__ import annotations

import json
import os

from .shared import ok_run, parse_error_run
from ..config import SECRET_REDACT
from ..models import Finding, ScannerOutput
from ..utils import run_command


def scan(workdir: str, seed: int, version: str = "") -> ScannerOutput:
    report_path = os.path.join(workdir, "_gitleaks.json")
    completed, duration = run_command([
        "gitleaks",
        "detect",
        "--source",
        workdir,
        "--no-banner",
        "--report-format",
        "json",
        "--report-path",
        report_path,
    ])
    raw = []
    if os.path.exists(report_path):
        try:
            with open(report_path, encoding="utf-8") as handle:
                raw = json.load(handle)
        except Exception as exc:  # noqa: BLE001
            return ScannerOutput(run=parse_error_run("gitleaks", completed, duration, version, exc))
        finally:
            try:
                os.remove(report_path)
            except OSError:
                pass

    findings: list[Finding] = []
    for index, result in enumerate(raw or []):
        findings.append(
            Finding(
                id=f"gl-{seed + index:05d}",
                scanner="gitleaks",
                rule_id=result.get("RuleID", "secret"),
                title=f"Hardcoded secret: {result.get('Description', result.get('RuleID', 'secret'))}"[:160],
                severity="HIGH",
                owasp="A02:2021",
                cwe="CWE-798",
                path=result.get("File", ""),
                start_line=result.get("StartLine", 0),
                end_line=result.get("EndLine", 0),
                snippet=SECRET_REDACT,
                fix_hint="Rotate the exposed secret, remove it from git history, move it to a secrets manager or environment variable, and add pre-commit scanning.",
                confidence="high",
            )
        )

    return ScannerOutput(findings=findings, run=ok_run("gitleaks", completed, duration, version, findings_count=len(findings)))
