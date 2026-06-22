"""Semgrep SAST adapter."""

from __future__ import annotations

from .shared import ok_run, parse_error_run
from ..models import Finding, ScannerOutput
from ..utils import SEVERITY_MAP, cwe_from, load_json_output, owasp_from, repo_relative, run_command


def scan(workdir: str, seed: int, version: str = "") -> ScannerOutput:
    completed, duration = run_command([
        "semgrep",
        "scan",
        "--config",
        "p/owasp-top-ten",
        "--config",
        "p/security-audit",
        "--json",
        "--quiet",
        workdir,
    ])
    try:
        raw = load_json_output(completed.stdout) or {}
    except Exception as exc:  # noqa: BLE001
        return ScannerOutput(run=parse_error_run("semgrep", completed, duration, version, exc))

    findings: list[Finding] = []
    for index, result in enumerate(raw.get("results", [])):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        findings.append(
            Finding(
                id=f"sg-{seed + index:05d}",
                scanner="semgrep",
                rule_id=result.get("check_id", ""),
                title=(extra.get("message") or result.get("check_id", ""))[:160],
                severity=SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), "MEDIUM"),
                owasp=owasp_from(metadata.get("owasp")) or owasp_from(metadata),
                cwe=cwe_from(metadata.get("cwe")) or cwe_from(metadata),
                path=repo_relative(result.get("path", ""), workdir),
                start_line=result.get("start", {}).get("line", 0),
                end_line=result.get("end", {}).get("line", 0),
                snippet=(extra.get("lines") or "")[:1200],
                fix_hint=(metadata.get("fix") or extra.get("fix") or "")[:600],
                confidence="medium",
                details=(metadata.get("source-rule-url") or "")[:300],
            )
        )

    return ScannerOutput(findings=findings, run=ok_run("semgrep", completed, duration, version, findings_count=len(findings)))
