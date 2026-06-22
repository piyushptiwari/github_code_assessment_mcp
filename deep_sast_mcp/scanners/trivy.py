"""Trivy filesystem vulnerability and misconfiguration scanner adapter."""

from __future__ import annotations

from .shared import ok_run, parse_error_run
from ..models import Finding, ScannerOutput
from ..utils import SEVERITY_MAP, cwe_from, load_json_output, run_command


def scan(workdir: str, seed: int, version: str = "") -> ScannerOutput:
    completed, duration = run_command([
        "trivy",
        "fs",
        "--scanners",
        "vuln,misconfig",
        "--format",
        "json",
        "--quiet",
        workdir,
    ])
    try:
        raw = load_json_output(completed.stdout) or {}
    except Exception as exc:  # noqa: BLE001
        return ScannerOutput(run=parse_error_run("trivy", completed, duration, version, exc))

    findings = normalize(raw, seed)
    return ScannerOutput(findings=findings, run=ok_run("trivy", completed, duration, version, findings_count=len(findings)))


def normalize(raw: dict, seed: int) -> list[Finding]:
    findings: list[Finding] = []
    index = 0
    for result in raw.get("Results") or []:
        target = result.get("Target", "")
        for misconfiguration in result.get("Misconfigurations") or []:
            cause = misconfiguration.get("CauseMetadata") or {}
            findings.append(
                Finding(
                    id=f"tv-{seed + index:05d}",
                    scanner="trivy",
                    rule_id=misconfiguration.get("ID", ""),
                    title=(misconfiguration.get("Title") or misconfiguration.get("ID", ""))[:160],
                    severity=SEVERITY_MAP.get(str(misconfiguration.get("Severity", "")).upper(), "MEDIUM"),
                    owasp="A05:2021",
                    cwe="",
                    path=target,
                    start_line=cause.get("StartLine", 0) or 0,
                    end_line=cause.get("EndLine", 0) or 0,
                    snippet="",
                    fix_hint=(misconfiguration.get("Resolution") or "")[:600],
                    confidence="medium",
                )
            )
            index += 1
        for vulnerability in result.get("Vulnerabilities") or []:
            fixed = vulnerability.get("FixedVersion", "")
            package_name = vulnerability.get("PkgName", "")
            findings.append(
                Finding(
                    id=f"tv-{seed + index:05d}",
                    scanner="trivy",
                    rule_id=vulnerability.get("VulnerabilityID", ""),
                    title=(
                        f"{package_name} {vulnerability.get('InstalledVersion', '')}: "
                        f"{vulnerability.get('Title') or vulnerability.get('VulnerabilityID', '')}"
                    )[:160],
                    severity=SEVERITY_MAP.get(str(vulnerability.get("Severity", "")).upper(), "MEDIUM"),
                    owasp="A06:2021",
                    cwe=cwe_from(vulnerability.get("CweIDs")),
                    path=target,
                    start_line=0,
                    end_line=0,
                    snippet="",
                    fix_hint=(f"Upgrade {package_name} to {fixed}" if fixed else "")[:600],
                    confidence="high",
                    details=(vulnerability.get("PrimaryURL") or "")[:300],
                )
            )
            index += 1
    return findings
