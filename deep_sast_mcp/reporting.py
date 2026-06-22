"""Detailed report generation and artifact storage."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
import uuid
import zipfile
from dataclasses import asdict
from typing import Any
from urllib.parse import quote

from .config import public_base_url
from .models import ReportArtifact, Scan
from .storage import REPORTS
from .utils import SEVERITY_ORDER, clean_table_text, sort_findings


FORMAT_EXTENSIONS = {"markdown": "md", "md": "md", "html": "html", "json": "json", "sarif": "sarif", "zip": "zip", "all": "zip"}
MEDIA_TYPES = {
    "md": "text/markdown; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "sarif": "application/sarif+json; charset=utf-8",
    "zip": "application/zip",
}


def canonical_format(format_name: str) -> str:
    value = (format_name or "markdown").strip().lower()
    if value == "md":
        return "markdown"
    if value == "all":
        return "zip"
    if value not in {"markdown", "html", "json", "sarif", "zip"}:
        return "markdown"
    return value


def generate_report_artifact(scan: Scan, format_name: str = "markdown") -> tuple[ReportArtifact, str]:
    report_format = canonical_format(format_name)
    content = render_zip(scan) if report_format == "zip" else render_report(scan, report_format).encode("utf-8")
    extension = FORMAT_EXTENSIONS[report_format]
    report_id = uuid.uuid4().hex
    os.makedirs(scan.reports_dir, exist_ok=True)
    filename = f"deep-sast-{scan.scan_id[:8]}-{report_id[:8]}.{extension}"
    path = os.path.join(scan.reports_dir, filename)
    with open(path, "wb") as handle:
        handle.write(content)
    digest = hashlib.sha256(content).hexdigest()
    base = public_base_url()
    relative_url = f"/reports/{scan.scan_id}/{quote(filename)}"
    artifact = ReportArtifact(
        report_id=report_id,
        scan_id=scan.scan_id,
        format=report_format,
        filename=filename,
        path=path,
        download_url=f"{base}{relative_url}" if base else relative_url,
        media_type=MEDIA_TYPES[extension],
        size_bytes=os.path.getsize(path),
        sha256=digest,
    )
    REPORTS[report_id] = artifact
    scan.reports.append(artifact)
    preview = "ZIP evidence pack generated. Use download_url to retrieve the artifact." if report_format == "zip" else content.decode("utf-8", errors="replace")
    return artifact, preview


def render_report(scan: Scan, format_name: str) -> str:
    if format_name == "json":
        return json.dumps(scan_snapshot(scan), indent=2, sort_keys=True)
    if format_name == "sarif":
        return json.dumps(render_sarif(scan), indent=2, sort_keys=True)
    if format_name == "html":
        return render_html(scan)
    return render_markdown(scan)


def render_zip(scan: Scan) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.md", render_markdown(scan))
        archive.writestr("report.html", render_html(scan))
        archive.writestr("report.json", render_report(scan, "json"))
        archive.writestr("report.sarif", render_report(scan, "sarif"))
        archive.writestr("dependency-vulnerabilities.csv", render_dependency_csv(scan))
    return buffer.getvalue()


def scan_snapshot(scan: Scan) -> dict[str, Any]:
    return {
        "scan_id": scan.scan_id,
        "repo_url": scan.repo_url,
        "ref": scan.ref,
        "state": scan.state,
        "error": scan.error,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "duration_seconds": scan.duration_seconds,
        "coverage": {"total_files": scan.total_files, "files_scanned": scan.files_scanned, "coverage_percent": coverage_percent(scan)},
        "selected_scanners": scan.selected_scanners,
        "scanner_versions": scan.scanner_versions,
        "scanner_runs": [asdict(run) for run in scan.scanner_runs],
        "finding_counts": {
            "total": len(scan.findings),
            "by_severity": severity_counts(scan.findings),
            "by_scanner": scanner_counts(scan.findings),
            "dependency_findings": len(scan.dependencies),
            "dependencies_by_ecosystem": dependency_counts(scan.dependencies),
        },
        "findings": [asdict(finding) for finding in sort_findings(scan.findings)],
        "dependencies": scan.dependencies,
        "reports": [asdict(report) for report in scan.reports],
    }


def coverage_percent(scan: Scan) -> float:
    if scan.total_files == 0:
        return 0.0
    return round((scan.files_scanned / scan.total_files) * 100, 2)


def severity_counts(findings: list) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        severity = getattr(finding, "severity", "INFO") or "INFO"
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def scanner_counts(findings: list) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        scanner = getattr(finding, "scanner", "unknown") or "unknown"
        counts[scanner] = counts.get(scanner, 0) + 1
    return counts


def dependency_counts(dependencies: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for dependency in dependencies:
        ecosystem = dependency.get("ecosystem") or "unknown"
        counts[ecosystem] = counts.get(ecosystem, 0) + 1
    return counts


def render_markdown(scan: Scan) -> str:
    findings = sort_findings(scan.findings)
    severity_summary = severity_counts(findings)
    scanner_summary = scanner_counts(findings)
    dependency_summary = dependency_counts(scan.dependencies)
    lines: list[str] = []
    lines.append("# Deep SAST Security Assessment Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Repository: `{scan.repo_url}`")
    lines.append(f"- Ref: `{scan.ref}`")
    lines.append(f"- Scan id: `{scan.scan_id}`")
    lines.append(f"- State: `{scan.state}`")
    if scan.error:
        lines.append(f"- Error: `{scan.error}`")
    lines.append(f"- Coverage: {scan.files_scanned}/{scan.total_files} files scanned ({coverage_percent(scan)}%)")
    lines.append(f"- Code/IaC/secrets/container findings: {len(findings)}")
    lines.append(f"- Dependency findings: {len(scan.dependencies)}")
    lines.append(f"- Started: {scan.started_at}")
    lines.append(f"- Completed: {scan.completed_at or 'not completed'}")
    lines.append(f"- Duration seconds: {scan.duration_seconds}")
    lines.append("")
    lines.append("## Coverage Ledger")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Total in-scope files | {scan.total_files} |")
    lines.append(f"| Files scanned by deterministic tools | {scan.files_scanned} |")
    lines.append(f"| Coverage percent | {coverage_percent(scan)} |")
    lines.append("| Skipped files | 0 |")
    lines.append("")
    lines.append("## Scanner Inventory")
    lines.append("")
    lines.append("| Scanner | Version | Status | Findings | Dependencies | Return code | Duration seconds |")
    lines.append("|---|---|---|---:|---:|---:|---:|")
    for run in scan.scanner_runs:
        version = clean_table_text(run.version or scan.scanner_versions.get(run.scanner, "") or "unknown")
        lines.append(f"| {run.scanner} | {version} | {run.status} | {run.findings_count} | {run.dependency_findings} | {run.return_code if run.return_code is not None else ''} | {run.duration_seconds} |")
    lines.append("")
    lines.append("## Severity Distribution")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for severity in sorted(severity_summary, key=lambda item: SEVERITY_ORDER.get(item, 99)):
        lines.append(f"| {severity} | {severity_summary[severity]} |")
    lines.append("")
    lines.append("## Scanner Distribution")
    lines.append("")
    lines.append("| Scanner | Count |")
    lines.append("|---|---:|")
    for scanner, count in sorted(scanner_summary.items()):
        lines.append(f"| {scanner} | {count} |")
    lines.append("")
    lines.append("## Top Risk Queue")
    lines.append("")
    top_findings = [finding for finding in findings if finding.severity in {"CRITICAL", "HIGH"}][:25]
    if top_findings:
        for finding in top_findings:
            lines.append(f"- `{finding.id}` {finding.severity} {finding.scanner}/{finding.rule_id}: {finding.title} at `{location(finding)}`")
    else:
        lines.append("- No critical or high code/IaC/secrets/container findings were reported.")
    lines.append("")
    lines.append("## Detailed Findings")
    lines.append("")
    if findings:
        for finding in findings:
            lines.extend(render_finding_markdown(finding))
    else:
        lines.append("No normalized code, secrets, IaC, or container findings were reported.")
        lines.append("")
    lines.append("## Dependency Vulnerability Appendix")
    lines.append("")
    lines.append("### Dependency Counts By Ecosystem")
    lines.append("")
    lines.append("| Ecosystem | Count |")
    lines.append("|---|---:|")
    for ecosystem, count in sorted(dependency_summary.items()):
        lines.append(f"| {ecosystem} | {count} |")
    if not dependency_summary:
        lines.append("| none | 0 |")
    lines.append("")
    if scan.dependencies:
        lines.append("### Dependency Details")
        lines.append("")
        lines.append("| ID | Package | Version | Ecosystem | Manifest | Fixed | Summary |")
        lines.append("|---|---|---|---|---|---|---|")
        for dependency in scan.dependencies:
            aliases = ", ".join(dependency.get("aliases") or [])
            advisory = dependency.get("id") or aliases or "unknown"
            fixed = ", ".join(dependency.get("fixed") or []) or "not published"
            summary = clean_table_text(dependency.get("summary") or "")[:220]
            lines.append(
                f"| {clean_table_text(advisory)} | {clean_table_text(dependency.get('package', ''))} | {clean_table_text(dependency.get('version', ''))} | {clean_table_text(dependency.get('ecosystem', ''))} | {clean_table_text(dependency.get('manifest', ''))} | {clean_table_text(fixed)} | {summary} |"
            )
        lines.append("")
    lines.append("## Remediation Guidance")
    lines.append("")
    lines.append("1. Patch critical and high dependency advisories first, especially remote code execution, code injection, SSRF, and path traversal issues.")
    lines.append("2. Rotate and remove exposed secrets, then purge them from git history where applicable.")
    lines.append("3. Fix IaC and API security misconfigurations that weaken authentication, validation, or network exposure.")
    lines.append("4. Re-run this MCP scan after remediation and compare scan ids for closure evidence.")
    lines.append("")
    lines.append("## Machine-Readable Artifacts")
    lines.append("")
    lines.append("Generate `json` for raw normalized evidence, `sarif` for code scanning import, or `zip` for a full evidence pack.")
    lines.append("")
    return "\n".join(lines)


def render_finding_markdown(finding) -> list[str]:
    lines = [
        f"### {finding.id}: {finding.title}",
        "",
        f"- Severity: {finding.severity}",
        f"- Scanner: {finding.scanner}",
        f"- Rule: `{finding.rule_id}`",
        f"- Location: `{location(finding)}`",
        f"- OWASP: {finding.owasp or 'not mapped'}",
        f"- CWE: {finding.cwe or 'not mapped'}",
        f"- Confidence: {finding.confidence}",
    ]
    if finding.details:
        lines.append(f"- Details: {finding.details}")
    if finding.fix_hint:
        lines.append(f"- Remediation: {finding.fix_hint}")
    if finding.snippet:
        lines.append("")
        lines.append("Evidence:")
        lines.append("")
        lines.append("```text")
        lines.append(finding.snippet[:1200])
        lines.append("```")
    lines.append("")
    return lines


def render_html(scan: Scan) -> str:
    markdown = render_markdown(scan)
    escaped = html.escape(markdown)
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Deep SAST Report {html.escape(scan.scan_id[:8])}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 0; color: #17202a; background: #f6f8fa; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px; }}
    pre {{ white-space: pre-wrap; background: white; border: 1px solid #d0d7de; border-radius: 6px; padding: 18px; line-height: 1.45; }}
  </style>
</head>
<body><main><pre>{escaped}</pre></main></body>
</html>"""


def render_sarif(scan: Scan) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in sort_findings(scan.findings):
        rule_key = f"{finding.scanner}:{finding.rule_id or finding.id}"
        rules.setdefault(
            rule_key,
            {
                "id": rule_key,
                "name": finding.title[:80],
                "shortDescription": {"text": finding.title},
                "properties": {"scanner": finding.scanner, "owasp": finding.owasp, "cwe": finding.cwe, "severity": finding.severity},
            },
        )
        results.append(
            {
                "ruleId": rule_key,
                "level": sarif_level(finding.severity),
                "message": {"text": finding.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path or "unknown"},
                            "region": {"startLine": max(finding.start_line, 1), "endLine": max(finding.end_line or finding.start_line, 1)},
                        }
                    }
                ],
                "properties": {"id": finding.id, "scanner": finding.scanner, "owasp": finding.owasp, "cwe": finding.cwe, "fix_hint": finding.fix_hint, "confidence": finding.confidence},
            }
        )

    for dependency in scan.dependencies:
        advisory = dependency.get("id") or "dependency-vulnerability"
        rule_key = f"osv:{advisory}"
        rules.setdefault(
            rule_key,
            {
                "id": rule_key,
                "name": advisory,
                "shortDescription": {"text": dependency.get("summary") or advisory},
                "properties": {"scanner": "osv", "category": "dependency", "owasp": "A06:2021"},
            },
        )
        results.append(
            {
                "ruleId": rule_key,
                "level": "warning",
                "message": {"text": f"{dependency.get('package', '')} {dependency.get('version', '')}: {dependency.get('summary') or advisory}"[:500]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": dependency.get("manifest") or "dependency-manifest"}}}],
                "properties": dependency,
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Deep SAST MCP", "informationUri": "https://github.com/piyushptiwari/github_code_assessment_mcp", "rules": list(rules.values())}},
                "automationDetails": {"id": scan.scan_id},
                "results": results,
            }
        ],
    }


def render_dependency_csv(scan: Scan) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["manifest", "package", "version", "ecosystem", "id", "aliases", "fixed", "summary"])
    for dependency in scan.dependencies:
        writer.writerow([
            dependency.get("manifest", ""),
            dependency.get("package", ""),
            dependency.get("version", ""),
            dependency.get("ecosystem", ""),
            dependency.get("id", ""),
            ", ".join(dependency.get("aliases") or []),
            ", ".join(dependency.get("fixed") or []),
            dependency.get("summary", ""),
        ])
    return buffer.getvalue()


def sarif_level(severity: str) -> str:
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"


def location(finding) -> str:
    if finding.start_line:
        end = finding.end_line or finding.start_line
        return f"{finding.path}:{finding.start_line}-{end}"
    return finding.path or "unknown"
