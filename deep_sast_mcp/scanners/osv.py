"""OSV dependency vulnerability scanner adapter."""

from __future__ import annotations

from .shared import ok_run, parse_error_run
from ..models import ScannerOutput
from ..utils import load_json_output, run_command


def scan(workdir: str, seed: int, version: str = "") -> ScannerOutput:  # noqa: ARG001
    completed, duration = run_command(["osv-scanner", "--format", "json", "-r", workdir])
    try:
        raw = load_json_output(completed.stdout) or {}
    except Exception as exc:  # noqa: BLE001
        return ScannerOutput(run=parse_error_run("osv", completed, duration, version, exc))

    dependencies = normalize(raw)
    return ScannerOutput(dependencies=dependencies, run=ok_run("osv", completed, duration, version, dependency_findings=len(dependencies)))


def normalize(raw: dict) -> list[dict]:
    dependencies: list[dict] = []
    for result in raw.get("results", []):
        source = result.get("source", {}).get("path", "")
        for package_block in result.get("packages", []):
            package_info = package_block.get("package", {})
            for vulnerability in package_block.get("vulnerabilities", []):
                dependencies.append(
                    {
                        "manifest": source,
                        "package": package_info.get("name", ""),
                        "version": package_info.get("version", ""),
                        "ecosystem": package_info.get("ecosystem", ""),
                        "id": vulnerability.get("id", ""),
                        "aliases": vulnerability.get("aliases", []),
                        "summary": (vulnerability.get("summary") or "")[:500],
                        "details": (vulnerability.get("details") or "")[:1200],
                        "fixed": fixed_versions(vulnerability),
                    }
                )
    return dependencies


def fixed_versions(vulnerability: dict) -> list[str]:
    fixed: list[str] = []
    for affected in vulnerability.get("affected", []):
        for range_block in affected.get("ranges", []):
            for event in range_block.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return sorted(set(fixed))
