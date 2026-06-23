"""FastMCP app, tool registration, and HTTP routes."""

from __future__ import annotations

import argparse
import os
import shutil
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from .auth import apply_bearer_auth
from .config import MAX_GET_FILE_LINES
from .models import Scan
from .reporting import generate_report_artifact, scan_snapshot
from .scan_engine import start_scan
from .storage import REPORTS, SCANS, remove_reports, reports_for_scan, safe_report_path
from .utils import sort_findings


mcp = FastMCP("deep-sast")

_RUNNING_STATES = {"queued", "cloning", "scanning"}


def _safe_repo_path(workdir: str, path: str) -> str | None:
    root = Path(workdir).resolve()
    candidate = (root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return str(candidate)


def _read_line_window(path: str, from_line: int, max_lines: int) -> tuple[list[str], int, bool]:
    """Read at most ``max_lines`` starting at 1-indexed ``from_line`` without loading
    the whole file into memory. Returns (lines, last_line_number, truncated)."""
    collected: list[str] = []
    last_line = from_line - 1
    truncated = False
    with open(path, errors="replace", encoding="utf-8") as handle:
        for _ in range(max(0, from_line - 1)):
            if handle.readline() == "":
                return collected, last_line, False
        for offset in range(max_lines):
            line = handle.readline()
            if line == "":
                break
            collected.append(line)
            last_line = from_line + offset
        else:
            truncated = handle.readline() != ""
    return collected, last_line, truncated


def elapsed_seconds(scan: Scan) -> float:
    if scan.state in {"done", "error"}:
        return scan.duration_seconds
    if scan.started_monotonic:
        return round(time.monotonic() - scan.started_monotonic, 1)
    return 0.0


def scan_progress(scan: Scan) -> dict[str, Any]:
    total = scan.scanners_total or len(scan.selected_scanners)
    done = scan.scanners_completed
    if scan.state == "done":
        percent = 100.0
    elif total:
        percent = round((done / total) * 100, 1)
    else:
        percent = 0.0
    return {
        "stage": scan.current_stage,
        "scanners_total": total,
        "scanners_completed": done,
        "percent": percent,
    }


def _next_step(scan: Scan) -> str:
    if scan.state in _RUNNING_STATES:
        return (
            "Scan is running asynchronously. Poll get_scan_status(scan_id) and show "
            "progress.stage to the user until state=='done', then call generate_report."
        )
    if scan.state == "error":
        return "Scan failed. Report the error to the user; do not call generate_report."
    return "Call generate_report(scan_id, format='markdown'|'html'|'json'|'sarif'|'zip') and return the download_url to the user."


def scan_summary(scan: Scan) -> dict[str, Any]:
    return {
        "scan_id": scan.scan_id,
        "state": scan.state,
        "current_stage": scan.current_stage,
        "progress": scan_progress(scan),
        "elapsed_seconds": elapsed_seconds(scan),
        "error": scan.error,
        "repo_url": scan.repo_url,
        "ref": scan.ref,
        "scanners": scan.selected_scanners,
        "total_files": scan.total_files,
        "files_scanned": scan.files_scanned,
        "coverage": {
            "total_discovered": scan.coverage.total_discovered,
            "in_scope": scan.coverage.in_scope,
            "scanned": scan.coverage.scanned,
            "coverage_percent": scan.coverage.coverage_percent,
            "skipped": scan.coverage.skipped,
            "languages": scan.coverage.languages,
            "lockfiles": scan.coverage.lockfiles,
            "reconciles": scan.coverage.reconciles,
            "selection_via_git": scan.coverage.used_git,
        },
        "findings_count": len(scan.findings),
        "dependency_findings": len(scan.dependencies),
        "scanner_runs": [asdict(run) for run in scan.scanner_runs],
        "reports": [asdict(report) for report in scan.reports],
        "next_step": _next_step(scan),
    }


@mcp.tool()
def scan_repository(repo_url: str, ref: str = "HEAD", scanners: str | None = None) -> dict:
    """Start an asynchronous repository scan and return immediately with a scan_id.

    Runs SAST, secrets, SCA, IaC, and container/filesystem scanners in parallel in a
    background worker so the call never blocks the agent turn (large repos previously
    timed out at 300s). Omit `scanners` to run everything, or pass a comma-separated
    string of aliases such as `sast,secrets,sca,iac,container`.

    The returned state is usually `queued`. Poll get_scan_status(scan_id), surface
    progress.stage to the user until state is `done`, then call generate_report.
    """
    scan = start_scan(repo_url=repo_url, ref=ref, scanners=scanners)
    return scan_summary(scan)


@mcp.tool()
def get_scan_status(scan_id: str) -> dict:
    """Return scan state, coverage, scanner run status, and report artifacts."""
    scan = SCANS.get(scan_id)
    if not scan:
        return {"error": "unknown scan_id"}
    return scan_summary(scan)


@mcp.tool()
def list_findings(
    scan_id: str,
    severity: str | None = None,
    path_prefix: str | None = None,
    cursor: int = 0,
    limit: int = 50,
) -> dict:
    """Paginated normalized findings. Filter by severity and/or repo-relative path prefix."""
    scan = SCANS.get(scan_id)
    if not scan:
        return {"error": "unknown scan_id"}
    items = sort_findings(scan.findings)
    if severity:
        items = [finding for finding in items if finding.severity == severity.upper()]
    if path_prefix:
        items = [finding for finding in items if finding.path.startswith(path_prefix)]
    limit = max(1, min(limit, 250))
    cursor = max(0, cursor)
    page = items[cursor:cursor + limit]
    next_cursor = cursor + limit if cursor + limit < len(items) else None
    return {"total": len(items), "next_cursor": next_cursor, "items": [asdict(item) for item in page]}


@mcp.tool()
def get_finding_context(scan_id: str, finding_id: str, context_lines: int = 30) -> dict:
    """Return exact code context around a finding for validation and remediation."""
    scan = SCANS.get(scan_id)
    if not scan:
        return {"error": "unknown scan_id"}
    finding = next((item for item in scan.findings if item.id == finding_id), None)
    if not finding:
        return {"error": "unknown finding_id"}
    if finding.scanner == "gitleaks":
        return {"finding": asdict(finding), "context": "***REDACTED***"}
    if not scan.workdir:
        return {"finding": asdict(finding), "context": None, "message": "scan workspace evicted; reports remain available"}
    absolute_path = _safe_repo_path(scan.workdir, finding.path)
    if not absolute_path or not os.path.isfile(absolute_path):
        return {"finding": asdict(finding), "context": None}
    context_lines = max(1, min(context_lines, 200))
    from_line = max(1, finding.start_line - context_lines)
    span = (finding.end_line or finding.start_line) - finding.start_line + 1
    max_lines = min(MAX_GET_FILE_LINES, span + 2 * context_lines)
    lines, last_line, _ = _read_line_window(absolute_path, from_line, max_lines)
    return {
        "finding": asdict(finding),
        "from_line": from_line,
        "to_line": last_line,
        "context": "".join(lines),
    }


@mcp.tool()
def get_file(scan_id: str, path: str, start_line: int = 1, end_line: int = 0) -> dict:
    """Return raw repo-relative file content for deep dives. end_line=0 reads to EOF,
    capped at MAX_GET_FILE_LINES lines per call to bound the response size."""
    scan = SCANS.get(scan_id)
    if not scan:
        return {"error": "unknown scan_id"}
    if not scan.workdir:
        return {"error": "scan workspace evicted; reports remain available via list_reports"}
    absolute_path = _safe_repo_path(scan.workdir, path)
    if not absolute_path:
        return {"error": "path outside scan workspace"}
    if not os.path.isfile(absolute_path):
        return {"error": "file not found"}
    start_line = max(1, start_line)
    if end_line and end_line >= start_line:
        requested = end_line - start_line + 1
    else:
        requested = MAX_GET_FILE_LINES
    max_lines = min(MAX_GET_FILE_LINES, requested)
    lines, last_line, truncated = _read_line_window(absolute_path, start_line, max_lines)
    return {
        "path": path,
        "from_line": start_line,
        "to_line": last_line,
        "truncated": truncated,
        "content": "".join(lines),
    }


@mcp.tool()
def get_dependency_report(scan_id: str) -> dict:
    """Return SCA results with package, version, advisory/CVE ids, aliases, and fixed versions."""
    scan = SCANS.get(scan_id)
    if not scan:
        return {"error": "unknown scan_id"}
    return {"scan_id": scan_id, "count": len(scan.dependencies), "dependencies": scan.dependencies}


@mcp.tool()
def generate_report(scan_id: str, format: str = "markdown", max_preview_chars: int = 6000) -> dict:
    """Generate a detailed downloadable report artifact.

    Supported formats: markdown, html, json, sarif, zip. The returned download_url is the
    full artifact; content_preview lets the agent include a concise excerpt in chat.
    """
    scan = SCANS.get(scan_id)
    if not scan:
        return {"error": "unknown scan_id"}
    if scan.state in _RUNNING_STATES:
        return {
            "scan_id": scan_id,
            "state": scan.state,
            "current_stage": scan.current_stage,
            "progress": scan_progress(scan),
            "elapsed_seconds": elapsed_seconds(scan),
            "message": "Scan still running. Poll get_scan_status until state=='done', then call generate_report.",
        }
    artifact, content = generate_report_artifact(scan, format)
    max_preview_chars = max(1, min(max_preview_chars, 50000))
    return {
        "scan_id": scan_id,
        "report_id": artifact.report_id,
        "format": artifact.format,
        "filename": artifact.filename,
        "download_url": artifact.download_url,
        "media_type": artifact.media_type,
        "size_bytes": artifact.size_bytes,
        "sha256": artifact.sha256,
        "content_preview": content[:max_preview_chars],
        "truncated": len(content) > max_preview_chars,
        "snapshot": scan_snapshot(scan)["finding_counts"],
        "next_step": "Share download_url with the user for the full detailed report.",
    }


@mcp.tool()
def get_report(report_id: str, max_chars: int = 12000) -> dict:
    """Return report artifact content by report_id. ZIP artifacts should be downloaded by URL."""
    artifact = REPORTS.get(report_id)
    if not artifact:
        return {"error": "unknown report_id"}
    if artifact.format == "zip":
        return {**asdict(artifact), "content": None, "message": "ZIP report is binary; use download_url."}
    if not os.path.isfile(artifact.path):
        return {"error": "report file missing"}
    with open(artifact.path, encoding="utf-8", errors="replace") as handle:
        content = handle.read()
    max_chars = max(1, min(max_chars, 100000))
    return {**asdict(artifact), "content": content[:max_chars], "truncated": len(content) > max_chars, "total_chars": len(content)}


@mcp.tool()
def list_reports(scan_id: str = "") -> dict:
    """List generated report artifacts, optionally filtered by scan_id."""
    reports = reports_for_scan(scan_id) if scan_id else list(REPORTS.values())
    return {"count": len(reports), "reports": [asdict(report) for report in reports]}


@mcp.tool()
def cleanup_scan(scan_id: str, keep_reports: bool = True) -> dict:
    """Delete the cloned repository workspace. Reports are preserved by default for download."""
    scan = SCANS.pop(scan_id, None)
    workspace_removed = False
    if scan and os.path.isdir(scan.workdir):
        shutil.rmtree(scan.workdir, ignore_errors=True)
        workspace_removed = True
    reports_removed = remove_reports(scan_id) if scan and not keep_reports else 0
    return {
        "scan_id": scan_id,
        "removed": bool(scan),
        "workspace_removed": workspace_removed,
        "reports_preserved": bool(keep_reports),
        "reports_removed": reports_removed,
    }


def build_asgi_app():
    try:
        app = mcp.http_app()
    except AttributeError:
        app = mcp.streamable_http_app()

    from starlette.responses import FileResponse, JSONResponse, PlainTextResponse
    from starlette.routing import Route

    async def root(_request):
        return PlainTextResponse("deep-sast-mcp")

    async def health(_request):
        return PlainTextResponse("ok")

    async def report_download(request):
        scan_id = request.path_params["scan_id"]
        filename = request.path_params["filename"]
        path = safe_report_path(scan_id, filename)
        if not path:
            return JSONResponse({"error": "report not found"}, status_code=404)
        artifact = next((item for item in REPORTS.values() if item.scan_id == scan_id and item.filename == filename), None)
        media_type = artifact.media_type if artifact else "application/octet-stream"
        return FileResponse(path, media_type=media_type, filename=filename)

    app.router.routes.insert(0, Route("/", root, methods=["GET"]))
    app.router.routes.insert(1, Route("/health", health, methods=["GET"]))
    app.router.routes.insert(2, Route("/reports/{scan_id}/{filename:path}", report_download, methods=["GET"]))
    return apply_bearer_auth(app)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", default="http", choices=["http", "stdio"])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run()
        return

    import uvicorn

    uvicorn.run(build_asgi_app(), host=args.host, port=args.port)
