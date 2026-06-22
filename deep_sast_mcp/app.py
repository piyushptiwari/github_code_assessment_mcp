"""FastMCP app, tool registration, and HTTP routes."""

from __future__ import annotations

import argparse
import os
import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from .auth import apply_bearer_auth
from .models import Scan
from .reporting import generate_report_artifact, scan_snapshot
from .scan_engine import start_scan
from .storage import REPORTS, SCANS, remove_reports, reports_for_scan, safe_report_path
from .utils import sort_findings


mcp = FastMCP("deep-sast")


def _safe_repo_path(workdir: str, path: str) -> str | None:
    root = Path(workdir).resolve()
    candidate = (root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return str(candidate)


def scan_summary(scan: Scan) -> dict[str, Any]:
    return {
        "scan_id": scan.scan_id,
        "state": scan.state,
        "error": scan.error,
        "repo_url": scan.repo_url,
        "ref": scan.ref,
        "scanners": scan.selected_scanners,
        "total_files": scan.total_files,
        "files_scanned": scan.files_scanned,
        "findings_count": len(scan.findings),
        "dependency_findings": len(scan.dependencies),
        "scanner_runs": [asdict(run) for run in scan.scanner_runs],
        "reports": [asdict(report) for report in scan.reports],
        "next_step": "Call generate_report(scan_id, format='markdown'|'html'|'json'|'sarif'|'zip') and return the download_url to the user.",
    }


@mcp.tool()
def scan_repository(repo_url: str, ref: str = "HEAD", scanners: str | None = None) -> dict:
    """Clone a public repo and run SAST, secrets, SCA, IaC, and container/filesystem scanners.

    Omit `scanners` to run everything. To restrict, pass a comma-separated string using
    aliases such as `sast,secrets,sca,iac,container`. The scan is synchronous and returns
    a scan_id plus coverage and finding counts.
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
    absolute_path = _safe_repo_path(scan.workdir, finding.path)
    if not absolute_path or not os.path.isfile(absolute_path):
        return {"finding": asdict(finding), "context": None}
    with open(absolute_path, errors="replace", encoding="utf-8") as handle:
        lines = handle.readlines()
    context_lines = max(1, min(context_lines, 200))
    low = max(0, finding.start_line - 1 - context_lines)
    high = min(len(lines), (finding.end_line or finding.start_line) + context_lines)
    return {
        "finding": asdict(finding),
        "from_line": low + 1,
        "to_line": high,
        "context": "".join(lines[low:high]),
    }


@mcp.tool()
def get_file(scan_id: str, path: str, start_line: int = 1, end_line: int = 0) -> dict:
    """Return raw repo-relative file content for deep dives. end_line=0 means EOF."""
    scan = SCANS.get(scan_id)
    if not scan:
        return {"error": "unknown scan_id"}
    absolute_path = _safe_repo_path(scan.workdir, path)
    if not absolute_path:
        return {"error": "path outside scan workspace"}
    if not os.path.isfile(absolute_path):
        return {"error": "file not found"}
    with open(absolute_path, errors="replace", encoding="utf-8") as handle:
        lines = handle.readlines()
    start_line = max(1, start_line)
    end = end_line or len(lines)
    end = max(start_line, min(end, len(lines)))
    return {"path": path, "from_line": start_line, "to_line": end, "content": "".join(lines[start_line - 1:end])}


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
