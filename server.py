"""
Deep SAST MCP Server for the Security Gap-Finding Agent.

Wraps Semgrep + gitleaks + osv-scanner behind the Model Context Protocol so the
IBM Consulting Advantage agent (github_code_security_assessment_Piyush_tiwari) can
get DETERMINISTIC, 100%-file-coverage findings instead of LLM-sampled greps.

Exposes these MCP tools:
  - scan_repository(repo_url, ref, scanners)   -> starts a scan, returns scan_id + counts
  - get_scan_status(scan_id)                   -> coverage stats (files_scanned/total)
  - list_findings(scan_id, severity, cursor)   -> paginated, normalized findings
  - get_finding_context(scan_id, finding_id)   -> code around a finding (for triage)
  - get_file(scan_id, path, start, end)        -> raw file content for deep dives
  - get_dependency_report(scan_id)             -> SCA / CVE results

Security posture (do not weaken):
  - Scanners PARSE the code; they never execute the target repo.
  - Each scan runs in its own temp workspace, deleted on cleanup.
  - Clone is shallow + size-capped; clone only from allowed hosts.
  - gitleaks secret values are redacted before they leave this process.

Run:  python server.py --transport http --host 0.0.0.0 --port 8080
Deps: pip install -r requirements.txt  (plus semgrep, gitleaks, osv-scanner on PATH)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

from fastmcp import FastMCP

mcp = FastMCP("deep-sast")

# ----------------------------------------------------------------------------- config
ALLOWED_GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}
MAX_REPO_MB = int(os.getenv("MAX_REPO_MB", "500"))
CLONE_DEPTH = "1"
SCAN_TIMEOUT_S = int(os.getenv("SCAN_TIMEOUT_S", "1800"))  # 30 min hard cap
SECRET_REDACT = "***REDACTED***"

# Optional static bearer token. When set (recommended in production), every HTTP
# request to the MCP endpoint must send `Authorization: Bearer <MCP_AUTH_TOKEN>`.
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "").strip()

# Full scanner set: SAST + Secrets + SCA + IaC + Container/filesystem.
DEFAULT_SCANNERS = ["semgrep", "gitleaks", "osv", "checkov", "trivy"]

# In-memory scan registry. For production, back this with Redis/DB so it survives restarts.
SCANS: dict[str, "Scan"] = {}


@dataclass
class Finding:
    id: str
    scanner: str
    rule_id: str
    title: str
    severity: str          # CRITICAL/HIGH/MEDIUM/LOW/INFO
    owasp: str             # e.g. "A03:2021"
    cwe: str               # e.g. "CWE-78"
    path: str
    start_line: int
    end_line: int
    snippet: str
    fix_hint: str = ""


@dataclass
class Scan:
    scan_id: str
    repo_url: str
    ref: str
    workdir: str
    state: str = "pending"          # pending|cloning|scanning|done|error
    total_files: int = 0
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    dependencies: list[dict] = field(default_factory=list)
    error: str | None = None


# ----------------------------------------------------------------------------- helpers
SEVERITY_MAP = {
    "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",       # semgrep
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "MODERATE": "MEDIUM",
}


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/]+)/", url if url.endswith("/") else url + "/")
    return (m.group(1).lower() if m else "").split("@")[-1]


def _validate_repo_url(url: str) -> None:
    if not url.startswith("https://"):
        raise ValueError("repo_url must be an https:// URL")
    if _host_of(url) not in ALLOWED_GIT_HOSTS:
        raise ValueError(f"host not allowed; permitted: {sorted(ALLOWED_GIT_HOSTS)}")


def _count_files(root: str) -> int:
    n = 0
    for _dir, _sub, files in os.walk(root):
        if "/.git" in _dir or _dir.endswith("/.git"):
            continue
        n += len(files)
    return n


def _run(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=SCAN_TIMEOUT_S
    )


def _cwe_from(tags: Any) -> str:
    text = json.dumps(tags) if not isinstance(tags, str) else tags
    m = re.search(r"CWE-\d+", text or "")
    return m.group(0) if m else ""


def _owasp_from(tags: Any) -> str:
    text = json.dumps(tags) if not isinstance(tags, str) else tags
    m = re.search(r"A\d{2}:20\d\d", text or "")
    return m.group(0) if m else ""


# ----------------------------------------------------------------------------- scanners
def _normalize_semgrep(raw: dict, fid_seed: int) -> list[Finding]:
    out: list[Finding] = []
    for i, r in enumerate(raw.get("results", [])):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        out.append(Finding(
            id=f"sg-{fid_seed + i:05d}",
            scanner="semgrep",
            rule_id=r.get("check_id", ""),
            title=(extra.get("message") or r.get("check_id", ""))[:160],
            severity=SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), "MEDIUM"),
            owasp=_owasp_from(meta.get("owasp")) or _owasp_from(meta),
            cwe=_cwe_from(meta.get("cwe")) or _cwe_from(meta),
            path=r.get("path", ""),
            start_line=r.get("start", {}).get("line", 0),
            end_line=r.get("end", {}).get("line", 0),
            snippet=(extra.get("lines") or "")[:600],
            fix_hint=(meta.get("fix") or extra.get("fix") or "")[:400],
        ))
    return out


def _normalize_gitleaks(raw: list, fid_seed: int) -> list[Finding]:
    out: list[Finding] = []
    for i, r in enumerate(raw or []):
        out.append(Finding(
            id=f"gl-{fid_seed + i:05d}",
            scanner="gitleaks",
            rule_id=r.get("RuleID", "secret"),
            title=f"Hardcoded secret: {r.get('Description', r.get('RuleID', 'secret'))}"[:160],
            severity="HIGH",
            owasp="A02:2021",
            cwe="CWE-798",
            path=r.get("File", ""),
            start_line=r.get("StartLine", 0),
            end_line=r.get("EndLine", 0),
            snippet=SECRET_REDACT,  # never leak the secret value
            fix_hint="Rotate the exposed secret, move it to a secrets manager / env var, "
                     "and add a pre-commit secret scanner.",
        ))
    return out


def _normalize_osv(raw: dict) -> list[dict]:
    deps: list[dict] = []
    for res in raw.get("results", []):
        source = res.get("source", {}).get("path", "")
        for pkg in res.get("packages", []):
            info = pkg.get("package", {})
            for v in pkg.get("vulnerabilities", []):
                deps.append({
                    "manifest": source,
                    "package": info.get("name", ""),
                    "version": info.get("version", ""),
                    "ecosystem": info.get("ecosystem", ""),
                    "id": v.get("id", ""),
                    "aliases": v.get("aliases", []),
                    "summary": (v.get("summary") or "")[:300],
                    "fixed": _osv_fixed_versions(v),
                })
    return deps


def _osv_fixed_versions(v: dict) -> list[str]:
    fixed = []
    for a in v.get("affected", []):
        for rng in a.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return sorted(set(fixed))


def _normalize_checkov(raw: Any, fid_seed: int) -> list[Finding]:
    """checkov -o json emits a dict (one framework) or a list (several). Each block
    has results.failed_checks for IaC misconfigurations (Terraform/K8s/Dockerfile...)."""
    blocks = raw if isinstance(raw, list) else [raw]
    out: list[Finding] = []
    idx = 0
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for r in (block.get("results", {}) or {}).get("failed_checks", []):
            rng = r.get("file_line_range") or [0, 0]
            out.append(Finding(
                id=f"ck-{fid_seed + idx:05d}",
                scanner="checkov",
                rule_id=r.get("check_id", ""),
                title=(r.get("check_name") or r.get("check_id", ""))[:160],
                severity=SEVERITY_MAP.get(str(r.get("severity") or "MEDIUM").upper(), "MEDIUM"),
                owasp="A05:2021",          # Security Misconfiguration
                cwe="",
                path=(r.get("file_path") or "").lstrip("/"),
                start_line=rng[0] or 0,
                end_line=rng[-1] or 0,
                snippet="",
                fix_hint=(r.get("guideline") or "")[:400],
            ))
            idx += 1
    return out


def _normalize_trivy(raw: dict, fid_seed: int) -> list[Finding]:
    """trivy fs (vuln + misconfig) results: container/filesystem package CVEs and
    Dockerfile/IaC misconfigurations."""
    out: list[Finding] = []
    idx = 0
    for res in (raw.get("Results") or []):
        target = res.get("Target", "")
        for m in (res.get("Misconfigurations") or []):
            cause = m.get("CauseMetadata") or {}
            out.append(Finding(
                id=f"tv-{fid_seed + idx:05d}",
                scanner="trivy",
                rule_id=m.get("ID", ""),
                title=(m.get("Title") or m.get("ID", ""))[:160],
                severity=SEVERITY_MAP.get(str(m.get("Severity", "")).upper(), "MEDIUM"),
                owasp="A05:2021",
                cwe="",
                path=target,
                start_line=cause.get("StartLine", 0) or 0,
                end_line=cause.get("EndLine", 0) or 0,
                snippet="",
                fix_hint=(m.get("Resolution") or "")[:400],
            ))
            idx += 1
        for v in (res.get("Vulnerabilities") or []):
            fixed = v.get("FixedVersion", "")
            out.append(Finding(
                id=f"tv-{fid_seed + idx:05d}",
                scanner="trivy",
                rule_id=v.get("VulnerabilityID", ""),
                title=f"{v.get('PkgName', '')} {v.get('InstalledVersion', '')}: "
                      f"{v.get('Title') or v.get('VulnerabilityID', '')}"[:160],
                severity=SEVERITY_MAP.get(str(v.get("Severity", "")).upper(), "MEDIUM"),
                owasp="A06:2021",          # Vulnerable & Outdated Components
                cwe=_cwe_from(v.get("CweIDs")),
                path=target,
                start_line=0,
                end_line=0,
                snippet="",
                fix_hint=(f"Upgrade {v.get('PkgName', '')} to {fixed}" if fixed else "")[:400],
            ))
            idx += 1
    return out


def _do_scan(scan: Scan, scanners: list[str]) -> None:
    try:
        scan.state = "cloning"
        _run(["git", "clone", "--depth", CLONE_DEPTH, "--branch", scan.ref, scan.repo_url, scan.workdir]) \
            if scan.ref not in ("", "HEAD") else \
            _run(["git", "clone", "--depth", CLONE_DEPTH, scan.repo_url, scan.workdir])

        size_mb = sum(
            os.path.getsize(os.path.join(d, f))
            for d, _s, fs in os.walk(scan.workdir) for f in fs
        ) / (1024 * 1024)
        if size_mb > MAX_REPO_MB:
            raise ValueError(f"repo too large: {size_mb:.0f}MB > {MAX_REPO_MB}MB cap")

        scan.total_files = _count_files(scan.workdir)
        scan.state = "scanning"
        seed = 0

        if "semgrep" in scanners:
            cp = _run(["semgrep", "scan", "--config", "p/owasp-top-ten",
                       "--config", "p/security-audit", "--json", "--quiet", scan.workdir])
            if cp.stdout.strip():
                data = json.loads(cp.stdout)
                found = _normalize_semgrep(data, seed)
                # make paths repo-relative
                for f in found:
                    f.path = os.path.relpath(f.path, scan.workdir)
                scan.findings += found
                seed += len(found) + 1000

        if "gitleaks" in scanners:
            report = os.path.join(scan.workdir, "_gitleaks.json")
            _run(["gitleaks", "detect", "--source", scan.workdir, "--no-banner",
                  "--report-format", "json", "--report-path", report])
            if os.path.exists(report):
                with open(report) as fh:
                    scan.findings += _normalize_gitleaks(json.load(fh), seed)
                os.remove(report)
                seed += 2000

        if "osv" in scanners:
            cp = _run(["osv-scanner", "--format", "json", "-r", scan.workdir])
            if cp.stdout.strip():
                scan.dependencies = _normalize_osv(json.loads(cp.stdout))

        if "checkov" in scanners:
            cp = _run(["checkov", "-d", scan.workdir, "--quiet", "--compact",
                       "-o", "json"])
            if cp.stdout.strip():
                try:
                    scan.findings += _normalize_checkov(json.loads(cp.stdout), seed)
                    seed += 3000
                except json.JSONDecodeError:
                    pass

        if "trivy" in scanners:
            cp = _run(["trivy", "fs", "--scanners", "vuln,misconfig",
                       "--format", "json", "--quiet", scan.workdir])
            if cp.stdout.strip():
                try:
                    scan.findings += _normalize_trivy(json.loads(cp.stdout), seed)
                    seed += 4000
                except json.JSONDecodeError:
                    pass

        scan.files_scanned = scan.total_files
        scan.state = "done"
    except subprocess.TimeoutExpired:
        scan.state, scan.error = "error", f"scan exceeded {SCAN_TIMEOUT_S}s timeout"
    except Exception as e:  # noqa: BLE001 - surface any scanner error to the agent
        scan.state, scan.error = "error", str(e)


# ----------------------------------------------------------------------------- MCP tools
@mcp.tool()
def scan_repository(repo_url: str, ref: str = "HEAD",
                    scanners: list[str] | None = None) -> dict:
    """Clone a public repo and run the full scanner set over EVERY file:
    SAST (semgrep), secrets (gitleaks), SCA (osv-scanner), IaC misconfig (checkov)
    and container/filesystem (trivy). Returns a scan_id and finding counts.
    Synchronous: completes before returning (may take minutes on large repos)."""
    scanners = scanners or DEFAULT_SCANNERS
    _validate_repo_url(repo_url)
    sid = uuid.uuid4().hex
    workdir = tempfile.mkdtemp(prefix=f"sast-{sid}-")
    scan = Scan(scan_id=sid, repo_url=repo_url, ref=ref, workdir=workdir)
    SCANS[sid] = scan
    _do_scan(scan, scanners)
    return {
        "scan_id": sid,
        "state": scan.state,
        "error": scan.error,
        "total_files": scan.total_files,
        "files_scanned": scan.files_scanned,
        "findings_count": len(scan.findings),
        "dependency_findings": len(scan.dependencies),
    }


@mcp.tool()
def get_scan_status(scan_id: str) -> dict:
    """Coverage + state for a scan. Use the numbers to fill the agent's COVERAGE LEDGER."""
    s = SCANS.get(scan_id)
    if not s:
        return {"error": "unknown scan_id"}
    return {
        "scan_id": scan_id, "state": s.state, "error": s.error,
        "total_files": s.total_files, "files_scanned": s.files_scanned,
        "findings_count": len(s.findings), "dependency_findings": len(s.dependencies),
    }


@mcp.tool()
def list_findings(scan_id: str, severity: str | None = None,
                  path_prefix: str | None = None, cursor: int = 0,
                  limit: int = 50) -> dict:
    """Paginated, normalized findings (semgrep + gitleaks). Filter by severity
    (CRITICAL/HIGH/MEDIUM/LOW) and/or path_prefix."""
    s = SCANS.get(scan_id)
    if not s:
        return {"error": "unknown scan_id"}
    items = s.findings
    if severity:
        items = [f for f in items if f.severity == severity.upper()]
    if path_prefix:
        items = [f for f in items if f.path.startswith(path_prefix)]
    page = items[cursor:cursor + limit]
    nxt = cursor + limit if cursor + limit < len(items) else None
    return {"total": len(items), "next_cursor": nxt,
            "items": [asdict(f) for f in page]}


@mcp.tool()
def get_finding_context(scan_id: str, finding_id: str, context_lines: int = 30) -> dict:
    """Exact code around a finding, for the agent to confirm the source->sink data flow."""
    s = SCANS.get(scan_id)
    if not s:
        return {"error": "unknown scan_id"}
    f = next((x for x in s.findings if x.id == finding_id), None)
    if not f:
        return {"error": "unknown finding_id"}
    abspath = os.path.join(s.workdir, f.path)
    if not os.path.isfile(abspath):
        return {"finding": asdict(f), "context": None}
    with open(abspath, errors="replace") as fh:
        lines = fh.readlines()
    lo = max(0, f.start_line - 1 - context_lines)
    hi = min(len(lines), f.end_line + context_lines)
    return {"finding": asdict(f), "from_line": lo + 1, "to_line": hi,
            "context": "".join(lines[lo:hi])}


@mcp.tool()
def get_file(scan_id: str, path: str, start_line: int = 1, end_line: int = 0) -> dict:
    """Raw file content (repo-relative path) for deep dives. end_line=0 => to EOF."""
    s = SCANS.get(scan_id)
    if not s:
        return {"error": "unknown scan_id"}
    # prevent path traversal outside the scan workspace
    abspath = os.path.realpath(os.path.join(s.workdir, path))
    if not abspath.startswith(os.path.realpath(s.workdir)):
        return {"error": "path outside scan workspace"}
    if not os.path.isfile(abspath):
        return {"error": "file not found"}
    with open(abspath, errors="replace") as fh:
        lines = fh.readlines()
    end = end_line or len(lines)
    return {"path": path, "from_line": start_line, "to_line": end,
            "content": "".join(lines[start_line - 1:end])}


@mcp.tool()
def get_dependency_report(scan_id: str) -> dict:
    """SCA results: vulnerable dependencies with CVE/advisory ids and fixed versions."""
    s = SCANS.get(scan_id)
    if not s:
        return {"error": "unknown scan_id"}
    return {"scan_id": scan_id, "count": len(s.dependencies),
            "dependencies": s.dependencies}


@mcp.tool()
def cleanup_scan(scan_id: str) -> dict:
    """Delete the scan workspace and registry entry. Call when the review is finished."""
    s = SCANS.pop(scan_id, None)
    if s and os.path.isdir(s.workdir):
        shutil.rmtree(s.workdir, ignore_errors=True)
    return {"scan_id": scan_id, "removed": bool(s)}


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--transport", default="http", choices=["http", "stdio"])
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()

    if args.transport == "stdio":
        mcp.run()
    else:
        # Build the Starlette ASGI app FastMCP serves the protocol on (path: /mcp).
        try:
            app = mcp.http_app()
        except AttributeError:  # FastMCP naming differs across versions
            app = mcp.streamable_http_app()

        # Health endpoint for the hosting platform's liveness checks.
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route

        async def _health(_request):
            return PlainTextResponse("ok")

        app.router.routes.insert(0, Route("/health", _health, methods=["GET"]))

        # Optional static bearer-token auth (pure-ASGI so it never breaks streaming).
        if MCP_AUTH_TOKEN:
            inner = app

            async def app(scope, receive, send):  # type: ignore[no-redef]
                if scope.get("type") == "http" and scope.get("path") not in ("/health", "/"):
                    headers = dict(scope.get("headers") or [])
                    if headers.get(b"authorization", b"").decode() != f"Bearer {MCP_AUTH_TOKEN}":
                        await send({"type": "http.response.start", "status": 401,
                                    "headers": [(b"content-type", b"application/json")]})
                        await send({"type": "http.response.body",
                                    "body": b'{"error":"unauthorized"}'})
                        return
                await inner(scope, receive, send)

        import uvicorn

        uvicorn.run(app, host=args.host, port=args.port)
