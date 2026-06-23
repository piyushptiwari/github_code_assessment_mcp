"""Runtime configuration for the Deep SAST MCP server."""

from __future__ import annotations

import os
import tempfile


def _csv_set(value: str) -> set[str]:
    return {item.strip().lower() for item in value.split(",") if item.strip()}


ALLOWED_GIT_HOSTS = _csv_set(os.getenv("ALLOWED_GIT_HOSTS", "github.com,gitlab.com,bitbucket.org"))
MAX_REPO_MB = int(os.getenv("MAX_REPO_MB", "500"))
CLONE_DEPTH = os.getenv("CLONE_DEPTH", "1")
SCAN_TIMEOUT_S = int(os.getenv("SCAN_TIMEOUT_S", "1800"))
COMMAND_VERSION_TIMEOUT_S = int(os.getenv("COMMAND_VERSION_TIMEOUT_S", "20"))
SECRET_REDACT = "***REDACTED***"

# --- File selection and memory bounds (large/noisy repositories) ---
# Per-file size cap for SAST. Semgrep's own default is 1 MB.
MAX_FILE_KB = int(os.getenv("MAX_FILE_KB", "1024"))
# Respect .gitignore via `git ls-files` so ignored content is excluded for free.
RESPECT_GITIGNORE = os.getenv("RESPECT_GITIGNORE", "true").strip().lower() not in {"0", "false", "no"}
# Cap findings retained per scanner so a pathological repo cannot exhaust memory.
MAX_FINDINGS_PER_SCANNER = int(os.getenv("MAX_FINDINGS_PER_SCANNER", "5000"))

# Default-exclude directories, seeded from Semgrep's default.semgrepignore plus
# common build/cache/vendor output. These are skipped even when committed.
_DEFAULT_EXCLUDE_DIRS = (
    "node_modules,bower_components,vendor,dist,build,out,target,.gradle,"
    ".venv,venv,env,.tox,.nox,__pycache__,.mypy_cache,.pytest_cache,.ruff_cache,"
    ".next,.nuxt,.svelte-kit,.angular,.cache,.parcel-cache,coverage,htmlcov,"
    ".terraform,.serverless,.idea,.vscode,.eggs,site-packages,jspm_packages,"
    ".yarn,.pnpm-store,.gradle-cache,deps,_build,.dart_tool"
)
EXCLUDE_DIRS = _csv_set(os.getenv("EXCLUDE_DIRS", _DEFAULT_EXCLUDE_DIRS))

MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "").strip()
PUBLIC_REPORTS = os.getenv("PUBLIC_REPORTS", "true").strip().lower() not in {"0", "false", "no"}
REPORTS_ROOT = os.getenv("REPORTS_ROOT", os.path.join(tempfile.gettempdir(), "deep-sast-reports"))

DEFAULT_SCANNERS = ["semgrep", "gitleaks", "osv", "checkov", "trivy"]
SCANNER_ALIASES = {
    "all": "all",
    "sast": "semgrep",
    "semgrep": "semgrep",
    "secrets": "gitleaks",
    "secret": "gitleaks",
    "gitleaks": "gitleaks",
    "sca": "osv",
    "deps": "osv",
    "dependencies": "osv",
    "osv": "osv",
    "osv-scanner": "osv",
    "iac": "checkov",
    "checkov": "checkov",
    "container": "trivy",
    "containers": "trivy",
    "image": "trivy",
    "filesystem": "trivy",
    "trivy": "trivy",
}


def public_base_url() -> str:
    """Return the externally reachable base URL for report links when hosting provides it."""
    explicit = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if explicit:
        return explicit

    space_host = os.getenv("SPACE_HOST", "").strip().rstrip("/")
    if space_host:
        return space_host if space_host.startswith("http") else f"https://{space_host}"

    space_id = os.getenv("SPACE_ID", "").strip()
    if "/" in space_id:
        owner, name = space_id.split("/", 1)
        return f"https://{owner}-{name}.hf.space"

    space_author = os.getenv("SPACE_AUTHOR_NAME", "").strip()
    space_repo = os.getenv("SPACE_REPO_NAME", "").strip()
    if space_author and space_repo:
        return f"https://{space_author}-{space_repo}.hf.space"

    return ""
