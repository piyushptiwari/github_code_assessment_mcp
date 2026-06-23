---
title: Deep SAST MCP
emoji: 🔒
colorFrom: blue
colorTo: red
sdk: docker
app_port: 8080
pinned: false
license: mit
---

# Deep SAST MCP Server

A Model Context Protocol server that gives IBM Consulting Advantage agents deterministic,
100%-file-coverage security findings by wrapping Semgrep, gitleaks, osv-scanner,
Checkov and Trivy behind Streamable HTTP.

## Scanner Coverage

| Scanner | Coverage |
|---|---|
| Semgrep | SAST rules for OWASP Top 10 and security audit patterns |
| gitleaks | Hardcoded secrets with redacted evidence |
| osv-scanner | Dependency CVEs and advisory metadata |
| Checkov | IaC, OpenAPI, Terraform, Kubernetes and Dockerfile misconfiguration |
| Trivy | Filesystem/container vulnerabilities and misconfiguration |

## Endpoint

- MCP protocol: `POST /mcp` (Streamable HTTP; register without a trailing slash)
- Health: `GET /health`
- Report downloads: `GET /reports/{scan_id}/{filename}`

## Hugging Face Logs

The Hugging Face Space exposes build and runtime logs through authenticated API endpoints.
Set `HF_TOKEN` in your shell; do not paste or commit the token value.

```bash
curl -N \
    -H "Authorization: Bearer $HF_TOKEN" \
    "https://huggingface.co/api/spaces/piyushptiwari/deep-sast-mcp/logs/run"

curl -N \
    -H "Authorization: Bearer $HF_TOKEN" \
    "https://huggingface.co/api/spaces/piyushptiwari/deep-sast-mcp/logs/build"
```

Use `logs/run` for live application requests and scanner/report runtime errors. Use
`logs/build` for Docker build, dependency install and Space startup failures.

Expected runtime log noise:

- `AuthlibDeprecationWarning` and `websockets...DeprecationWarning` come from FastMCP/Uvicorn
    dependencies and do not indicate scanner failure.
- `GET /favicon.ico` returning 404 is a browser probe and is harmless.
- Streamable HTTP commonly logs `POST /mcp` 202, `GET /mcp` 200 and `DELETE /mcp` 200 during
    MCP session setup, streaming and teardown.
- Occasional `POST /mcp` or `GET /mcp` 400/404 entries usually mean a malformed probe, stale
    MCP session id or request after the client already closed the session. Treat them as noise
    when `tools/list`, scans and report downloads still return 200.
- `Error in standalone SSE writer ... anyio.ClosedResourceError` is emitted by the MCP
    stream writer when a client closes an SSE stream early. It is non-blocking if subsequent
    MCP calls and report downloads continue to succeed.

## Files

- `server.py` - thin entrypoint.
- `deep_sast_mcp/app.py` - FastMCP tool registration and HTTP/report routes.
- `deep_sast_mcp/scan_engine.py` - clone, scanner selection and orchestration.
- `deep_sast_mcp/scanners/` - one adapter per scanner.
- `deep_sast_mcp/reporting.py` - Markdown, HTML, JSON, SARIF and ZIP evidence packs.
- `requirements.txt` - Python dependencies.
- `Dockerfile` - image with scanner CLIs on PATH.

## Tools

| Tool | Purpose |
|---|---|
| `scan_repository(repo_url, ref, scanners)` | Clone and scan every in-scope file, then return scan_id, coverage and counts |
| `get_scan_status(scan_id)` | Return coverage, scanner run status and generated artifacts |
| `list_findings(scan_id, severity, path_prefix, cursor, limit)` | Paginated normalized findings |
| `get_finding_context(scan_id, finding_id, context_lines)` | Exact source context around a finding |
| `get_file(scan_id, path, start_line, end_line)` | Raw repo-relative file content for deep dives |
| `get_dependency_report(scan_id)` | SCA/CVE results with package, advisory and fixed version metadata |
| `generate_report(scan_id, format)` | Create a detailed downloadable report artifact |
| `get_report(report_id, max_chars)` | Return text report content through MCP |
| `list_reports(scan_id)` | List generated artifacts and download URLs |
| `cleanup_scan(scan_id, keep_reports)` | Delete the clone workspace; preserve reports by default |

Normalized finding fields: `id, scanner, rule_id, title, severity, owasp, cwe, path,
start_line, end_line, snippet, fix_hint, confidence, details`. gitleaks snippets are redacted.

## Large Repository Handling

Selection is deterministic and produces an honest coverage ledger instead of asserting
100%. For every discovered file the server records one of: in-scope source, dependency
lockfile (kept for SCA), or a categorized skip (`excluded_dir`, `binary`,
`generated_minified`, `too_large`, `unsupported_language`, `gitignored_untracked`).

- `.gitignore` is respected via `git ls-files`, so ignored content is excluded for free.
- Default-excluded directories (seeded from Semgrep's `default.semgrepignore`) are pruned
  during the walk, e.g. `node_modules`, `vendor`, `dist`, `build`, `__pycache__`, `.venv`,
  `target`, `.terraform`. They never inflate the coverage denominator.
- Binary files (null-byte heuristic + known binary extensions) are never scanned.
- Files larger than `MAX_FILE_KB` are skipped for SAST and accounted as `too_large`.
- The same exclude set is pushed into Semgrep (`--exclude`, `--max-target-bytes`), Trivy
  (`--skip-dirs`) and Checkov (`--skip-path`) so scanners do less work and use less memory.
- Each scanner's findings are capped at `MAX_FINDINGS_PER_SCANNER` to bound memory.

The ledger (`coverage` block of `get_scan_status` / report) always satisfies
`in_scope + sum(skipped) == total_discovered`.

Tunable environment variables: `MAX_FILE_KB` (default 1024), `MAX_FINDINGS_PER_SCANNER`
(default 5000), `RESPECT_GITIGNORE` (default true), `EXCLUDE_DIRS` (comma-separated override).

## Report Formats

- `markdown` - human report with executive summary, coverage ledger, scanner inventory,
  severity/scanner distributions, detailed findings, dependency appendix and remediation plan.
- `html` - browser-readable copy of the Markdown report.
- `json` - raw normalized evidence for downstream automation.
- `sarif` - importable into code scanning tools.
- `zip` - evidence pack containing Markdown, HTML, JSON, SARIF and dependency CSV.

## Auth

Set `MCP_AUTH_TOKEN` to require `Authorization: Bearer <token>` on MCP requests.
Leave unset only for development/open access. By default, report download URLs are public
when generated; set `PUBLIC_REPORTS=false` to require the same bearer token for reports.

## Register In IBM Consulting Advantage

Register the hosted endpoint in ContextForge / MCP Gateway:

| Field | Value |
|---|---|
| MCP Server Name | `Deep SAST` |
| MCP Server URL | `https://piyushptiwari-deep-sast-mcp.hf.space/mcp` |
| Description | `Semgrep + gitleaks + osv-scanner + Checkov + Trivy security scanning over MCP` |
| Tags | `security,sast,code-review,sca,secrets,iac,container` |
| Visibility | Team |
| Transport Type | Streamable HTTP |
| Authentication Type | Match `MCP_AUTH_TOKEN` configuration |

ContextForge federates the MCP tools; group them into a virtual server and attach that
virtual server to the Agentic App / DeepAgent.

## Agent Workflow

1. `scan_repository(repo_url)` with `scanners` omitted unless the user asks for a targeted scan.
2. `get_scan_status(scan_id)` and reconcile coverage as `files_scanned / total_files`.
3. `list_findings(...)` and `get_dependency_report(scan_id)` for triage.
4. `get_finding_context(...)` for high-impact evidence validation.
5. `generate_report(scan_id, "markdown")` for the user-facing report.
6. Generate `json`, `sarif` or `zip` when machine-readable evidence or a full pack is needed.
7. Share the returned `download_url` with the user.
8. `cleanup_scan(scan_id)` when done. Reports are preserved by default so the URL remains usable.

## Run Locally

```bash
pip install -r requirements.txt
python server.py --transport http --host 127.0.0.1 --port 8080
```

The Docker image installs the scanner CLIs. Local non-Docker runs also need scanner binaries
on PATH.

## Security Notes

- Scanners parse target code; they do not execute the target repository.
- Repositories are shallow-cloned from allowed hosts only and size-capped by `MAX_REPO_MB`.
- Each clone uses a per-scan temp workspace removed by `cleanup_scan`.
- Report artifacts are stored separately from the clone workspace and can be preserved after cleanup.
- Secret values are redacted before leaving the scanner process.
- `get_file` and report downloads block path traversal outside their scan/report roots.
