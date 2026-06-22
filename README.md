# Deep SAST MCP Server — hosting & platform registration

A Model Context Protocol server that gives the agent
`github_code_security_assessment_Piyush_tiwari` deterministic, 100%-file-coverage
security findings by wrapping **Semgrep** (SAST), **gitleaks** (secrets),
**osv-scanner** (dependency CVEs), **Checkov** (IaC/OpenAPI) and **Trivy**
(filesystem/container vulnerabilities and misconfigurations).

Why: the agent's GitHub tools sample code; this server PARSES every file. The LLM then
triages real findings instead of grepping — that's the thoroughness unlock.

## Files
- `server.py` - thin entrypoint.
- `deep_sast_mcp/app.py` - FastMCP tool registration and HTTP/report routes.
- `deep_sast_mcp/scan_engine.py` - clone, scanner selection, and orchestration.
- `deep_sast_mcp/scanners/` - one adapter per scanner.
- `deep_sast_mcp/reporting.py` - Markdown, HTML, JSON, SARIF, and ZIP evidence packs.
- `requirements.txt` - Python deps.
- `Dockerfile` - image with scanner CLIs on PATH.

## Tools exposed to the agent
| Tool | Purpose |
|---|---|
| `scan_repository(repo_url, ref, scanners)` | clone + scan EVERY file, returns scan_id + counts |
| `get_scan_status(scan_id)` | files_scanned / total_files → fills the COVERAGE LEDGER |
| `list_findings(scan_id, severity, path_prefix, cursor)` | paginated normalized findings |
| `get_finding_context(scan_id, finding_id, context_lines)` | code around a sink, for triage |
| `get_file(scan_id, path, start_line, end_line)` | raw file for deep dives |
| `get_dependency_report(scan_id)` | SCA / CVE results |
| `generate_report(scan_id, format)` | creates a detailed downloadable report artifact |
| `get_report(report_id, max_chars)` | returns text report content through MCP |
| `list_reports(scan_id)` | lists generated artifacts and download URLs |
| `cleanup_scan(scan_id, keep_reports)` | delete the clone workspace; preserves reports by default |

Normalized finding fields: `id, scanner, rule_id, title, severity, owasp, cwe, path,
start_line, end_line, snippet, fix_hint, confidence, details`. (gitleaks snippet is redacted.)

Report formats:
- `markdown` - human report with executive summary, coverage ledger, scanner inventory,
  severity/scanner distributions, detailed findings, dependency appendix and remediation plan.
- `html` - browser-readable copy of the Markdown report.
- `json` - raw normalized evidence for downstream automation.
- `sarif` - importable into code scanning tools.
- `zip` - evidence pack containing Markdown, HTML, JSON, SARIF and dependency CSV.

## 1. Run locally (smoke test)
```bash
cd mcp-server
pip install -r requirements.txt
# also install the binaries locally if not using Docker:
#   brew install gitleaks osv-scanner   (mac)  — or download release binaries
python server.py --transport http --host 127.0.0.1 --port 8080
```
The server prints its MCP HTTP endpoint (e.g. http://127.0.0.1:8080/mcp).

## 2. Build & run with Docker (recommended)
```bash
cd mcp-server
docker build -t deep-sast-mcp .
docker run --rm -p 8080:8080 \
  -e MAX_REPO_MB=500 -e SCAN_TIMEOUT_S=1800 \
  --read-only --tmpfs /tmp \
  --security-opt no-new-privileges \
  deep-sast-mcp
```
Notes: `--read-only` + `--tmpfs /tmp` keep clones in memory-backed tmp and block writes
elsewhere. The container runs as non-root.

## 3. Host with a public HTTPS endpoint (required by the platform)
The platform can only register tools at a public **https://** URL. Pick one:
- **IBM Code Engine**: `ibmcloud ce application create --name deep-sast-mcp \
  --image <registry>/deep-sast-mcp --port 8080 --min-scale 0`. It gives an https URL.
- **OpenShift / ROKS**: deploy the image, expose a Route (TLS edge), use the Route host.
- **Any container host** behind an HTTPS load balancer.

Harden the endpoint:
- Put it behind an auth token (bearer) or mTLS. Add a check in `server.py` if needed.
- Restrict egress: the server should only reach github.com/gitlab.com/bitbucket.org
  (clone) — block everything else to limit SSRF/exfil from a malicious repo.
- Set CPU/mem limits and keep `SCAN_TIMEOUT_S` / `MAX_REPO_MB` sane.

## 4. Register the MCP server in IBM Consulting Advantage

The platform runs **IBM ContextForge MCP Gateway** (github.com/IBM/mcp-context-forge).
You register our server there as a new MCP gateway.

Path: open your **Agentic App → Tools tab → "Access MCP Gateway"**. This opens the
ContextForge admin ("Gateway Administration"). Go to **MCP Servers** (the `#gateways`
section) → **"Add New MCP Server or Gateway"** and fill:

| Field | Value |
|---|---|
| MCP Server Name | `Deep SAST` (or similar) |
| MCP Server URL | your hosted endpoint, e.g. `https://deep-sast-mcp.<region>.codeengine.appdomain.cloud/mcp` |
| Description | "Semgrep + gitleaks + osv-scanner + Checkov + Trivy security scanning over MCP" |
| Tags | `security,sast,code-review` |
| Visibility | **Team** (Public is disabled by platform config) |
| Transport Type | **Streamable HTTP** (our FastMCP server uses HTTP; not SSE) |
| Authentication Type | None / Basic / Bearer — match what you configured on the server |

After adding, ContextForge federates the server, its tools appear under **Tools**, and you
can group them into a **Virtual Server** (with its own API key) that the app's agents consume.

Note: existing team servers show URLs like
`https://servicesessentials.ibm.com/mcp-gateway/service/gateway/servers/<id>/mcp` — that is
the gateway's federated proxy URL it assigns AFTER you register your real backend URL.
Your backend (this server) must be reachable over public HTTPS for the gateway to reach it.

## 5. Wire it into the agent / multi-agent app
- **Single agent**: Edit `github_code_security_assessment_Piyush_tiwari` → Add tools →
  select the Deep SAST tools → Republish. Update instructions to prefer
  `scan_repository` for coverage, then `list_findings` + `get_finding_context` to triage.
- **Multi-agent app** (Agentic App Studio): give `scan_repository`/`list_findings`/
  `get_finding_context`/`get_file`/`get_dependency_report` to the Inventory + Reviewer
  agents (see ../design/multi-agent-app-spec.md). The Inventory agent calls
  `scan_repository`; reviewers consume `list_findings` filtered by severity/path.

## 6. Agent workflow once registered
1. `scan_repository(url)` → wait for state=done (report files_scanned/total).
2. `list_findings` (paginate; filter by severity) → the complete finding set.
3. For each finding → `get_finding_context` → confirm source→sink, drop false positives,
   finalize severity + remediation.
4. `get_dependency_report` → supply-chain findings; confirm notable CVEs via Web Search.
5. `generate_report(scan_id, "markdown")` for the human report; also generate `json`,
   `sarif`, or `zip` when machine-readable evidence is needed.
6. Share the returned `download_url` with the user.
7. `cleanup_scan(scan_id)` when done. Reports are preserved by default so the URL remains usable.

## Security notes (do not weaken)
- Scanners parse, never execute, the target code.
- Per-scan temp workspace, deleted by `cleanup_scan`.
- Report artifacts are stored separately from the clone workspace and can be preserved after cleanup.
- Clone is shallow, host-allowlisted, and size-capped (`MAX_REPO_MB`).
- gitleaks secret VALUES are redacted before leaving the process.
- `get_file` blocks path traversal outside the scan workspace.
