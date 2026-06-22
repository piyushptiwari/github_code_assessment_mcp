# Deep SAST MCP Server — hosting & platform registration

A Model Context Protocol server that gives the agent
`github_code_security_assessment_Piyush_tiwari` deterministic, 100%-file-coverage
security findings by wrapping **Semgrep** (SAST), **gitleaks** (secrets) and
**osv-scanner** (dependency CVEs).

Why: the agent's GitHub tools sample code; this server PARSES every file. The LLM then
triages real findings instead of grepping — that's the thoroughness unlock.

## Files
- `server.py` — the MCP server (FastMCP). 7 tools: scan_repository, get_scan_status,
  list_findings, get_finding_context, get_file, get_dependency_report, cleanup_scan.
- `requirements.txt` — Python deps (fastmcp, semgrep).
- `Dockerfile` — image with all three scanners on PATH.

## Tools exposed to the agent
| Tool | Purpose |
|---|---|
| `scan_repository(repo_url, ref, scanners)` | clone + scan EVERY file, returns scan_id + counts |
| `get_scan_status(scan_id)` | files_scanned / total_files → fills the COVERAGE LEDGER |
| `list_findings(scan_id, severity, path_prefix, cursor)` | paginated normalized findings |
| `get_finding_context(scan_id, finding_id, context_lines)` | code around a sink, for triage |
| `get_file(scan_id, path, start_line, end_line)` | raw file for deep dives |
| `get_dependency_report(scan_id)` | SCA / CVE results |
| `cleanup_scan(scan_id)` | delete the scan workspace |

Normalized finding fields: `id, scanner, rule_id, title, severity, owasp, cwe, path,
start_line, end_line, snippet, fix_hint`. (gitleaks snippet is redacted.)

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
| Description | "Semgrep + gitleaks + osv-scanner SAST over MCP" |
| Tags | `security,sast,code-review` |
| Visibility | **Team** (Public is disabled by platform config) |
| Transport Type | **Streamable HTTP** (our FastMCP server uses HTTP; not SSE) |
| Authentication Type | None / Basic / Bearer — match what you configured on the server |

After adding, ContextForge federates the server, its 7 tools appear under **Tools**, and you
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
5. Emit the report + a COVERAGE LEDGER backed by REAL scanner numbers (not an estimate).
6. `cleanup_scan(scan_id)` when done.

## Security notes (do not weaken)
- Scanners parse, never execute, the target code.
- Per-scan temp workspace, deleted by `cleanup_scan`.
- Clone is shallow, host-allowlisted, and size-capped (`MAX_REPO_MB`).
- gitleaks secret VALUES are redacted before leaving the process.
- `get_file` blocks path traversal outside the scan workspace.
