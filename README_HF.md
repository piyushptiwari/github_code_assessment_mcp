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

Model Context Protocol server exposing **deterministic** security scanners over HTTP:

| Scanner | Coverage |
|---|---|
| Semgrep | SAST (OWASP Top 10, CWE) |
| gitleaks | Hardcoded secrets |
| osv-scanner | Dependency CVEs (SCA) |
| checkov | IaC misconfiguration (Terraform/K8s/Dockerfile) |
| trivy | Container / filesystem vulns + misconfig |

## Endpoint
- MCP protocol: `POST /mcp/` (Streamable HTTP)
- Health: `GET /health`

## Tools
`scan_repository`, `get_scan_status`, `list_findings`, `get_finding_context`,
`get_file`, `get_dependency_report`, `cleanup_scan`.

## Auth
Set the `MCP_AUTH_TOKEN` Space secret to require `Authorization: Bearer <token>` on all
MCP requests. Leave unset for open access (not recommended).

See [README.md](README.md) for full hosting & registration details.
