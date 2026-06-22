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

Model Context Protocol server exposing deterministic Semgrep, gitleaks,
osv-scanner, Checkov and Trivy scans over Streamable HTTP.

Endpoints:

- MCP protocol: `POST /mcp`
- Health: `GET /health`
- Report artifacts: `GET /reports/{scan_id}/{filename}`

Tools include scan, status, paginated findings, finding context, file access,
dependency reports, `generate_report`, `get_report`, `list_reports`, and cleanup.

Detailed reports are available as Markdown, HTML, JSON, SARIF, or ZIP evidence packs.
