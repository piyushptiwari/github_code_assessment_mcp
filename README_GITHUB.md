# Deep SAST MCP Server

FastMCP server for deterministic repository security scans. It wraps Semgrep,
gitleaks, osv-scanner, Checkov and Trivy, then exposes scanner output through MCP
tools and downloadable report artifacts.

Core tools:

- `scan_repository`
- `get_scan_status`
- `list_findings`
- `get_finding_context`
- `get_file`
- `get_dependency_report`
- `generate_report`
- `get_report`
- `list_reports`
- `cleanup_scan`

Report formats: `markdown`, `html`, `json`, `sarif`, and `zip` evidence pack.

See [README.md](README.md) for hosting, ContextForge registration, and agent workflow details.
