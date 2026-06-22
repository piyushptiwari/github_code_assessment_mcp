# Deep SAST MCP Server
# Image exposing Semgrep + gitleaks + osv-scanner + checkov + trivy over MCP/HTTP.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    GITLEAKS_VERSION=8.18.4 \
    OSV_VERSION=1.8.5 \
    TRIVY_VERSION=0.55.0 \
    TRIVY_CACHE_DIR=/tmp/trivy \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates tar gnupg \
 && rm -rf /var/lib/apt/lists/*

# gitleaks (secret scanning)
RUN curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      -o /tmp/gitleaks.tgz \
 && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
 && rm /tmp/gitleaks.tgz \
 && gitleaks version

# osv-scanner (dependency / SCA scanning)
RUN curl -sSfL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" \
      -o /usr/local/bin/osv-scanner \
 && chmod +x /usr/local/bin/osv-scanner \
 && osv-scanner --version

# trivy (container / filesystem vuln + misconfig scanning) via official APT repo
RUN curl -sSfL https://aquasecurity.github.io/trivy-repo/deb/public.key \
      | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
      > /etc/apt/sources.list.d/trivy.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends trivy \
 && rm -rf /var/lib/apt/lists/* \
 && trivy --version

WORKDIR /app
COPY requirements.txt .
# installs fastmcp + semgrep (SAST) + checkov (IaC) + uvicorn
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
COPY deep_sast_mcp ./deep_sast_mcp

# Run as non-root; scanners only parse code, they never execute the target repo.
RUN useradd -m scanner && mkdir -p /tmp/trivy && chown -R scanner /tmp/trivy
USER scanner

EXPOSE 8080
# Optional hardening / config knobs (override at deploy):
#   MAX_REPO_MB, SCAN_TIMEOUT_S, MCP_AUTH_TOKEN, PUBLIC_BASE_URL, PUBLIC_REPORTS
CMD ["python", "server.py", "--transport", "http", "--host", "0.0.0.0", "--port", "8080"]
