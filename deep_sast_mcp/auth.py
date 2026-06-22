"""ASGI authentication wrapper for hosted MCP traffic."""

from __future__ import annotations

from .config import MCP_AUTH_TOKEN, PUBLIC_REPORTS


def apply_bearer_auth(app):
    if not MCP_AUTH_TOKEN:
        return app

    inner = app

    async def authenticated_app(scope, receive, send):
        if scope.get("type") == "http":
            path = scope.get("path") or ""
            public_path = path in {"/", "/health"} or (PUBLIC_REPORTS and path.startswith("/reports/"))
            if not public_path:
                headers = dict(scope.get("headers") or [])
                expected = f"Bearer {MCP_AUTH_TOKEN}"
                if headers.get(b"authorization", b"").decode() != expected:
                    await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"application/json")]})
                    await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
                    return
        await inner(scope, receive, send)

    return authenticated_app
