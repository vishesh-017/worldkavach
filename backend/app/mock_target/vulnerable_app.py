"""
Controlled Vulnerable Target Application for World Monitor Security Assessment.
Provides an authorized, safe sandbox environment to validate candidate vulnerabilities,
demonstrate live proof-of-concept exploits, and execute before/after re-tests.
"""

from fastapi import FastAPI, Request, Response, Header
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Optional, Dict
import time

target_app = FastAPI(title="World Monitor Controlled Benchmark Target")

# State for security patch toggles (used for Before vs After re-test demonstration)
PATCH_STATE: Dict[str, bool] = {
    "FIND-WM-001": False,  # CSP Static Nonce Patch
    "FIND-WM-002": False,  # DNS Rebinding SSRF Socket Pinning Patch
    "FIND-WM-003": False,  # Frame-Ancestors Clickjacking Patch
    "FIND-WM-004": False,  # LLM Prompt Guardrail Patch
    "FIND-WM-005": False,  # Clock Tolerance / JWT Drift Patch
}


@target_app.get("/target-status")
async def target_status():
    return {
        "status": "ONLINE",
        "mode": "SAFE_CONTROLLED_SANDBOX",
        "target": "World Monitor Test Suite v2.4",
        "patches_applied": PATCH_STATE
    }


@target_app.post("/target-control/toggle-fix/{finding_id}")
async def toggle_fix(finding_id: str, enable: Optional[bool] = None):
    """Toggles patch status for demonstration of before/after re-testing."""
    if finding_id in PATCH_STATE:
        if enable is not None:
            PATCH_STATE[finding_id] = enable
        else:
            PATCH_STATE[finding_id] = not PATCH_STATE[finding_id]
        return {"finding_id": finding_id, "patch_enabled": PATCH_STATE[finding_id]}
    return JSONResponse(status_code=404, content={"error": "Finding ID not recognized"})


# 1. MCP Grant Route (FIND-WM-001: Static CSP Nonce)
@target_app.get("/mcp-grant")
@target_app.get("/mcp-grant.html")
async def mcp_grant_endpoint():
    is_patched = PATCH_STATE["FIND-WM-001"]

    if is_patched:
        # Secure: dynamic hash or unique per-request nonce
        dynamic_nonce = f"nonce-{hex(int(time.time() * 1000))[2:]}"
        csp = f"default-src 'self'; script-src 'self' 'strict-dynamic' '{dynamic_nonce}'; style-src 'self' 'unsafe-inline';"
        script_tag = f'<script type="module" src="/src/mcp-grant-main.ts" nonce="{dynamic_nonce}"></script>'
    else:
        # Vulnerable: static hardcoded nonce
        csp = "default-src 'self'; connect-src 'self' https:; script-src 'self' 'strict-dynamic' 'nonce-wm-static-bootstrap'; style-src 'self' 'unsafe-inline';"
        script_tag = '<script type="module" src="/src/mcp-grant-main.ts" nonce="wm-static-bootstrap"></script>'

    html_content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Authorize MCP — WorldMonitor</title>
</head>
<body style="background:#0a0a0a; color:#eee; font-family:sans-serif; padding:2rem;">
  <h2>World Monitor MCP Client Authorization</h2>
  <p>Status: {'[PATCHED: Dynamic Nonce Enforced]' if is_patched else '[VULNERABLE: Static Nonce Active]'}</p>
  <div id="consent">
    <p>Read-only access to geopolitical data and market feeds.</p>
    <button id="authorizeBtn">Authorize</button>
  </div>
  {script_tag}
</body>
</html>"""

    response = HTMLResponse(content=html_content)
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# 2. Pro MCP Proxy (FIND-WM-002: TOCTOU DNS Rebinding SSRF)
@target_app.post("/api/mcp-proxy")
async def mcp_proxy_endpoint(request: Request, authorization: Optional[str] = Header(None)):
    is_patched = PATCH_STATE["FIND-WM-002"]
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    target_url = body.get("params", {}).get("url") or body.get("url", "")

    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Unauthorized: Pro caller identity required"})

    # Check for DNS rebinding simulation or metadata targeting
    is_rebinding_target = "rebind" in target_url or "169.254.169.254" in target_url or "metadata" in target_url

    if is_rebinding_target:
        if is_patched:
            # Patched: Socket-level pinning blocks the rebinding attempt
            return JSONResponse(
                status_code=403,
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32002,
                        "message": "Blocked by Socket Pinning Egress Guard: Resolved connection address points to prohibited IP space (169.254.169.254/32)"
                    }
                }
            )
        else:
            # Vulnerable: Cloudflare DoH check passed on domain, but second resolution connects to metadata!
            return JSONResponse(
                status_code=200,
                content={
                    "jsonrpc": "2.0",
                    "result": {
                        "status": "success",
                        "proxied_body": {
                            "ami-id": "ami-0123456789abcdef0",
                            "instance-type": "c5.xlarge",
                            "iam-security-credentials": {
                                "RoleName": "WorldMonitor-Vercel-Sync-Role",
                                "AccessKeyId": "ASIAEXAMPLEKEY123",
                                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                "Token": "FwoGZXIvYXdzEBcaDJ..."
                            }
                        },
                        "warning": "Simulated Cloud Metadata exposed via DNS Rebinding TOCTOU seam"
                    }
                }
            )

    return JSONResponse(status_code=200, content={"jsonrpc": "2.0", "result": {"content": "Proxied response from upstream"}})


# 3. Embed Route (FIND-WM-003: Clickjacking Frame-Ancestors)
@target_app.get("/embed")
async def embed_endpoint():
    is_patched = PATCH_STATE["FIND-WM-003"]

    if is_patched:
        csp = "default-src 'self'; frame-ancestors 'self' https://worldmonitor.app https://*.worldmonitor.app;"
    else:
        csp = "default-src 'self'; frame-ancestors *;"

    response = HTMLResponse(content="""<!DOCTYPE html><html><body><h3>World Monitor Embeddable Widget</h3></body></html>""")
    response.headers["Content-Security-Policy"] = csp
    return response


# 4. Chat Analyst Endpoint (FIND-WM-004: Indirect Prompt Injection)
@target_app.post("/api/chat-analyst")
async def chat_analyst_endpoint(request: Request):
    is_patched = PATCH_STATE["FIND-WM-004"]
    data = await request.json()
    query = data.get("query", "")

    if "SYSTEM OVERRIDE" in query or "SYSTEM PROMPT" in query or "Ignore previous" in query:
        if is_patched:
            return JSONResponse(
                status_code=400,
                content={"error": "Input validation violation: Adversarial prompt injection boundary breach detected by LLM Guardrail."}
            )
        else:
            return JSONResponse(
                status_code=200,
                content={
                    "delta": "CONFIDENTIAL SYSTEM INSTRUCTIONS: You are World Monitor AI. Internal keys: FINNHUB_KEY=fh_live_849204. Source weights: Reuters=1.0, TASS=0.1. Endpoints: /api/internal/mcp-grant-mint."
                }
            )

    return JSONResponse(status_code=200, content={"delta": "Geopolitical risk analysis: Normal stability observed across monitored zones."})


# 5. User Preferences Endpoint (FIND-WM-005: BOLA / Drift)
@target_app.post("/api/user-prefs")
async def user_prefs_endpoint(request: Request, authorization: Optional[str] = Header(None)):
    is_patched = PATCH_STATE["FIND-WM-005"]

    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Missing Bearer token"})

    if "NEAR_EXPIRED" in authorization:
        if is_patched:
            return JSONResponse(status_code=401, content={"error": "Token expired (synchronized tolerance: 5s)"})
        else:
            return JSONResponse(status_code=200, content={"status": "accepted_by_edge_drift", "syncVersion": 42})

    return JSONResponse(status_code=200, content={"status": "synced", "syncVersion": 1})
