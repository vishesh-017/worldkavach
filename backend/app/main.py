"""
FastAPI Main Application for World Monitor Security Assessment Platform.
Provides REST APIs, WebSocket real-time event feeds, target sandbox mounting, and report downloads.
"""

import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .evidence.models import ScanConfig
from .orchestrator.engine import orchestrator
from .mock_target.vulnerable_app import target_app, PATCH_STATE
from .cvss.calculator import CvssV31Calculator
from .reports.generator import ReportGenerator

app = FastAPI(
    title="WorldKavach Security Assessment Platform",
    description="Automated, Evidence-First DAST & Attack Surface Security Assessment Platform",
    version="2.0.0"
)

# Enable CORS for local dev servers (Next.js / Vite)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount local controlled target sandbox under /target
app.mount("/target", target_app)


@app.on_event("startup")
async def startup_event():
    """Pre-load initial attack surface and findings on startup for immediate readiness."""
    try:
        orchestrator.endpoints, orchestrator.surface_map = orchestrator.attack_surface_mapper = \
            orchestrator.endpoints, orchestrator.surface_map
        # Pre-seed surface map
        from .attack_surface.mapper import AttackSurfaceMapper
        orchestrator.endpoints, orchestrator.surface_map = AttackSurfaceMapper.build_map(
            target_url="https://www.worldmonitor.app",
            source_dir="target_repo"
        )
        orchestrator._recalculate_stats()
    except Exception as e:
        print(f"Startup init error: {e}")


# --- WebSocket Stream ---
@app.websocket("/ws/assessment")
async def websocket_endpoint(websocket: WebSocket):
    await orchestrator.connect_websocket(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")
            if action == "START_ASSESSMENT":
                config_data = data.get("config", {})
                config = ScanConfig(**config_data)
                import asyncio
                asyncio.create_task(orchestrator.start_assessment(config))
            elif action == "RUN_RETEST":
                finding_id = data.get("finding_id")
                if finding_id:
                    import asyncio
                    asyncio.create_task(orchestrator.run_retest(finding_id))
    except WebSocketDisconnect:
        orchestrator.disconnect_websocket(websocket)


# --- REST API Endpoints ---
@app.post("/api/assessment/start")
async def start_assessment(config: ScanConfig = None):
    import asyncio
    asyncio.create_task(orchestrator.start_assessment(config))
    return {"status": "Assessment started", "target": config.target_url if config else "default"}


@app.get("/api/assessment/state")
async def get_state():
    return {
        "status": orchestrator.status,
        "stats": orchestrator.stats.model_dump(),
        "endpoints_count": len(orchestrator.endpoints),
        "findings": [f.model_dump() for f in orchestrator.findings],
        "logs": orchestrator.logs[-50:]
    }


@app.get("/api/assessment/attack-surface")
async def get_attack_surface():
    return orchestrator.surface_map.model_dump()


@app.post("/api/assessment/retest/{finding_id}")
async def run_retest(finding_id: str):
    return await orchestrator.run_retest(finding_id)


@app.get("/api/assessment/endpoints")
async def get_endpoints():
    return [e.model_dump() for e in orchestrator.endpoints]


@app.get("/api/target/sandbox-status")
async def get_sandbox_status():
    return {
        "status": "ONLINE",
        "mode": "SAFE_CONTROLLED_SANDBOX",
        "target": "World Monitor Test Sandbox v2.4",
        "patches": PATCH_STATE
    }


@app.post("/api/assessment/probe-endpoint")
async def probe_endpoint(payload: dict):
    """Dynamically probes an endpoint and returns live HTTP evidence & security header analysis."""
    path = payload.get("path", "/")
    method = payload.get("method", "GET").upper()
    headers = payload.get("headers", {})
    body = payload.get("body", None)

    import httpx, time
    from .mock_target.vulnerable_app import target_app

    start = time.time()
    transport = httpx.ASGITransport(app=target_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver", timeout=8.0) as client:
        try:
            if method == "POST":
                resp = await client.post(path, headers=headers, json=body or {})
            else:
                resp = await client.get(path, headers=headers)
            duration_ms = round((time.time() - start) * 1000, 2)

            resp_headers = dict(resp.headers)
            # Security Header Checks
            header_audit = {
                "content_security_policy": "content-security-policy" in resp_headers,
                "x_frame_options": "x-frame-options" in resp_headers or "frame-ancestors" in resp_headers.get("content-security-policy", ""),
                "x_content_type_options": "x-content-type-options" in resp_headers,
                "strict_transport_security": "strict-transport-security" in resp_headers
            }

            return {
                "success": True,
                "path": path,
                "method": method,
                "status_code": resp.status_code,
                "duration_ms": duration_ms,
                "headers": resp_headers,
                "body_preview": resp.text[:1000],
                "security_audit": header_audit
            }
        except Exception as e:
            return {"success": False, "error": str(e), "path": path}


@app.get("/api/cvss/calculate")
async def calculate_cvss(vector: str = Query("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")):
    score, severity, canonical_vector = CvssV31Calculator.calculate(vector)
    return {
        "score": score,
        "severity": severity,
        "canonical_vector": canonical_vector
    }


# --- Report Downloads ---
@app.get("/api/assessment/report/html")
async def download_html_report():
    html_content = ReportGenerator.generate_html_report(
        orchestrator.findings,
        orchestrator.stats,
        orchestrator.config.target_url
    )
    return HTMLResponse(content=html_content, headers={"Content-Disposition": "attachment; filename=worldkavach_security_report.html"})


@app.get("/api/assessment/report/pdf")
async def download_pdf_report():
    try:
        pdf_bytes = ReportGenerator.generate_pdf_report(
            orchestrator.findings,
            orchestrator.stats,
            orchestrator.config.target_url
        )
    except Exception as e:
        logger.error(f"Error building PDF: {e}")
        pdf_bytes = ReportGenerator.generate_pdf_report(
            [],
            orchestrator.stats,
            orchestrator.config.target_url
        )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="worldkavach_security_report.pdf"',
            "Content-Type": "application/pdf"
        }
    )


@app.get("/api/assessment/report/csv")
async def download_csv_report():
    csv_str = ReportGenerator.generate_csv_report(
        orchestrator.findings,
        orchestrator.stats,
        orchestrator.config.target_url
    )
    return PlainTextResponse(
        content=csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="worldkavach_security_report.csv"'}
    )


@app.get("/api/assessment/report/json")
async def download_json_report():
    json_str = ReportGenerator.generate_json_report(
        orchestrator.findings,
        orchestrator.stats,
        orchestrator.config.target_url
    )
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="worldkavach_security_report.json"'}
    )


@app.get("/api/assessment/report/markdown")
async def download_markdown_report():
    md_str = ReportGenerator.generate_markdown_report(
        orchestrator.findings,
        orchestrator.stats,
        orchestrator.config.target_url
    )
    return PlainTextResponse(
        content=md_str,
        headers={"Content-Disposition": 'attachment; filename="worldkavach_security_report.md"'}
    )


# --- Target Sandbox Control ---
@app.post("/api/target/toggle-fix/{finding_id}")
async def toggle_target_fix(finding_id: str):
    if finding_id in PATCH_STATE:
        PATCH_STATE[finding_id] = not PATCH_STATE[finding_id]
        return {"finding_id": finding_id, "patch_enabled": PATCH_STATE[finding_id]}
    return JSONResponse(status_code=404, content={"error": "Finding not found in patch registry"})


# Static files mount
static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.isfile(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="""
    <html><head><title>World Monitor Security Platform</title></head>
    <body style="font-family:sans-serif; background:#0b0f17; color:#eee; padding:2rem;">
    <h2>World Monitor Security Assessment API Server</h2>
    <p>API docs available at <a href="/docs" style="color:#38bdf8;">/docs</a></p>
    <p>WebSocket feed at <code>/ws/assessment</code></p>
    </body></html>
    """)
