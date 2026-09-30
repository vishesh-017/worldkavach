"""
WorldKavach Autonomous DAST Security Assessment Platform
One-Click Platform Runner.
Combines: Advanced SecOps Platform + Deterministic Evidence DAST + Red Room 3-Agent Workflow.
"""

import os
import uvicorn
import webbrowser
import threading
import time
import sys

def open_browser(port):
    time.sleep(1.5)
    print(f"\n[+] WorldKavach Platform Ready! Opening http://127.0.0.1:{port} in your browser...\n")
    try:
        webbrowser.open(f"http://127.0.0.1:{port}")
    except Exception:
        pass

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")

    print("=" * 75)
    print("   WORLDKAVACH AUTONOMOUS DAST SECURITY ASSESSMENT PLATFORM")
    print("   Architecture: Evidence-First DAST + Multi-Agent Orchestration")
    print("   Target: Universal (Default Benchmark: https://www.worldmonitor.app)")
    print(f"   Binding: http://{host}:{port}")
    print("=" * 75)

    # Launch browser only in local interactive environments (not in cloud/headless container)
    if not os.environ.get("RENDER") and not os.environ.get("PORT"):
        threading.Thread(target=open_browser, args=(port,), daemon=True).start()

    uvicorn.run("backend.app.main:app", host=host, port=port, reload=False, log_level="info")

