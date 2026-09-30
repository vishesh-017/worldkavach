"""
WorldKavach Autonomous DAST Security Assessment Platform
One-Click Platform Runner.
Combines: Advanced SecOps Platform + Deterministic Evidence DAST + Red Room 3-Agent Workflow.
"""

import uvicorn
import webbrowser
import threading
import time
import sys

def open_browser():
    time.sleep(1.5)
    print("\n[+] WorldKavach Platform Ready! Opening http://127.0.0.1:8000 in your browser...\n")
    try:
        webbrowser.open("http://127.0.0.1:8000")
    except Exception:
        pass

if __name__ == "__main__":
    print("=" * 75)
    print("   WORLDKAVACH AUTONOMOUS DAST SECURITY ASSESSMENT PLATFORM")
    print("   Architecture: Evidence-First DAST + Multi-Agent Orchestration")
    print("   Target: Universal (Default Benchmark: https://www.worldmonitor.app)")
    print("=" * 75)

    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
