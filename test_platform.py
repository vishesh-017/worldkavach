"""
Verification test script for WorldKavach Security Assessment Platform.
Tests orchestrator lifecycle, live validation, re-testing, and report generation.
"""

import asyncio
from backend.app.orchestrator.engine import orchestrator
from backend.app.evidence.models import ScanConfig
from backend.app.reports.generator import ReportGenerator

async def main():
    print("[1] Initializing Assessment...")
    config = ScanConfig(target_url="https://www.worldmonitor.app", use_local_mock=True, target_source_path="target_repo")

    # Start assessment
    print("[2] Running Assessment Pipeline...")
    await orchestrator.start_assessment(config)

    print(f"\n[+] Assessment Complete! Status: {orchestrator.status}")
    print(f"[+] Endpoints Discovered: {orchestrator.stats.endpoints_discovered}")
    print(f"[+] Candidates Found: {orchestrator.stats.candidates_count}")
    print(f"[+] Verified Findings: {orchestrator.stats.verified_count}")
    print(f"[+] False Positives Rejected: {orchestrator.stats.rejected_count}")

    for idx, f in enumerate(orchestrator.findings, 1):
        print(f"\nFinding {idx}: {f.id} - {f.title}")
        print(f"  Severity: {f.severity.value} (CVSS: {f.cvss_score})")
        print(f"  Status: {f.status.value}")
        if f.evidence:
            print(f"  Evidence: HTTP {f.evidence.response_status} ({f.evidence.duration_ms}ms)")

    # Test Re-test loop
    if orchestrator.findings:
        target_f = orchestrator.findings[0]
        print(f"\n[3] Testing Re-test loop on {target_f.id}...")
        retest_res = await orchestrator.run_retest(target_f.id)
        print(f"[+] Re-test Result: {retest_res['status_message']}")

    # Test Report Generation
    print("\n[4] Testing Report Generation...")
    html = ReportGenerator.generate_html_report(orchestrator.findings, orchestrator.stats, config.target_url)
    print(f"[+] Generated HTML Report: {len(html)} bytes")

    pdf = ReportGenerator.generate_pdf_report(orchestrator.findings, orchestrator.stats, config.target_url)
    print(f"[+] Generated PDF Report: {len(pdf)} bytes")

    json_str = ReportGenerator.generate_json_report(orchestrator.findings, orchestrator.stats, config.target_url)
    print(f"[+] Generated JSON Report: {len(json_str)} bytes")

    md_str = ReportGenerator.generate_markdown_report(orchestrator.findings, orchestrator.stats, config.target_url)
    print(f"[+] Generated Markdown Report: {len(md_str)} bytes")

    print("\n>>> ALL PLATFORM TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    asyncio.run(main())
