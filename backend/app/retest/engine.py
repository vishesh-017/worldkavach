"""
Automated Re-Test Engine.
Demonstrates the full vulnerability lifecycle by verifying remediation:
Before (Verified Vulnerability) -> Fix Applied -> After (Fix Verified via Live Re-test).
"""

import httpx
from typing import Dict, Any, Tuple
from ..evidence.models import Finding, FindingStatus, HttpEvidence
from ..evidence.validator import EvidenceValidator
from ..mock_target.vulnerable_app import PATCH_STATE


class RetestEngine:
    """
    Executes automated re-testing to confirm whether proposed remediations mitigate findings.
    """

    def __init__(self, target_base_url: str = "http://127.0.0.1:8000/target"):
        self.target_base_url = target_base_url
        self.validator = EvidenceValidator(target_base_url)

    async def execute_retest(self, finding: Finding, apply_fix_first: bool = True) -> Tuple[bool, Finding]:
        """
        Applies patch to the controlled target, re-runs the validation check,
        and records before/after re-test evidence.
        """
        if apply_fix_first and finding.id in PATCH_STATE:
            PATCH_STATE[finding.id] = True

        # Re-run the validation
        updated_finding = await self.validator.validate_finding(finding)

        # In a re-test scenario, REJECTED by the exploit validator means the VULNERABILITY IS MITIGATED (FIX VERIFIED)!
        if updated_finding.status == FindingStatus.REJECTED:
            updated_finding.status = FindingStatus.RETEST_PASSED
            updated_finding.retest_status = "FIX_VERIFIED"
            updated_finding.retest_evidence = updated_finding.evidence
            fix_successful = True
        else:
            updated_finding.status = FindingStatus.RETEST_FAILED
            updated_finding.retest_status = "STILL_VULNERABLE"
            fix_successful = False

        return fix_successful, updated_finding
