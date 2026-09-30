"""
Agent 2: Prover.
Responsible for:
1. Taking candidate findings
2. Running controlled validation against live endpoints or sandbox target
3. Confirming or rejecting findings based on live HTTP evidence
4. Emitting VERIFIED or REJECTED status with full request/response traces.
"""

from typing import List, Callable, Optional, Awaitable
from ..evidence.models import Finding
from ..evidence.validator import EvidenceValidator


class ProverAgent:
    """
    Prover agent executing controlled validation for each candidate finding.
    """

    def __init__(self, target_base_url: str = "http://127.0.0.1:8000/target"):
        self.validator = EvidenceValidator(target_base_url)

    async def prove_findings(
        self,
        candidates: List[Finding],
        on_progress: Optional[Callable[[Finding], Awaitable[None]]] = None
    ) -> List[Finding]:
        """
        Validates all candidates in sequence, invoking on_progress callback for real-time WebSocket updates.
        """
        validated_findings = []
        for candidate in candidates:
            if on_progress:
                await on_progress(candidate)

            validated = await self.validator.validate_finding(candidate)

            if on_progress:
                await on_progress(validated)

            validated_findings.append(validated)
        return validated_findings
