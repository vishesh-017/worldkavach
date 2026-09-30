"""
AI Security Team Workflow Graph.
Orchestrates the 3-agent pipeline:
Discoverer ("What?") -> Prover ("Is it real?") -> Fixer ("How to fix?")
"""

from typing import List, Dict, Any, Callable, Optional, Awaitable
from ..evidence.models import Endpoint, Finding, AttackSurfaceMapData
from .discoverer import DiscovererAgent
from .prover import ProverAgent
from .fixer import FixerAgent


class AgentWorkflowGraph:
    """
    Coordinates state transitions across Discoverer, Prover, and Fixer agents.
    """

    def __init__(self, repo_path: str = "target_repo", target_base_url: str = "http://127.0.0.1:8000/target"):
        self.discoverer = DiscovererAgent(repo_path)
        self.prover = ProverAgent(target_base_url)
        self.fixer = FixerAgent()

    async def execute(
        self,
        endpoints: List[Endpoint],
        surface_map: AttackSurfaceMapData,
        log_callback: Optional[Callable[[str, str], Awaitable[None]]] = None,
        finding_callback: Optional[Callable[[Finding], Awaitable[None]]] = None
    ) -> List[Finding]:
        """
        Executes the full agent graph:
        Phase 1: Discoverer maps routes and selects candidates.
        Phase 2: Prover executes controlled live HTTP validation.
        Phase 3: Fixer generates contextual patches for verified issues.
        """
        # --- Stage 1: Discoverer ---
        if log_callback:
            await log_callback("DISCOVERER", f"Discoverer agent analyzing {len(endpoints)} endpoints across attack surface.")

        candidates = self.discoverer.discover_candidates(endpoints)

        if log_callback:
            await log_callback("DISCOVERER", f"Discoverer identified {len(candidates)} high-priority candidate vulnerabilities.")

        for c in candidates:
            if finding_callback:
                await finding_callback(c)

        # --- Stage 2: Prover ---
        if log_callback:
            await log_callback("PROVER", f"Prover agent starting controlled live HTTP validation of {len(candidates)} candidates.")

        async def prover_progress(f: Finding):
            if log_callback:
                await log_callback("PROVER", f"Validation status for {f.id} ({f.title[:35]}...): {f.status.value}")
            if finding_callback:
                await finding_callback(f)

        validated_findings = await self.prover.prove_findings(candidates, on_progress=prover_progress)

        verified_count = sum(1 for f in validated_findings if f.status.value in ["VERIFIED", "FIX_PROPOSED"])
        rejected_count = sum(1 for f in validated_findings if f.status.value == "REJECTED")

        if log_callback:
            await log_callback(
                "PROVER",
                f"Validation completed: {verified_count} VERIFIED with live HTTP evidence, {rejected_count} REJECTED as false positives."
            )

        # --- Stage 3: Fixer ---
        if log_callback:
            await log_callback("FIXER", f"Fixer ('Surgeon') generating context-aware remediations and unified code diffs for {verified_count} verified vulnerabilities.")

        final_findings = self.fixer.generate_remediations(validated_findings)

        if log_callback:
            await log_callback("FIXER", "Remediation generation complete. All verified findings packaged with deployable patches.")

        return final_findings
