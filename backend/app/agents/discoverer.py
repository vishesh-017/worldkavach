"""
Agent 1: Discoverer / Saboteur.
Responsible for:
1. Mapping the application attack surface
2. Identifying endpoints and classifications
3. Applying Applicability Engine rules to prune irrelevant tests
4. Emitting high-confidence Candidate vulnerabilities.
"""

from typing import List
from ..evidence.models import Endpoint, Finding
from ..applicability.engine import ApplicabilityEngine
from ..scanner.source_analyzer import SourceCodeAnalyzer


class DiscovererAgent:
    """
    Discoverer agent that discovers attack surface and emits candidate vulnerabilities.
    """

    def __init__(self, repo_path: str = "target_repo"):
        self.repo_path = repo_path
        self.source_analyzer = SourceCodeAnalyzer(repo_path)

    def discover_candidates(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Evaluates endpoints and source code to generate candidate findings.
        """
        # Run static source analysis across World Monitor codebase
        candidates = self.source_analyzer.run_all_checks()

        # Update endpoints with risk candidate counts
        for c in candidates:
            for ep in endpoints:
                if ep.path == c.endpoint_path:
                    ep.risk_candidates_count += 1
                    ep.tests_performed.extend(ApplicabilityEngine.get_applicable_tests(ep))

        return candidates
