"""
Applicability Engine.
Filters and maps security test suites to specific endpoint classifications,
preventing inappropriate injection attacks against static assets and reducing false positives.
"""

from typing import List, Dict, Set
from ..evidence.models import EndpointClassification, Endpoint


class TestSuite:
    SSRF_CHECKS = "SSRF_CHECKS"
    DNS_REBINDING = "DNS_REBINDING"
    CLOUD_METADATA_EXTRACTION = "CLOUD_METADATA_EXTRACTION"
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    IDOR_BOLA = "IDOR_BOLA"
    AUTH_BYPASS = "AUTH_BYPASS"
    SESSION_FIXATION = "SESSION_FIXATION"
    CORS_MISCONFIGURATION = "CORS_MISCONFIGURATION"
    CSP_NONCE_BYPASS = "CSP_NONCE_BYPASS"
    CLICKJACKING = "CLICKJACKING"
    PARAMETER_POLLUTION = "PARAMETER_POLLUTION"
    RATE_LIMIT_EVASION = "RATE_LIMIT_EVASION"
    CACHE_CONTROL_VALIDATION = "CACHE_CONTROL_VALIDATION"


class ApplicabilityEngine:
    """
    Determines applicable security checks based on route type.
    """

    # Mapping from classification to allowed test suites
    APPLICABILITY_MATRIX: Dict[EndpointClassification, Set[str]] = {
        EndpointClassification.STATIC_ASSET: {
            TestSuite.CACHE_CONTROL_VALIDATION
        },
        EndpointClassification.PUBLIC_PAGE: {
            TestSuite.CSP_NONCE_BYPASS,
            TestSuite.CLICKJACKING,
            TestSuite.CORS_MISCONFIGURATION
        },
        EndpointClassification.PROXY_ENDPOINT: {
            TestSuite.SSRF_CHECKS,
            TestSuite.DNS_REBINDING,
            TestSuite.CLOUD_METADATA_EXTRACTION,
            TestSuite.RATE_LIMIT_EVASION,
            TestSuite.CORS_MISCONFIGURATION
        },
        EndpointClassification.API_ENDPOINT: {
            TestSuite.PARAMETER_POLLUTION,
            TestSuite.PROMPT_INJECTION,
            TestSuite.CORS_MISCONFIGURATION,
            TestSuite.RATE_LIMIT_EVASION,
            TestSuite.SQL_INJECTION,
            TestSuite.COMMAND_INJECTION
        },
        EndpointClassification.AUTHENTICATED_ROUTE: {
            TestSuite.IDOR_BOLA,
            TestSuite.AUTH_BYPASS,
            TestSuite.SESSION_FIXATION,
            TestSuite.CORS_MISCONFIGURATION
        },
        EndpointClassification.INTERNAL_RPC: {
            TestSuite.AUTH_BYPASS,
            TestSuite.IDOR_BOLA,
            TestSuite.CORS_MISCONFIGURATION
        }
    }

    @classmethod
    def get_applicable_tests(cls, endpoint: Endpoint) -> List[str]:
        """Returns the list of applicable test suites for an endpoint."""
        tests = set(cls.APPLICABILITY_MATRIX.get(endpoint.classification, set()))

        # Additional contextual additions
        if "chat" in endpoint.path or "ask" in endpoint.path:
            tests.add(TestSuite.PROMPT_INJECTION)
        if "download" in endpoint.path or "symbol" in endpoint.path:
            tests.add(TestSuite.PARAMETER_POLLUTION)
        if endpoint.auth_required:
            tests.add(TestSuite.IDOR_BOLA)
            tests.add(TestSuite.AUTH_BYPASS)

        return sorted(list(tests))

    @classmethod
    def should_test(cls, endpoint: Endpoint, test_name: str) -> bool:
        """Checks if a particular test should be run against an endpoint."""
        applicable = cls.get_applicable_tests(endpoint)
        return test_name in applicable
