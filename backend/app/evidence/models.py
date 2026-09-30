"""
Evidence and Data Models for World Monitor Security Assessment Platform.
Implements the evidence-first lifecycle:
Candidate -> Analyzing -> Validating -> Verified / Rejected -> Retest
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import datetime


class FindingStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    ANALYZING = "ANALYZING"
    VALIDATING = "VALIDATING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    FIX_PROPOSED = "FIX_PROPOSED"
    RETEST_PASSED = "RETEST_PASSED"
    RETEST_FAILED = "RETEST_FAILED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingCategory(str, Enum):
    AUTH_SESSION = "Authentication and Session Management"
    AUTH_ACCESS = "Authorization and Access Control"
    INPUT_VALIDATION = "Input Validation and Data Handling"
    API_SECURITY = "API Security & SSRF"
    CLIENT_SIDE = "Client-Side Security Controls"
    SECURE_COMM = "Secure Communication Mechanisms"
    DATA_STORAGE = "Data Storage and Privacy Protections"


class EndpointClassification(str, Enum):
    API_ENDPOINT = "API_ENDPOINT"
    AUTHENTICATED_ROUTE = "AUTHENTICATED_ROUTE"
    PUBLIC_PAGE = "PUBLIC_PAGE"
    STATIC_ASSET = "STATIC_ASSET"
    INTERNAL_RPC = "INTERNAL_RPC"
    PROXY_ENDPOINT = "PROXY_ENDPOINT"


class HttpEvidence(BaseModel):
    url: str
    method: str = "GET"
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: int = 0
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[str] = None
    duration_ms: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    validation_notes: Optional[str] = None


class Finding(BaseModel):
    id: str
    title: str
    category: FindingCategory
    severity: Severity
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    cvss_score: float = 7.5
    affected_component: str
    endpoint_path: Optional[str] = None
    http_method: Optional[str] = "GET"
    description: str
    steps_to_reproduce: List[str] = Field(default_factory=list)
    poc_code: str = ""
    evidence: Optional[HttpEvidence] = None
    rejection_reason: Optional[str] = None
    business_impact: str
    remediation_recommendations: str
    remediation_diff: Optional[str] = None
    status: FindingStatus = FindingStatus.CANDIDATE
    confidence: float = 0.90
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    retest_status: Optional[str] = None
    retest_evidence: Optional[HttpEvidence] = None
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class Endpoint(BaseModel):
    id: str
    path: str
    method: str = "GET"
    classification: EndpointClassification
    auth_required: bool = False
    parameters: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    description: Optional[str] = None
    risk_candidates_count: int = 0
    tests_performed: List[str] = Field(default_factory=list)
    status: str = "DISCOVERED"


class SurfaceNode(BaseModel):
    id: str
    label: str
    type: str  # target, page, api, proxy, asset, internal
    classification: Optional[str] = None
    method: Optional[str] = None
    status: str = "clean"  # clean, candidate, verified, rejected
    risk_level: Optional[str] = "LOW"
    details: Dict[str, Any] = Field(default_factory=dict)


class SurfaceEdge(BaseModel):
    source: str
    target: str
    label: Optional[str] = None
    relationship: str = "contains"


class AttackSurfaceMapData(BaseModel):
    nodes: List[SurfaceNode] = Field(default_factory=list)
    edges: List[SurfaceEdge] = Field(default_factory=list)


class AssessmentStats(BaseModel):
    endpoints_discovered: int = 0
    api_endpoints: int = 0
    authenticated_routes: int = 0
    static_assets: int = 0
    candidates_count: int = 0
    analyzing_count: int = 0
    validating_count: int = 0
    verified_count: int = 0
    rejected_count: int = 0
    retest_passed_count: int = 0
    risk_critical: int = 0
    risk_high: int = 0
    risk_medium: int = 0
    risk_low: int = 0


class ScanConfig(BaseModel):
    target_url: str = "https://www.worldmonitor.app"
    use_local_mock: bool = True
    enable_crawler: bool = True
    enable_source_analysis: bool = True
    enable_active_validation: bool = True
    target_source_path: str = "target_repo"
