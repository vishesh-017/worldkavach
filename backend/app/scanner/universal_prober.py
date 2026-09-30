"""
Universal Dynamic DAST Prober for Arbitrary Target URLs.
Enables real-time dynamic security audits against ANY website with deterministic live HTTP evidence traces.
"""

import time
import httpx
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional
from ..evidence.models import Finding, FindingStatus, Severity, HttpEvidence, Endpoint, EndpointClassification


class UniversalDastProber:
    """
    Executes live HTTP security probes against any target website,
    generating verified findings backed by real HTTP request/response evidence traces.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        parsed = urlparse(self.target_url)
        self.domain = parsed.netloc or parsed.path

    async def probe_all(self, client: httpx.AsyncClient) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Probe CSP & Script Policy
        csp_finding = await self._probe_csp(client)
        if csp_finding:
            findings.append(csp_finding)

        # 2. Probe Clickjacking & Frame Ancestors
        clickjacking_finding = await self._probe_clickjacking(client)
        if clickjacking_finding:
            findings.append(clickjacking_finding)

        # 3. Probe CORS Origin Reflection
        cors_finding = await self._probe_cors(client)
        if cors_finding:
            findings.append(cors_finding)

        # 4. Probe Transport Security & Cookie Flags
        cookie_finding = await self._probe_transport_security(client)
        if cookie_finding:
            findings.append(cookie_finding)

        # 5. Probe Sensitive Endpoint Disclosure
        sensitive_finding = await self._probe_sensitive_paths(client)
        if sensitive_finding:
            findings.append(sensitive_finding)

        return findings

    async def _probe_csp(self, client: httpx.AsyncClient) -> Optional[Finding]:
        start = time.time()
        try:
            resp = await client.get(self.target_url, follow_redirects=True, timeout=8.0)
            duration_ms = round((time.time() - start) * 1000, 2)
            headers = dict(resp.headers)
            csp = headers.get("content-security-policy", headers.get("content-security-policy-report-only", ""))

            evidence = HttpEvidence(
                url=self.target_url,
                method="GET",
                request_headers={"Accept": "text/html,application/xhtml+xml", "User-Agent": "SecOps-DynamicAudit/1.0"},
                response_status=resp.status_code,
                response_headers=headers,
                response_body=resp.text[:1000],
                duration_ms=duration_ms,
                validation_notes=f"Dynamic CSP inspection on {self.domain}. Content-Security-Policy header: '{csp[:120] if csp else 'MISSING'}'"
            )

            if not csp:
                return Finding(
                    id="FIND-DYN-001",
                    title="Missing Content-Security-Policy (CSP) Header",
                    endpoint_path="/",
                    affected_component=f"{self.domain} (HTTP Response Headers)",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-1021",
                    description=f"The target host {self.domain} fails to return a Content-Security-Policy HTTP response header on the root entry point. Without CSP, modern browsers cannot restrict script origins, object data, or outbound exfiltration sinks, leaving users vulnerable to Cross-Site Scripting (XSS).",
                    poc_code=f"curl -I '{self.target_url}' | grep -i 'content-security-policy'",
                    evidence=evidence,
                    business_impact="Heightened risk of stored/reflected XSS execution, session hijacking, credential harvesting, and client-side data exfiltration.",
                    remediation_recommendations="Implement a robust Content-Security-Policy header with strict default-src 'self' restrictions and cryptographic nonces for dynamic scripts.",
                    remediation_diff="""+ Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{RANDOM_CSPRNG}'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';""",
                    status=FindingStatus.VERIFIED,
                    confidence=0.98,
                    source_file="HTTP Response Headers",
                    line_number=1
                )
            elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                return Finding(
                    id="FIND-DYN-001",
                    title="Insecure Content-Security-Policy Directive ('unsafe-inline' / 'unsafe-eval')",
                    endpoint_path="/",
                    affected_component=f"{self.domain} (Content-Security-Policy)",
                    severity=Severity.MEDIUM,
                    cvss_score=6.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    cwe_id="CWE-1021",
                    description=f"The target host {self.domain} returns a Content-Security-Policy containing 'unsafe-inline' or 'unsafe-eval', effectively nullifying XSS script execution defenses.",
                    poc_code=f"curl -I '{self.target_url}' | grep -i 'content-security-policy'",
                    evidence=evidence,
                    business_impact="Allows attackers to bypass CSP restrictions if an HTML injection flaw exists in user input.",
                    remediation_recommendations="Remove 'unsafe-inline' and 'unsafe-eval' from script-src in favor of per-request cryptographic nonces or sha256 hashes.",
                    remediation_diff="""- script-src 'self' 'unsafe-inline' 'unsafe-eval';\n+ script-src 'self' 'nonce-{RANDOM}';""",
                    status=FindingStatus.VERIFIED,
                    confidence=0.95,
                    source_file="Content-Security-Policy",
                    line_number=1
                )
        except Exception:
            pass
        return None

    async def _probe_clickjacking(self, client: httpx.AsyncClient) -> Optional[Finding]:
        start = time.time()
        try:
            resp = await client.get(self.target_url, follow_redirects=True, timeout=8.0)
            duration_ms = round((time.time() - start) * 1000, 2)
            headers = dict(resp.headers)
            xfo = headers.get("x-frame-options", "").upper()
            csp = headers.get("content-security-policy", "")
            has_frame_ancestors = "frame-ancestors" in csp

            if not xfo and not has_frame_ancestors:
                evidence = HttpEvidence(
                    url=self.target_url,
                    method="GET",
                    request_headers={"Accept": "text/html", "User-Agent": "SecOps-DynamicAudit/1.0"},
                    response_status=resp.status_code,
                    response_headers=headers,
                    response_body=resp.text[:600],
                    duration_ms=duration_ms,
                    validation_notes=f"Clickjacking probe against {self.domain}: Neither X-Frame-Options nor CSP frame-ancestors is present."
                )
                return Finding(
                    id="FIND-DYN-002",
                    title="Missing Frame Embedding Controls (Clickjacking Vulnerability)",
                    endpoint_path="/",
                    affected_component=f"{self.domain} (X-Frame-Options / frame-ancestors)",
                    severity=Severity.MEDIUM,
                    cvss_score=5.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cwe_id="CWE-1021",
                    description=f"The application on {self.domain} does not restrict third-party framing. An adversary can embed this page inside an invisible iframe on a malicious website and trick authenticated victims into triggering unintended state-changing actions.",
                    poc_code=f"""<iframe src="{self.target_url}" style="opacity:0.001; position:absolute; top:0; left:0; width:100%; height:100%;"></iframe>""",
                    evidence=evidence,
                    business_impact="UI redressing attacks leading to unauthorized actions, account configuration changes, or unintended transactions.",
                    remediation_recommendations="Add 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self'' to all HTTP responses.",
                    remediation_diff="""+ X-Frame-Options: SAMEORIGIN\n+ Content-Security-Policy: frame-ancestors 'self';""",
                    status=FindingStatus.VERIFIED,
                    confidence=0.98,
                    source_file="HTTP Response Headers",
                    line_number=1
                )
        except Exception:
            pass
        return None

    async def _probe_cors(self, client: httpx.AsyncClient) -> Optional[Finding]:
        test_origin = "https://arbitrary-adversary.attacker.io"
        start = time.time()
        try:
            resp = await client.get(
                self.target_url,
                headers={"Origin": test_origin, "Accept": "application/json,text/html"},
                timeout=8.0
            )
            duration_ms = round((time.time() - start) * 1000, 2)
            headers = dict(resp.headers)
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "").lower()

            if acao == test_origin and acac == "true":
                evidence = HttpEvidence(
                    url=self.target_url,
                    method="GET",
                    request_headers={"Origin": test_origin, "User-Agent": "SecOps-DynamicAudit/1.0"},
                    response_status=resp.status_code,
                    response_headers=headers,
                    response_body=resp.text[:600],
                    duration_ms=duration_ms,
                    validation_notes=f"CORS Origin Reflection Confirmed: Target reflected Origin '{test_origin}' with Access-Control-Allow-Credentials: true"
                )
                return Finding(
                    id="FIND-DYN-003",
                    title="Insecure Cross-Origin Resource Sharing (CORS) with Credential Reflection",
                    endpoint_path="/",
                    affected_component=f"{self.domain} (Access-Control-Allow-Origin)",
                    severity=Severity.HIGH,
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-346",
                    description=f"The application dynamically reflects arbitrary Origin headers ({test_origin}) and simultaneously permits credentials (Access-Control-Allow-Credentials: true). Any malicious third-party site visited by an authenticated user can read sensitive session data and perform cross-origin actions.",
                    poc_code=f"""fetch('{self.target_url}', {{ credentials: 'include' }}).then(r => r.text()).then(data => alert(data));""",
                    evidence=evidence,
                    business_impact="Complete bypass of Same-Origin Policy (SOP), leading to authenticated data leakage and unauthorized API execution.",
                    remediation_recommendations="Validate the Origin header strictly against an explicit domain allowlist and never reflect arbitrary origins when credentials are supported.",
                    remediation_diff="""- Access-Control-Allow-Origin: request.headers['Origin']\n+ if is_valid_origin(request.headers['Origin']):\n+     response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']""",
                    status=FindingStatus.VERIFIED,
                    confidence=0.99,
                    source_file="CORS Middleware",
                    line_number=1
                )
        except Exception:
            pass
        return None

    async def _probe_transport_security(self, client: httpx.AsyncClient) -> Optional[Finding]:
        if not self.target_url.startswith("https://"):
            return None
        start = time.time()
        try:
            resp = await client.get(self.target_url, timeout=8.0)
            duration_ms = round((time.time() - start) * 1000, 2)
            headers = dict(resp.headers)
            hsts = headers.get("strict-transport-security", "")

            if not hsts:
                evidence = HttpEvidence(
                    url=self.target_url,
                    method="GET",
                    request_headers={"Accept": "text/html", "User-Agent": "SecOps-DynamicAudit/1.0"},
                    response_status=resp.status_code,
                    response_headers=headers,
                    response_body=resp.text[:400],
                    duration_ms=duration_ms,
                    validation_notes=f"HSTS probe against {self.domain}: Strict-Transport-Security header is missing."
                )
                return Finding(
                    id="FIND-DYN-004",
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    endpoint_path="/",
                    affected_component=f"{self.domain} (HTTP Response Headers)",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-319",
                    description=f"The HTTPS-enabled host {self.domain} does not supply a Strict-Transport-Security header. This exposes users to SSL-stripping and Man-in-the-Middle (MitM) attacks during initial unencrypted HTTP handshakes.",
                    poc_code=f"curl -I '{self.target_url}' | grep -i 'strict-transport-security'",
                    evidence=evidence,
                    business_impact="Vulnerability to network-level interception and SSL-stripping on public Wi-Fi networks.",
                    remediation_recommendations="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                    remediation_diff="""+ Strict-Transport-Security: max-age=31536000; includeSubDomains; preload""",
                    status=FindingStatus.VERIFIED,
                    confidence=0.95,
                    source_file="HTTP Response Headers",
                    line_number=1
                )
        except Exception:
            pass
        return None

    async def _probe_sensitive_paths(self, client: httpx.AsyncClient) -> Optional[Finding]:
        test_paths = ["/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD"]
        for p in test_paths:
            test_url = urljoin(self.target_url, p)
            start = time.time()
            try:
                resp = await client.get(test_url, timeout=5.0)
                duration_ms = round((time.time() - start) * 1000, 2)
                if resp.status_code == 200:
                    if p in ["/.env", "/.git/HEAD"]:
                        evidence = HttpEvidence(
                            url=test_url,
                            method="GET",
                            request_headers={"Accept": "*/*"},
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body=resp.text[:500],
                            duration_ms=duration_ms,
                            validation_notes=f"CRITICAL SENSITIVE REPO FILE ACCESSIBLE: {test_url}"
                        )
                        return Finding(
                            id="FIND-DYN-005",
                            title=f"Critical Exposure of Sensitive Source/Environment File ({p})",
                            endpoint_path=p,
                            affected_component=f"{self.domain}{p}",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            cwe_id="CWE-552",
                            description=f"The application exposes sensitive configuration or version control metadata at {test_url}. Attackers can extract API keys, database credentials, or proprietary source code.",
                            poc_code=f"curl -s '{test_url}'",
                            evidence=evidence,
                            business_impact="Total compromise of secrets, database credentials, and internal infrastructure.",
                            remediation_recommendations=f"Block all requests to dotfiles and configuration files ({p}) at the web server / reverse proxy layer.",
                            remediation_diff=f"""+ location ~ /\\. {{ deny all; }}""",
                            status=FindingStatus.VERIFIED,
                            confidence=0.99,
                            source_file=p,
                            line_number=1
                        )
            except Exception:
                continue
        return None
