"""
Endpoint Classifier for World Monitor Attack Surface.
Categorizes discovered routes into distinct security scopes to drive the Applicability Engine.
"""

from typing import Tuple, List, Dict
from ..evidence.models import EndpointClassification


class EndpointClassifier:
    """
    Classifies endpoints and determines required authorization and parameters.
    """

    STATIC_EXTENSIONS = ('.css', '.js', '.map', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.json')

    AUTH_ROUTES = {
        '/mcp-grant', '/oauth/token', '/oauth/register', '/oauth/authorize',
        '/agent/auth', '/api/agent-auth', '/api/wm-session', '/api/user-prefs'
    }

    PROXY_ROUTES = {
        '/api/mcp-proxy', '/api/rss-proxy', '/api/relay'
    }

    INTERNAL_ROUTES = {
        '/api/internal/mcp-grant-mint', '/api/internal/mcp-grant-context',
        '/api/internal/brief-why-matters', '/api/cache-purge'
    }

    @classmethod
    def classify(cls, path: str, method: str = "GET") -> Tuple[EndpointClassification, bool, List[str]]:
        """
        Returns (classification, auth_required, common_parameters)
        """
        clean_path = path.split('?')[0].lower()

        # Static assets
        if clean_path.startswith('/assets/') or clean_path.startswith('/public/') or clean_path.endswith(cls.STATIC_EXTENSIONS):
            return EndpointClassification.STATIC_ASSET, False, []

        # Internal RPCs
        if any(clean_path.startswith(ir) for ir in cls.INTERNAL_ROUTES) or '/internal/' in clean_path:
            return EndpointClassification.INTERNAL_RPC, True, ["internal_token", "hmac_signature"]

        # Proxies
        if any(clean_path.startswith(pr) for pr in cls.PROXY_ROUTES):
            params = ["url", "target", "protocol"] if "mcp" in clean_path else ["url", "fallback"]
            return EndpointClassification.PROXY_ENDPOINT, ("mcp" in clean_path), params

        # Auth flows
        if any(clean_path == ar or clean_path.startswith(ar + '/') for ar in cls.AUTH_ROUTES):
            return EndpointClassification.AUTHENTICATED_ROUTE, True, ["client_id", "code", "token", "grant_type"]

        # API Endpoints
        if clean_path.startswith('/api/'):
            auth_req = any(kw in clean_path for kw in ['user', 'session', 'quota', 'chat-analyst', 'notify', 'checkout'])
            params = []
            if 'symbol-search' in clean_path:
                params = ['q', 'limit']
            elif 'download' in clean_path:
                params = ['platform', 'variant']
            elif 'chat-analyst' in clean_path:
                params = ['query', 'history', 'domainFocus']
            return EndpointClassification.API_ENDPOINT, auth_req, params

        # Public Pages / SPAs
        return EndpointClassification.PUBLIC_PAGE, False, []
