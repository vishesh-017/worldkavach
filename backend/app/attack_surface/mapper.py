"""
Attack Surface Mapper for World Monitor.
Extracts, structures, and builds an interactive attack surface graph.
"""

import os
import json
from typing import List, Dict, Any, Tuple
from .classifier import EndpointClassifier
from ..evidence.models import Endpoint, SurfaceNode, SurfaceEdge, AttackSurfaceMapData, EndpointClassification


class AttackSurfaceMapper:
    """
    Constructs an interactive attack surface map from source code and runtime crawling.
    """

    DEFAULT_WORLD_MONITOR_ROUTES = [
        # Public Pages
        {"path": "/", "method": "GET", "desc": "Main Situational Awareness Dashboard (3D globe / Deck.gl)"},
        {"path": "/dashboard", "method": "GET", "desc": "Live intelligence feeds & monitors"},
        {"path": "/pro", "method": "GET", "desc": "Pro tier landing and subscription portal"},
        {"path": "/mcp-grant", "method": "GET", "desc": "MCP Client OAuth authorization page"},
        {"path": "/settings", "method": "GET", "desc": "Desktop and user configuration panel"},
        {"path": "/embed", "method": "GET", "desc": "Embeddable widget viewer for third-party sites"},
        {"path": "/live-channels", "method": "GET", "desc": "Live streaming OSINT video channels"},
        {"path": "/story", "method": "GET", "desc": "Geopolitical story viewer"},
        {"path": "/crises", "method": "GET", "desc": "Crisis and conflict tracker"},
        {"path": "/tools", "method": "GET", "desc": "OSINT intelligence toolkit"},

        # Proxy Layer
        {"path": "/api/mcp-proxy", "method": "POST", "desc": "Outbound MCP Pro-gated proxy with DoH validation"},
        {"path": "/api/rss-proxy", "method": "GET", "desc": "RSS feed fetcher with domain allowlist filter"},

        # API Endpoints
        {"path": "/api/symbol-search", "method": "GET", "desc": "Stock symbol typeahead search backed by Finnhub"},
        {"path": "/api/download", "method": "GET", "desc": "Desktop client binary asset redirector"},
        {"path": "/api/chat-analyst", "method": "POST", "desc": "AI analyst streaming reasoning endpoint"},
        {"path": "/api/ask", "method": "POST", "desc": "Q&A querying against OSINT knowledge base"},
        {"path": "/api/notify", "method": "POST", "desc": "Webhook notification dispatcher"},
        {"path": "/api/notification-channels", "method": "GET", "desc": "Configured user notification channels"},
        {"path": "/api/latest-brief", "method": "GET", "desc": "AI-synthesized geopolitical summary brief"},
        {"path": "/api/reverse-geocode", "method": "GET", "desc": "Geographic coordinate resolution"},
        {"path": "/api/create-checkout", "method": "POST", "desc": "DodoPayments/Stripe billing checkout"},

        # Auth & User Routes
        {"path": "/api/wm-session", "method": "POST", "desc": "User session HMAC issuance & validation"},
        {"path": "/api/user-prefs", "method": "GET", "desc": "Convex-synced user preferences"},
        {"path": "/api/user-prefs", "method": "POST", "desc": "User preferences mutation"},
        {"path": "/api/user/mcp-quota", "method": "GET", "desc": "User-specific MCP quota inquiry"},
        {"path": "/api/user/mcp-revoke", "method": "POST", "desc": "Revocation of authorized MCP tokens"},
        {"path": "/api/oauth/token", "method": "POST", "desc": "OAuth2 access token minting"},
        {"path": "/api/oauth/register", "method": "POST", "desc": "Dynamic client registration"},

        # Internal RPCs
        {"path": "/api/internal/mcp-grant-mint", "method": "POST", "desc": "Privileged MCP token minting"},
        {"path": "/api/internal/mcp-grant-context", "method": "GET", "desc": "MCP grant authorization context"},
        {"path": "/api/internal/brief-why-matters", "method": "POST", "desc": "Automated reasoning generator"},
        {"path": "/api/cache-purge", "method": "POST", "desc": "Administrative Upstash cache eviction"},

        # Static Assets
        {"path": "/assets/main.css", "method": "GET", "desc": "Core dashboard stylesheet"},
        {"path": "/assets/main.js", "method": "GET", "desc": "Bundled SPA client bundle"},
        {"path": "/robots.txt", "method": "GET", "desc": "Search engine crawler policy"}
    ]

    @classmethod
    def discover_from_source(cls, source_dir: str = "target_repo") -> List[Dict[str, Any]]:
        """Scans local target_repo if present to discover additional endpoints."""
        discovered = list(cls.DEFAULT_WORLD_MONITOR_ROUTES)
        seen_paths = {f"{r['method']}:{r['path']}" for r in discovered}

        api_dir = os.path.join(source_dir, "api")
        if os.path.isdir(api_dir):
            try:
                for entry in os.listdir(api_dir):
                    if entry.endswith(('.js', '.ts')) and not entry.startswith('_') and not entry.endswith(('.test.js', '.test.ts', '.test.mjs')):
                        route_name = os.path.splitext(entry)[0]
                        path = f"/api/{route_name}"
                        key = f"GET:{path}"
                        if key not in seen_paths:
                            discovered.append({
                                "path": path,
                                "method": "GET",
                                "desc": f"Discovered Vercel edge endpoint: {entry}"
                            })
                            seen_paths.add(key)
            except Exception:
                pass
        return discovered

    @classmethod
    def build_map(cls, target_url: str = "https://www.worldmonitor.app", source_dir: str = "target_repo") -> Tuple[List[Endpoint], AttackSurfaceMapData]:
        """Constructs the full endpoint catalog and graph map data."""
        raw_routes = cls.discover_from_source(source_dir)
        endpoints: List[Endpoint] = []
        nodes: List[SurfaceNode] = []
        edges: List[SurfaceEdge] = []

        root_id = "target_root"
        nodes.append(SurfaceNode(
            id=root_id,
            label="World Monitor Target\n(worldmonitor.app)",
            type="target",
            risk_level="HIGH",
            details={"url": target_url, "platform": "Vercel Edge + Tauri Desktop"}
        ))

        # Groups
        groups = {
            "group_pages": ("Web Pages / SPAs", "page"),
            "group_apis": ("API Endpoints", "api"),
            "group_proxies": ("Proxies & SSRF Gateways", "proxy"),
            "group_auth": ("Auth & Session Flows", "auth"),
            "group_internal": ("Internal RPCs", "internal"),
            "group_assets": ("Static Assets", "asset")
        }

        for gid, (glabel, gtype) in groups.items():
            nodes.append(SurfaceNode(
                id=gid,
                label=glabel,
                type=gtype,
                details={"category": glabel}
            ))
            edges.append(SurfaceEdge(source=root_id, target=gid, label="routes to"))

        for idx, route in enumerate(raw_routes):
            path = route["path"]
            method = route["method"]
            desc = route.get("desc", "")
            classification, auth_req, params = EndpointClassifier.classify(path, method)

            ep_id = f"ep_{idx}_{classification.value.lower()}"
            endpoint_obj = Endpoint(
                id=ep_id,
                path=path,
                method=method,
                classification=classification,
                auth_required=auth_req,
                parameters=params,
                description=desc,
                status="DISCOVERED"
            )
            endpoints.append(endpoint_obj)

            # Determine parent group
            if classification == EndpointClassification.PUBLIC_PAGE:
                parent_group = "group_pages"
                node_type = "page"
            elif classification == EndpointClassification.PROXY_ENDPOINT:
                parent_group = "group_proxies"
                node_type = "proxy"
            elif classification == EndpointClassification.AUTHENTICATED_ROUTE:
                parent_group = "group_auth"
                node_type = "auth"
            elif classification == EndpointClassification.INTERNAL_RPC:
                parent_group = "group_internal"
                node_type = "internal"
            elif classification == EndpointClassification.STATIC_ASSET:
                parent_group = "group_assets"
                node_type = "asset"
            else:
                parent_group = "group_apis"
                node_type = "api"

            nodes.append(SurfaceNode(
                id=ep_id,
                label=f"{method} {path}",
                type=node_type,
                classification=classification.value,
                method=method,
                status="candidate" if "proxy" in path or "mcp" in path or "user-prefs" in path or "download" in path else "clean",
                risk_level="HIGH" if ("proxy" in path or "mcp" in path or "internal" in path) else ("MEDIUM" if auth_req else "LOW"),
                details={
                    "path": path,
                    "method": method,
                    "auth_required": auth_req,
                    "parameters": params,
                    "description": desc
                }
            ))
            edges.append(SurfaceEdge(source=parent_group, target=ep_id, label="exposes"))

        return endpoints, AttackSurfaceMapData(nodes=nodes, edges=edges)

    @classmethod
    def build_dynamic_map(cls, target_url: str, crawled_routes: List[Dict[str, Any]] = None) -> Tuple[List[Endpoint], AttackSurfaceMapData]:
        """Constructs an interactive attack surface graph dynamically for any arbitrary target website."""
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path or "Target Host"

        routes = list(crawled_routes or [])
        if not any(r.get("path") == "/" for r in routes):
            routes.insert(0, {"path": "/", "method": "GET", "desc": "Root Entry Point"})

        common_sinks = [
            {"path": "/robots.txt", "method": "GET", "desc": "Crawler access policy & sensitive path disclosure hints"},
            {"path": "/sitemap.xml", "method": "GET", "desc": "Structured public XML route catalog"},
            {"path": "/api", "method": "GET", "desc": "Public API route index / Gateway"},
            {"path": "/login", "method": "GET", "desc": "Authentication entry sink"}
        ]
        for s in common_sinks:
            if not any(r.get("path") == s["path"] for r in routes):
                routes.append(s)

        endpoints: List[Endpoint] = []
        nodes: List[SurfaceNode] = []
        edges: List[SurfaceEdge] = []

        root_id = "target_root"
        nodes.append(SurfaceNode(
            id=root_id,
            label=f"Target Host\n({domain})",
            type="target",
            risk_level="MEDIUM",
            details={"url": target_url, "domain": domain}
        ))

        groups = {
            "group_pages": ("Web Pages / SPAs", "page"),
            "group_apis": ("API Endpoints", "api"),
            "group_auth": ("Auth & Session Sinks", "auth"),
            "group_assets": ("Client Assets & Scripts", "asset")
        }

        for gid, (glabel, gtype) in groups.items():
            nodes.append(SurfaceNode(id=gid, label=glabel, type=gtype, details={"category": glabel}))
            edges.append(SurfaceEdge(source=root_id, target=gid, label="routes to"))

        for idx, route in enumerate(routes):
            path = route.get("path", "/")
            method = route.get("method", "GET")
            desc = route.get("desc", f"Dynamically discovered route on {domain}")
            classification, auth_req, params = EndpointClassifier.classify(path, method)

            ep_id = f"ep_dyn_{idx}"
            endpoint_obj = Endpoint(
                id=ep_id,
                path=path,
                method=method,
                classification=classification,
                auth_required=auth_req,
                parameters=params,
                description=desc,
                status="DISCOVERED"
            )
            endpoints.append(endpoint_obj)

            if classification == EndpointClassification.PUBLIC_PAGE:
                parent_group, node_type = "group_pages", "page"
            elif classification in [EndpointClassification.AUTHENTICATED_ROUTE, EndpointClassification.INTERNAL_RPC]:
                parent_group, node_type = "group_auth", "auth"
            elif classification == EndpointClassification.STATIC_ASSET:
                parent_group, node_type = "group_assets", "asset"
            else:
                parent_group, node_type = "group_apis", "api"

            nodes.append(SurfaceNode(
                id=ep_id,
                label=f"{method} {path}",
                type=node_type,
                classification=classification.value,
                method=method,
                status="clean",
                risk_level="HIGH" if auth_req else "LOW",
                details={"path": path, "method": method, "auth_required": auth_req, "description": desc}
            ))
            edges.append(SurfaceEdge(source=parent_group, target=ep_id, label="exposes"))

        return endpoints, AttackSurfaceMapData(nodes=nodes, edges=edges)
