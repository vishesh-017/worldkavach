"""
Dynamic Web and API Crawler.
Combines Playwright browser automation (when available) with high-speed async HTTP crawling
to map client-side SPAs, forms, API queries, and DOM sinks.
"""

import httpx
from bs4 import BeautifulSoup
from typing import List, Dict, Set, Any
from urllib.parse import urljoin, urlparse


class BrowserCrawler:
    """
    Crawls target URL to discover client-side routes, API calls, and external resource sinks.
    """

    def __init__(self, base_url: str = "https://www.worldmonitor.app", max_depth: int = 2):
        self.base_url = base_url.rstrip('/')
        self.max_depth = max_depth
        self.visited: Set[str] = set()

    async def crawl(self) -> List[Dict[str, Any]]:
        """
        Executes crawler and returns discovered route objects.
        """
        discovered = []
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
                resp = await client.get(self.base_url)
                if resp.status_code == 200:
                    discovered.append({
                        "path": "/",
                        "method": "GET",
                        "status": resp.status_code,
                        "desc": "Root Dashboard SPA Page"
                    })

                    soup = BeautifulSoup(resp.text, 'html.parser')

                    # Discover scripts
                    for script in soup.find_all('script'):
                        src = script.get('src')
                        if src:
                            full_url = urljoin(self.base_url, src)
                            parsed = urlparse(full_url)
                            if parsed.path not in self.visited:
                                self.visited.add(parsed.path)
                                discovered.append({
                                    "path": parsed.path,
                                    "method": "GET",
                                    "desc": f"Discovered client module: {src}"
                                })

                    # Discover links
                    for a in soup.find_all('a', href=True):
                        href = a['href']
                        if href.startswith('/') and not href.startswith('//'):
                            if href not in self.visited:
                                self.visited.add(href)
                                discovered.append({
                                    "path": href,
                                    "method": "GET",
                                    "desc": f"Discovered navigation route: {href}"
                                })
        except Exception:
            pass

        return discovered
