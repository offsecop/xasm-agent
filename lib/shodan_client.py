"""
Shodan API Client
Shared library for Shodan agent tools
"""

import aiohttp
import asyncio
import ssl
import os
from typing import Dict, List, Optional, Any


class ShodanClient:
    """Async Shodan API client for agent tools"""

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str, rate_limit_delay: float = 1.0, verify_ssl: bool = True):
        """
        Initialize Shodan client

        Args:
            api_key: Shodan API key
            rate_limit_delay: Delay between requests in seconds (default 1s for free tier)
            verify_ssl: Verify SSL certificates (set False for Docker environments with proxy)
        """
        self.api_key = api_key
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time = 0
        # Allow SSL verification to be disabled via environment variable
        self.verify_ssl = os.environ.get('SHODAN_VERIFY_SSL', 'false').lower() != 'false' if not verify_ssl else verify_ssl

    async def _rate_limit(self):
        """Enforce rate limiting between requests"""
        import time
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    def _get_ssl_context(self):
        """Get SSL context for HTTP requests"""
        if not self.verify_ssl:
            # Create an SSL context that doesn't verify certificates
            # This is needed in some Docker environments with SSL proxy interception
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            return ssl_context
        return None  # Use default SSL verification

    async def _request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """
        Make authenticated request to Shodan API

        Args:
            endpoint: API endpoint path
            params: Optional query parameters

        Returns:
            JSON response as dict
        """
        await self._rate_limit()

        url = f"{self.BASE_URL}{endpoint}"
        request_params = {"key": self.api_key}
        if params:
            request_params.update(params)

        # Create connector with SSL context
        ssl_context = self._get_ssl_context()
        connector = aiohttp.TCPConnector(ssl=ssl_context) if ssl_context else aiohttp.TCPConnector()

        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, params=request_params) as response:
                if response.status == 401:
                    raise ValueError("Invalid Shodan API key")
                if response.status == 429:
                    raise ValueError("Shodan API rate limit exceeded")
                if response.status != 200:
                    error_text = await response.text()
                    raise ValueError(f"Shodan API error {response.status}: {error_text}")

                return await response.json()

    async def get_api_info(self) -> Dict:
        """
        Get API plan information and credits

        Returns:
            API info including query_credits, scan_credits, etc.
        """
        return await self._request("/api-info")

    async def get_host(self, ip: str, history: bool = False, minify: bool = False) -> Dict:
        """
        Get all available information on an IP address

        Args:
            ip: IP address to look up
            history: Include historical banners
            minify: Return only basic host info

        Returns:
            Host information including services, banners, CVEs
        """
        params = {}
        if history:
            params["history"] = "true"
        if minify:
            params["minify"] = "true"

        return await self._request(f"/shodan/host/{ip}", params)

    async def search(
        self,
        query: str,
        page: int = 1,
        minify: bool = False,
        facets: Optional[str] = None
    ) -> Dict:
        """
        Search Shodan for hosts matching query

        Args:
            query: Shodan search query (e.g., "product:nginx port:443")
            page: Page number for pagination (100 results per page)
            minify: Only return host IP and port
            facets: Comma-separated list of facets

        Returns:
            Search results with matches array
        """
        params = {
            "query": query,
            "page": str(page),
        }
        if minify:
            params["minify"] = "true"
        if facets:
            params["facets"] = facets

        return await self._request("/shodan/host/search", params)

    async def search_count(self, query: str, facets: Optional[str] = None) -> Dict:
        """
        Get count of search results without consuming query credits

        Args:
            query: Shodan search query
            facets: Optional facets

        Returns:
            Total count and facet data
        """
        params = {"query": query}
        if facets:
            params["facets"] = facets

        return await self._request("/shodan/host/count", params)

    async def dns_resolve(self, hostnames: List[str]) -> Dict[str, str]:
        """
        Resolve hostnames to IP addresses

        Args:
            hostnames: List of hostnames to resolve

        Returns:
            Dict mapping hostnames to IP addresses
        """
        result = await self._request(
            "/dns/resolve",
            {"hostnames": ",".join(hostnames)}
        )
        return result

    async def dns_reverse(self, ips: List[str]) -> Dict[str, List[str]]:
        """
        Reverse DNS lookup for IP addresses

        Args:
            ips: List of IP addresses

        Returns:
            Dict mapping IPs to lists of hostnames
        """
        result = await self._request(
            "/dns/reverse",
            {"ips": ",".join(ips)}
        )
        return result

    def extract_cves(self, host_data: Dict) -> List[Dict]:
        """
        Extract CVE information from host data

        Args:
            host_data: Host data from get_host()

        Returns:
            List of CVE dictionaries with id, cvss, summary, port
        """
        cves = []
        seen_cves = set()

        # Extract from top-level vulns
        if "vulns" in host_data:
            for cve_id in host_data["vulns"]:
                if cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    cves.append({
                        "id": cve_id,
                        "cvss": None,
                        "summary": None,
                        "port": None,
                    })

        # Extract from service data with details
        for service in host_data.get("data", []):
            if "vulns" not in service:
                continue

            port = service.get("port")
            for cve_id, vuln_info in service["vulns"].items():
                if cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    cves.append({
                        "id": cve_id,
                        "cvss": vuln_info.get("cvss"),
                        "summary": vuln_info.get("summary"),
                        "port": port,
                        "verified": vuln_info.get("verified", False),
                        "references": vuln_info.get("references", []),
                    })

        return cves

    def extract_services(self, host_data: Dict) -> List[Dict]:
        """
        Extract service information from host data

        Args:
            host_data: Host data from get_host()

        Returns:
            List of service dictionaries
        """
        services = []

        for service in host_data.get("data", []):
            services.append({
                "port": service.get("port"),
                "transport": service.get("transport", "tcp"),
                "product": service.get("product"),
                "version": service.get("version"),
                "cpe": service.get("cpe", []),
                "banner": service.get("data", "")[:500] if service.get("data") else None,
                "ssl": service.get("ssl") is not None,
                "http": service.get("http") is not None,
            })

        return services
