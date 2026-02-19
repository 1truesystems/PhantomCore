"""
CVE Search Collector
=====================

Asynchronous collector for CVE vulnerability data from online and local
sources. Queries the NVD (National Vulnerability Database) API format
and caches results in the local SQLite database for offline access
and performance.

The collector implements a two-tier lookup strategy:
  1. Check the local SQLite cache (fast, no network required)
  2. If cache miss or stale, query online NVD-compatible API
  3. Cache the fresh result for future lookups

References:
    - NIST. (2023). National Vulnerability Database APIs.
      https://nvd.nist.gov/developers
    - CVE Program. (2023). https://www.cve.org/
    - NIST. (2023). NVD CVE API 2.0.
      https://services.nvd.nist.gov/rest/json/cves/2.0
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from shared.network import PhantomHTTP, PhantomHTTPError

from nexus.core.database import CVEDatabase
from nexus.core.models import CVERecord

logger = logging.getLogger("nexus.collectors.cve_search")

# NVD API v2.0 base URL
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVESearchCollector:
    """Asynchronous CVE search collector with local caching.

    Provides online and offline CVE lookup capabilities with automatic
    caching in a local SQLite database. Supports single CVE lookup,
    batch queries, and keyword search.

    Attributes:
        db: CVEDatabase instance for local caching.
        http: PhantomHTTP client for online queries.

    Usage::

        db = CVEDatabase("nexus_cves.db")
        db.create_tables()

        async with CVESearchCollector(db=db) as collector:
            record = await collector.search_online("CVE-2021-44228")
            if record:
                print(f"{record.cve_id}: {record.cvss_score}")
    """

    # Rate limit for NVD API (unauthenticated: 5 req / 30 sec)
    NVD_RATE_LIMIT: float = 0.17  # ~1 request per 6 seconds

    def __init__(
        self,
        db: Optional[CVEDatabase] = None,
        http: Optional[PhantomHTTP] = None,
        api_key: Optional[str] = None,
    ) -> None:
        """Initialise the CVE search collector.

        Args:
            db: CVEDatabase for local caching. Created automatically
               if not provided.
            http: PhantomHTTP client. Created automatically if not provided.
            api_key: Optional NVD API key for higher rate limits.
        """
        self._owns_db = db is None
        self.db = db or CVEDatabase()

        self._owns_http = http is None
        self._http_instance = http
        self._http: Optional[PhantomHTTP] = None

        self.api_key = api_key

    async def __aenter__(self) -> CVESearchCollector:
        """Enter async context."""
        self.db.create_tables()

        if self._http_instance is not None:
            self._http = self._http_instance
        else:
            headers: dict[str, str] = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            self._http = PhantomHTTP(
                base_url=NVD_API_BASE,
                timeout=30.0,
                max_retries=3,
                cache_ttl=3600.0,
                headers=headers,
            )

        return self

    async def __aexit__(self, *exc: object) -> None:
        """Exit async context."""
        if self._owns_http and self._http is not None:
            await self._http.close()
        if self._owns_db:
            self.db.close()

    def _get_http(self) -> PhantomHTTP:
        """Get the HTTP client, raising if not initialised.

        Returns:
            The PhantomHTTP instance.

        Raises:
            RuntimeError: If called outside async context.
        """
        if self._http is None:
            raise RuntimeError(
                "CVESearchCollector must be used as an async context manager. "
                "Use 'async with CVESearchCollector(...) as collector:'"
            )
        return self._http

    # ================================================================== #
    #  Local Cache Search
    # ================================================================== #

    async def search_local(self, cve_id: str) -> Optional[CVERecord]:
        """Search for a CVE in the local SQLite cache.

        Returns the cached record if it exists and is within the
        cache TTL. Returns None if the record is not found or stale.

        Args:
            cve_id: CVE identifier (e.g. "CVE-2021-44228").

        Returns:
            Cached CVERecord or None.
        """
        cve_id = cve_id.upper().strip()

        # Check cache validity
        if not self.db.is_cache_valid(cve_id):
            return None

        return self.db.get_by_id(cve_id)

    # ================================================================== #
    #  Online Search
    # ================================================================== #

    async def search_online(self, cve_id: str) -> Optional[CVERecord]:
        """Search for a CVE via the NVD API and cache the result.

        Queries the NVD CVE API 2.0 for the specified CVE identifier,
        parses the response into a CVERecord, and stores it in the
        local SQLite database.

        Falls back to the local cache if the online query fails.

        Reference:
            NIST. (2023). NVD CVE API 2.0 Documentation.

        Args:
            cve_id: CVE identifier (e.g. "CVE-2021-44228").

        Returns:
            CVERecord if found, None if not found.
        """
        cve_id = cve_id.upper().strip()
        http = self._get_http()

        try:
            # NVD API 2.0: GET /rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX
            data = await http.fetch_json(
                "",
                params={"cveId": cve_id},
                use_cache=True,
            )

            record = self._parse_nvd_response(data, cve_id)
            if record is not None:
                self.db.insert_cve(record)
                logger.info(
                    "CVE %s fetched and cached successfully", cve_id
                )
                return record

            logger.warning("CVE %s not found in NVD response", cve_id)
            return None

        except PhantomHTTPError as exc:
            logger.warning(
                "Online search failed for %s: %s. "
                "Falling back to local cache.",
                cve_id, exc,
            )
            return self.db.get_by_id(cve_id)

        except Exception as exc:
            logger.error(
                "Unexpected error searching for %s: %s", cve_id, exc
            )
            return self.db.get_by_id(cve_id)

    # ================================================================== #
    #  Batch Search
    # ================================================================== #

    async def batch_search(
        self,
        cve_ids: list[str],
        prefer_online: bool = True,
    ) -> list[CVERecord]:
        """Search for multiple CVEs, combining local and online sources.

        For each CVE ID:
          1. Check local cache first
          2. If not found or stale and prefer_online is True, query online
          3. Collect all found records

        Respects NVD API rate limits by spacing online requests.

        Args:
            cve_ids: List of CVE identifiers.
            prefer_online: If True, query online for cache misses.

        Returns:
            List of found CVERecord instances (may be shorter than
            input if some CVEs are not found).
        """
        results: list[CVERecord] = []
        online_needed: list[str] = []

        # Phase 1: Check local cache
        for cve_id in cve_ids:
            cve_id = cve_id.upper().strip()
            local = await self.search_local(cve_id)
            if local is not None:
                results.append(local)
            else:
                online_needed.append(cve_id)

        # Phase 2: Query online for cache misses
        if prefer_online and online_needed:
            for cve_id in online_needed:
                try:
                    record = await self.search_online(cve_id)
                    if record is not None:
                        results.append(record)
                except Exception as exc:
                    logger.warning(
                        "Failed to fetch %s online: %s", cve_id, exc
                    )

                # Rate limiting between requests
                await asyncio.sleep(1.0 / max(self.NVD_RATE_LIMIT, 0.01))

        return results

    # ================================================================== #
    #  NVD Response Parsing
    # ================================================================== #

    def _parse_nvd_response(
        self,
        data: Any,
        cve_id: str,
    ) -> Optional[CVERecord]:
        """Parse a NVD API 2.0 JSON response into a CVERecord.

        Handles the nested NVD response structure:
          { "vulnerabilities": [{ "cve": { ... } }] }

        Reference:
            NIST. (2023). NVD CVE API 2.0 Response Schema.

        Args:
            data: Parsed JSON response from the NVD API.
            cve_id: Expected CVE identifier for validation.

        Returns:
            CVERecord if the response contains valid CVE data, None otherwise.
        """
        if not isinstance(data, dict):
            return None

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        # Find the matching vulnerability entry
        cve_data: Optional[dict[str, Any]] = None
        for vuln in vulnerabilities:
            cve_entry = vuln.get("cve", {})
            if cve_entry.get("id", "").upper() == cve_id:
                cve_data = cve_entry
                break

        if cve_data is None:
            # Use first entry if ID doesn't match exactly
            cve_data = vulnerabilities[0].get("cve", {})

        if not cve_data:
            return None

        # Extract description (prefer English)
        description = ""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang", "") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # Extract CVSS metrics
        cvss_score = 0.0
        cvss_vector = ""
        severity = "unknown"

        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2.0
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                primary = metric_list[0]
                cvss_data = primary.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = cvss_data.get("baseSeverity", "unknown").lower()
                break

        if cvss_score == 0.0:
            v2_metrics = metrics.get("cvssMetricV2", [])
            if v2_metrics:
                primary = v2_metrics[0]
                cvss_data = primary.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = primary.get("baseSeverity", "unknown").lower()

        # Extract CWE IDs
        cwe_ids: list[str] = []
        weaknesses = cve_data.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwe_ids.append(value)

        # Extract references
        references: list[str] = []
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        # Extract affected products (CPE)
        affected_products: list[str] = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if criteria:
                        affected_products.append(criteria)

        # Extract dates
        published = cve_data.get("published", "")
        modified = cve_data.get("lastModified", "")

        return CVERecord(
            cve_id=cve_data.get("id", cve_id).upper(),
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            published_date=published,
            modified_date=modified,
            references=references[:20],  # Limit to 20 references
            cwe_ids=cwe_ids,
            affected_products=affected_products[:50],  # Limit to 50 CPEs
        )

    # ================================================================== #
    #  Utility: Construct CVE Record from Minimal Data
    # ================================================================== #

    @staticmethod
    def create_manual_record(
        cve_id: str,
        description: str = "",
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        severity: str = "",
        cwe_ids: Optional[list[str]] = None,
    ) -> CVERecord:
        """Create a CVERecord from manually supplied data.

        Useful for creating records when online lookup is not available
        or for testing purposes.

        Args:
            cve_id: CVE identifier.
            description: Vulnerability description.
            cvss_score: CVSS base score.
            cvss_vector: CVSS vector string.
            severity: Qualitative severity.
            cwe_ids: Associated CWE identifiers.

        Returns:
            A CVERecord instance.
        """
        if not severity and cvss_score > 0:
            if cvss_score >= 9.0:
                severity = "critical"
            elif cvss_score >= 7.0:
                severity = "high"
            elif cvss_score >= 4.0:
                severity = "medium"
            else:
                severity = "low"

        return CVERecord(
            cve_id=cve_id.upper().strip(),
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity or "unknown",
            cwe_ids=cwe_ids or [],
        )
