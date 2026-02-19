"""
Nexus CVE Database
===================

SQLite3-backed storage for CVE records with FTS5 (Full-Text Search)
support for efficient vulnerability querying. Provides caching with
configurable TTL to reduce redundant API calls.

The database schema uses SQLite's FTS5 extension for high-performance
text search across CVE descriptions, identifiers, and affected products.
FTS5 implements the BM25 ranking function by default, producing relevance-
ranked search results.

References:
    - SQLite FTS5 Extension Documentation.
      https://www.sqlite.org/fts5.html
    - Robertson, S., & Zaragoza, H. (2009). The Probabilistic Relevance
      Framework: BM25 and Beyond. Foundations and Trends in Information
      Retrieval, 3(4), 333-389.
    - NIST. (2023). National Vulnerability Database.
      https://nvd.nist.gov/
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

from nexus.core.models import CVERecord


class CVEDatabase:
    """SQLite3 CVE database with FTS5 full-text search.

    Manages a local cache of CVE records with full-text indexing
    for fast vulnerability lookup and search operations. Supports
    cache TTL checking to determine when records need refreshing
    from upstream sources.

    Attributes:
        db_path: Filesystem path to the SQLite database file.
        cache_ttl: Cache time-to-live in seconds (default 86400 = 24h).

    Usage::

        db = CVEDatabase("/path/to/cves.db")
        db.create_tables()
        db.insert_cve(cve_record)
        results = db.search("remote code execution")
    """

    # Default cache TTL: 24 hours
    DEFAULT_CACHE_TTL: int = 86400

    def __init__(
        self,
        db_path: str | Path = "nexus_cves.db",
        cache_ttl: int = DEFAULT_CACHE_TTL,
    ) -> None:
        """Initialise the CVE database.

        Args:
            db_path: Path to the SQLite database file. Created if absent.
            cache_ttl: Cache time-to-live in seconds. Records older than
                       this are considered stale.
        """
        self.db_path = Path(db_path)
        self.cache_ttl = cache_ttl
        self._connection: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------ #
    #  Connection management
    # ------------------------------------------------------------------ #

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create the SQLite connection.

        Returns:
            An active sqlite3.Connection with WAL mode and foreign keys
            enabled for performance and data integrity.
        """
        if self._connection is None:
            self._connection = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
        return self._connection

    def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    # ------------------------------------------------------------------ #
    #  Schema creation
    # ------------------------------------------------------------------ #

    def create_tables(self) -> None:
        """Create the CVE table and FTS5 virtual table if they do not exist.

        The schema includes:
          - ``cves``: Main table storing full CVE record data.
          - ``cves_fts``: FTS5 content-sync table indexing cve_id,
            description, and affected_products for text search.

        The FTS5 table uses a content-sync approach (content=cves)
        to avoid data duplication while enabling BM25-ranked search.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Main CVE table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id            TEXT PRIMARY KEY,
                description       TEXT NOT NULL DEFAULT '',
                cvss_score        REAL NOT NULL DEFAULT 0.0,
                cvss_vector       TEXT NOT NULL DEFAULT '',
                severity          TEXT NOT NULL DEFAULT 'unknown',
                published         TEXT,
                modified          TEXT,
                references_json   TEXT NOT NULL DEFAULT '[]',
                cwe_ids           TEXT NOT NULL DEFAULT '[]',
                affected_products TEXT NOT NULL DEFAULT '[]',
                exploit_prob      REAL NOT NULL DEFAULT 0.0,
                has_public_exploit INTEGER NOT NULL DEFAULT 0,
                is_actively_exploited INTEGER NOT NULL DEFAULT 0,
                cached_at         REAL NOT NULL DEFAULT 0.0
            )
        """)

        # FTS5 full-text search virtual table
        # Using content= to sync with the main cves table
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
                cve_id,
                description,
                affected_products,
                content=cves,
                content_rowid=rowid
            )
        """)

        # Triggers to keep FTS5 in sync with main table
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
                INSERT INTO cves_fts(rowid, cve_id, description, affected_products)
                VALUES (new.rowid, new.cve_id, new.description, new.affected_products);
            END
        """)

        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS cves_ad AFTER DELETE ON cves BEGIN
                INSERT INTO cves_fts(cves_fts, rowid, cve_id, description, affected_products)
                VALUES ('delete', old.rowid, old.cve_id, old.description, old.affected_products);
            END
        """)

        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
                INSERT INTO cves_fts(cves_fts, rowid, cve_id, description, affected_products)
                VALUES ('delete', old.rowid, old.cve_id, old.description, old.affected_products);
                INSERT INTO cves_fts(rowid, cve_id, description, affected_products)
                VALUES (new.rowid, new.cve_id, new.description, new.affected_products);
            END
        """)

        # Index on severity for filtered queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity)
        """)

        # Index on cached_at for TTL checks
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cves_cached_at ON cves(cached_at)
        """)

        conn.commit()

    # ------------------------------------------------------------------ #
    #  Insert / Upsert
    # ------------------------------------------------------------------ #

    def insert_cve(self, record: CVERecord) -> None:
        """Insert or update a CVE record in the database.

        Uses SQLite's INSERT OR REPLACE (upsert) to handle both new
        records and updates to existing entries. The cache timestamp
        is set to the current time.

        Args:
            record: The CVERecord to persist.
        """
        conn = self._get_connection()
        conn.execute(
            """
            INSERT OR REPLACE INTO cves
                (cve_id, description, cvss_score, cvss_vector, severity,
                 published, modified, references_json, cwe_ids,
                 affected_products, exploit_prob, has_public_exploit,
                 is_actively_exploited, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.cve_id,
                record.description,
                record.cvss_score,
                record.cvss_vector,
                record.severity,
                record.published_date,
                record.modified_date,
                json.dumps(record.references),
                json.dumps(record.cwe_ids),
                json.dumps(record.affected_products),
                record.exploit_probability,
                int(record.has_public_exploit),
                int(record.is_actively_exploited),
                time.time(),
            ),
        )
        conn.commit()

    def insert_many(self, records: list[CVERecord]) -> None:
        """Bulk-insert multiple CVE records.

        Uses a single transaction for performance when inserting
        large batches of records.

        Args:
            records: List of CVERecord instances to persist.
        """
        conn = self._get_connection()
        now = time.time()
        rows = [
            (
                r.cve_id, r.description, r.cvss_score, r.cvss_vector,
                r.severity, r.published_date, r.modified_date,
                json.dumps(r.references), json.dumps(r.cwe_ids),
                json.dumps(r.affected_products), r.exploit_probability,
                int(r.has_public_exploit), int(r.is_actively_exploited), now,
            )
            for r in records
        ]
        conn.executemany(
            """
            INSERT OR REPLACE INTO cves
                (cve_id, description, cvss_score, cvss_vector, severity,
                 published, modified, references_json, cwe_ids,
                 affected_products, exploit_prob, has_public_exploit,
                 is_actively_exploited, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()

    # ------------------------------------------------------------------ #
    #  Retrieval
    # ------------------------------------------------------------------ #

    def _row_to_record(self, row: sqlite3.Row) -> CVERecord:
        """Convert a database row to a CVERecord model instance.

        Args:
            row: A sqlite3.Row from a query result.

        Returns:
            A populated CVERecord.
        """
        return CVERecord(
            cve_id=row["cve_id"],
            description=row["description"],
            cvss_score=row["cvss_score"],
            cvss_vector=row["cvss_vector"],
            severity=row["severity"],
            published_date=row["published"],
            modified_date=row["modified"],
            references=json.loads(row["references_json"]),
            cwe_ids=json.loads(row["cwe_ids"]),
            affected_products=json.loads(row["affected_products"]),
            exploit_probability=row["exploit_prob"],
            has_public_exploit=bool(row["has_public_exploit"]),
            is_actively_exploited=bool(row["is_actively_exploited"]),
        )

    def get_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """Retrieve a CVE record by its identifier.

        Args:
            cve_id: CVE identifier (e.g. "CVE-2021-44228").

        Returns:
            The matching CVERecord, or None if not found.
        """
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM cves WHERE cve_id = ?",
            (cve_id.upper(),),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def search(self, query: str, limit: int = 50) -> list[CVERecord]:
        """Full-text search across CVE records using FTS5 BM25 ranking.

        Searches cve_id, description, and affected_products fields.
        Results are ranked by BM25 relevance score.

        Reference:
            Robertson, S., & Zaragoza, H. (2009). The Probabilistic
            Relevance Framework: BM25 and Beyond.

        Args:
            query: Search query string (supports FTS5 query syntax).
            limit: Maximum number of results to return.

        Returns:
            List of matching CVERecord instances, ranked by relevance.
        """
        conn = self._get_connection()

        # Sanitise query for FTS5: wrap terms in quotes if they contain
        # special characters that are not FTS5 operators
        safe_query = query.strip()
        if not safe_query:
            return []

        try:
            cursor = conn.execute(
                """
                SELECT cves.*
                FROM cves_fts
                JOIN cves ON cves.cve_id = cves_fts.cve_id
                WHERE cves_fts MATCH ?
                ORDER BY rank
                LIMIT ?
                """,
                (safe_query, limit),
            )
            rows = cursor.fetchall()
        except sqlite3.OperationalError:
            # If FTS5 query syntax fails, fall back to LIKE search
            like_pattern = f"%{safe_query}%"
            cursor = conn.execute(
                """
                SELECT * FROM cves
                WHERE cve_id LIKE ? OR description LIKE ?
                   OR affected_products LIKE ?
                ORDER BY cvss_score DESC
                LIMIT ?
                """,
                (like_pattern, like_pattern, like_pattern, limit),
            )
            rows = cursor.fetchall()

        return [self._row_to_record(row) for row in rows]

    def get_by_cwe(self, cwe_id: str, limit: int = 50) -> list[CVERecord]:
        """Retrieve CVE records associated with a specific CWE.

        Args:
            cwe_id: CWE identifier (e.g. "CWE-79").
            limit: Maximum results to return.

        Returns:
            List of matching CVERecord instances.
        """
        conn = self._get_connection()
        like_pattern = f"%{cwe_id}%"
        cursor = conn.execute(
            """
            SELECT * FROM cves
            WHERE cwe_ids LIKE ?
            ORDER BY cvss_score DESC
            LIMIT ?
            """,
            (like_pattern, limit),
        )
        return [self._row_to_record(row) for row in cursor.fetchall()]

    def get_by_product(self, product: str, limit: int = 50) -> list[CVERecord]:
        """Retrieve CVE records affecting a specific product.

        Args:
            product: Product name or CPE substring to search for.
            limit: Maximum results to return.

        Returns:
            List of matching CVERecord instances.
        """
        conn = self._get_connection()
        like_pattern = f"%{product}%"
        cursor = conn.execute(
            """
            SELECT * FROM cves
            WHERE affected_products LIKE ?
            ORDER BY cvss_score DESC
            LIMIT ?
            """,
            (like_pattern, limit),
        )
        return [self._row_to_record(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------ #
    #  Cache TTL management
    # ------------------------------------------------------------------ #

    def is_cache_valid(self, cve_id: str) -> bool:
        """Check whether a cached CVE record is still within its TTL.

        Args:
            cve_id: CVE identifier to check.

        Returns:
            True if the record exists and was cached within the TTL window.
        """
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT cached_at FROM cves WHERE cve_id = ?",
            (cve_id.upper(),),
        )
        row = cursor.fetchone()
        if row is None:
            return False

        age = time.time() - row["cached_at"]
        return age < self.cache_ttl

    def get_stale_records(self, limit: int = 100) -> list[str]:
        """Get CVE IDs of records that have exceeded the cache TTL.

        Useful for batch-refreshing stale entries from upstream sources.

        Args:
            limit: Maximum number of stale IDs to return.

        Returns:
            List of CVE ID strings that need refreshing.
        """
        conn = self._get_connection()
        cutoff = time.time() - self.cache_ttl
        cursor = conn.execute(
            """
            SELECT cve_id FROM cves
            WHERE cached_at < ?
            ORDER BY cached_at ASC
            LIMIT ?
            """,
            (cutoff, limit),
        )
        return [row["cve_id"] for row in cursor.fetchall()]

    def get_record_count(self) -> int:
        """Return the total number of CVE records in the database.

        Returns:
            Integer count of records.
        """
        conn = self._get_connection()
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM cves")
        row = cursor.fetchone()
        return row["cnt"] if row else 0
