"""
PhantomCore Async Network Client
==================================

Production-grade async HTTP client built on **httpx**, featuring:

- Automatic retry with exponential backoff and jitter.
- Response caching with configurable TTL (time-to-live).
- Circuit-breaker pattern to prevent cascading failures.
- Structured logging integration.

Design is informed by the following architectural patterns:

References:
    - Nygard, M. T. (2018). Release It!: Design and Deploy
      Production-Ready Software. 2nd ed. Pragmatic Bookshelf.
      Chapter 5: Stability Patterns (Circuit Breaker).
    - Fielding, R. T. (2000). Architectural Styles and the Design of
      Network-based Software Architectures. UC Irvine PhD Dissertation.
    - AWS Architecture Blog (2015). Exponential Backoff and Jitter.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx

logger = logging.getLogger("phantomcore.network")


# ========================== Circuit Breaker ================================


class CircuitState(str, Enum):
    """Three-state model for the circuit breaker.

    Reference:
        Nygard (2018), Release It!, Ch. 5 -- Circuit Breaker pattern.

    Attributes:
        CLOSED:    Normal operation; requests pass through.
        OPEN:      Failure threshold reached; requests are rejected.
        HALF_OPEN: Recovery probe in progress; one request allowed.
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass
class CircuitBreaker:
    """Lightweight circuit breaker protecting upstream services.

    When the consecutive failure count reaches *failure_threshold* the
    circuit **opens** and all subsequent calls fail fast for
    *recovery_timeout* seconds.  After the timeout the circuit enters
    **half-open** state and allows a single probe request through.

    Attributes:
        failure_threshold:  Number of consecutive failures before opening.
        recovery_timeout:   Seconds to wait before probing recovery.
        state:              Current circuit state.
        fail_count:         Consecutive failure counter.
        last_failure_time:  Monotonic epoch of the most recent failure.
    """

    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    state: CircuitState = CircuitState.CLOSED
    fail_count: int = 0
    last_failure_time: float = 0.0

    def record_success(self) -> None:
        """Record a successful request; reset the circuit to CLOSED."""
        self.fail_count = 0
        self.state = CircuitState.CLOSED

    def record_failure(self) -> None:
        """Record a failed request; open the circuit if threshold met."""
        self.fail_count += 1
        self.last_failure_time = time.monotonic()
        if self.fail_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(
                "Circuit breaker OPEN "
                "after %d consecutive failures",
                self.fail_count,
            )

    def allow_request(self) -> bool:
        """Determine whether the next request should be permitted.

        Returns:
            ``True`` if the request may proceed, ``False`` otherwise.
        """
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            elapsed = time.monotonic() - self.last_failure_time
            if elapsed >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                logger.info(
                    "Circuit breaker HALF_OPEN (probing)"
                )
                return True
            return False

        # HALF_OPEN: allow exactly one probe
        return True


# ========================== Response Cache =================================


@dataclass
class _CacheEntry:
    """Internal cache entry holding the response and its expiry epoch."""

    data: Any
    expires_at: float


@dataclass
class ResponseCache:
    """Simple in-memory dict-based response cache with TTL eviction.

    Cache keys are SHA-256 digests of ``method + url + sorted(params)``.

    Attributes:
        default_ttl: Default time-to-live in seconds for cached responses.
    """

    default_ttl: float = 300.0
    _store: dict[str, _CacheEntry] = field(default_factory=dict, repr=False)

    @staticmethod
    def _key(method: str, url: str, params: dict[str, Any] | None = None) -> str:
        """Produce a deterministic cache key from request components."""
        parts = f"{method.upper()}|{url}"
        if params:
            sorted_params = "&".join(
                f"{k}={v}" for k, v in sorted(params.items())
            )
            parts += f"|{sorted_params}"
        return hashlib.sha256(parts.encode()).hexdigest()

    def get(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> Any | None:
        """Retrieve a cached response, or ``None`` if absent / expired."""
        key = self._key(method, url, params)
        entry = self._store.get(key)
        if entry is None:
            return None
        if time.monotonic() > entry.expires_at:
            del self._store[key]
            return None
        return entry.data

    def put(
        self,
        method: str,
        url: str,
        data: Any,
        params: dict[str, Any] | None = None,
        ttl: float | None = None,
    ) -> None:
        """Store a response in the cache."""
        key = self._key(method, url, params)
        self._store[key] = _CacheEntry(
            data=data,
            expires_at=time.monotonic() + (ttl if ttl is not None else self.default_ttl),
        )

    def invalidate(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> None:
        """Remove a specific cache entry."""
        key = self._key(method, url, params)
        self._store.pop(key, None)

    def clear(self) -> None:
        """Drop all cached entries."""
        self._store.clear()

    def prune_expired(self) -> int:
        """Remove all expired entries and return the count pruned."""
        now = time.monotonic()
        expired = [k for k, v in self._store.items() if now > v.expires_at]
        for k in expired:
            del self._store[k]
        return len(expired)


# ========================== Exception ======================================


class PhantomHTTPError(Exception):
    """Custom exception for PhantomCore HTTP operations.

    Wraps transport errors, timeout errors, and retryable HTTP status
    failures into a single exception hierarchy.
    """

    pass


# ========================== HTTP Client ====================================


class PhantomHTTP:
    """Async HTTP client with retry, caching, and circuit-breaker support.

    Usage::

        async with PhantomHTTP(base_url="https://api.example.com") as http:
            data = await http.fetch_json("/v1/endpoint", params={"q": "test"})

    Args:
        base_url:               Base URL prepended to all relative paths.
        timeout:                Request timeout in seconds.
        max_retries:            Maximum retry attempts on transient errors.
        backoff_base:           Base delay (seconds) for exponential backoff.
        backoff_max:            Maximum delay cap (seconds).
        cache_ttl:              Default cache TTL in seconds (0 disables caching).
        cb_failure_threshold:   Circuit-breaker failure threshold.
        cb_recovery_timeout:    Circuit-breaker recovery timeout (seconds).
        headers:                Default HTTP headers merged into every request.
        user_agent:             User-Agent header value.
    """

    # HTTP status codes eligible for retry (transient server errors + rate limit)
    _RETRYABLE_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})

    def __init__(
        self,
        *,
        base_url: str = "",
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_base: float = 1.0,
        backoff_max: float = 60.0,
        cache_ttl: float = 300.0,
        cb_failure_threshold: int = 5,
        cb_recovery_timeout: float = 30.0,
        headers: dict[str, str] | None = None,
        user_agent: str = "PhantomCore/1.0 (Educational Toolkit)",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max

        default_headers = {"User-Agent": user_agent}
        if headers:
            default_headers.update(headers)

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout),
            headers=default_headers,
            follow_redirects=True,
        )
        self._cache = ResponseCache(default_ttl=cache_ttl)
        self._breaker = CircuitBreaker(
            failure_threshold=cb_failure_threshold,
            recovery_timeout=cb_recovery_timeout,
        )

    # ------------------------------------------------------------------ #
    #  Async context manager
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> PhantomHTTP:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Gracefully close the underlying httpx client."""
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    #  Core fetch
    # ------------------------------------------------------------------ #

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        use_cache: bool = True,
        cache_ttl: float | None = None,
    ) -> httpx.Response:
        """Execute an HTTP request with retry, caching, and circuit-breaker.

        Args:
            url:        URL path (relative to *base_url*) or absolute URL.
            method:     HTTP method (GET, POST, PUT, PATCH, DELETE).
            params:     Query-string parameters.
            json_body:  JSON body for POST/PUT/PATCH requests.
            headers:    Per-request headers (merged with defaults).
            use_cache:  Whether to consult / populate the response cache.
            cache_ttl:  Override the default cache TTL for this request.

        Returns:
            :class:`httpx.Response` on success.

        Raises:
            PhantomHTTPError: On exhausted retries or open circuit breaker.
        """
        # -- Check cache (GET only) --
        if use_cache and method.upper() == "GET":
            cached = self._cache.get(method, url, params)
            if cached is not None:
                logger.debug("Cache HIT for %s %s", method, url)
                return cached

        # -- Circuit breaker gate --
        if not self._breaker.allow_request():
            raise PhantomHTTPError(
                f"Circuit breaker OPEN -- "
                f"requests to {url} are blocked"
            )

        # -- Retry loop with exponential backoff + full jitter --
        last_exc: BaseException | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = await self._client.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    json=json_body,
                    headers=headers,
                )

                # Retryable HTTP status code
                if response.status_code in self._RETRYABLE_STATUS:
                    logger.warning(
                        "HTTP %d on %s %s (attempt %d/%d)",
                        response.status_code,
                        method,
                        url,
                        attempt + 1,
                        self._max_retries + 1,
                    )
                    last_exc = PhantomHTTPError(
                        f"HTTP {response.status_code} from {url}"
                    )
                    if attempt < self._max_retries:
                        await self._backoff(attempt)
                        continue
                    # Final attempt still retryable -> record failure
                    self._breaker.record_failure()
                    raise last_exc

                # Non-retryable HTTP error
                response.raise_for_status()

                # -- Success --
                self._breaker.record_success()
                if use_cache and method.upper() == "GET":
                    self._cache.put(method, url, response, params, cache_ttl)
                return response

            except httpx.HTTPStatusError as exc:
                self._breaker.record_failure()
                raise PhantomHTTPError(str(exc)) from exc

            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_exc = exc
                logger.warning(
                    "Transport error on %s %s "
                    "(attempt %d/%d): %s",
                    method,
                    url,
                    attempt + 1,
                    self._max_retries + 1,
                    exc,
                )
                if attempt < self._max_retries:
                    await self._backoff(attempt)
                else:
                    self._breaker.record_failure()
                    raise PhantomHTTPError(
                        f"All "
                        f"{self._max_retries + 1} attempts exhausted "
                        f"for {url}"
                    ) from exc

        # Should not be reached; satisfies type checker
        assert last_exc is not None
        raise PhantomHTTPError(str(last_exc))

    async def fetch_json(
        self,
        url: str,
        *,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        use_cache: bool = True,
        cache_ttl: float | None = None,
    ) -> Any:
        """Convenience wrapper that returns parsed JSON from the response.

        Args:
            (Same as :meth:`fetch`.)

        Returns:
            Parsed JSON (usually a dict or list).

        Raises:
            PhantomHTTPError: On HTTP or JSON-decoding failure.
        """
        response = await self.fetch(
            url,
            method=method,
            params=params,
            json_body=json_body,
            headers=headers,
            use_cache=use_cache,
            cache_ttl=cache_ttl,
        )
        try:
            return response.json()
        except Exception as exc:
            raise PhantomHTTPError(
                f"JSON decode error from {url}"
            ) from exc

    # ------------------------------------------------------------------ #
    #  Public accessors
    # ------------------------------------------------------------------ #

    @property
    def cache(self) -> ResponseCache:
        """Direct access to the response cache."""
        return self._cache

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        """Direct access to the circuit breaker."""
        return self._breaker

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    async def _backoff(self, attempt: int) -> None:
        """Sleep with exponential backoff and full jitter.

        .. math::

            \\text{delay} = \\min(\\text{max}, \\text{base} \\cdot 2^{\\text{attempt}})
                            \\times \\text{random}(0, 1)

        Reference:
            AWS Architecture Blog (2015). Exponential Backoff and Jitter.
        """
        base_delay = min(
            self._backoff_max, self._backoff_base * (2 ** attempt)
        )
        jittered = base_delay * random.random()
        logger.debug(
            "Backing off %.2fs (attempt %d)", jittered, attempt + 1
        )
        await asyncio.sleep(jittered)
