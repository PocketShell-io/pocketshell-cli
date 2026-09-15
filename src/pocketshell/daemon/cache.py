"""Per-method TTL result cache for daemon RPC handlers."""
from __future__ import annotations
import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional


# Per-method TTL table. Add new methods here; consumers should NOT
# special-case TTL outside this map so the cache policy stays auditable
# in one place.
METHOD_TTLS: Mapping[str, float] = {
    "usage.fetch": 30.0,
    # `repos.list_local` is cheap-to-recompute but the Android picker may
    # poll it repeatedly while the user types; a short cache keeps the
    # filesystem walk off the hot path without showing stale state for
    # more than a couple of seconds.
    "repos.list_local": 10.0,
    # `repos.list_remote` hits the GitHub REST API (5000 req/hour for
    # authenticated calls) so we cache for 5 min. Remote repositories
    # rarely change minute-to-minute; the longer window keeps the
    # Android picker fast without burning rate-limit quota.
    "repos.list_remote": 300.0,
    # Session lists are cheap, but Android may poll them from dashboards.
    # Keep the window short so external session changes are not hidden for
    # long.
    "sessions.list": 5.0,
    # `tree.get` is the cold-start hydrate read. Short TTL like `sessions.list`
    # so a `tree.upsert` mutation (which also invalidates it explicitly) is not
    # masked for long and an external edit is not hidden. `tree.upsert` and
    # `tree.reconcile` carry NO TTL (mutations) so their results are never
    # cached.
    "tree.get": 5.0,
    # Issue #1715: the file-workspace hydrate read. Short TTL like `tree.get`
    # so a `tree.workspace.upsert` mutation is not masked; the mutation itself
    # carries no TTL and invalidates this cache explicitly.
    "tree.workspace.get": 5.0,
}


@dataclass(frozen=True)
class _CacheKey:
    """Hashable cache key derived from ``(method, params)``.

    JSON params are normalised by ``json.dumps(..., sort_keys=True)``
    so semantically-equal param dicts collapse to one entry even when
    the client sends keys in a different order.
    """

    method: str
    params_json: str

    @classmethod
    def of(cls, method: str, params: Optional[Mapping[str, Any]]) -> "_CacheKey":
        # ``no_cache`` is a control flag, not a parameter that affects
        # the upstream call. Strip it before keying so a no-cache miss
        # still populates the same slot a subsequent cached call uses.
        params_filtered = {
            k: v for k, v in (params or {}).items() if k != "no_cache"
        }
        return cls(
            method=method,
            params_json=json.dumps(params_filtered, sort_keys=True),
        )


class _Cache:
    """In-memory ``(method, params) -> (expires_at, value)`` cache.

    Per-method TTL is consulted via :data:`METHOD_TTLS`. Failures are
    never cached: only the handler decides what to put here, and the
    handler only stores success responses.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[_CacheKey, tuple[float, Any]] = {}

    def get(self, key: _CacheKey) -> Optional[Any]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if self._clock() >= expires_at:
                # Lazy eviction: drop the stale entry so the dict does
                # not grow unbounded over the daemon's life.
                self._entries.pop(key, None)
                return None
            return value

    def put(self, key: _CacheKey, value: Any, ttl_secs: float) -> None:
        if ttl_secs <= 0:
            return
        expires_at = self._clock() + ttl_secs
        with self._lock:
            self._entries[key] = (expires_at, value)

    def invalidate_method(self, method: str) -> int:
        """Drop every cache entry for ``method``, regardless of params.

        Used after a side-effecting call (e.g. ``repos.clone``) so the
        next read of an affected method (``repos.list_local``) recomputes
        rather than serving a now-stale cached scan. Returns the number of
        entries evicted (handy for tests asserting the invalidation fired).
        """
        with self._lock:
            stale = [key for key in self._entries if key.method == method]
            for key in stale:
                self._entries.pop(key, None)
            return len(stale)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
