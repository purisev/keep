"""
Process-local TTL cache for resolved resource permissions.

Why this exists
---------------
resolve_allowed_resource_ids() runs on every request to a protected route, and
the UI polls: the alerts table and the incident list refetch every ~6 seconds
and the preset counters every 5. For a role that has rules, each of those
requests means either one CEL query per rule (incidents, up to
KEEP_RESOURCE_PERMISSIONS_MAX_SCAN rows materialised into a list of IDs) or a
scan of the tenant's presets plus matching in Python. The answer is identical
across all of them, because it depends on nothing that varies per request.

The cache key is (tenant_id, role, resource_type) -- not the token and not the
user. Rules come from configuration and the role comes from the token, so every
user holding the same role in the same tenant shares one entry.

Staleness
---------
The entry is bounded by a TTL and nothing else. Cross-process invalidation is
not available: REDIS is optional in Keep (keep/api/consts.py, default false) and
the API runs under `gunicorn --workers 4`, so each worker holds its own cache
and incidents are created by the alert pipeline in yet other processes (ARQ).
invalidate() exists for the preset write path, but it only reaches the worker
that handled the write -- it shortens the window, it does not bound it. The TTL
is the guarantee.

KEEP_RESOURCE_PERMISSIONS_CACHE_TTL sets it, in seconds. 0 disables the cache
entirely, which is the escape hatch for a deployment that cannot accept any
staleness in what a restricted role sees.
"""

import logging
import os
import threading
import time
from typing import Callable

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 15
# One incidents entry can hold up to KEEP_RESOURCE_PERMISSIONS_MAX_SCAN ids
# (10000 by default, a few hundred KB), and there is one entry per role per
# resource type per worker, so the cap is not cosmetic.
MAX_ENTRIES = 256

CacheKey = tuple[str, str, str]

# Mirrors oidc_permissions.RESOURCE_TYPE_PRESET, spelled out rather than
# imported: keep/api/routes/preset.py calls invalidate_presets() for every auth
# type, and importing oidc_permissions there would run its import-time
# _load_rules() -- which deliberately aborts on a malformed rule set -- in
# deployments that do not use OIDC at all. This module stays stdlib-only on
# purpose. tests/test_oidc_permission_cache.py asserts the two agree.
RESOURCE_TYPE_PRESET = "preset"

# key -> (expires_at_monotonic, resolved_ids)
_CACHE: dict[CacheKey, tuple[float, list[str]]] = {}
_LOCK = threading.Lock()
# Rule-set generation the cached entries were resolved against; see
# oidc_permissions.rules_version().
_VERSION: int = -1


def ttl_seconds() -> int:
    """
    TTL from the environment; 0 means the cache is disabled.

    Shaped like _max_scan() in oidc_resource_resolver.py on purpose, so the two
    knobs of this feature read the same way.
    """
    raw = os.environ.get("KEEP_RESOURCE_PERMISSIONS_CACHE_TTL", "").strip()
    if not raw:
        return DEFAULT_TTL_SECONDS
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "Invalid KEEP_RESOURCE_PERMISSIONS_CACHE_TTL %r, using %s",
            raw,
            DEFAULT_TTL_SECONDS,
        )
        return DEFAULT_TTL_SECONDS
    if value < 0:
        logger.warning(
            "Negative KEEP_RESOURCE_PERMISSIONS_CACHE_TTL %r, using %s",
            raw,
            DEFAULT_TTL_SECONDS,
        )
        return DEFAULT_TTL_SECONDS
    return value


def _evict_if_needed(now: float) -> None:
    """Drop expired entries, and if that was not enough, the soonest to expire.

    Caller holds _LOCK.
    """
    if len(_CACHE) < MAX_ENTRIES:
        return
    for key in [key for key, (expires_at, _) in _CACHE.items() if expires_at <= now]:
        _CACHE.pop(key, None)
    while len(_CACHE) >= MAX_ENTRIES:
        oldest = min(_CACHE, key=lambda key: _CACHE[key][0])
        _CACHE.pop(oldest, None)


def get_or_compute(
    key: CacheKey, compute: Callable[[], list[str]], version: int = 0
) -> tuple[list[str], bool]:
    """
    Return (ids, cached). `compute` runs on a miss and its result is stored.

    `version` is the rule-set generation the answer depends on. When it moves,
    every entry is dropped: an entry resolved against a rule set that no longer
    exists is not stale data, it is the wrong authorization answer. The caller
    passes it (rather than this module reading it) to keep this module free of
    the oidc_permissions import -- see RESOURCE_TYPE_PRESET above.

    Two properties this must preserve, both of them load-bearing for the
    fail-open contract documented in oidc_resource_resolver.py:

    * An exception from `compute` propagates and nothing is written. A cached
      failure -- or a stale entry served on failure -- would be a silent
      authorization decision made from data nobody checked.
    * Whatever `compute` returns is stored verbatim, [DENY_ALL_SENTINEL_ID]
      included: "restricted but matching nothing" is a real answer, not a miss.

    `compute` runs outside the lock. A slow CEL query for one role must not
    block every other role, and the worst case of the resulting race is that
    two threads resolve the same key at once and one overwrites the other with
    an equivalent value.
    """
    ttl = ttl_seconds()
    if ttl == 0:
        return compute(), False

    now = time.monotonic()
    with _LOCK:
        global _VERSION
        if version != _VERSION:
            _CACHE.clear()
            _VERSION = version
        entry = _CACHE.get(key)
        if entry is not None and entry[0] > now:
            return list(entry[1]), True

    ids = compute()

    with _LOCK:
        # Another thread may have bumped the rule set while `compute` ran; that
        # answer belongs to the older generation, so drop it rather than store it.
        if version != _VERSION:
            return ids, False
        _evict_if_needed(time.monotonic())
        _CACHE[key] = (time.monotonic() + ttl, list(ids))
    return ids, False


def invalidate(tenant_id: str, resource_type: str) -> None:
    """
    Drop this tenant's entries for one resource type, across all roles.

    Best-effort by construction: it only affects the calling process. See the
    module docstring.
    """
    with _LOCK:
        for key in [
            key for key in _CACHE if key[0] == tenant_id and key[2] == resource_type
        ]:
            _CACHE.pop(key, None)


def invalidate_presets(tenant_id: str) -> None:
    """
    Called from the preset write routes for every auth type; a no-op unless the
    OIDC resolver has populated the cache in this process.
    """
    invalidate(tenant_id, RESOURCE_TYPE_PRESET)


def clear() -> None:
    """Drop everything. Used by the test suite between tests."""
    global _VERSION
    with _LOCK:
        _CACHE.clear()
        _VERSION = -1
