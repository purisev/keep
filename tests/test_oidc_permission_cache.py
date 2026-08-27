"""
Unit tests for the resource-permission TTL cache.

Database-free: the two expensive resolution paths (`get_last_incidents_by_cel`
for incidents, `_fetch_preset_records` for presets) are replaced with counting
stubs, which is exactly what these tests are about -- how many times the
expensive thing runs, and when a cached answer is or is not served.

What the resolution itself produces is covered by tests/test_oidc_permissions.py
and tests/test_oidc_resource_resolver.py.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keep.identitymanager import rbac  # noqa: E402
from keep.identitymanager.identity_managers.oidc import (  # noqa: E402
    oidc_permission_cache,
    oidc_permissions,
    oidc_resource_resolver,
)
from keep.identitymanager.identity_managers.oidc.oidc_permissions import (  # noqa: E402
    DENY_ALL_SENTINEL_ID,
)
from keep.identitymanager.identity_managers.oidc.oidc_resource_resolver import (  # noqa: E402
    resolve_allowed_resource_ids,
)

TENANT = "keep"
OTHER_TENANT = "keep2"


class _Incident:
    """Minimal stand-in: the resolver only reads `.id`."""

    def __init__(self, incident_id):
        self.id = incident_id


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    """
    Fresh rule registry, fresh cache, default TTL, for every test.

    The registry is mutated in place rather than reloaded: the resolver binds
    get_rules_for/apply_rules at import time, so a reloaded module would not be
    the one under test (same reasoning as tests/test_oidc_resource_resolver.py).
    """
    monkeypatch.delenv("KEEP_RESOURCE_PERMISSIONS_CACHE_TTL", raising=False)
    saved_rules = dict(oidc_permissions._RULE_REGISTRY)
    oidc_permissions._RULE_REGISTRY.clear()
    oidc_permission_cache.clear()

    created_roles = []
    for name in ("dba", "payments-oncall"):
        if name not in rbac.get_all_roles():
            rbac.register_role(name, ["read:*"], "test role")
            created_roles.append(name)

    yield

    oidc_permissions._RULE_REGISTRY.clear()
    oidc_permissions._RULE_REGISTRY.update(saved_rules)
    oidc_permission_cache.clear()
    for name in created_roles:
        rbac._ROLE_REGISTRY.pop(name, None)


def install_rule(**definition):
    oidc_permissions.register_rule(oidc_permissions.build_rule(definition))


@pytest.fixture
def incident_calls(monkeypatch):
    """Replace the CEL query with a counting stub; returns the call log."""
    calls = []

    def fake_query(tenant_id, cel, limit, offset):
        calls.append((tenant_id, cel))
        return [_Incident(f"incident-{len(calls)}")], 1

    monkeypatch.setattr(oidc_resource_resolver, "get_last_incidents_by_cel", fake_query)
    return calls


@pytest.fixture
def preset_calls(monkeypatch):
    calls = []

    def fake_fetch(tenant_id, limit):
        calls.append(tenant_id)
        return [{"id": "preset-1", "name": "payments", "tag": [], "created_by": "x"}]

    monkeypatch.setitem(
        oidc_resource_resolver._FETCHERS,
        oidc_permissions.RESOURCE_TYPE_PRESET,
        fake_fetch,
    )
    return calls


# --------------------------------------------------------------------------- #
# Hits and misses
# --------------------------------------------------------------------------- #


def test_second_call_is_served_from_cache(incident_calls):
    install_rule(role="dba", resource_type="incident", cel="service in ['postgres']")

    first = resolve_allowed_resource_ids(TENANT, "dba", "incident")
    second = resolve_allowed_resource_ids(TENANT, "dba", "incident")

    assert first == second
    assert len(incident_calls) == 1, "the CEL query ran twice"


def test_entry_expires_after_ttl(monkeypatch, incident_calls):
    install_rule(role="dba", resource_type="incident", cel="service in ['postgres']")

    clock = {"now": 1000.0}
    monkeypatch.setattr(oidc_permission_cache.time, "monotonic", lambda: clock["now"])

    resolve_allowed_resource_ids(TENANT, "dba", "incident")
    clock["now"] += oidc_permission_cache.DEFAULT_TTL_SECONDS - 1
    resolve_allowed_resource_ids(TENANT, "dba", "incident")
    assert len(incident_calls) == 1, "expired early"

    clock["now"] += 2
    resolve_allowed_resource_ids(TENANT, "dba", "incident")
    assert len(incident_calls) == 2, "did not expire"


def test_ttl_zero_disables_the_cache(monkeypatch, incident_calls):
    monkeypatch.setenv("KEEP_RESOURCE_PERMISSIONS_CACHE_TTL", "0")
    install_rule(role="dba", resource_type="incident", cel="service in ['postgres']")

    resolve_allowed_resource_ids(TENANT, "dba", "incident")
    resolve_allowed_resource_ids(TENANT, "dba", "incident")

    assert len(incident_calls) == 2
    assert not oidc_permission_cache._CACHE


def test_invalid_ttl_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv("KEEP_RESOURCE_PERMISSIONS_CACHE_TTL", "not-a-number")
    assert oidc_permission_cache.ttl_seconds() == (
        oidc_permission_cache.DEFAULT_TTL_SECONDS
    )
    monkeypatch.setenv("KEEP_RESOURCE_PERMISSIONS_CACHE_TTL", "-5")
    assert oidc_permission_cache.ttl_seconds() == (
        oidc_permission_cache.DEFAULT_TTL_SECONDS
    )


# --------------------------------------------------------------------------- #
# Key isolation
# --------------------------------------------------------------------------- #


def test_roles_tenants_and_resource_types_do_not_share_entries(
    incident_calls, preset_calls
):
    install_rule(role="dba", resource_type="incident", cel="service in ['postgres']")
    install_rule(
        role="payments-oncall", resource_type="incident", cel="service in ['payments']"
    )
    install_rule(role="dba", resource_type="preset", match={"name": ["payments"]})

    resolve_allowed_resource_ids(TENANT, "dba", "incident")
    resolve_allowed_resource_ids(TENANT, "payments-oncall", "incident")
    resolve_allowed_resource_ids(OTHER_TENANT, "dba", "incident")
    resolve_allowed_resource_ids(TENANT, "dba", "preset")

    assert len(incident_calls) == 3, "different role/tenant collapsed into one entry"
    assert len(preset_calls) == 1
    assert len(oidc_permission_cache._CACHE) == 4


def test_unrestricted_role_never_enters_the_cache(incident_calls):
    # No rules installed for this role at all.
    assert resolve_allowed_resource_ids(TENANT, "dba", "incident") == []
    assert not oidc_permission_cache._CACHE
    assert not incident_calls


# --------------------------------------------------------------------------- #
# Fail-open contract
# --------------------------------------------------------------------------- #


def test_failure_propagates_and_is_not_cached(monkeypatch):
    install_rule(role="dba", resource_type="incident", cel="service in ['postgres']")

    attempts = {"count": 0}

    def exploding_query(tenant_id, cel, limit, offset):
        attempts["count"] += 1
        raise RuntimeError("database is down")

    monkeypatch.setattr(
        oidc_resource_resolver, "get_last_incidents_by_cel", exploding_query
    )

    for _ in range(2):
        with pytest.raises(RuntimeError):
            resolve_allowed_resource_ids(TENANT, "dba", "incident")

    # Caching the failure, or serving [] on it, would mean "unrestricted".
    assert attempts["count"] == 2
    assert not oidc_permission_cache._CACHE


def test_deny_all_sentinel_is_cached_like_any_other_answer(monkeypatch):
    install_rule(role="dba", resource_type="incident", cel="service in ['nothing']")

    calls = {"count": 0}

    def empty_query(tenant_id, cel, limit, offset):
        calls["count"] += 1
        return [], 0

    monkeypatch.setattr(
        oidc_resource_resolver, "get_last_incidents_by_cel", empty_query
    )

    first = resolve_allowed_resource_ids(TENANT, "dba", "incident")
    second = resolve_allowed_resource_ids(TENANT, "dba", "incident")

    assert first == [DENY_ALL_SENTINEL_ID]
    assert second == [DENY_ALL_SENTINEL_ID]
    assert calls["count"] == 1


def test_caller_cannot_mutate_the_cached_list(incident_calls):
    install_rule(role="dba", resource_type="incident", cel="service in ['postgres']")

    first = resolve_allowed_resource_ids(TENANT, "dba", "incident")
    first.append("smuggled-in")
    second = resolve_allowed_resource_ids(TENANT, "dba", "incident")

    assert "smuggled-in" not in second


# --------------------------------------------------------------------------- #
# Invalidation and bookkeeping
# --------------------------------------------------------------------------- #


def test_invalidate_presets_drops_only_that_tenant_and_type(
    incident_calls, preset_calls
):
    install_rule(role="dba", resource_type="incident", cel="service in ['postgres']")
    install_rule(role="dba", resource_type="preset", match={"name": ["payments"]})

    resolve_allowed_resource_ids(TENANT, "dba", "incident")
    resolve_allowed_resource_ids(TENANT, "dba", "preset")
    resolve_allowed_resource_ids(OTHER_TENANT, "dba", "preset")

    oidc_permission_cache.invalidate_presets(TENANT)

    resolve_allowed_resource_ids(TENANT, "dba", "incident")
    resolve_allowed_resource_ids(OTHER_TENANT, "dba", "preset")
    assert len(incident_calls) == 1, "incidents were dropped by a preset invalidation"
    assert len(preset_calls) == 2, "another tenant's presets were dropped"

    resolve_allowed_resource_ids(TENANT, "dba", "preset")
    assert len(preset_calls) == 3, "the invalidated entry was still served"


def test_registering_a_rule_invalidates_everything(incident_calls):
    """
    A cached answer belongs to the rule set it was resolved against.

    _load_rules() only runs at import in production, so this cannot happen
    there -- but the cache must not be the thing that depends on that, and the
    permission test modules do swap rule sets inside a single test.
    """
    install_rule(role="dba", resource_type="incident", cel="service in ['postgres']")
    resolve_allowed_resource_ids(TENANT, "dba", "incident")
    assert len(incident_calls) == 1

    oidc_permissions._RULE_REGISTRY.clear()
    install_rule(role="dba", resource_type="incident", cel="service in ['payments']")

    resolve_allowed_resource_ids(TENANT, "dba", "incident")
    assert len(incident_calls) == 2, "resolved against the previous rule set"
    assert incident_calls[-1][1] == "service in ['payments']"


def test_preset_resource_type_constant_matches_oidc_permissions():
    # The two are spelled separately so keep/api/routes/preset.py can invalidate
    # without importing oidc_permissions (whose import runs _load_rules()).
    assert (
        oidc_permission_cache.RESOURCE_TYPE_PRESET
        == oidc_permissions.RESOURCE_TYPE_PRESET
    )


def test_cache_size_is_bounded(monkeypatch, incident_calls):
    monkeypatch.setattr(oidc_permission_cache, "MAX_ENTRIES", 4)
    install_rule(role="dba", resource_type="incident", cel="service in ['postgres']")

    for index in range(20):
        resolve_allowed_resource_ids(f"tenant-{index}", "dba", "incident")

    assert len(oidc_permission_cache._CACHE) <= 4
