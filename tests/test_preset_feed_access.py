"""
Functional test: does a role scoped to its own presets still get the app's
default landing view?

This is not a test of oidc_resource_resolver.py's internals in isolation
(that's tests/test_oidc_resource_resolver.py) -- it drives the real route
handlers in keep/api/routes/preset.py the way the UI actually calls them,
because the behaviour pinned here spans the boundary between two pieces that
are each individually correct and separately tested.

Background: keep-ui/middleware.ts redirects EVERY navigation into the app to
`/alerts/feed`, and roughly a dozen other places in keep-ui
(incidents-not-found.tsx, alert-fingerprint-page.tsx, webhook-settings.tsx,
CustomPresetAlertLinks.tsx, ...) hard-code `router.push("/alerts/feed")` as
the "go back to a safe place" fallback. Keep's built-in static "feed" preset
(STATIC_PRESETS["feed"]) is a fixed sentinel id, not a database row, and
keep/api/routes/preset.py originally showed/allowed it only when
allowed_preset_ids was empty ("fully unrestricted") -- so the moment a role
had ANY preset rule (the entire point of this feature: presets_provisioning.py
documents "grant its role access to that preset through the OIDC resource
permission rules, and the team gets a feed containing only its own alerts"),
the sentinel could never appear in a query over real Preset rows, and the
role was 403'd off the very page the app's own navigation sends it to.

Fixed in two places:
  * oidc_resource_resolver._fetch_preset_records projects the synthetic feed
    preset into the same pool real presets are matched against, so a preset
    rule CAN reference it (e.g. match: {name: ["feed"]}).
  * keep/api/routes/preset.py's get_presets() adds STATIC_PRESETS["feed"] to
    the list when unrestricted OR when a rule explicitly granted it, not only
    when unrestricted.

This does NOT make "feed" available to every scoped role by default -- that
would defeat the point of scoping (feed's CEL is "", i.e. every alert). It
makes the sentinel id reachable by an ordinary rule, so an operator can opt a
role back into it deliberately, auditable the same way as any other grant.
"""

from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException, Response

from keep.api.consts import STATIC_PRESETS
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.db.preset import Preset
from keep.api.routes.preset import get_preset_alerts, get_presets
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.identity_managers.oidc import oidc_permissions
from keep.identitymanager.identity_managers.oidc.oidc_resource_resolver import (
    resolve_allowed_resource_ids,
)
from keep.identitymanager import rbac

ROLE = "dba"


@pytest.fixture
def dba_role():
    created = ROLE not in rbac.get_all_roles()
    if created:
        rbac.register_role(ROLE, ["read:*"], "database team")
    yield
    if created:
        rbac._ROLE_REGISTRY.pop(ROLE, None)


@pytest.fixture
def scoped_to_own_preset_only(monkeypatch, dba_role):
    """
    The exact setup presets_provisioning.py's docstring describes: a role
    scoped to a per-team preset via an OIDC resource permission rule that
    says nothing about "feed".
    """
    monkeypatch.setenv("AUTH_TYPE", "oidc")
    oidc_permissions._RULE_REGISTRY.clear()
    oidc_permissions.register_rule(
        oidc_permissions.build_rule(
            {"role": ROLE, "resource_type": "preset", "match": {"name": ["dba-*"]}}
        )
    )
    yield
    oidc_permissions._RULE_REGISTRY.clear()


@pytest.fixture
def scoped_but_feed_explicitly_granted(monkeypatch, dba_role):
    """Same role, but the rule also explicitly names "feed"."""
    monkeypatch.setenv("AUTH_TYPE", "oidc")
    oidc_permissions._RULE_REGISTRY.clear()
    oidc_permissions.register_rule(
        oidc_permissions.build_rule(
            {
                "role": ROLE,
                "resource_type": "preset",
                "match": {"name": ["dba-*", "feed"]},
            }
        )
    )
    yield
    oidc_permissions._RULE_REGISTRY.clear()


def _entity() -> AuthenticatedEntity:
    return AuthenticatedEntity(tenant_id=SINGLE_TENANT_UUID, email="dba@example.com", role=ROLE)


def _fake_request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(trace_id="test-trace"))


def _own_preset(db_session) -> Preset:
    preset = Preset(
        tenant_id=SINGLE_TENANT_UUID,
        name="dba-feed",
        created_by="provisioning",
        options=[{"label": "CEL", "value": "service in ['postgres']"}],
    )
    db_session.add(preset)
    db_session.commit()
    return preset


# --------------------------------------------------------------------------- #
# Default: a rule that says nothing about "feed" must not grant it -- feed's
# CEL is "" (every alert), so leaking it here would defeat the scoping this
# whole feature exists to provide.
# --------------------------------------------------------------------------- #


def test_scoped_role_without_a_feed_rule_does_not_list_it(
    scoped_to_own_preset_only, db_session
):
    _own_preset(db_session)

    result = get_presets(
        authenticated_entity=_entity(), session=db_session, time_stamp=None
    )

    names = {preset.name for preset in result}
    assert "dba-feed" in names, "the role's own scoped preset must still be listed"
    assert "feed" not in names


def test_scoped_role_without_a_feed_rule_is_forbidden_from_feed_alerts(
    scoped_to_own_preset_only, db_session
):
    with pytest.raises(HTTPException) as exc_info:
        get_preset_alerts(
            request=_fake_request(),
            bg_tasks=BackgroundTasks(),
            preset_name="feed",
            response=Response(),
            authenticated_entity=_entity(),
        )
    assert exc_info.value.status_code == 403


def test_resolver_never_grants_feed_without_a_matching_rule(
    scoped_to_own_preset_only, db_session
):
    _own_preset(db_session)
    allowed = resolve_allowed_resource_ids(
        tenant_id=SINGLE_TENANT_UUID, role=ROLE, resource_type="preset"
    )
    assert str(STATIC_PRESETS["feed"].id) not in allowed


# --------------------------------------------------------------------------- #
# An operator who explicitly grants "feed" gets it -- the fix: the sentinel
# id is now reachable by an ordinary rule instead of being structurally
# unreachable the moment a role has any preset restriction at all.
# --------------------------------------------------------------------------- #


def test_resolver_grants_feed_when_a_rule_names_it(
    scoped_but_feed_explicitly_granted, db_session
):
    allowed = resolve_allowed_resource_ids(
        tenant_id=SINGLE_TENANT_UUID, role=ROLE, resource_type="preset"
    )
    assert str(STATIC_PRESETS["feed"].id) in allowed


def test_scoped_role_with_a_feed_rule_lists_it(
    scoped_but_feed_explicitly_granted, db_session
):
    _own_preset(db_session)

    result = get_presets(
        authenticated_entity=_entity(), session=db_session, time_stamp=None
    )

    names = {preset.name for preset in result}
    assert "dba-feed" in names
    assert "feed" in names


def test_scoped_role_with_a_feed_rule_can_open_feed_alerts(
    scoped_but_feed_explicitly_granted, db_session
):
    # get_preset_alerts() reaches SearchEngine.search_alerts() once the 403
    # guard passes, which needs more infra than this test sets up -- the
    # guard itself (the thing this feature controls) is what's under test.
    try:
        get_preset_alerts(
            request=_fake_request(),
            bg_tasks=BackgroundTasks(),
            preset_name="feed",
            response=Response(),
            authenticated_entity=_entity(),
        )
    except HTTPException as exc:
        assert exc.status_code != 403, (
            "a role with a rule explicitly granting feed must not be 403'd "
            "from it"
        )
