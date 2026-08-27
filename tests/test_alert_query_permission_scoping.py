"""
Functional test: does POST /alerts/query actually respect preset permission
rules for a scoped OIDC role?

Before this fix, it didn't. query_alerts() (keep/api/routes/alerts.py) took
`query.cel` straight from the client and handed it to query_last_alerts()
without ever consulting identity_manager.get_user_permission_on_resource_type()
-- so the entire OIDC resource-permission feature (see
presets_provisioning.py's module docstring: "grant its role access to that
preset... and the team gets a feed containing only its own alerts") only ever
constrained which presets a role could see LISTED. The actual alert data
returned by /alerts/query -- which is what the real alerts table UI calls
(useLastAlerts in keep-ui/entities/alerts/model/useAlerts.ts); the other hook,
usePresetAlerts, which hits the permission-checked /preset/{name}/alerts
route, has no callers anywhere in keep-ui -- was reachable with any CEL the
client cared to send, completely bypassing the role's rules.

Fixed by having query_alerts() resolve the caller's allowed preset ids and,
when restricted, AND the client's CEL with the union of the allowed presets'
own CEL queries (_scope_query_to_allowed_presets). An explicit grant of the
static "feed" preset, or any allowed preset with cel="", is treated as
unrestricted for this purpose -- matching what granting either one already
means for the preset list/detail routes.

Alerts are inserted directly as Alert/LastAlert rows (same shape as
tests/conftest.py's setup_alerts fixture, minus its elasticsearch indexing
step, which this file has no need of) rather than through the create_alert
fixture's process_event() path -- process_event() resolves provider_type
against ProvidersFactory and calls that provider's real format_alert(), which
rejects source values that aren't installed, real providers with a matching
payload shape.
"""

import datetime
import uuid

import pytest
from unittest.mock import MagicMock

from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.alert import AlertStatus
from keep.api.models.db.alert import Alert, LastAlert
from keep.api.models.db.preset import Preset
from keep.api.models.query import QueryDto
from keep.api.routes.alerts import query_alerts
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.identity_managers.oidc import oidc_permissions
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


def _install_rule(monkeypatch, definition):
    monkeypatch.setenv("AUTH_TYPE", "oidc")
    oidc_permissions._RULE_REGISTRY.clear()
    oidc_permissions.register_rule(oidc_permissions.build_rule(definition))


def _entity(role=ROLE) -> AuthenticatedEntity:
    return AuthenticatedEntity(
        tenant_id=SINGLE_TENANT_UUID, email="dba@example.com", role=role
    )


def _query(cel="", authenticated_entity=None):
    return query_alerts(
        request=MagicMock(),
        query=QueryDto(cel=cel),
        bg_tasks=MagicMock(),
        authenticated_entity=authenticated_entity or _entity(),
    )


def _make_preset(db_session, name: str, cel: str) -> Preset:
    preset = Preset(
        tenant_id=SINGLE_TENANT_UUID,
        name=name,
        created_by="provisioning",
        options=[{"label": "CEL", "value": cel}],
    )
    db_session.add(preset)
    db_session.commit()
    return preset


def _make_alert(db_session, fingerprint: str, source: str, status: str) -> None:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    alert = Alert(
        tenant_id=SINGLE_TENANT_UUID,
        provider_type=source,
        provider_id="test",
        fingerprint=fingerprint,
        event={
            "id": str(uuid.uuid4()),
            "name": "some-test-event",
            "fingerprint": fingerprint,
            "source": [source],
            "status": status,
            "lastReceived": now.isoformat(),
        },
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    db_session.add(
        LastAlert(
            tenant_id=SINGLE_TENANT_UUID,
            fingerprint=fingerprint,
            timestamp=alert.timestamp,
            first_timestamp=alert.timestamp,
            alert_id=alert.id,
        )
    )
    db_session.commit()


def test_scoped_role_only_sees_alerts_within_its_allowed_preset(
    monkeypatch, db_session, dba_role
):
    _make_preset(db_session, "dba-sentry", 'source == "sentry"')
    _install_rule(
        monkeypatch,
        {"role": ROLE, "resource_type": "preset", "match": {"name": ["dba-*"]}},
    )

    _make_alert(db_session, "sentry-alert", "sentry", "firing")
    _make_alert(db_session, "grafana-alert", "grafana", "firing")

    result = _query()

    assert result["count"] == 1
    assert result["results"][0].fingerprint == "sentry-alert"


def test_unrestricted_role_sees_everything(monkeypatch, db_session):
    # No preset rule for this role at all -> get_user_permission_on_resource_type
    # returns [], the documented fail-open contract.
    monkeypatch.setenv("AUTH_TYPE", "oidc")
    oidc_permissions._RULE_REGISTRY.clear()

    _make_alert(db_session, "sentry-alert", "sentry", "firing")
    _make_alert(db_session, "grafana-alert", "grafana", "firing")

    result = _query(authenticated_entity=_entity(role="admin"))

    assert result["count"] == 2


def test_client_cel_is_anded_with_the_role_scope_not_replaced(
    monkeypatch, db_session, dba_role
):
    """A role restricted to sentry alerts, additionally filtering by status
    client-side, must get the intersection -- not the role scope alone, and
    not the client filter alone."""
    _make_preset(db_session, "dba-sentry", 'source == "sentry"')
    _install_rule(
        monkeypatch,
        {"role": ROLE, "resource_type": "preset", "match": {"name": ["dba-*"]}},
    )

    _make_alert(db_session, "sentry-firing", "sentry", "firing")
    _make_alert(db_session, "sentry-resolved", "sentry", "resolved")
    _make_alert(db_session, "grafana-firing", "grafana", "firing")

    result = _query(cel='status == "firing"')

    assert result["count"] == 1
    assert result["results"][0].fingerprint == "sentry-firing"


def test_role_restricted_to_nothing_gets_empty_results_not_an_error(
    monkeypatch, db_session, dba_role
):
    """A rule that matches no preset (DENY_ALL_SENTINEL_ID, or every allowed
    id turning out stale) must return an empty page, not leak data and not
    500 -- _scope_query_to_allowed_presets returning None short-circuits
    before query_last_alerts() ever runs."""
    _install_rule(
        monkeypatch,
        {
            "role": ROLE,
            "resource_type": "preset",
            "match": {"name": ["nothing-matches-*"]},
        },
    )

    _make_alert(db_session, "sentry-alert", "sentry", "firing")

    result = _query()

    assert result["count"] == 0
    assert result["results"] == []


def test_explicit_feed_grant_lifts_the_restriction(
    monkeypatch, db_session, dba_role
):
    """A rule that names the static "feed" preset alongside the role's own
    preset is the operator opting this role into the unfiltered view -- see
    tests/test_preset_feed_access.py for the list/detail-route half of this."""
    _make_preset(db_session, "dba-sentry", 'source == "sentry"')
    _install_rule(
        monkeypatch,
        {
            "role": ROLE,
            "resource_type": "preset",
            "match": {"name": ["dba-sentry", "feed"]},
        },
    )

    _make_alert(db_session, "sentry-alert", "sentry", "firing")
    _make_alert(db_session, "grafana-alert", "grafana", "firing")

    result = _query()

    assert result["count"] == 2
