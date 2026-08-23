"""
Functional tests: every alert-returning or alert-addressed route respects
preset permission rules for a scoped OIDC role, not just POST /alerts/query.

POST /alerts/query was scoped first (tests/test_alert_query_permission_scoping.py),
but the alerts feed is reachable through more doors, and each one used to hand
the caller everything in the tenant:

- GET  /alerts               fetched the last 1000 alerts unfiltered
- POST /alerts/batch         returned any alert whose fingerprint you knew
- POST /alerts/search        ran any CEL through the SearchEngine unchecked
- POST /alerts/facets/options counted every alert in the tenant, and its
  query builder joins per-facet CEL with a bare " && " -- && binds tighter
  than || in CEL, so a facet query with a top-level || escaped even a scoped
  base CEL
- GET  /alerts/{fp}/history, /audit routes, assign/enrich/unenrich/delete
  accepted any fingerprint verbatim
- GET  /alerts/event/error and /quality/metrics exposed tenant-wide data that
  no preset CEL can classify into a team's scope

The scope is resolved once per request (_allowed_alerts_cel) and applied in
SQL where the route already goes through the CEL-to-SQL layer, in memory
(RulesEngine.filter_alerts -- the same evaluation presets themselves use)
where it does not.

Alert rows are inserted directly (same rationale as
tests/test_alert_query_permission_scoping.py's module docstring).
"""

import asyncio
import datetime
import uuid

import pytest

from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.alert import EnrichAlertRequestBody
from keep.api.models.db.alert import Alert, LastAlert
from keep.api.models.db.preset import Preset, PresetSearchQuery
from keep.api.models.facet import FacetOptionsQueryDto
from keep.api.models.search_alert import SearchAlertsRequest
from keep.api.routes.alerts import (
    assign_alert,
    enrich_alert,
    get_alert_history,
    get_alert_quality,
    get_all_alerts,
    get_alerts_by_fingerprints_batch,
    get_error_alerts,
    fetch_alert_facet_options,
    search_alerts,
)
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.identity_managers.oidc import oidc_permissions
from keep.identitymanager import rbac
from fastapi import HTTPException

ROLE = "dba"

SEVERITY_FACET_ID = "f8a91ac7-4916-4ad0-9b46-a5ddb85bfbb8"
SOURCE_FACET_ID = "461bef05-fc20-4363-b427-9d26fe064e7f"


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


def _clear_rules(monkeypatch):
    monkeypatch.setenv("AUTH_TYPE", "oidc")
    oidc_permissions._RULE_REGISTRY.clear()


def _entity(role=ROLE) -> AuthenticatedEntity:
    return AuthenticatedEntity(
        tenant_id=SINGLE_TENANT_UUID, email="dba@example.com", role=role
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


@pytest.fixture
def sentry_scoped(monkeypatch, db_session, dba_role):
    """One sentry alert in scope, one grafana alert out of scope, and a rule
    restricting ROLE to presets named dba-* (whose only member selects
    sentry)."""
    _make_preset(db_session, "dba-sentry", 'source == "sentry"')
    _install_rule(
        monkeypatch,
        {"role": ROLE, "resource_type": "preset", "match": {"name": ["dba-*"]}},
    )
    _make_alert(db_session, "sentry-alert", "sentry", "firing")
    _make_alert(db_session, "grafana-alert", "grafana", "firing")


def test_get_all_alerts_is_scoped(sentry_scoped):
    result = get_all_alerts(authenticated_entity=_entity())
    assert [a.fingerprint for a in result] == ["sentry-alert"]


def test_get_all_alerts_unrestricted_role_sees_everything(
    monkeypatch, db_session, sentry_scoped
):
    result = get_all_alerts(authenticated_entity=_entity(role="admin"))
    assert {a.fingerprint for a in result} == {"sentry-alert", "grafana-alert"}


def test_batch_by_fingerprints_is_scoped(sentry_scoped):
    result = get_alerts_by_fingerprints_batch(
        fingerprints=["sentry-alert", "grafana-alert"],
        authenticated_entity=_entity(),
    )
    assert [a.fingerprint for a in result] == ["sentry-alert"]


def test_search_is_scoped(sentry_scoped):
    request = SearchAlertsRequest(
        query=PresetSearchQuery(cel_query='status == "firing"', sql_query={}),
        timeframe=0,
    )
    result = asyncio.run(
        search_alerts(search_request=request, authenticated_entity=_entity())
    )
    assert [a.fingerprint for a in result] == ["sentry-alert"]


def test_facet_options_are_scoped(sentry_scoped):
    result = fetch_alert_facet_options(
        facet_options_query=FacetOptionsQueryDto(
            cel="", facet_queries={SOURCE_FACET_ID: ""}
        ),
        authenticated_entity=_entity(),
    )
    source_values = {
        option.display_name: option.matches_count
        for option in result[SOURCE_FACET_ID]
        if option.matches_count
    }
    assert "grafana" not in source_values
    assert source_values.get("sentry") == 1


def test_facet_options_top_level_or_cannot_escape_the_scope(sentry_scoped):
    """The facets query builder joins base cel and facet cel with a bare
    " && "; && binds tighter than || in CEL, so an unparenthesized facet
    query 'true || true' would turn (scope) && true || true into
    ((scope && true) || true) and count everything."""
    result = fetch_alert_facet_options(
        facet_options_query=FacetOptionsQueryDto(
            cel="", facet_queries={SOURCE_FACET_ID: "1 == 1 || 1 == 1"}
        ),
        authenticated_entity=_entity(),
    )
    source_values = {
        option.display_name: option.matches_count
        for option in result[SOURCE_FACET_ID]
        if option.matches_count
    }
    assert "grafana" not in source_values


def test_facet_options_deny_all_returns_empty_options(
    monkeypatch, db_session, dba_role
):
    _install_rule(
        monkeypatch,
        {
            "role": ROLE,
            "resource_type": "preset",
            "match": {"name": ["nothing-matches-*"]},
        },
    )
    _make_alert(db_session, "sentry-alert", "sentry", "firing")
    result = fetch_alert_facet_options(
        facet_options_query=FacetOptionsQueryDto(
            cel="", facet_queries={SOURCE_FACET_ID: ""}
        ),
        authenticated_entity=_entity(),
    )
    assert result == {SOURCE_FACET_ID: []}


def test_history_of_an_out_of_scope_fingerprint_is_refused(sentry_scoped):
    with pytest.raises(HTTPException) as excinfo:
        get_alert_history(
            fingerprint="grafana-alert", authenticated_entity=_entity()
        )
    assert excinfo.value.status_code == 403


def test_history_of_an_in_scope_fingerprint_is_served(sentry_scoped):
    result = get_alert_history(
        fingerprint="sentry-alert", authenticated_entity=_entity()
    )
    assert len(result) == 1


def test_history_of_an_unknown_fingerprint_is_refused_for_restricted_roles(
    sentry_scoped,
):
    """A fingerprint resolving to no alert cannot be shown to be in scope;
    the enrichment routes sharing this gate would otherwise create state
    for it."""
    with pytest.raises(HTTPException) as excinfo:
        get_alert_history(
            fingerprint="no-such-alert", authenticated_entity=_entity()
        )
    assert excinfo.value.status_code == 403


def test_enrich_of_an_out_of_scope_fingerprint_is_refused(
    sentry_scoped, db_session
):
    with pytest.raises(HTTPException) as excinfo:
        enrich_alert(
            enrich_data=EnrichAlertRequestBody(
                enrichments={"note": "not yours"}, fingerprint="grafana-alert"
            ),
            authenticated_entity=_entity(),
            session=db_session,
        )
    assert excinfo.value.status_code == 403


def test_assign_of_an_out_of_scope_fingerprint_is_refused(sentry_scoped):
    with pytest.raises(HTTPException) as excinfo:
        assign_alert(
            fingerprint="grafana-alert",
            last_received=datetime.datetime.now(
                tz=datetime.timezone.utc
            ).isoformat(),
            authenticated_entity=_entity(),
        )
    assert excinfo.value.status_code == 403


def test_error_alerts_are_hidden_from_restricted_roles(sentry_scoped):
    assert get_error_alerts(authenticated_entity=_entity()) == []


def test_quality_metrics_are_hidden_from_restricted_roles(sentry_scoped):
    assert (
        get_alert_quality(
            authenticated_entity=_entity(), time_stamp=None, fields=[]
        )
        == {}
    )


def test_unrestricted_role_is_untouched_everywhere(
    monkeypatch, db_session
):
    """No rules at all: every route behaves exactly as before the feature."""
    _clear_rules(monkeypatch)
    _make_alert(db_session, "sentry-alert", "sentry", "firing")
    _make_alert(db_session, "grafana-alert", "grafana", "firing")

    entity = _entity(role="admin")
    assert len(get_all_alerts(authenticated_entity=entity)) == 2
    assert (
        len(
            get_alerts_by_fingerprints_batch(
                fingerprints=["sentry-alert", "grafana-alert"],
                authenticated_entity=entity,
            )
        )
        == 2
    )
    history = get_alert_history(
        fingerprint="grafana-alert", authenticated_entity=entity
    )
    assert len(history) == 1
