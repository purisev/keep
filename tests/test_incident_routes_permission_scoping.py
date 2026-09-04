"""
Functional tests: the id-addressed incident routes respect incident
permission rules for a scoped OIDC role.

The list, facets and report routes already passed the caller's allowed
incident ids into their SQL (keep/api/routes/incidents.py), but every route
addressed by a single incident id -- GET /incidents/{id}, its alerts,
assign, status, enrich and the rest -- took the id verbatim, so a restricted
role could read or mutate any incident in the tenant by guessing (or having
once seen) its id. Now they all pass through _ensure_incidents_allowed,
which raises 403 for an id outside the caller's resolved scope and stays
out of the way (the documented fail-open contract) when the role has no
incident rules at all.

Incidents are created through create_incident_from_dict, same as
tests/test_oidc_incident_service_field.py.
"""

import pytest
from fastapi import HTTPException

from keep.api.core.db import create_incident_from_dict
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.routes.incidents import (
    assign_incident,
    get_incident,
    get_incident_alerts,
)
from keep.identitymanager import rbac
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.identity_managers.oidc import oidc_permissions

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
def postgres_only_rule(monkeypatch):
    monkeypatch.setenv("AUTH_TYPE", "oidc")
    oidc_permissions._RULE_REGISTRY.clear()
    oidc_permissions.register_rule(
        oidc_permissions.build_rule(
            {
                "role": ROLE,
                "resource_type": "incident",
                "cel": "service in ['postgres']",
            }
        )
    )
    yield
    oidc_permissions._RULE_REGISTRY.clear()


def _entity(role=ROLE) -> AuthenticatedEntity:
    return AuthenticatedEntity(
        tenant_id=SINGLE_TENANT_UUID, email="dba@example.com", role=role
    )


def _make_incident(db_session, service: str):
    return create_incident_from_dict(
        SINGLE_TENANT_UUID,
        {
            "user_generated_name": f"{service} down",
            "user_summary": f"{service} down",
            "affected_services": [service],
            "sources": ["prometheus"],
        },
        session=db_session,
    )


def test_get_incident_out_of_scope_is_refused(
    db_session, dba_role, postgres_only_rule
):
    billing = _make_incident(db_session, "billing")
    with pytest.raises(HTTPException) as excinfo:
        get_incident(incident_id=billing.id, authenticated_entity=_entity())
    assert excinfo.value.status_code == 403


def test_get_incident_in_scope_is_served(
    db_session, dba_role, postgres_only_rule
):
    postgres = _make_incident(db_session, "postgres")
    result = get_incident(
        incident_id=postgres.id, authenticated_entity=_entity()
    )
    assert str(result.id) == str(postgres.id)


def test_incident_alerts_out_of_scope_are_refused(
    db_session, dba_role, postgres_only_rule
):
    billing = _make_incident(db_session, "billing")
    with pytest.raises(HTTPException) as excinfo:
        get_incident_alerts(
            incident_id=billing.id, authenticated_entity=_entity()
        )
    assert excinfo.value.status_code == 403


def test_assign_out_of_scope_incident_is_refused(
    db_session, dba_role, postgres_only_rule
):
    billing = _make_incident(db_session, "billing")
    with pytest.raises(HTTPException) as excinfo:
        assign_incident(
            incident_id=billing.id,
            authenticated_entity=_entity(),
            session=db_session,
        )
    assert excinfo.value.status_code == 403


def test_unrestricted_role_is_untouched(db_session, monkeypatch):
    monkeypatch.setenv("AUTH_TYPE", "oidc")
    oidc_permissions._RULE_REGISTRY.clear()
    billing = _make_incident(db_session, "billing")
    result = get_incident(
        incident_id=billing.id, authenticated_entity=_entity(role="admin")
    )
    assert str(result.id) == str(billing.id)
