"""
Database-backed tests for the OIDC resource-permission resolver.

These REQUIRE a working Keep test environment (sqlmodel, sqlalchemy, pytest and
the `db_session` fixture from tests/conftest.py). They were written but could
not be executed in the sandbox used to develop this feature, which has no
database stack installed. The database-free half of the feature is covered by
tests/test_oidc_permissions.py, which does run there.

They cover the part tests/test_oidc_permissions.py cannot: that an incident
rule's CEL expression reaches Keep's query layer and selects the right rows --
in particular that `service in [...]` resolves against `affected_services`, a
JSON column whose containment predicate differs per SQL dialect -- and that the
preset projection feeds the matcher the attributes it expects.
"""

import pytest

from keep.api.core.db import create_incident_from_dict
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.db.preset import Preset, PresetTagLink, Tag
from keep.identitymanager.identity_managers.oidc import oidc_permissions
from keep.identitymanager.identity_managers.oidc.oidc_resource_resolver import (
    resolve_allowed_resource_ids,
)


@pytest.fixture
def rules():
    """
    Install rules on the live registry and remove them afterwards.

    The registry is mutated in place rather than reloading the module: the
    resolver binds get_rules_for/apply_rules at import time, so a reloaded
    module would not be the one under test.
    """
    oidc_permissions._RULE_REGISTRY.clear()

    def install(*definitions):
        for definition in definitions:
            oidc_permissions.register_rule(oidc_permissions.build_rule(definition))

    yield install
    oidc_permissions._RULE_REGISTRY.clear()


@pytest.fixture
def dba_role():
    """Register the custom role the rules refer to, then remove it."""
    from keep.identitymanager import rbac

    created = []
    for name in ("dba", "payments-oncall"):
        if name not in rbac.get_all_roles():
            rbac.register_role(name, ["read:*"], "test role")
            created.append(name)
    yield
    for name in created:
        rbac._ROLE_REGISTRY.pop(name, None)


def _create_incidents(db_session):
    postgres = create_incident_from_dict(
        SINGLE_TENANT_UUID,
        {
            "user_generated_name": "postgres down",
            "user_summary": "postgres down",
            "affected_services": ["postgres", "api"],
            "sources": ["prometheus"],
        },
        session=db_session,
    )
    billing = create_incident_from_dict(
        SINGLE_TENANT_UUID,
        {
            "user_generated_name": "billing down",
            "user_summary": "billing down",
            "affected_services": ["billing"],
            "sources": ["datadog"],
        },
        session=db_session,
    )
    no_services = create_incident_from_dict(
        SINGLE_TENANT_UUID,
        {
            "user_generated_name": "unknown",
            "user_summary": "unknown",
            "affected_services": [],
            "sources": ["prometheus"],
        },
        session=db_session,
    )
    return postgres, billing, no_services


def _create_presets(db_session):
    presets = [
        Preset(
            tenant_id=SINGLE_TENANT_UUID,
            name="payments-firing",
            created_by="alice@example.com",
            options=[],
        ),
        Preset(
            tenant_id=SINGLE_TENANT_UUID,
            name="infra-overview",
            created_by="bob@example.com",
            options=[],
        ),
    ]
    db_session.add_all(presets)
    db_session.commit()
    for preset in presets:
        db_session.refresh(preset)

    tag = Tag(tenant_id=SINGLE_TENANT_UUID, name="payments")
    db_session.add(tag)
    db_session.commit()
    db_session.add(
        PresetTagLink(
            tenant_id=SINGLE_TENANT_UUID, preset_id=presets[1].id, tag_id=tag.id
        )
    )
    db_session.commit()
    return presets


def test_incident_cel_resolves_against_json_column(db_session, dba_role, rules):
    postgres, billing, no_services = _create_incidents(db_session)
    rules(
        {
            "role": "dba",
            "resource_type": "incident",
            "cel": "service in ['postgres', 'patroni']",
        }
    )

    allowed = resolve_allowed_resource_ids(
        tenant_id=SINGLE_TENANT_UUID, role="dba", resource_type="incident"
    )
    assert str(postgres.id) in allowed
    # The restriction has to exclude, not just include.
    assert str(billing.id) not in allowed
    assert str(no_services.id) not in allowed


def test_role_without_rules_is_unrestricted(db_session, dba_role, rules):
    _create_incidents(db_session)
    rules(
        {
            "role": "dba",
            "resource_type": "incident",
            "cel": "service == 'postgres'",
        }
    )

    # admin has no rules: empty list means "no limitations" upstream.
    assert (
        resolve_allowed_resource_ids(
            tenant_id=SINGLE_TENANT_UUID, role="admin", resource_type="incident"
        )
        == []
    )
    # dba has rules for incidents but none for presets.
    assert (
        resolve_allowed_resource_ids(
            tenant_id=SINGLE_TENANT_UUID, role="dba", resource_type="preset"
        )
        == []
    )


def test_restricted_role_matching_nothing_is_denied_not_unrestricted(
    db_session, dba_role, rules
):
    _create_incidents(db_session)
    rules(
        {
            "role": "dba",
            "resource_type": "incident",
            "cel": "service in ['cassandra']",
        }
    )

    allowed = resolve_allowed_resource_ids(
        tenant_id=SINGLE_TENANT_UUID, role="dba", resource_type="incident"
    )
    assert allowed == [oidc_permissions.DENY_ALL_SENTINEL_ID]
    assert allowed, "must stay truthy or the call sites read it as 'allow all'"


def test_incident_severity_matches_configured_name(db_session, dba_role, rules):
    incident = create_incident_from_dict(
        SINGLE_TENANT_UUID,
        {
            "user_generated_name": "critical one",
            "user_summary": "critical one",
            "affected_services": ["postgres"],
            "severity": 5,
        },
        session=db_session,
    )
    low = create_incident_from_dict(
        SINGLE_TENANT_UUID,
        {
            "user_generated_name": "low one",
            "user_summary": "low one",
            "affected_services": ["postgres"],
            "severity": 1,
        },
        session=db_session,
    )
    rules(
        {
            "role": "dba",
            "resource_type": "incident",
            "cel": "severity == 'critical'",
        }
    )

    allowed = resolve_allowed_resource_ids(
        tenant_id=SINGLE_TENANT_UUID, role="dba", resource_type="incident"
    )
    assert str(incident.id) in allowed
    assert str(low.id) not in allowed


def test_preset_name_glob_and_tag(db_session, dba_role, rules):
    payments, infra = _create_presets(db_session)

    rules(
        {
            "role": "payments-oncall",
            "resource_type": "preset",
            "match": {"name": ["payments-*"]},
        }
    )
    allowed = resolve_allowed_resource_ids(
        tenant_id=SINGLE_TENANT_UUID, role="payments-oncall", resource_type="preset"
    )
    assert str(payments.id) in allowed
    assert str(infra.id) not in allowed

    oidc_permissions._RULE_REGISTRY.clear()
    rules(
        {
            "role": "payments-oncall",
            "resource_type": "preset",
            "match": {"tag": ["payments"]},
        }
    )
    allowed = resolve_allowed_resource_ids(
        tenant_id=SINGLE_TENANT_UUID, role="payments-oncall", resource_type="preset"
    )
    assert str(infra.id) in allowed
    assert str(payments.id) not in allowed


def test_other_tenants_are_never_visible(db_session, dba_role, rules):
    postgres, _, _ = _create_incidents(db_session)
    rules(
        {
            "role": "dba",
            "resource_type": "incident",
            "cel": "service == 'postgres'",
        }
    )

    allowed = resolve_allowed_resource_ids(
        tenant_id="some-other-tenant", role="dba", resource_type="incident"
    )
    assert allowed == [oidc_permissions.DENY_ALL_SENTINEL_ID]
    assert str(postgres.id) not in allowed


def test_missing_tenant_or_role_raises(db_session, dba_role, rules):
    rules(
        {
            "role": "dba",
            "resource_type": "incident",
            "cel": "service == 'postgres'",
        }
    )
    # Never silently return [] here: [] means "unrestricted" at the call site.
    with pytest.raises(ValueError):
        resolve_allowed_resource_ids(
            tenant_id=SINGLE_TENANT_UUID, role="", resource_type="incident"
        )
    with pytest.raises(ValueError):
        resolve_allowed_resource_ids(
            tenant_id="", role="dba", resource_type="incident"
        )
