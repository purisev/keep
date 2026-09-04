"""
Native role composition (KEEP_OIDC_ROLE_COMPOSITION=union): a token whose
groups map to several Keep roles gets a composite role assembled on the fly —
scopes are the union of the members' scopes, and resource permissions expand
back to the members with unrestricted-wins semantics. Without this, the
mappings were strictly first-match and a user in two teams silently got only
the first team's feed; the operator's alternative was hand-maintained
composite groups for every combination.

The separator ("+") is a character ROLE_NAME_PATTERN rejects, so an
operator-defined role can never collide with a composite name.
"""

import datetime
import uuid

import pytest

from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.db.alert import Alert, LastAlert
from keep.api.models.db.preset import Preset
from keep.api.models.query import QueryDto
from keep.api.routes.alerts import query_alerts
from keep.identitymanager import rbac
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.identity_managers.oidc import oidc_permissions
from keep.identitymanager.identity_managers.oidc.oidc_authverifier import (
    OidcAuthVerifier,
)
from keep.identitymanager.identity_managers.oidc.oidc_resource_resolver import (
    resolve_allowed_resource_ids,
)
from unittest.mock import MagicMock


@pytest.fixture
def two_team_roles():
    created = []
    for name, scopes in (
        ("team-a", ["read:*"]),
        ("team-b", ["read:*", "write:alert"]),
    ):
        if name not in rbac.get_all_roles():
            rbac.register_role(name, scopes, f"test role {name}")
            created.append(name)
    yield
    for name in created:
        rbac._ROLE_REGISTRY.pop(name, None)
    # Composites derived from the test roles must not leak across tests.
    for name in [n for n in rbac.get_all_roles() if "+" in n]:
        rbac._ROLE_REGISTRY.pop(name, None)


def _verifier(mode: str, mappings=None) -> OidcAuthVerifier:
    """A verifier with only what _resolve_role needs — no JWKS, no network."""
    verifier = object.__new__(OidcAuthVerifier)
    verifier.role_claim = ""
    verifier.default_role = ""
    verifier.groups_claim = "groups"
    verifier.role_composition = mode
    verifier.role_mappings = mappings or [
        ("keep-admins", "admin"),
        ("g-team-a", "team-a"),
        ("g-team-b", "team-b"),
    ]
    verifier.logger = MagicMock()
    return verifier


def _install_rules(monkeypatch, definitions):
    monkeypatch.setenv("AUTH_TYPE", "oidc")
    oidc_permissions._RULE_REGISTRY.clear()
    for definition in definitions:
        oidc_permissions.register_rule(oidc_permissions.build_rule(definition))


# --------------------------------------------------------------------------- #
# Composite registration
# --------------------------------------------------------------------------- #


def test_composite_role_unions_scopes_and_is_idempotent(two_team_roles):
    name = rbac.get_or_register_composite_role(["team-b", "team-a"])
    assert name == "team-a+team-b"  # sorted, stable
    role = rbac.get_role_by_role_name(name)
    assert set(role.SCOPES) == {"read:*", "write:alert"}
    assert role.COMPOSITE_OF == ("team-a", "team-b")
    # Second call returns the same registration, no duplicate error.
    assert rbac.get_or_register_composite_role(["team-a", "team-b"]) == name


def test_composite_requires_two_distinct_members(two_team_roles):
    with pytest.raises(ValueError):
        rbac.get_or_register_composite_role(["team-a", "team-a"])


def test_operator_cannot_define_a_colliding_role_name():
    with pytest.raises(rbac.CustomRoleConfigurationError):
        rbac.register_role("team-a+team-b", ["read:*"])


# --------------------------------------------------------------------------- #
# Verifier resolution
# --------------------------------------------------------------------------- #


def test_union_mode_builds_a_composite_from_all_matching_groups(two_team_roles):
    role = _verifier("union")._resolve_role({"groups": ["g-team-a", "g-team-b"]})
    assert role == "team-a+team-b"


def test_union_mode_with_one_match_stays_a_plain_role(two_team_roles):
    role = _verifier("union")._resolve_role({"groups": ["g-team-b"]})
    assert role == "team-b"


def test_first_match_mode_keeps_the_ordered_precedence(two_team_roles):
    role = _verifier("first-match")._resolve_role(
        {"groups": ["g-team-b", "g-team-a"]}
    )
    # Mapping order decides, not token order: g-team-a is listed first.
    assert role == "team-a"


def test_union_mode_admin_membership_joins_the_composite(two_team_roles):
    role = _verifier("union")._resolve_role(
        {"groups": ["keep-admins", "g-team-a"]}
    )
    # admin has no resource rules -> unrestricted-wins makes the composite
    # unrestricted, and the scopes union carries admin's scopes.
    assert role == "admin+team-a"
    assert set(rbac.get_role_by_role_name("admin").SCOPES).issubset(
        set(rbac.get_role_by_role_name(role).SCOPES)
    )


# --------------------------------------------------------------------------- #
# Rules expansion
# --------------------------------------------------------------------------- #


def test_composite_rules_are_the_union_when_all_members_are_restricted(
    monkeypatch, two_team_roles
):
    _install_rules(
        monkeypatch,
        [
            {"role": "team-a", "resource_type": "preset", "match": {"name": ["a-*"]}},
            {"role": "team-b", "resource_type": "preset", "match": {"name": ["b-*"]}},
        ],
    )
    rules = oidc_permissions.get_rules_for("team-a+team-b", "preset")
    assert len(rules) == 2


def test_composite_is_unrestricted_when_any_member_is(monkeypatch, two_team_roles):
    _install_rules(
        monkeypatch,
        [{"role": "team-a", "resource_type": "preset", "match": {"name": ["a-*"]}}],
    )
    # team-b has no preset rules: alone it sees everything, so the composite
    # must too — anything else makes two teams grant less than one.
    assert oidc_permissions.get_rules_for("team-a+team-b", "preset") == []


# --------------------------------------------------------------------------- #
# End to end: resolver and the alert feed
# --------------------------------------------------------------------------- #


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


def _make_alert(db_session, fingerprint: str, source: str) -> None:
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
            "status": "firing",
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


def test_composite_resolver_unions_the_allowed_presets(
    monkeypatch, db_session, two_team_roles
):
    preset_a = _make_preset(db_session, "a-sentry", 'source == "sentry"')
    preset_b = _make_preset(db_session, "b-grafana", 'source == "grafana"')
    _make_preset(db_session, "c-other", 'source == "other"')
    _install_rules(
        monkeypatch,
        [
            {"role": "team-a", "resource_type": "preset", "match": {"name": ["a-*"]}},
            {"role": "team-b", "resource_type": "preset", "match": {"name": ["b-*"]}},
        ],
    )
    allowed = resolve_allowed_resource_ids(
        tenant_id=SINGLE_TENANT_UUID, role="team-a+team-b", resource_type="preset"
    )
    assert set(allowed) == {str(preset_a.id), str(preset_b.id)}


def test_composite_feed_is_the_union_of_both_teams(
    monkeypatch, db_session, two_team_roles
):
    _make_preset(db_session, "a-sentry", 'source == "sentry"')
    _make_preset(db_session, "b-grafana", 'source == "grafana"')
    _install_rules(
        monkeypatch,
        [
            {"role": "team-a", "resource_type": "preset", "match": {"name": ["a-*"]}},
            {"role": "team-b", "resource_type": "preset", "match": {"name": ["b-*"]}},
        ],
    )
    _make_alert(db_session, "sentry-alert", "sentry")
    _make_alert(db_session, "grafana-alert", "grafana")
    _make_alert(db_session, "other-alert", "other")

    rbac.get_or_register_composite_role(["team-a", "team-b"])
    entity = AuthenticatedEntity(
        tenant_id=SINGLE_TENANT_UUID,
        email="both@example.com",
        role="team-a+team-b",
    )
    result = query_alerts(
        request=MagicMock(),
        query=QueryDto(cel=""),
        bg_tasks=MagicMock(),
        authenticated_entity=entity,
    )
    assert {a.fingerprint for a in result["results"]} == {
        "sentry-alert",
        "grafana-alert",
    }
