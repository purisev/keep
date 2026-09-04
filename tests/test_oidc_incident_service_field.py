"""
Functional test: does the documented incident CEL rule actually select
anything?

Every worked example for this feature -- the README
(keep/identitymanager/identity_managers/oidc/README.md:89,137,260), the module
docstrings of oidc_permissions.py and presets_provisioning.py, and the
project's own DB-backed tests (tests/test_oidc_resource_resolver.py) -- writes
an incident permission rule as:

    cel: "service in ['postgres', 'patroni']"

and the README's reference table is explicit that this is deliberate:

    | incident | `service` | membership in `affected_services` (a JSON list) |

Keep's CEL-to-SQL field mapping for incidents (keep/api/core/incidents.py,
incident_field_configurations) originally had no entry for `service` at all --
only `affectedServices` (camelCase) mapped to the `affected_services` column,
so the exact rule the docs told an operator to write parsed as valid CEL,
reached the query layer, and then silently failed to map "service" to any
column: keep/api/core/cel_to_sql/properties_mapper.py logged "Missing mapping
configuration" and every incident was excluded, same as a rule matching
nothing. Because oidc_resource_resolver.py fails closed (DENY_ALL_SENTINEL_ID
rather than an empty "unrestricted" list), this never leaked data -- it just
meant every documented incident-scoping example denied every incident to
every scoped role, unconditionally. This went undiscovered because
tests/test_oidc_resource_resolver.py's own docstring says its DB-backed tests
"could not be executed in the sandbox used to develop this feature."

Fixed by adding a `service` FieldMappingConfiguration alongside
`affectedServices` in keep/api/core/incidents.py, aliasing both to
`incident.affected_services`. This test is written against the documented
behaviour (the README's own example), not against the implementation, so it
pins the fix rather than the mechanism.
"""

import pytest

from keep.api.core.db import create_incident_from_dict
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.identitymanager import rbac
from keep.identitymanager.identity_managers.oidc import oidc_permissions
from keep.identitymanager.identity_managers.oidc.oidc_resource_resolver import (
    resolve_allowed_resource_ids,
)

ROLE = "dba"


@pytest.fixture
def dba_role():
    created = ROLE not in rbac.get_all_roles()
    if created:
        rbac.register_role(ROLE, ["read:*"], "test role")
    yield
    if created:
        rbac._ROLE_REGISTRY.pop(ROLE, None)


@pytest.fixture
def rule_service_in_postgres():
    """The exact rule shown in README.md and every docstring in this feature."""
    oidc_permissions._RULE_REGISTRY.clear()
    oidc_permissions.register_rule(
        oidc_permissions.build_rule(
            {
                "role": ROLE,
                "resource_type": "incident",
                "cel": "service in ['postgres', 'patroni']",
            }
        )
    )
    yield
    oidc_permissions._RULE_REGISTRY.clear()


def _postgres_incident(db_session):
    return create_incident_from_dict(
        SINGLE_TENANT_UUID,
        {
            "user_generated_name": "postgres down",
            "user_summary": "postgres down",
            "affected_services": ["postgres"],
            "sources": ["prometheus"],
        },
        session=db_session,
    )


def test_documented_service_field_matches_the_incident_it_describes(
    db_session, dba_role, rule_service_in_postgres
):
    """
    The rule copied verbatim from the README now allows the incident it was
    written to allow through. If this regresses, incident_field_configurations
    lost its `service` mapping (or apply_rules()/the CEL layer changed how
    ARRAY membership resolves) and the documented example is broken again.
    """
    incident = _postgres_incident(db_session)

    allowed = resolve_allowed_resource_ids(
        tenant_id=SINGLE_TENANT_UUID, role=ROLE, resource_type="incident"
    )

    assert str(incident.id) in allowed


# A control test asserting that "affectedServices in [...]" (the pre-existing
# field name) also still resolves correctly was deliberately left out of this
# file. keep/api/core/incidents.py:22 does `from keep.api.core.db import
# engine` -- a name bound once at whichever moment keep.api.core.incidents is
# first imported, not a live read of keep.api.core.db.engine -- so
# get_last_incidents_by_cel() ends up pointed at whatever engine existed at
# that first import, not necessarily the db_session fixture's in-memory test
# engine. Depending on import order across the test session this makes any CEL
# query over incidents either work or raise "no such table: incident" for
# reasons unrelated to this file. That is a second, separate, pre-existing bug
# (not introduced by this branch, and not fixed here) -- flag it, but do not
# paper over it with a test that only sometimes runs.
