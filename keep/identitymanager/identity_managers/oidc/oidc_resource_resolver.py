"""
Resolve configured permission rules to concrete resource IDs.

This is the only part of the resource-permission feature that touches the
database. It turns configured rules into the concrete resource IDs the caller is
allowed to see.

Two resolution paths, because the two resource types speak different languages
-----------------------------------------------------------------------------
**Incidents (CEL).** The rule's CEL expression is handed to
`get_last_incidents_by_cel()`, so Keep's own translator produces the SQL. That
is what makes `service in ['postgres']` work at all: `affected_services` is a
JSON column, and JSON containment has no portable spelling --

    PostgreSQL  affected_services::jsonb @> '["postgres"]'
    MySQL       JSON_CONTAINS(affected_services, '"postgres"')
    SQLite      EXISTS (SELECT 1 FROM json_each(affected_services) ...)

-- so hand-writing it meant either breaking two dialects or maintaining three
code paths for a security-relevant filter. `keep/api/core/cel_to_sql/` already
has a provider per dialect and is exercised by the rest of the product.

**Presets (attribute matching).** Keep has no CEL query path over presets, and
they do not need one: `name` and `created_by` are scalar columns, `tag` is a
relationship, and a tenant has orders of magnitude fewer presets than incidents.
Rows are fetched and matched in Python by oidc_permissions.apply_rules().

Cost
----
Only a role that actually has rules pays anything; unrestricted roles return
before any query runs.

For incidents the filtering happens in SQL, so the cost is a query, not a scan,
and KEEP_RESOURCE_PERMISSIONS_MAX_SCAN now bounds **matched** rows rather than
scanned ones. That matters: a selective rule over a 500k-incident tenant returns
its few hundred matches and never approaches the cap, where the previous
implementation would have examined the newest 10000 rows and found whatever
happened to be among them.

The cap still exists because the upstream call sites take a list of IDs, so the
allowed set has to be enumerated. Truncation *narrows* what a restricted role
sees -- the safe direction -- but it is still wrong, so hitting it is logged as
an error rather than a warning.

What is left is paid once per (tenant, role, resource type) per TTL rather than
once per request, because the UI polls these routes every few seconds and the
answer does not vary per request. See oidc_permission_cache.py for the TTL and
what it does and does not guarantee.
"""

import logging
import os

from sqlmodel import Session, select

# Imported as a module, not `from ... import engine`: the engine is created at
# import time and is monkeypatched by the test fixtures, so binding the name here
# would pin the production engine.
from keep.api.consts import STATIC_PRESETS
from keep.api.core import db as core_db
from keep.api.core.incidents import get_last_incidents_by_cel
from keep.api.models.db.preset import Preset
from keep.identitymanager.identity_managers.oidc.oidc_permission_cache import (
    get_or_compute,
)
from keep.identitymanager.identity_managers.oidc.oidc_permissions import (
    DENY_ALL_SENTINEL_ID,
    RESOURCE_TYPE_INCIDENT,
    RESOURCE_TYPE_PRESET,
    apply_rules,
    get_rules_for,
    rules_version,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_SCAN = 10000


def _max_scan() -> int:
    raw = os.environ.get("KEEP_RESOURCE_PERMISSIONS_MAX_SCAN", "").strip()
    if not raw:
        return DEFAULT_MAX_SCAN
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "Invalid KEEP_RESOURCE_PERMISSIONS_MAX_SCAN %r, using %s",
            raw,
            DEFAULT_MAX_SCAN,
        )
        return DEFAULT_MAX_SCAN
    return value if value > 0 else DEFAULT_MAX_SCAN


def _resolve_incident_ids(tenant_id: str, rules, limit: int) -> list[str]:
    """
    Union of the incident IDs selected by each rule's CEL expression.

    Rules for the same role are ORed, which is done by running each rule and
    unioning the results rather than by joining the expressions with `||`:
    one malformed expression then fails loudly on its own instead of silently
    changing what a different, correct rule selects.

    `is_candidate=False` is not passed, and neither is any status filter: the
    caller intersects this list with its own query, which already applies those.
    Pre-filtering here would make a restricted role unable to reach views that
    the same role can reach when unrestricted.
    """
    allowed: list[str] = []
    seen: set[str] = set()

    for rule in rules:
        incidents, total_count = get_last_incidents_by_cel(
            tenant_id=tenant_id,
            cel=rule.cel,
            limit=limit,
            offset=0,
        )
        if total_count > limit:
            logger.error(
                "Resource permission rule for role %s matched %s incidents but "
                "KEEP_RESOURCE_PERMISSIONS_MAX_SCAN is %s; incidents beyond the "
                "newest %s are hidden from this role. CEL: %s",
                rule.role,
                total_count,
                limit,
                limit,
                rule.cel,
            )
        for incident in incidents:
            incident_id = str(incident.id)
            if incident_id not in seen:
                seen.add(incident_id)
                allowed.append(incident_id)

    if not allowed:
        # Restricted but matching nothing. Never [] -- see DENY_ALL_SENTINEL_ID.
        return [DENY_ALL_SENTINEL_ID]
    return allowed


def _fetch_preset_records(tenant_id: str, limit: int) -> list[dict]:
    """
    Project a tenant's presets onto the attribute keys rules match against.

    Presets are loaded as full ORM objects because `tags` is a relationship
    (lazy="joined"), and there are orders of magnitude fewer presets than
    incidents, so the projection saving is not worth a manual join here.
    """
    with Session(core_db.engine) as session:
        presets = (
            session.exec(
                select(Preset).where(Preset.tenant_id == tenant_id).limit(limit + 1)
            )
            .unique()
            .all()
        )

    if len(presets) > limit:
        logger.error(
            "Resource permission scan hit KEEP_RESOURCE_PERMISSIONS_MAX_SCAN (%s) "
            "for tenant %s; some presets are hidden from restricted roles",
            limit,
            tenant_id,
        )
        presets = presets[:limit]

    records = [
        {
            "id": preset.id,
            "name": preset.name,
            "tag": [tag.name for tag in (preset.tags or [])],
            "created_by": preset.created_by,
        }
        for preset in presets
    ]

    # Keep's built-in "feed" preset (STATIC_PRESETS["feed"]) isn't a database
    # row -- it's a fixed sentinel id, shown by keep/api/routes/preset.py only
    # when a role has no preset restriction at all. Once a role has ANY
    # preset rule, that sentinel can never appear in a query over real Preset
    # rows, so a role scoped to its own presets lost the default feed with no
    # way for an operator to grant it back. Projecting it into the same pool
    # real presets are matched against lets a rule opt a role back in
    # explicitly, e.g. match: {name: ["feed"]} -- an ordinary, auditable
    # configuration choice instead of a structural dead end.
    feed = STATIC_PRESETS["feed"]
    records.append(
        {
            "id": feed.id,
            "name": feed.name,
            "tag": [],
            "created_by": feed.created_by,
        }
    )
    return records


# Resource types whose rules are matched over fetched records. Incidents are
# absent on purpose: they are resolved by CEL through the query layer.
_FETCHERS = {
    RESOURCE_TYPE_PRESET: _fetch_preset_records,
}


def resolve_allowed_resource_ids(
    tenant_id: str, role: str, resource_type: str
) -> list[str]:
    """
    IDs of `resource_type` that `role` may see in `tenant_id`.

    Returns an empty list when the role is unrestricted, which the call sites
    read as "no limitations". When the role is restricted but nothing matches,
    the result is [DENY_ALL_SENTINEL_ID] instead, so "matches nothing" can never
    be mistaken for "unrestricted".

    Exceptions are intentionally not caught: because the contract is fail-open,
    swallowing a database error here would hand the caller an empty list and
    grant access to everything. A 500 is the correct outcome.
    """
    if not role or not tenant_id:
        # Should not happen for an authenticated entity; refuse to guess.
        raise ValueError(
            "Cannot resolve resource permissions without a tenant and a role"
        )

    rules = get_rules_for(role, resource_type)
    if not rules:
        # Unrestricted, and free already: a dict lookup, no query. Returning
        # before the cache keeps [] -- "no limitations" -- out of it entirely,
        # so an unrestricted role can never be served from a stale entry.
        return []

    limit = _max_scan()

    def _resolve() -> list[str]:
        if resource_type == RESOURCE_TYPE_INCIDENT:
            return _resolve_incident_ids(tenant_id, rules, limit)
        fetch = _FETCHERS.get(resource_type)
        if fetch is None:
            # get_rules_for() only returns rules for supported resource types, so
            # this is unreachable unless SUPPORTED_RESOURCE_TYPES, _FETCHERS and
            # the CEL branch above drift apart.
            raise ValueError(f"No resolver for resource type {resource_type!r}")
        return apply_rules(rules, fetch(tenant_id, limit))

    allowed, cached = get_or_compute(
        (tenant_id, role, resource_type), _resolve, version=rules_version()
    )
    logger.debug(
        "Resolved %s allowed %s ids for role %s (tenant %s) from %s rules (cached=%s)",
        len(allowed),
        resource_type,
        role,
        tenant_id,
        len(rules),
        cached,
    )
    return allowed
