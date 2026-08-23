"""
Resource-level permission rules for the generic OIDC identity manager.

A rule says "role R may see resources of type T selected by S". Rules are
attribute-based, never object-based: nobody grants access to an individual
incident, so a resource created after the rule was written is covered by it
automatically. Resolving a rule to concrete resource IDs happens at request
time, in oidc_resource_resolver.py.

**The selector language differs by resource type, and that is deliberate.**

    incident  ->  cel:    a CEL expression, handed to Keep's own query layer
    preset    ->  match:  attribute matching performed here

Incidents use CEL because Keep already has a tested, dialect-aware CEL-to-SQL
translator (keep/api/core/cel_to_sql/, with separate providers for SQLite,
MySQL and PostgreSQL). Hand-writing a matcher for them meant reimplementing JSON
containment three times over -- `affected_services` is a JSON column and the
three dialects spell "does this array contain X" incompatibly -- and it meant
scanning rows in Python, which is why an upper bound on scanned rows was needed
at all. Delegating removes both problems and deletes the code that had them.

Presets keep attribute matching because there is no CEL path over presets in
Keep, and they do not need one: their selectable attributes are scalar columns
and a relationship, there is no JSON containment involved, and a tenant has
orders of magnitude fewer presets than incidents.

Configuration (same pattern as KEEP_CUSTOM_ROLES in rbac.py):

    KEEP_RESOURCE_PERMISSIONS_FILE    path to a YAML or JSON file
    KEEP_RESOURCE_PERMISSIONS         the same content, inline JSON

A malformed rule set always aborts start-up; there is no opt-out. See
_load_rules() for why this one has no escape hatch.

File schema:

    rules:
      - role: dba
        resource_type: incident
        cel: "service in ['postgres', 'patroni']"
      - role: payments-oncall
        resource_type: preset
        match:
          name: [payments-*]

Precedence, in one place so it is not spread over three call sites:

  * Values of one match key are ORed      (name: [a, b]  -> a or b)
  * Different keys inside one match are ANDed
    (name: [a], created_by: [b] -> name a AND created_by b)
  * Several rules for the same (role, resource_type) are ORed
    (the allowed set is the union of the IDs each rule resolves to)
  * No rule at all for a (role, resource_type) means "unrestricted", which is
    the fail-open contract the upstream call sites document:
        # Note: if no limitations (allowed_preset_ids is []), then all presets are allowed

Because the contract is fail-open, "no rules" and "rules that match nothing"
must never be represented the same way. A role that is restricted but whose
rules match nothing resolves to DENY_ALL_SENTINEL_ID rather than to an empty
list -- see apply_rules() and resolve_allowed_resource_ids().
"""

import fnmatch
import json
import logging
import os
import re
from typing import Any, Iterable, Mapping, Sequence

import yaml

from keep.identitymanager.rbac import COMPOSITE_ROLE_SEPARATOR, get_all_roles

logger = logging.getLogger(__name__)

RESOURCE_TYPE_INCIDENT = "incident"
RESOURCE_TYPE_PRESET = "preset"

# Only the resource types that already have an enforcement call site in Keep.
# Adding a type here without a call site would create a rule that silently does
# nothing, which is the worst possible failure mode for an access-control rule.
SUPPORTED_RESOURCE_TYPES = (RESOURCE_TYPE_INCIDENT, RESOURCE_TYPE_PRESET)

# Which selector language each resource type uses. A type appears in exactly one
# of these, and build_rule() rejects a rule that uses the other one -- accepting
# both would mean two code paths per type and two ways to express the same
# restriction.
CEL_RESOURCE_TYPES = (RESOURCE_TYPE_INCIDENT,)
MATCH_RESOURCE_TYPES = (RESOURCE_TYPE_PRESET,)

# Attributes a `match:` rule may select on, per resource type. Keys are
# normalised names, not column names; oidc_resource_resolver.py maps columns onto
# them.
SUPPORTED_MATCH_KEYS: dict[str, tuple[str, ...]] = {
    RESOURCE_TYPE_PRESET: ("name", "tag", "created_by"),
}

# Returned instead of an empty list when a role is restricted but nothing
# matches. The upstream call sites read an empty list as "no limitations", so an
# empty list would turn "matches nothing" into "sees everything". This UUID is
# never produced by uuid4() and is not one of the static preset IDs, so it
# filters every real row out of `id IN (...)` while staying truthy.
DENY_ALL_SENTINEL_ID = "00000000-0000-0000-0000-000000000000"

ROLE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

# Characters that make a configured value a glob rather than a literal.
_GLOB_CHARS = ("*", "?", "[")


class ResourcePermissionConfigurationError(Exception):
    """Raised when KEEP_RESOURCE_PERMISSIONS / _FILE cannot be applied."""


def _normalize(value: Any) -> list[str]:
    """
    Flatten a resource attribute into a list of lower-cased strings.

    An attribute may be a scalar (status), a JSON list (affected_services) or
    None. Matching is case-insensitive because service, source and tag names
    reach Keep from many tools with inconsistent casing.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip().lower()] if value.strip() else []
    if isinstance(value, bool):
        return [str(value).lower()]
    if isinstance(value, (int, float)):
        return [str(value).lower()]
    if isinstance(value, (list, tuple, set)):
        flattened: list[str] = []
        for item in value:
            flattened.extend(_normalize(item))
        return flattened
    return [str(value).strip().lower()]


class PermissionRule:
    """
    One `rules:` entry. Immutable once built.

    Exactly one selector is populated: `cel` for the resource types in
    CEL_RESOURCE_TYPES, `match` for those in MATCH_RESOURCE_TYPES.
    """

    __slots__ = ("role", "resource_type", "match", "cel")

    def __init__(
        self,
        role: str,
        resource_type: str,
        match: Mapping[str, Sequence[str]] | None = None,
        cel: str | None = None,
    ) -> None:
        self.role = role
        self.resource_type = resource_type
        self.cel = cel
        self.match: dict[str, tuple[str, ...]] = {
            key: tuple(patterns) for key, patterns in (match or {}).items()
        }

    @property
    def is_cel(self) -> bool:
        return self.cel is not None

    def matches(self, attributes: Mapping[str, Any]) -> bool:
        """
        True when every match key is satisfied by `attributes` (keys ANDed,
        values within a key ORed).

        A key whose attribute is missing or empty is not satisfied, so an
        incomplete record is excluded rather than granted.

        Only meaningful for `match:` rules. A CEL rule is resolved by the
        database, never by this method, so calling it here is a programming
        error rather than a "no match".
        """
        if self.is_cel:
            raise TypeError(
                f"Rule for role {self.role!r} on {self.resource_type!r} is a CEL "
                "rule and must be resolved through the query layer, not matched "
                "in Python"
            )
        for key, patterns in self.match.items():
            candidates = _normalize(attributes.get(key))
            if not candidates:
                return False
            if not any(
                fnmatch.fnmatchcase(candidate, pattern)
                for pattern in patterns
                for candidate in candidates
            ):
                return False
        return True

    def describe(self) -> str:
        """Human-readable form, used for the read-only permissions listing."""
        if self.is_cel:
            return f"{self.resource_type} where {self.cel}"
        parts = [
            f"{key} in [{', '.join(patterns)}]" for key, patterns in self.match.items()
        ]
        return f"{self.resource_type} where " + " and ".join(parts)

    def __repr__(self) -> str:
        selector = f"cel={self.cel!r}" if self.is_cel else f"match={self.match!r}"
        return (
            f"PermissionRule(role={self.role!r}, "
            f"resource_type={self.resource_type!r}, {selector})"
        )


def _validate_cel_syntax(cel: str, role: str) -> None:
    """
    Parse a CEL expression so a typo fails at start-up rather than at request
    time, where it would surface as a 500 for one unlucky user.

    Keep's CEL parser pulls in celpy and lark. Both are ordinary Keep runtime
    dependencies, but they are absent in a bare unit-test environment, so the
    import is optional: without it the expression is still checked for being a
    non-empty string, and an invalid one fails closed later (the query raises,
    and nothing in the resolution path converts a failure into "unrestricted").
    """
    try:
        from keep.api.core.cel_to_sql.cel_ast_converter import CelToAstConverter
    except ImportError:  # pragma: no cover - depends on the environment
        logger.warning(
            "CEL parser unavailable; skipping syntax validation of the rule for "
            "role %s. Syntax errors will surface at query time instead.",
            role,
        )
        return

    try:
        CelToAstConverter.convert_to_ast(cel)
    except Exception as exc:
        raise ResourcePermissionConfigurationError(
            f"Invalid CEL in rule for role {role!r}: {cel!r} ({exc})"
        ) from exc


def build_rule(definition: Any) -> PermissionRule:
    """
    Validate one rule definition and turn it into a PermissionRule.

    Strict on purpose, like register_role() in rbac.py: a rule that is silently
    dropped surfaces later as a user seeing data they should not see, which is
    far harder to notice than a failed start-up.
    """
    if not isinstance(definition, dict):
        raise ResourcePermissionConfigurationError(
            f"Rule must be a mapping, got {definition!r}"
        )

    role = definition.get("role")
    if not isinstance(role, str) or not ROLE_NAME_PATTERN.match(role):
        raise ResourcePermissionConfigurationError(
            f"Invalid role {role!r} in rule {definition!r}: "
            f"expected {ROLE_NAME_PATTERN.pattern}"
        )
    known_roles = get_all_roles()
    if role not in known_roles:
        raise ResourcePermissionConfigurationError(
            f"Rule refers to unknown role {role!r}. Known roles: "
            f"{sorted(known_roles)}. Define it via KEEP_CUSTOM_ROLES first."
        )

    resource_type = definition.get("resource_type")
    if resource_type not in SUPPORTED_RESOURCE_TYPES:
        raise ResourcePermissionConfigurationError(
            f"Unsupported resource_type {resource_type!r} for role {role!r}: "
            f"expected one of {list(SUPPORTED_RESOURCE_TYPES)}"
        )

    raw_cel = definition.get("cel")
    raw_match = definition.get("match")

    # Reject the wrong selector explicitly. Ignoring it would silently apply a
    # rule the author did not write -- e.g. a `match:` block on an incident rule
    # would be dropped, leaving a rule with no restriction at all.
    if resource_type in CEL_RESOURCE_TYPES:
        if raw_match is not None:
            raise ResourcePermissionConfigurationError(
                f"Rule for role {role!r} on {resource_type!r} uses 'match', but "
                f"{resource_type!r} rules are written in CEL. Use "
                "cel: \"service in ['postgres']\" instead."
            )
        if not isinstance(raw_cel, str) or not raw_cel.strip():
            raise ResourcePermissionConfigurationError(
                f"Rule for role {role!r} on {resource_type!r} needs a non-empty "
                "'cel' expression. An empty selector is ambiguous between "
                "'everything' and 'nothing'."
            )
        cel = raw_cel.strip()
        _validate_cel_syntax(cel, role)
        return PermissionRule(role=role, resource_type=resource_type, cel=cel)

    if raw_cel is not None:
        raise ResourcePermissionConfigurationError(
            f"Rule for role {role!r} on {resource_type!r} uses 'cel', but "
            f"{resource_type!r} rules are written with 'match'. Keep has no CEL "
            f"query path over {resource_type!r}."
        )
    if not isinstance(raw_match, dict) or not raw_match:
        raise ResourcePermissionConfigurationError(
            f"Rule for role {role!r} on {resource_type!r} has an empty match block. "
            "An empty match is ambiguous between 'everything' and 'nothing'."
        )

    allowed_keys = SUPPORTED_MATCH_KEYS[resource_type]
    match: dict[str, tuple[str, ...]] = {}
    for key, raw_values in raw_match.items():
        if key not in allowed_keys:
            raise ResourcePermissionConfigurationError(
                f"Unsupported match key {key!r} for resource_type "
                f"{resource_type!r}: expected one of {list(allowed_keys)}"
            )
        if isinstance(raw_values, (str, int, float)) and not isinstance(
            raw_values, bool
        ):
            raw_values = [raw_values]
        if not isinstance(raw_values, (list, tuple)) or not raw_values:
            raise ResourcePermissionConfigurationError(
                f"Match key {key!r} for role {role!r} must be a non-empty "
                f"string or list, got {raw_values!r}"
            )
        patterns: list[str] = []
        for value in raw_values:
            if isinstance(value, bool) or not isinstance(value, (str, int, float)):
                raise ResourcePermissionConfigurationError(
                    f"Match value {value!r} for key {key!r} (role {role!r}) "
                    "must be a string or a number"
                )
            pattern = str(value).strip().lower()
            if not pattern:
                raise ResourcePermissionConfigurationError(
                    f"Empty match value for key {key!r} (role {role!r})"
                )
            patterns.append(pattern)
        match[key] = tuple(patterns)

    return PermissionRule(role=role, resource_type=resource_type, match=match)


def apply_rules(
    rules: Sequence[PermissionRule], records: Iterable[Mapping[str, Any]]
) -> list[str]:
    """
    Resolve a rule set against already-fetched resource records.

    `records` are plain mappings with an "id" key plus the attribute keys listed
    in SUPPORTED_MATCH_KEYS; keeping this function free of ORM objects is what
    lets the whole matching path be unit-tested without a database.

    Returns:
        []                        when `rules` is empty (unrestricted)
        [DENY_ALL_SENTINEL_ID]    when rules exist but nothing matched
        [id, ...]                 the matching IDs, in the order records arrived
    """
    if not rules:
        # No rules configured for this (role, resource_type): unrestricted, the
        # upstream fail-open contract.
        return []

    allowed: list[str] = []
    seen: set[str] = set()
    for record in records:
        record_id = record.get("id")
        if record_id is None:
            continue
        record_id = str(record_id)
        if record_id in seen:
            continue
        # Rules for the same (role, resource_type) are ORed.
        if any(rule.matches(record) for rule in rules):
            seen.add(record_id)
            allowed.append(record_id)

    if not allowed:
        return [DENY_ALL_SENTINEL_ID]
    return allowed


# --------------------------------------------------------------------------- #
# Configuration loading
# --------------------------------------------------------------------------- #

# Keyed by (role, resource_type) because that is exactly the lookup every call
# site performs.
_RULE_REGISTRY: dict[tuple[str, str], list[PermissionRule]] = {}


def register_rule(rule: PermissionRule) -> None:
    _RULE_REGISTRY.setdefault((rule.role, rule.resource_type), []).append(rule)


def get_rules_for(role: str, resource_type: str) -> list[PermissionRule]:
    """
    Rules restricting `role` on `resource_type`; empty means unrestricted.

    A composite role ("team-a+team-b", produced by the verifier in
    KEEP_OIDC_ROLE_COMPOSITION=union mode) expands to its members with
    unrestricted-wins semantics: if ANY member has no rules for this resource
    type, that member alone would see everything, so the composite must too —
    returning the other members' rules instead would make belonging to two
    teams grant LESS than belonging to one. When every member is restricted,
    the members' rules concatenate and the resolver ORs them as usual.
    """
    if COMPOSITE_ROLE_SEPARATOR in role:
        combined: list[PermissionRule] = []
        for member in role.split(COMPOSITE_ROLE_SEPARATOR):
            member_rules = _RULE_REGISTRY.get((member, resource_type))
            if not member_rules:
                return []
            combined.extend(member_rules)
        return combined
    return list(_RULE_REGISTRY.get((role, resource_type), ()))


def get_all_rules() -> list[PermissionRule]:
    """Every configured rule, in configuration order per (role, resource_type)."""
    rules: list[PermissionRule] = []
    for bucket in _RULE_REGISTRY.values():
        rules.extend(bucket)
    return rules


def has_rules() -> bool:
    return bool(_RULE_REGISTRY)


def _read_rule_definitions() -> list[dict]:
    """
    Read rule definitions from KEEP_RESOURCE_PERMISSIONS_FILE (JSON or YAML) and
    KEEP_RESOURCE_PERMISSIONS (inline JSON). Both may be set; file is applied
    first. Either source may be a bare list or a mapping with a "rules" key.
    """
    definitions: list[dict] = []

    path = os.environ.get("KEEP_RESOURCE_PERMISSIONS_FILE", "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                # yaml.safe_load also parses JSON.
                parsed = yaml.safe_load(handle) or []
        except OSError as exc:
            raise ResourcePermissionConfigurationError(
                f"Cannot read KEEP_RESOURCE_PERMISSIONS_FILE {path!r}: {exc}"
            ) from exc
        except yaml.YAMLError as exc:
            raise ResourcePermissionConfigurationError(
                f"Cannot parse KEEP_RESOURCE_PERMISSIONS_FILE {path!r}: {exc}"
            ) from exc
        if isinstance(parsed, dict):
            # Insist on the key rather than defaulting to []: a typo in the top
            # level key would otherwise load zero rules, and zero rules means
            # every role is unrestricted.
            if "rules" not in parsed:
                raise ResourcePermissionConfigurationError(
                    f"KEEP_RESOURCE_PERMISSIONS_FILE {path!r} is a mapping without "
                    "a 'rules' key"
                )
            parsed = parsed["rules"]
        if not isinstance(parsed, list):
            raise ResourcePermissionConfigurationError(
                f"KEEP_RESOURCE_PERMISSIONS_FILE {path!r} must contain a list of rules"
            )
        definitions.extend(parsed)

    inline = os.environ.get("KEEP_RESOURCE_PERMISSIONS", "").strip()
    if inline:
        try:
            parsed = json.loads(inline)
        except ValueError as exc:
            raise ResourcePermissionConfigurationError(
                f"Cannot parse KEEP_RESOURCE_PERMISSIONS as JSON: {exc}"
            ) from exc
        if isinstance(parsed, dict):
            if "rules" not in parsed:
                raise ResourcePermissionConfigurationError(
                    "KEEP_RESOURCE_PERMISSIONS is a mapping without a 'rules' key"
                )
            parsed = parsed["rules"]
        if not isinstance(parsed, list):
            raise ResourcePermissionConfigurationError(
                "KEEP_RESOURCE_PERMISSIONS must be a list of rules"
            )
        definitions.extend(parsed)

    return definitions


def _load_rules() -> None:
    """
    Populate the rule registry from configuration.

    A malformed rule set always aborts start-up. There is deliberately no
    "continue anyway" switch, unlike KEEP_CUSTOM_ROLES_STRICT.

    The asymmetry that motivated removing it: dropping custom roles degrades
    CLOSED (an unknown role gets 403 and someone notices within seconds),
    whereas dropping restriction rules degrades OPEN -- every role silently sees
    everything, with no error, no failed request, and a healthy-looking UI. An
    escape hatch that is reached for during an outage must not be the one that
    quietly removes an access control.

    Aborting is safe in a rolling deployment: the new pod never becomes ready,
    the previous pods keep serving with the rule set they loaded at their own
    start-up, and the rollout stalls instead of degrading. Catching bad rules
    before they reach a cluster belongs in CI, which is not built yet.
    """
    for definition in _read_rule_definitions():
        register_rule(build_rule(definition))

    if _RULE_REGISTRY:
        logger.info(
            "Loaded %s resource permission rules for %s (role, resource_type) pairs",
            len(get_all_rules()),
            len(_RULE_REGISTRY),
        )


_load_rules()
