# Most simple and naive RBAC implementation
# Got the inspiration from Auth0 -
# - https://github.com/auth0-developer-hub/api_fastapi_python_hello-world
# - https://developer.auth0.com/resources/code-samples/api/fastapi/basic-role-based-access-control#set-up-role-based-access-control-rbac

# The scope convention {verb}:{resource} is inspired by Auth0's RBAC

# Note that since we don't use Auth0's RBAC, I just took the concepts but left the implementation more simple

# TODO: move resources (alert, rule, etc.) to class constants
# TODO: move verbs (read, write, delete, update) to class constants
# TODO: implement a solid RBAC mechanism (probably OPA over Keycloak)

# Custom roles are supported through a registry populated at import time from
# KEEP_CUSTOM_ROLES / KEEP_CUSTOM_ROLES_FILE. Generated role classes are injected
# into this module's namespace on purpose: identitymanager.py builds
# PREDEFINED_ROLES by running inspect.getmembers() over this module, so a role
# that is only in the registry would authorize correctly but stay invisible to
# the roles API and the UI.


import enum
import json
import logging
import os
import re

import yaml
from fastapi import HTTPException

logger = logging.getLogger(__name__)

# Scopes are "{verb}:{resource}"; the resource may be "*".
SCOPE_PATTERN = re.compile(r"^[a-z]+:[a-z0-9_*-]+$")
# Role names travel in JWT claims, headers and the DB, so keep them boring.
ROLE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


class Roles(enum.Enum):
    ADMIN = "admin"
    NOC = "noc"
    WEBHOOK = "webhook"
    WORKFLOW_RUNNER = "workflowrunner"


class Role:
    @classmethod
    def get_name(cls):
        return cls.__name__.lower()

    @classmethod
    def has_scopes(cls, scopes: list[str]) -> bool:
        required_scopes = set(scopes)
        available_scopes = set(cls.SCOPES)

        for scope in required_scopes:
            # First, check if the scope is available
            if scope in available_scopes:
                # Exact match, on to the next scope
                continue

            # If not, check if there's a wildcard permission for this action
            scope_parts = scope.split(":")
            if len(scope_parts) != 2:
                return False  # Invalid scope format
            action, resource = scope_parts
            if f"{action}:*" not in available_scopes:
                return False  # No wildcard permission for this action
        # All scopes are available
        return True


# Noc has read permissions and it can assign itself to alert
class Noc(Role):
    SCOPES = ["read:*", "execute:workflows"]
    DESCRIPTION = "read permissions and assign itself to alert"


# Admin has all permissions
class Admin(Role):
    SCOPES = ["read:*", "write:*", "delete:*", "update:*", "execute:*"]
    DESCRIPTION = "do everything"


# Webhook has write:alert permission to write alerts
# this is internal role used by API keys
class Webhook(Role):
    SCOPES = ["write:alert", "write:incident"]
    DESCRIPTION = "write alerts using API keys"


class WorkflowRunner(Role):
    SCOPES = ["write:workflows", "execute:workflows"]
    DESCRIPTION = "Run workflows using API keys"


BUILTIN_ROLES: dict[str, type] = {
    Roles.ADMIN.value: Admin,
    Roles.NOC.value: Noc,
    Roles.WEBHOOK.value: Webhook,
    Roles.WORKFLOW_RUNNER.value: WorkflowRunner,
}

# Built-ins first; custom roles are added by _load_custom_roles() below.
_ROLE_REGISTRY: dict[str, type] = dict(BUILTIN_ROLES)


def get_role_by_role_name(role_name: str) -> type:
    role = _ROLE_REGISTRY.get(role_name)
    if role is None:
        raise HTTPException(
            status_code=403,
            detail=f"Role {role_name} not found",
        )
    return role


def get_all_roles() -> dict[str, type]:
    """Every role known to this process, built-in and custom."""
    return dict(_ROLE_REGISTRY)


class CustomRoleConfigurationError(Exception):
    """Raised when KEEP_CUSTOM_ROLES / KEEP_CUSTOM_ROLES_FILE cannot be applied."""


def _class_attr_name(role_name: str) -> str:
    """Turn a role name into a unique CamelCase attribute name for this module."""
    base = "".join(part.title() for part in re.split(r"[^0-9a-zA-Z]+", role_name) if part)
    base = base or "CustomRole"
    candidate = base
    suffix = 2
    while candidate in globals():
        candidate = f"{base}{suffix}"
        suffix += 1
    return candidate


COMPOSITE_ROLE_SEPARATOR = "+"


def get_or_register_composite_role(member_roles: list[str]) -> str:
    """
    Register (idempotently) a composite of already-registered roles and return
    its canonical name: the sorted member names joined with "+".

    Composites exist for OIDC users whose token carries several mapped groups
    (KEEP_OIDC_ROLE_COMPOSITION=union): the composite's scopes are the union of
    the members' scopes, and the resource-permission lookup expands the name
    back into its members (see oidc_permissions.get_rules_for). The separator
    is deliberately a character ROLE_NAME_PATTERN rejects, so an
    operator-defined role can never collide with a composite name.
    """
    members = sorted(set(member_roles))
    if len(members) < 2:
        raise ValueError("A composite role needs at least two distinct members")
    name = COMPOSITE_ROLE_SEPARATOR.join(members)
    if name in _ROLE_REGISTRY:
        return name

    scopes: list[str] = []
    for member in members:
        # Raises 403 for an unknown member; the verifier resolves members from
        # validated mappings, so this only fires on registry drift.
        member_class = get_role_by_role_name(member)
        for scope in member_class.SCOPES:
            if scope not in scopes:
                scopes.append(scope)

    attr_name = _class_attr_name(name)
    role_class = type(
        attr_name,
        (Role,),
        {
            "SCOPES": scopes,
            "DESCRIPTION": f"composite of {', '.join(members)}",
            "ROLE_NAME": name,
            "COMPOSITE_OF": tuple(members),
            "get_name": classmethod(lambda cls: cls.ROLE_NAME),
        },
    )
    globals()[attr_name] = role_class
    _ROLE_REGISTRY[name] = role_class
    logger.info("Registered composite role %s with scopes %s", name, scopes)
    return name


def register_role(role_name: str, scopes: list[str], description: str = "") -> type:
    """
    Register a custom role and expose it as a class on this module.

    Returns the generated class. Raises CustomRoleConfigurationError on anything
    malformed — a half-applied role set is worse than a failed start, because the
    missing role surfaces later as an unexplained 403 for real users.
    """
    if not isinstance(role_name, str) or not ROLE_NAME_PATTERN.match(role_name):
        raise CustomRoleConfigurationError(
            f"Invalid role name {role_name!r}: expected {ROLE_NAME_PATTERN.pattern}"
        )
    if role_name in BUILTIN_ROLES:
        raise CustomRoleConfigurationError(
            f"Role {role_name!r} is built-in and cannot be redefined"
        )
    if role_name in _ROLE_REGISTRY:
        raise CustomRoleConfigurationError(f"Role {role_name!r} is defined twice")
    if not isinstance(scopes, list) or not scopes:
        raise CustomRoleConfigurationError(f"Role {role_name!r} has no scopes")
    for scope in scopes:
        if not isinstance(scope, str) or not SCOPE_PATTERN.match(scope):
            raise CustomRoleConfigurationError(
                f"Role {role_name!r} has invalid scope {scope!r}: expected {{verb}}:{{resource}}"
            )

    attr_name = _class_attr_name(role_name)
    role_class = type(
        attr_name,
        (Role,),
        {
            "SCOPES": list(scopes),
            "DESCRIPTION": description or f"custom role {role_name}",
            "ROLE_NAME": role_name,
            # Role.get_name() derives the name from __name__, which would lose
            # any character that is not valid in a Python identifier.
            "get_name": classmethod(lambda cls: cls.ROLE_NAME),
        },
    )
    globals()[attr_name] = role_class
    _ROLE_REGISTRY[role_name] = role_class
    logger.info("Registered custom role %s with scopes %s", role_name, scopes)
    return role_class


def _read_custom_role_definitions() -> list[dict]:
    """
    Read role definitions from KEEP_CUSTOM_ROLES (inline JSON) and
    KEEP_CUSTOM_ROLES_FILE (JSON or YAML). Both may be set; file is applied first.

    Expected shape, in either source:
        [{"name": "dba", "scopes": ["read:*"], "description": "..."}]
    """
    definitions: list[dict] = []

    path = os.environ.get("KEEP_CUSTOM_ROLES_FILE", "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                # yaml.safe_load also parses JSON.
                parsed = yaml.safe_load(handle) or []
        except OSError as exc:
            raise CustomRoleConfigurationError(
                f"Cannot read KEEP_CUSTOM_ROLES_FILE {path!r}: {exc}"
            ) from exc
        except yaml.YAMLError as exc:
            raise CustomRoleConfigurationError(
                f"Cannot parse KEEP_CUSTOM_ROLES_FILE {path!r}: {exc}"
            ) from exc
        if isinstance(parsed, dict):
            parsed = parsed.get("roles", [])
        if not isinstance(parsed, list):
            raise CustomRoleConfigurationError(
                f"KEEP_CUSTOM_ROLES_FILE {path!r} must contain a list of roles"
            )
        definitions.extend(parsed)

    inline = os.environ.get("KEEP_CUSTOM_ROLES", "").strip()
    if inline:
        try:
            parsed = json.loads(inline)
        except ValueError as exc:
            raise CustomRoleConfigurationError(
                f"Cannot parse KEEP_CUSTOM_ROLES as JSON: {exc}"
            ) from exc
        if isinstance(parsed, dict):
            parsed = parsed.get("roles", [])
        if not isinstance(parsed, list):
            raise CustomRoleConfigurationError(
                "KEEP_CUSTOM_ROLES must be a list of roles"
            )
        definitions.extend(parsed)

    return definitions


def _load_custom_roles() -> None:
    """
    Populate the registry from configuration.

    Strict by default: a malformed role set aborts start-up. Set
    KEEP_CUSTOM_ROLES_STRICT=false to log and continue with built-ins only —
    that degrades closed (unknown roles get 403), but it degrades silently.
    """
    strict = os.environ.get("KEEP_CUSTOM_ROLES_STRICT", "true").lower() != "false"
    try:
        for definition in _read_custom_role_definitions():
            if not isinstance(definition, dict):
                raise CustomRoleConfigurationError(
                    f"Role definition must be a mapping, got {definition!r}"
                )
            register_role(
                definition.get("name"),
                definition.get("scopes"),
                definition.get("description", ""),
            )
    except CustomRoleConfigurationError:
        if strict:
            raise
        logger.exception("Failed to load custom roles; continuing with built-ins only")


_load_custom_roles()
