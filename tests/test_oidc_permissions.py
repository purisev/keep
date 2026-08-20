"""
Unit tests for the OIDC resource-permission rules.

These tests exercise configuration parsing, validation, the rule-language split
between resource types, and preset attribute matching. They deliberately do not
touch the database.

Note what is and is not covered here after the move to CEL. Incident selection
is now performed by Keep's own CEL-to-SQL layer, so it cannot be exercised
without a database; what remains testable here is that incident rules are
*accepted, rejected and stored* correctly, and that they are never matched in
Python by accident. The behaviour of the resulting query lives in
tests/test_oidc_resource_resolver.py, which needs a live DB.

The file is a normal pytest module and is also runnable directly
(`python3 tests/test_oidc_permissions.py`) so it can be checked in environments
where the full Keep test dependency set is not installed.
"""

import importlib
import json
import os
import sys
import tempfile

import pytest

# Running this file directly puts tests/ on sys.path, not the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TENANT = "keep"

# Captured once at collection time, before any fresh() reload. Other modules
# (oidc_resource_resolver.py, tests/test_oidc_resource_resolver.py) bind
# `rbac`/`oidc_permissions` names at their OWN first import -- also collection
# time, to these same original instances. fresh() below swaps new module
# objects into sys.modules on every call; without restoring the originals
# afterward, any test file that runs later in the same pytest process and
# reads through one of those stale bound references (e.g.
# oidc_resource_resolver.get_last_incidents_by_cel's sibling
# apply_rules/get_rules_for, or oidc_permissions.build_rule()'s internal
# get_all_roles() call) desyncs from whatever this file's fresh() last left in
# sys.modules, producing spurious "unknown role" errors with no relation to
# whatever that later file is actually testing.
_ORIGINAL_RBAC = importlib.import_module("keep.identitymanager.rbac")
_ORIGINAL_OIDC_PERMISSIONS = importlib.import_module(
    "keep.identitymanager.identity_managers.oidc.oidc_permissions"
)


@pytest.fixture(autouse=True)
def _restore_original_modules():
    yield
    # Reimporting a submodule doesn't just replace the sys.modules entry --
    # it also overwrites the PARENT PACKAGE's own attribute of the same name
    # (e.g. keep.identitymanager.rbac as an attribute on the keep.identitymanager
    # package object). `from keep.identitymanager import rbac`-style imports
    # resolve through that attribute, not through sys.modules, so both have to
    # be restored or a fresh() call from this file leaves a stale module
    # reachable via attribute access even after sys.modules looks correct.
    sys.modules["keep.identitymanager.rbac"] = _ORIGINAL_RBAC
    sys.modules["keep.identitymanager"].rbac = _ORIGINAL_RBAC
    sys.modules[
        "keep.identitymanager.identity_managers.oidc.oidc_permissions"
    ] = _ORIGINAL_OIDC_PERMISSIONS
    sys.modules[
        "keep.identitymanager.identity_managers.oidc"
    ].oidc_permissions = _ORIGINAL_OIDC_PERMISSIONS

# Roles the rules refer to must exist in the rbac registry, so every reload
# registers them through the same KEEP_CUSTOM_ROLES path production uses.
CUSTOM_ROLES = json.dumps(
    [
        {"name": "dba", "scopes": ["read:*"]},
        {"name": "payments-oncall", "scopes": ["read:*"]},
    ]
)


def fresh(**env):
    """Reload rbac and oidc_permissions with a clean, explicit environment."""
    for key in list(os.environ):
        if key.startswith("KEEP_RESOURCE_PERMISSIONS") or key.startswith(
            "KEEP_CUSTOM_ROLES"
        ):
            del os.environ[key]
    os.environ["KEEP_CUSTOM_ROLES"] = CUSTOM_ROLES
    os.environ.update(env)
    # rbac must be reloaded too: oidc_permissions binds get_all_roles at import
    # time, and role validation has to see the roles registered above.
    sys.modules.pop("keep.identitymanager.rbac", None)
    sys.modules.pop(
        "keep.identitymanager.identity_managers.oidc.oidc_permissions", None
    )
    return importlib.import_module(
        "keep.identitymanager.identity_managers.oidc.oidc_permissions"
    )


def assert_config_error(why, **env):
    """
    Assert that loading `env` raises ResourcePermissionConfigurationError.

    Matched by class name rather than by identity: fresh() reloads the module,
    so each reload produces a distinct exception class object.
    """
    try:
        fresh(**env)
    except Exception as exc:  # noqa: BLE001 - identity-independent check
        assert (
            type(exc).__name__ == "ResourcePermissionConfigurationError"
        ), f"{why}: unexpected {type(exc).__name__}: {exc}"
        return
    raise AssertionError(f"malformed config accepted: {why}")


PRESETS = [
    {
        "id": "aaaaaaaa-0000-0000-0000-000000000001",
        "name": "payments-firing",
        "tag": ["payments"],
        "created_by": "alice@example.com",
    },
    {
        "id": "aaaaaaaa-0000-0000-0000-000000000002",
        "name": "payments-resolved",
        "tag": [],
        "created_by": "bob@example.com",
    },
    {
        "id": "aaaaaaaa-0000-0000-0000-000000000003",
        "name": "infra-overview",
        "tag": ["payments"],
        "created_by": "alice@example.com",
    },
]

PRESET_IDS = {preset["name"]: preset["id"] for preset in PRESETS}


def rules_json(*rules):
    return json.dumps({"rules": list(rules)})


def preset_rule(role, **match):
    return {"role": role, "resource_type": "preset", "match": match}


def incident_rule(role, cel):
    return {"role": role, "resource_type": "incident", "cel": cel}


def resolve_presets(module, role):
    """Run the preset rules for `role` over PRESETS, as the resolver would."""
    return module.apply_rules(module.get_rules_for(role, "preset"), PRESETS)


# --------------------------------------------------------------------------- #
# The fail-open contract
# --------------------------------------------------------------------------- #


def test_no_config_means_unrestricted():
    module = fresh()
    assert module.get_all_rules() == []
    assert module.get_rules_for("dba", "preset") == []
    assert module.get_rules_for("dba", "incident") == []
    # An empty list is how the call sites spell "no limitations".
    assert resolve_presets(module, "dba") == []


def test_matching_nothing_denies_instead_of_allowing_everything():
    """
    The single most dangerous case: a role IS restricted but nothing matches.

    Returning [] here would read as "unrestricted" at the call site and grant
    access to every preset, so the sentinel must come back instead.
    """
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(preset_rule("dba", name=["nothing-*"]))
    )
    allowed = resolve_presets(module, "dba")
    assert allowed == [module.DENY_ALL_SENTINEL_ID]
    assert allowed, "must stay truthy, otherwise the call site reads it as unrestricted"
    for preset in PRESETS:
        assert preset["id"] not in allowed


def test_a_role_restricted_on_one_type_is_unrestricted_on_the_other():
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(preset_rule("dba", name=["infra-*"]))
    )
    assert resolve_presets(module, "dba") == [PRESET_IDS["infra-overview"]]
    assert module.get_rules_for("dba", "incident") == []


# --------------------------------------------------------------------------- #
# The rule-language split
# --------------------------------------------------------------------------- #


def test_incident_rules_are_cel_and_stored_verbatim():
    cel = "service in ['postgres', 'patroni']"
    module = fresh(KEEP_RESOURCE_PERMISSIONS=rules_json(incident_rule("dba", cel)))
    rules = module.get_rules_for("dba", "incident")
    assert len(rules) == 1
    assert rules[0].is_cel is True
    assert rules[0].cel == cel, "the expression must reach the query layer unchanged"
    assert rules[0].match == {}


def test_incident_rule_with_match_is_rejected():
    """
    Silently ignoring the wrong selector would leave a rule with no restriction
    at all, which is the fail-open direction.
    """
    assert_config_error(
        "incident rule using match",
        KEEP_RESOURCE_PERMISSIONS=rules_json(
            {
                "role": "dba",
                "resource_type": "incident",
                "match": {"service": ["postgres"]},
            }
        ),
    )


def test_preset_rule_with_cel_is_rejected():
    """Keep has no CEL query path over presets, so accepting it would do nothing."""
    assert_config_error(
        "preset rule using cel",
        KEEP_RESOURCE_PERMISSIONS=rules_json(
            {
                "role": "payments-oncall",
                "resource_type": "preset",
                "cel": "name.startsWith('payments')",
            }
        ),
    )


def test_cel_rule_is_never_matched_in_python():
    """
    A CEL rule reaching apply_rules() means a resolver branch is wrong. It must
    fail loudly rather than return False, which would silently deny everything.
    """
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(incident_rule("dba", "service == 'x'"))
    )
    rule = module.get_rules_for("dba", "incident")[0]
    try:
        rule.matches({"service": ["x"]})
    except TypeError:
        return
    raise AssertionError("a CEL rule was matched in Python instead of raising")


def test_empty_cel_is_rejected():
    for bad in ("", "   ", None, 42):
        assert_config_error(
            f"cel={bad!r}",
            KEEP_RESOURCE_PERMISSIONS=rules_json(
                {"role": "dba", "resource_type": "incident", "cel": bad}
            ),
        )


# --------------------------------------------------------------------------- #
# Preset attribute matching
# --------------------------------------------------------------------------- #


def test_preset_name_glob():
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(preset_rule("payments-oncall", name=["payments-*"]))
    )
    allowed = resolve_presets(module, "payments-oncall")
    assert PRESET_IDS["payments-firing"] in allowed
    assert PRESET_IDS["payments-resolved"] in allowed
    assert PRESET_IDS["infra-overview"] not in allowed


def test_keys_are_anded_and_values_are_ored():
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(
            preset_rule(
                "dba",
                name=["payments-*", "infra-*"],
                created_by=["alice@example.com"],
            )
        )
    )
    allowed = resolve_presets(module, "dba")
    # Both name patterns match, but only alice's presets satisfy the AND.
    assert PRESET_IDS["payments-firing"] in allowed
    assert PRESET_IDS["infra-overview"] in allowed
    assert PRESET_IDS["payments-resolved"] not in allowed


def test_multiple_rules_are_ored():
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(
            preset_rule("dba", name=["infra-*"]),
            preset_rule("dba", created_by=["bob@example.com"]),
        )
    )
    allowed = resolve_presets(module, "dba")
    assert PRESET_IDS["infra-overview"] in allowed
    assert PRESET_IDS["payments-resolved"] in allowed
    assert PRESET_IDS["payments-firing"] not in allowed


def test_preset_tag_matching():
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(preset_rule("dba", tag=["payments"]))
    )
    allowed = resolve_presets(module, "dba")
    assert PRESET_IDS["payments-firing"] in allowed
    assert PRESET_IDS["infra-overview"] in allowed
    # No tags at all must not match a tag rule.
    assert PRESET_IDS["payments-resolved"] not in allowed


def test_matching_is_case_insensitive():
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(
            preset_rule("dba", created_by=["ALICE@Example.COM"])
        )
    )
    allowed = resolve_presets(module, "dba")
    assert PRESET_IDS["payments-firing"] in allowed


def test_missing_or_empty_attribute_never_matches():
    """An incomplete record must be excluded, not granted."""
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(preset_rule("dba", tag=["*"]))
    )
    rule = module.get_rules_for("dba", "preset")[0]
    assert rule.matches({"tag": ["anything"]}) is True
    assert rule.matches({"tag": []}) is False
    assert rule.matches({"tag": None}) is False
    assert rule.matches({}) is False


def test_records_without_id_are_skipped_not_allowed():
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(preset_rule("dba", name=["*"]))
    )
    rules = module.get_rules_for("dba", "preset")
    allowed = module.apply_rules(rules, [{"name": "no-id-here"}])
    assert allowed == [module.DENY_ALL_SENTINEL_ID]


def test_scalar_match_value_is_accepted():
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(
            {
                "role": "dba",
                "resource_type": "preset",
                "match": {"name": "infra-overview"},
            }
        )
    )
    assert resolve_presets(module, "dba") == [PRESET_IDS["infra-overview"]]


# --------------------------------------------------------------------------- #
# Configuration sources and validation
# --------------------------------------------------------------------------- #


def test_yaml_file_source():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        handle.write(
            "rules:\n"
            "  - role: dba\n"
            "    resource_type: incident\n"
            "    cel: \"service == 'postgres'\"\n"
            "  - role: payments-oncall\n"
            "    resource_type: preset\n"
            "    match:\n"
            "      name: ['payments-*']\n"
        )
        path = handle.name

    module = fresh(KEEP_RESOURCE_PERMISSIONS_FILE=path)
    assert len(module.get_all_rules()) == 2
    assert module.get_rules_for("dba", "incident")[0].cel == "service == 'postgres'"
    assert PRESET_IDS["payments-firing"] in resolve_presets(module, "payments-oncall")


def test_strict_validation_rejects_malformed_config():
    cases = {
        "not a mapping or list": "true",
        "rule is not a mapping": rules_json("dba"),
        "unknown role": rules_json(incident_rule("nosuchrole", "service == 'x'")),
        "invalid role name": rules_json(incident_rule("DBA", "service == 'x'")),
        "unsupported resource_type": rules_json(
            {"role": "dba", "resource_type": "alert", "cel": "service == 'x'"}
        ),
        "missing selector entirely": rules_json(
            {"role": "dba", "resource_type": "preset"}
        ),
        "empty match block": rules_json({
            "role": "dba", "resource_type": "preset", "match": {}
        }),
        "unsupported match key": rules_json(preset_rule("dba", nope=["x"])),
        "empty match value list": rules_json(preset_rule("dba", name=[])),
        "empty match value string": rules_json(preset_rule("dba", name=[""])),
        "boolean match value": rules_json(preset_rule("dba", name=[True])),
        "malformed json": "{not json",
        "top-level key typo": json.dumps({"rulez": [preset_rule("dba", name=["x"])]}),
    }
    for why, payload in cases.items():
        assert_config_error(why, KEEP_RESOURCE_PERMISSIONS=payload)


def test_there_is_no_way_to_continue_with_a_broken_rule_set():
    """
    A malformed rule set must abort start-up unconditionally.

    There used to be a KEEP_RESOURCE_PERMISSIONS_STRICT=false escape hatch. It
    was removed because it degraded OPEN -- dropping the rules made every role
    unrestricted, silently. This test pins that no such switch comes back: the
    variable is set here, and loading must still raise.
    """
    broken = rules_json(
        {"role": "dba", "resource_type": "alert", "cel": "service == 'x'"}
    )
    for env in (
        {"KEEP_RESOURCE_PERMISSIONS_STRICT": "false"},
        {"KEEP_RESOURCE_PERMISSIONS_STRICT": "0"},
        {},
    ):
        assert_config_error(
            f"broken rule set with env {env}",
            KEEP_RESOURCE_PERMISSIONS=broken,
            **env,
        )


def test_describe_is_stable():
    module = fresh(
        KEEP_RESOURCE_PERMISSIONS=rules_json(
            incident_rule("dba", "service == 'postgres'"),
            preset_rule("payments-oncall", name=["payments-*"]),
        )
    )
    incident = module.get_rules_for("dba", "incident")[0]
    preset = module.get_rules_for("payments-oncall", "preset")[0]
    assert incident.describe() == "incident where service == 'postgres'"
    assert preset.describe() == "preset where name in [payments-*]"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as exc:  # noqa: BLE001 - standalone runner
                failures += 1
                print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    print()
    if failures:
        print(f"{failures} TEST(S) FAILED")
        sys.exit(1)
    print("ALL OIDC PERMISSION TESTS PASSED")
