"""
Unit tests for keep.identitymanager.rbac custom role registration.

Covers _read_custom_role_definitions(), register_role() and _load_custom_roles():
the KEEP_CUSTOM_ROLES / KEEP_CUSTOM_ROLES_FILE parsing and validation path that
turns environment configuration into role classes exposed through
get_all_roles() / get_role_by_role_name(). Both oidc_identitymanager.get_roles()
and oidc_authverifier._resolve_role() depend on this registry to recognize a
role name at all -- a role that fails to register here fails 403 at login, not
at start-up, unless KEEP_CUSTOM_ROLES_STRICT keeps its default.

Same shape (and same reload trick) as tests/test_oidc_permissions.py: the
module runs _load_custom_roles() as an import-time side effect, so every case
needs a fresh reload rather than calling a function directly.

The file is a normal pytest module and is also runnable directly
(`python3 tests/test_rbac_custom_roles.py`).
"""

import importlib
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ENV_KEYS = ("KEEP_CUSTOM_ROLES", "KEEP_CUSTOM_ROLES_FILE", "KEEP_CUSTOM_ROLES_STRICT")

# Captured once, at collection time, before any fresh() reload runs. Every
# other module that does `from keep.identitymanager.rbac import get_all_roles`
# (oidc_permissions.py, authverifierbase.py, ...) binds that name at ITS OWN
# first import -- also at collection time, to this same original instance.
# fresh() below replaces sys.modules["keep.identitymanager.rbac"] with a new
# module object each call; if that replacement is still in place when this
# file's tests finish, every module holding one of those stale bound
# references stays desynced from the registry for the rest of the pytest
# process -- e.g. oidc_permissions.build_rule()'s get_all_roles() call would
# keep reading this original, pre-fresh() instance forever, "unknown role"
# errors and all. The autouse fixture below restores the original reference
# after every test in this file so later files see a consistent world again.
_ORIGINAL_RBAC = importlib.import_module("keep.identitymanager.rbac")


@pytest.fixture(autouse=True)
def _restore_original_rbac_module():
    yield
    # Reimporting rbac doesn't just replace the sys.modules entry -- it also
    # overwrites keep.identitymanager's own `rbac` attribute (set as a side
    # effect of importing any submodule). `from keep.identitymanager import
    # rbac`-style imports (used by e.g. test_oidc_resource_resolver.py's
    # dba_role fixture) resolve through that attribute, not sys.modules, so
    # both have to be restored.
    sys.modules["keep.identitymanager.rbac"] = _ORIGINAL_RBAC
    sys.modules["keep.identitymanager"].rbac = _ORIGINAL_RBAC


def fresh(**env):
    """Reload rbac with a clean, explicit environment."""
    for key in ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(env)
    sys.modules.pop("keep.identitymanager.rbac", None)
    return importlib.import_module("keep.identitymanager.rbac")


def assert_config_error(why, **env):
    """
    Assert that loading `env` raises CustomRoleConfigurationError.

    Matched by class name rather than by identity: fresh() reloads the module,
    so each reload produces a distinct exception class object.
    """
    try:
        fresh(**env)
    except Exception as exc:  # noqa: BLE001 - identity-independent check
        assert (
            type(exc).__name__ == "CustomRoleConfigurationError"
        ), f"{why}: unexpected {type(exc).__name__}: {exc}"
        return
    raise AssertionError(f"malformed custom role config accepted: {why}")


def roles_json(*roles):
    return json.dumps(list(roles))


def role(name, scopes=("read:*",), description=None):
    definition = {"name": name, "scopes": list(scopes)}
    if description is not None:
        definition["description"] = description
    return definition


# --------------------------------------------------------------------------- #
# Built-ins are unaffected by the registry existing at all
# --------------------------------------------------------------------------- #


def test_builtin_roles_always_present():
    module = fresh()
    names = set(module.get_all_roles())
    assert names == {"admin", "noc", "webhook", "workflowrunner"}
    assert module.get_role_by_role_name("admin") is module.Admin
    assert module.get_role_by_role_name("noc") is module.Noc
    assert module.get_role_by_role_name("webhook") is module.Webhook
    assert module.get_role_by_role_name("workflowrunner") is module.WorkflowRunner


def test_unknown_role_raises_403():
    module = fresh()
    try:
        module.get_role_by_role_name("nosuchrole")
    except module.HTTPException as exc:
        assert exc.status_code == 403
        return
    raise AssertionError("unknown role did not raise HTTPException")


def test_get_all_roles_returns_a_copy():
    """Mutating the returned dict must not corrupt the live registry."""
    module = fresh()
    snapshot = module.get_all_roles()
    snapshot["admin"] = None
    snapshot["intruder"] = object()
    assert module.get_role_by_role_name("admin") is module.Admin
    assert "intruder" not in module.get_all_roles()


# --------------------------------------------------------------------------- #
# register_role: successful registration and how it is exposed
# --------------------------------------------------------------------------- #


def test_custom_role_is_registered_and_exposed():
    module = fresh(
        KEEP_CUSTOM_ROLES=roles_json(
            role("dba", ["read:*", "write:preset"], "DBA team")
        )
    )
    assert "dba" in module.get_all_roles()
    role_cls = module.get_role_by_role_name("dba")
    assert role_cls.SCOPES == ["read:*", "write:preset"]
    assert role_cls.DESCRIPTION == "DBA team"
    assert role_cls.get_name() == "dba"
    assert issubclass(role_cls, module.Role)


def test_custom_role_default_description():
    module = fresh(KEEP_CUSTOM_ROLES=roles_json(role("dba")))
    assert module.get_role_by_role_name("dba").DESCRIPTION == "custom role dba"


def test_multiple_custom_roles_all_registered():
    module = fresh(
        KEEP_CUSTOM_ROLES=roles_json(
            role("dba", ["read:*"]), role("payments-oncall", ["read:*", "write:preset"])
        )
    )
    names = set(module.get_all_roles())
    assert {"dba", "payments-oncall"} <= names
    assert module.get_role_by_role_name("payments-oncall").SCOPES == [
        "read:*",
        "write:preset",
    ]


def test_role_name_with_hyphen_underscore_survives_class_name_sanitisation():
    """
    get_name() must return the raw configured name even though the generated
    Python class attribute name cannot contain '-' or '_' as Keep's
    CamelCase convention strips them.
    """
    module = fresh(KEEP_CUSTOM_ROLES=roles_json(role("on-call_secondary")))
    role_cls = module.get_role_by_role_name("on-call_secondary")
    assert role_cls.get_name() == "on-call_secondary"


def test_class_attr_collision_does_not_clobber_first_role():
    """
    'dba-team' and 'dba_team' both sanitise to the class attribute 'DbaTeam';
    the second registration must be exposed under a different attribute name
    without silently replacing the first role's class object.
    """
    module = fresh(
        KEEP_CUSTOM_ROLES=roles_json(role("dba-team"), role("dba_team"))
    )
    first = module.get_role_by_role_name("dba-team")
    second = module.get_role_by_role_name("dba_team")
    assert first is not second
    assert first.get_name() == "dba-team"
    assert second.get_name() == "dba_team"
    assert module.DbaTeam is first
    assert module.DbaTeam2 is second


# --------------------------------------------------------------------------- #
# register_role: validation
# --------------------------------------------------------------------------- #


def test_invalid_role_names_rejected():
    for bad in ("", "DBA", "role name", "role.name", "role:name", None, 123):
        assert_config_error(f"name={bad!r}", KEEP_CUSTOM_ROLES=roles_json(role(bad)))


def test_builtin_name_collision_rejected():
    for builtin in ("admin", "noc", "webhook", "workflowrunner"):
        assert_config_error(
            f"collides with builtin {builtin}",
            KEEP_CUSTOM_ROLES=roles_json(role(builtin)),
        )


def test_duplicate_custom_role_name_rejected():
    assert_config_error(
        "same name twice",
        KEEP_CUSTOM_ROLES=roles_json(
            role("dba", ["read:*"]), role("dba", ["write:*"])
        ),
    )


def test_missing_or_invalid_scopes_rejected():
    cases = {
        "no scopes key": {"name": "dba"},
        "empty scopes list": role("dba", []),
        "scopes not a list": {"name": "dba", "scopes": "read:*"},
        "scopes is None": {"name": "dba", "scopes": None},
    }
    for why, definition in cases.items():
        assert_config_error(why, KEEP_CUSTOM_ROLES=roles_json(definition))


def test_invalid_scope_pattern_rejected():
    for bad_scope in ("read", "READ:*", "read:", ":resource", "read:My-Resource", "", 42):
        assert_config_error(
            f"scope={bad_scope!r}",
            KEEP_CUSTOM_ROLES=roles_json(role("dba", [bad_scope])),
        )


def test_role_definition_not_a_mapping_rejected():
    assert_config_error(
        "definition is a string, not a mapping",
        KEEP_CUSTOM_ROLES=roles_json("dba"),
    )


def test_register_role_called_directly_validates_too():
    """The public entry point used by tests/fixtures elsewhere must validate
    exactly like the env-var path, since it is the same function."""
    module = fresh()
    try:
        module.register_role("admin", ["read:*"])
    except module.CustomRoleConfigurationError:
        pass
    else:
        raise AssertionError("register_role() accepted a built-in name")

    role_cls = module.register_role("dba", ["read:*"], "DBA")
    assert module.get_role_by_role_name("dba") is role_cls


# --------------------------------------------------------------------------- #
# Configuration sources: inline JSON, file (YAML/JSON), and their combination
# --------------------------------------------------------------------------- #


def test_yaml_file_source():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        handle.write(
            "roles:\n"
            "  - name: dba\n"
            "    scopes: [\"read:*\"]\n"
            "    description: DBA team\n"
        )
        path = handle.name

    module = fresh(KEEP_CUSTOM_ROLES_FILE=path)
    assert module.get_role_by_role_name("dba").DESCRIPTION == "DBA team"


def test_file_and_inline_are_both_applied():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        handle.write("roles:\n  - name: from-file\n    scopes: [\"read:*\"]\n")
        path = handle.name

    module = fresh(
        KEEP_CUSTOM_ROLES_FILE=path,
        KEEP_CUSTOM_ROLES=roles_json(role("from-inline")),
    )
    names = set(module.get_all_roles())
    assert {"from-file", "from-inline"} <= names


def test_bare_list_and_roles_wrapped_dict_both_accepted():
    module_a = fresh(KEEP_CUSTOM_ROLES=roles_json(role("dba")))
    assert "dba" in module_a.get_all_roles()

    module_b = fresh(
        KEEP_CUSTOM_ROLES=json.dumps({"roles": [role("dba")]})
    )
    assert "dba" in module_b.get_all_roles()


def test_definitions_not_a_list_rejected():
    assert_config_error(
        "top-level JSON is a plain string",
        KEEP_CUSTOM_ROLES=json.dumps("dba"),
    )


def test_malformed_json_rejected():
    assert_config_error("bad json", KEEP_CUSTOM_ROLES="{not json")


def test_malformed_yaml_file_rejected():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        handle.write("roles:\n  - name: dba\n  scopes: [broken indentation\n")
        path = handle.name
    assert_config_error("malformed yaml file", KEEP_CUSTOM_ROLES_FILE=path)


def test_missing_file_rejected():
    assert_config_error(
        "file does not exist",
        KEEP_CUSTOM_ROLES_FILE="/nonexistent/keep-custom-roles.yaml",
    )


# --------------------------------------------------------------------------- #
# Strict vs. non-strict start-up behaviour
# --------------------------------------------------------------------------- #


def test_strict_is_the_default():
    broken = roles_json({"name": "admin", "scopes": ["read:*"]})
    assert_config_error("strict by default", KEEP_CUSTOM_ROLES=broken)


def test_strict_false_falls_back_when_nothing_registers():
    """A single broken definition with strict=false must not raise, and must
    leave only the built-ins registered."""
    broken = roles_json({"name": "admin", "scopes": ["read:*"]})
    module = fresh(KEEP_CUSTOM_ROLES=broken, KEEP_CUSTOM_ROLES_STRICT="false")
    assert set(module.get_all_roles()) == {"admin", "noc", "webhook", "workflowrunner"}


def test_strict_false_keeps_roles_registered_before_the_broken_one():
    """
    register_role() mutates the registry immediately, and _load_custom_roles()
    stops the loop at the first error -- it does not roll back roles that
    registered successfully earlier in the same list. So "continue with
    built-ins only" is the common case, not a guarantee: a role ahead of the
    broken definition stays registered. Pinning the actual behaviour here so a
    future change to make this transactional (or not) is a deliberate choice.
    """
    module = fresh(
        KEEP_CUSTOM_ROLES=roles_json(
            role("dba"), {"name": "admin", "scopes": ["read:*"]}
        ),
        KEEP_CUSTOM_ROLES_STRICT="false",
    )
    assert "dba" in module.get_all_roles()


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
    print("ALL RBAC CUSTOM ROLE TESTS PASSED")
