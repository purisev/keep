"""
Unit tests for declarative preset provisioning.

These cover configuration reading and validation only. That half of
keep/api/core/presets_provisioning.py imports no database stack on purpose, so
it runs anywhere -- including in a CI job whose whole point is to reject a bad
configuration before it reaches a cluster.

Reconciliation itself (upsert, tag sync, and above all the deletion rules) needs
a live database and is covered by tests/test_presets_reconcile.py, which does
not run in an environment without sqlmodel.

Runnable directly: `python3 tests/test_presets_provisioning.py`.
"""

import importlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def fresh(**env):
    """Reload the provisioning module with a clean, explicit environment."""
    for key in ("KEEP_PRESETS", "KEEP_PRESETS_FILE"):
        os.environ.pop(key, None)
    os.environ.update(env)
    sys.modules.pop("keep.api.core.presets_provisioning", None)
    return importlib.import_module("keep.api.core.presets_provisioning")


def assert_invalid(why, module, definition):
    try:
        module._validate(definition)
    except Exception as exc:  # noqa: BLE001 - identity-independent check
        assert (
            type(exc).__name__ == "PresetProvisioningError"
        ), f"{why}: unexpected {type(exc).__name__}: {exc}"
        return
    raise AssertionError(f"invalid preset accepted: {why}")


def test_unconfigured_is_distinct_from_empty():
    """
    The distinction that prevents an accident: with nothing configured the
    provisioner must do nothing, not reconcile against an empty set and delete
    every provisioned preset.
    """
    module = fresh()
    definitions, source = module._read_definitions()
    assert definitions == []
    assert source is None, "unconfigured must be None, not an empty source"

    module = fresh(KEEP_PRESETS=json.dumps({"presets": []}))
    definitions, source = module._read_definitions()
    assert definitions == []
    assert source is not None, "an explicit empty list is a real configuration"


def test_minimal_definition_is_normalised():
    module = fresh()
    spec = module._validate({"name": "dba-feed", "cel": "service == 'postgres'"})
    assert spec["name"] == "dba-feed"
    assert spec["cel"] == "service == 'postgres'"
    assert spec["tags"] == []
    assert spec["is_private"] is False
    assert spec["created_by"] == module.DEFAULT_CREATED_BY


def test_options_payload_carries_both_query_labels():
    """
    PresetDto.cel_query and .sql_query select their entry by label, so both must
    be present even when the SQL half is unused.
    """
    module = fresh()
    options = module._options_for("service == 'postgres'")
    labels = {entry["label"] for entry in options}
    assert labels == {"CEL", "SQL"}
    cel = [entry for entry in options if entry["label"] == "CEL"][0]
    assert cel["value"] == "service == 'postgres'"


def test_static_preset_name_is_refused():
    """
    A provisioned preset named `feed` would be shadowed by Keep's built-in
    static preset and never resolve, so it must not be accepted silently.
    """
    module = fresh()
    for name in module.STATIC_PRESET_NAMES:
        assert_invalid(f"static name {name}", module, {"name": name, "cel": ""})


def test_validation_rejects_malformed_definitions():
    module = fresh()
    cases = {
        "not a mapping": "dba-feed",
        "missing name": {"cel": ""},
        "empty name": {"name": "   ", "cel": ""},
        "missing cel": {"name": "x"},
        "non-string cel": {"name": "x", "cel": 42},
        "tags not a list": {"name": "x", "cel": "", "tags": "dba"},
        "tag not a string": {"name": "x", "cel": "", "tags": [1]},
        "empty tag": {"name": "x", "cel": "", "tags": ["  "]},
        "non-boolean flag": {"name": "x", "cel": "", "is_private": "yes"},
    }
    for why, definition in cases.items():
        assert_invalid(why, module, definition)


def test_empty_cel_is_allowed_as_an_unfiltered_feed():
    """Unlike a permission rule, an empty query is a legitimate preset."""
    module = fresh()
    assert module._validate({"name": "everything", "cel": ""})["cel"] == ""


def test_yaml_file_and_inline_are_both_read():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        handle.write(
            "presets:\n"
            "  - name: dba-feed\n"
            "    cel: \"service == 'postgres'\"\n"
            "    tags: [dba]\n"
        )
        path = handle.name

    module = fresh(
        KEEP_PRESETS_FILE=path,
        KEEP_PRESETS=json.dumps(
            [{"name": "payments-feed", "cel": "service == 'billing'"}]
        ),
    )
    definitions, source = module._read_definitions()
    names = [module._validate(d)["name"] for d in definitions]
    assert names == ["dba-feed", "payments-feed"], names
    assert path in source and module.INLINE_SOURCE in source


def test_malformed_sources_raise():
    module_name = "keep.api.core.presets_provisioning"
    for why, env in {
        "bad json": {"KEEP_PRESETS": "{not json"},
        "not a list": {"KEEP_PRESETS": json.dumps({"presets": "dba"})},
        "missing file": {"KEEP_PRESETS_FILE": "/nonexistent/presets.yaml"},
    }.items():
        module = fresh(**env)
        try:
            module._read_definitions()
        except Exception as exc:  # noqa: BLE001
            assert (
                type(exc).__name__ == "PresetProvisioningError"
            ), f"{why}: unexpected {type(exc).__name__}: {exc}"
            continue
        raise AssertionError(f"malformed source accepted: {why} ({module_name})")


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
    print("ALL PRESET PROVISIONING TESTS PASSED")
