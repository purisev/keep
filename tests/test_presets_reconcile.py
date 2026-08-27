"""Tests for keep.api.core.presets_provisioning.provision_presets_from_env.

Mirrors the structure of tests/test_mapping_rules_provisioning.py -- uses real
in-memory SQLite sessions (via the `db_session` fixture from tests/conftest.py)
rather than patching DB helpers, because the provisioning function operates on
SQLModel sessions directly.

This is the file keep/api/core/presets_provisioning.py's own module docstring
and tests/test_presets_provisioning.py both point to for the database half of
provisioning. Its absence was exactly why `provision_presets_from_env()` could
reference `Session`, `select`, `core_db`, `Preset` and `PresetTagLink` without
importing any of them and still ship: every existing test either never touched
the database path (the early return) or exercised parsing/validation only, so
nothing here ever ran a NameError into a failure. See
/opt/shared/keep-preset-provisioning-defect.md.
"""

import json

import pytest
from sqlmodel import Session, select

import keep.api.core.db as db
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.core.presets_provisioning import (
    PresetProvisioningError,
    provision_presets_from_env,
)
from keep.api.models.db.preset import Preset, PresetTagLink, Tag


def _all_presets(tenant_id=SINGLE_TENANT_UUID) -> list[Preset]:
    with Session(db.engine) as session:
        return (
            session.exec(select(Preset).where(Preset.tenant_id == tenant_id))
            .unique()
            .all()
        )


def _provisioned_presets(tenant_id=SINGLE_TENANT_UUID) -> list[Preset]:
    with Session(db.engine) as session:
        return (
            session.exec(
                select(Preset).where(
                    Preset.tenant_id == tenant_id,
                    Preset.is_provisioned == True,  # noqa: E712
                )
            )
            .unique()
            .all()
        )


def _tag_names(preset_id, tenant_id=SINGLE_TENANT_UUID) -> set[str]:
    with Session(db.engine) as session:
        links = session.exec(
            select(PresetTagLink).where(
                PresetTagLink.tenant_id == tenant_id,
                PresetTagLink.preset_id == preset_id,
            )
        ).all()
        return {
            session.exec(select(Tag).where(Tag.id == link.tag_id)).first().name
            for link in links
        }


def _set_presets_env(monkeypatch, *presets):
    # KEEP_PRESETS_FILE takes precedence in _read_definitions() and, unlike
    # KEEP_PRESETS here, other test modules (tests/test_presets_provisioning.py)
    # leave it set in os.environ after their own tests finish -- clear it
    # explicitly rather than depending on running first/alone in the session.
    monkeypatch.delenv("KEEP_PRESETS_FILE", raising=False)
    monkeypatch.setenv("KEEP_PRESETS", json.dumps(list(presets)))


def test_creates_new_preset(monkeypatch, db_session):
    """Empty DB + one definition -> preset is created and marked provisioned."""
    _set_presets_env(
        monkeypatch,
        {"name": "dba-feed", "cel": "service == 'postgres'", "tags": ["dba"]},
    )

    provision_presets_from_env(SINGLE_TENANT_UUID)

    presets = _provisioned_presets()
    assert len(presets) == 1
    preset = presets[0]
    assert preset.name == "dba-feed"
    assert preset.is_provisioned is True
    assert preset.created_by == "provisioning"
    labels = {entry["label"] for entry in preset.options}
    assert labels == {"CEL", "SQL"}
    cel_entry = [e for e in preset.options if e["label"] == "CEL"][0]
    assert cel_entry["value"] == "service == 'postgres'"
    assert _tag_names(preset.id) == {"dba"}


def test_provisions_multiple_presets(monkeypatch, db_session):
    _set_presets_env(
        monkeypatch,
        {"name": "dba-feed", "cel": "service == 'postgres'"},
        {"name": "payments-feed", "cel": "service == 'billing'"},
    )

    provision_presets_from_env(SINGLE_TENANT_UUID)

    names = sorted(p.name for p in _provisioned_presets())
    assert names == ["dba-feed", "payments-feed"]


def test_is_idempotent(monkeypatch, db_session):
    """Running provisioning twice does not create duplicates or new ids."""
    _set_presets_env(monkeypatch, {"name": "dba-feed", "cel": "service == 'postgres'"})

    provision_presets_from_env(SINGLE_TENANT_UUID)
    first_ids = sorted(p.id for p in _provisioned_presets())
    assert len(first_ids) == 1

    provision_presets_from_env(SINGLE_TENANT_UUID)
    second_ids = sorted(p.id for p in _provisioned_presets())

    assert first_ids == second_ids


def test_updates_existing_provisioned_preset(monkeypatch, db_session):
    """Re-running with a changed cel/tags updates the row in place."""
    _set_presets_env(
        monkeypatch,
        {"name": "dba-feed", "cel": "service == 'postgres'", "tags": ["dba"]},
    )
    provision_presets_from_env(SINGLE_TENANT_UUID)
    original_id = _provisioned_presets()[0].id

    _set_presets_env(
        monkeypatch,
        {
            "name": "dba-feed",
            "cel": "service in ['postgres', 'patroni']",
            "tags": ["dba", "critical"],
        },
    )
    provision_presets_from_env(SINGLE_TENANT_UUID)

    presets = _provisioned_presets()
    assert len(presets) == 1
    preset = presets[0]
    assert preset.id == original_id
    cel_entry = [e for e in preset.options if e["label"] == "CEL"][0]
    assert cel_entry["value"] == "service in ['postgres', 'patroni']"
    assert _tag_names(preset.id) == {"dba", "critical"}


def test_tag_removed_from_config_is_unlinked(monkeypatch, db_session):
    """A tag dropped from the definition is unlinked, not just left stale."""
    _set_presets_env(
        monkeypatch, {"name": "dba-feed", "cel": "", "tags": ["dba", "critical"]}
    )
    provision_presets_from_env(SINGLE_TENANT_UUID)
    preset_id = _provisioned_presets()[0].id
    assert _tag_names(preset_id) == {"dba", "critical"}

    _set_presets_env(monkeypatch, {"name": "dba-feed", "cel": "", "tags": ["dba"]})
    provision_presets_from_env(SINGLE_TENANT_UUID)

    assert _tag_names(preset_id) == {"dba"}


def test_deletes_provisioned_preset_removed_from_config(monkeypatch, db_session):
    """A provisioned preset dropped from the config is deleted, tag links included."""
    _set_presets_env(
        monkeypatch,
        {"name": "dba-feed", "cel": "", "tags": ["dba"]},
        {"name": "payments-feed", "cel": ""},
    )
    provision_presets_from_env(SINGLE_TENANT_UUID)
    assert len(_provisioned_presets()) == 2
    dba_id = [p for p in _provisioned_presets() if p.name == "dba-feed"][0].id

    _set_presets_env(monkeypatch, {"name": "payments-feed", "cel": ""})
    provision_presets_from_env(SINGLE_TENANT_UUID)

    remaining = _provisioned_presets()
    assert len(remaining) == 1
    assert remaining[0].name == "payments-feed"

    with Session(db.engine) as session:
        leftover_links = session.exec(
            select(PresetTagLink).where(PresetTagLink.preset_id == dba_id)
        ).all()
        assert leftover_links == []


def test_unsetting_env_after_being_set_does_not_deprovision(monkeypatch, db_session):
    """
    Unsetting both env vars must be a no-op, NOT "reconcile against an empty
    set". Per provision_presets_from_env's own docstring: "an unconfigured
    deployment must not have its provisioned presets deleted just because the
    variables are absent" -- e.g. an operator's env got dropped by mistake
    must not silently wipe every provisioned preset for every tenant.
    """
    _set_presets_env(monkeypatch, {"name": "dba-feed", "cel": ""})
    provision_presets_from_env(SINGLE_TENANT_UUID)
    assert len(_provisioned_presets()) == 1

    monkeypatch.delenv("KEEP_PRESETS", raising=False)
    monkeypatch.delenv("KEEP_PRESETS_FILE", raising=False)
    provision_presets_from_env(SINGLE_TENANT_UUID)

    assert len(_provisioned_presets()) == 1


def test_noop_when_unconfigured_and_no_provisioned_presets(monkeypatch, db_session):
    """No env set, nothing in the DB: must not touch the database at all."""
    monkeypatch.delenv("KEEP_PRESETS", raising=False)
    monkeypatch.delenv("KEEP_PRESETS_FILE", raising=False)
    assert len(_all_presets()) == 0

    provision_presets_from_env(SINGLE_TENANT_UUID)

    assert len(_all_presets()) == 0


def test_refuses_to_adopt_non_provisioned_preset(monkeypatch, db_session):
    """A same-named preset a human made in the UI (is_provisioned=False) must
    not be silently taken over -- doing so would let the next config change
    delete somebody's own preset."""
    with Session(db.engine) as session:
        ui_preset = Preset(
            tenant_id=SINGLE_TENANT_UUID,
            name="dba-feed",
            created_by="ui-user@example.com",
            options=[{"label": "CEL", "value": "service == 'legacy'"}],
            is_provisioned=False,
        )
        session.add(ui_preset)
        session.commit()
        ui_preset_id = ui_preset.id

    _set_presets_env(monkeypatch, {"name": "dba-feed", "cel": "service == 'postgres'"})

    with pytest.raises(PresetProvisioningError):
        provision_presets_from_env(SINGLE_TENANT_UUID)

    with Session(db.engine) as session:
        preset = session.exec(
            select(Preset).where(Preset.id == ui_preset_id)
        ).first()
        assert preset is not None
        assert preset.is_provisioned is False
        cel_entry = [e for e in preset.options if e["label"] == "CEL"][0]
        assert cel_entry["value"] == "service == 'legacy'"


def test_leaves_unrelated_non_provisioned_preset_untouched(monkeypatch, db_session):
    """A UI preset whose name does NOT collide with any definition is left alone,
    including on reconciliation delete (it was never ours to delete)."""
    with Session(db.engine) as session:
        ui_preset = Preset(
            tenant_id=SINGLE_TENANT_UUID,
            name="someone-elses-feed",
            created_by="ui-user@example.com",
            options=[{"label": "CEL", "value": "service == 'whatever'"}],
            is_provisioned=False,
        )
        session.add(ui_preset)
        session.commit()
        ui_preset_id = ui_preset.id

    _set_presets_env(monkeypatch, {"name": "dba-feed", "cel": ""})
    provision_presets_from_env(SINGLE_TENANT_UUID)

    with Session(db.engine) as session:
        preset = session.exec(
            select(Preset).where(Preset.id == ui_preset_id)
        ).first()
        assert preset is not None
        assert preset.is_provisioned is False

    all_presets = _all_presets()
    assert len(all_presets) == 2  # the UI preset + the provisioned one


def test_duplicate_names_in_config_raise(monkeypatch, db_session):
    _set_presets_env(
        monkeypatch,
        {"name": "dba-feed", "cel": ""},
        {"name": "dba-feed", "cel": "service == 'postgres'"},
    )

    with pytest.raises(PresetProvisioningError):
        provision_presets_from_env(SINGLE_TENANT_UUID)

    assert len(_all_presets()) == 0


def test_static_preset_name_raises_and_touches_nothing(monkeypatch, db_session):
    """The full provisioning path also refuses Keep's built-in static name, and
    does so before mutating anything."""
    _set_presets_env(monkeypatch, {"name": "feed", "cel": ""})

    with pytest.raises(PresetProvisioningError):
        provision_presets_from_env(SINGLE_TENANT_UUID)

    assert len(_all_presets()) == 0
